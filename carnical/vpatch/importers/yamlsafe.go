// SPDX-License-Identifier: Apache-2.0

package importers

import (
	"bytes"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"time"
	"unicode/utf8"

	"github.com/goccy/go-yaml"
	"github.com/goccy/go-yaml/ast"
	"github.com/goccy/go-yaml/parser"
)

// Errors from DecodeYAML. Each is also a skip reason in the reports.
var (
	ErrYAMLTooLarge   = errors.New("yaml-too-large")
	ErrYAMLInvalid    = errors.New("yaml-invalid")
	ErrYAMLUnsafe     = errors.New("yaml-unsafe")
	ErrYAMLEmpty      = errors.New("yaml-empty")
	ErrYAMLMultiple   = errors.New("yaml-multiple-documents")
	ErrYAMLNotUTF8    = errors.New("yaml-not-utf8")
	ErrYAMLSlow       = errors.New("yaml-too-slow")
	ErrYAMLInternal   = errors.New("yaml-internal-error")
	errYAMLComplexity = errors.New("yaml-too-complex")
)

// maxYAMLNodes bounds how many nodes a document may have. A 1 MiB document of "- a" lines has about 350,000.
const maxYAMLNodes = 500000

// DecodeYAML reads one YAML document into plain Go values (map[string]any, []any, string, bool, numbers, nil).
//
// The rule files this reads are untrusted, and the YAML library's cost is not linear in the size of its input: measured here, 64 KiB
// of nested "[" takes about 9 seconds and 64 KiB of "- " about 2 (four times as long for each doubling). So before the library
// sees a document it is refused if it is larger than lim.MaxDocBytes, is not UTF-8, holds a NUL byte, or has a line shaped like
// those inputs (see yamlPreScan). The parsed tree is refused, before anything is expanded, if it has more than one document, uses
// anchors, aliases or merge keys (the "billion laughs" shape), is nested more deeply than lim.MaxNesting*4 levels, or has more
// than 500,000 nodes. No rule feed this reads uses anchors. Last, decoding runs under a time limit, and no more than four
// decodes run at once. The same deadline bounds waiting for a parser slot and waiting for its result; workers that time out
// retain their slots until they finish, so outstanding parser work remains bounded.
func DecodeYAML(data []byte, lim Limits) (any, error) {
	lim = lim.Normalize()
	if len(data) > lim.MaxDocBytes {
		return nil, ErrYAMLTooLarge
	}
	if !utf8.Valid(data) {
		return nil, ErrYAMLNotUTF8
	}
	if bytes.IndexByte(data, 0) >= 0 {
		return nil, fmt.Errorf("%w: NUL byte", ErrYAMLInvalid)
	}
	if err := yamlPreScan(data); err != nil {
		return nil, err
	}
	type result struct {
		v   any
		err error
	}
	timer := time.NewTimer(yamlTimeout)
	defer timer.Stop()
	select {
	case yamlSlots <- struct{}{}: // includes timed-out parsers that are still running
	case <-timer.C:
		return nil, ErrYAMLSlow
	}
	done := make(chan result, 1)
	go func() {
		defer func() { <-yamlSlots }()
		defer func() {
			if r := recover(); r != nil {
				done <- result{nil, ErrYAMLInternal}
			}
		}()
		v, err := decodeYAML(data, lim)
		done <- result{v, err}
	}()
	select {
	case r := <-done:
		return r.v, r.err
	case <-timer.C:
		return nil, ErrYAMLSlow
	}
}

const (
	yamlTimeout       = 10 * time.Second
	yamlMaxConcurrent = 4
)

var yamlSlots = make(chan struct{}, yamlMaxConcurrent)

func decodeYAML(data []byte, lim Limits) (any, error) {
	file, err := parser.ParseBytes(data, 0)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrYAMLInvalid, firstLine(err.Error()))
	}
	switch len(file.Docs) {
	case 0:
		return nil, ErrYAMLEmpty
	case 1:
	default:
		return nil, ErrYAMLMultiple
	}
	body := file.Docs[0].Body
	if body == nil {
		return nil, ErrYAMLEmpty
	}
	st := &safetyState{}
	ast.Walk(&safetyVisitor{st: st, maxDepth: lim.MaxNesting * 4}, body)
	if st.unsafe {
		return nil, ErrYAMLUnsafe
	}
	if st.complex {
		return nil, errYAMLComplexity
	}
	var out any
	if err := yaml.NodeToValue(body, &out); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrYAMLInvalid, firstLine(err.Error()))
	}
	return out, nil
}

var blockScalarRe = regexp.MustCompile(`(?:^|[:\-])\s*[|>][+-]?[0-9]?[+-]?\s*(?:#.*)?$`)

// yamlPreScan refuses the line shapes that make the YAML library slow: deep indentation, a long run of "- " (nested sequences),
// deep or very many flow brackets, and thousands of quotes or ": " on one line. Real rule files have none of these. Lines inside a
// block scalar ("key: |") are free text and are not looked at, except that they count toward the size limit already applied.
func yamlPreScan(data []byte) error {
	blockIndent := -1
	for len(data) > 0 {
		var line []byte
		if i := bytes.IndexByte(data, byteNL); i >= 0 {
			line, data = data[:i], data[i+1:]
		} else {
			line, data = data, nil
		}
		indent := 0
		for indent < len(line) && line[indent] == ' ' {
			indent++
		}
		if indent > yamlMaxIndent {
			return fmt.Errorf("%w: indentation", ErrYAMLUnsafe)
		}
		rest := line[indent:]
		if blockIndent >= 0 {
			if len(bytes.TrimSpace(rest)) == 0 || indent > blockIndent {
				continue // inside a block scalar
			}
			blockIndent = -1
		}
		if len(rest) == 0 || rest[0] == '#' {
			continue
		}
		dashes := 0
		for len(rest) >= 2 && rest[0] == '-' && rest[1] == ' ' {
			dashes++
			rest = rest[2:]
			for len(rest) > 0 && rest[0] == ' ' {
				rest = rest[1:]
			}
		}
		if dashes > yamlMaxDashes {
			return fmt.Errorf("%w: nested sequence markers", ErrYAMLUnsafe)
		}
		if blockScalarRe.Match(line) {
			blockIndent = indent
		}
		depth, maxDepth, tokens := 0, 0, 0
		if bytes.Count(rest, []byte{byteDoubleQuote})+bytes.Count(rest, []byte{byteSingleQuote}) > yamlMaxQuotesPerLine {
			return fmt.Errorf("%w: quote characters", ErrYAMLUnsafe)
		}
		var quote byte
		for i := 0; i < len(rest); i++ {
			c := rest[i]
			if quote != 0 {
				switch {
				case quote == byteDoubleQuote && c == byteBackslash:
					i++
				case c == quote:
					if quote == byteSingleQuote && i+1 < len(rest) && rest[i+1] == byteSingleQuote {
						i++
					} else {
						quote = 0
					}
				}
				continue
			}
			switch c {
			case byteDoubleQuote, byteSingleQuote:
				// A quote opens a quoted scalar only at the start of a value; elsewhere it is an ordinary character.
				if i == 0 || rest[i-1] == ' ' || rest[i-1] == '[' || rest[i-1] == '{' || rest[i-1] == ',' || rest[i-1] == ':' {
					quote = c
					tokens++
				}
			case '[', '{':
				depth++
				tokens++
				if depth > maxDepth {
					maxDepth = depth
				}
			case ']', '}':
				if depth > 0 {
					depth--
				}
			case ':':
				if i+1 >= len(rest) || rest[i+1] == ' ' {
					tokens++
				}
			case '#':
				if i > 0 && rest[i-1] == ' ' {
					i = len(rest) // a comment
				}
			}
		}
		if maxDepth > yamlMaxFlowDepth || tokens > yamlMaxTokensPerLine {
			return fmt.Errorf("%w: flow nesting or token count", ErrYAMLUnsafe)
		}
	}
	return nil
}

// Byte values written as numbers, so that no backslash escape is needed in this file.
const (
	byteNL          = 10
	byteBackslash   = 0x5c
	byteSingleQuote = 0x27
	byteDoubleQuote = 0x22
)

const (
	yamlMaxIndent        = 96
	yamlMaxQuotesPerLine = 4096
	yamlMaxDashes        = 8
	yamlMaxFlowDepth     = 24
	yamlMaxTokensPerLine = 2000
)

func firstLine(s string) string {
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			s = s[:i]
			break
		}
	}
	if len(s) > 120 {
		s = s[:120]
	}
	return SafeName(s)
}

type safetyState struct {
	nodes   int
	unsafe  bool
	complex bool
}

type safetyVisitor struct {
	st       *safetyState
	depth    int
	maxDepth int
}

func (v *safetyVisitor) Visit(n ast.Node) ast.Visitor {
	if v.st.unsafe || v.st.complex {
		return nil
	}
	v.st.nodes++
	if v.st.nodes > maxYAMLNodes || v.depth > v.maxDepth {
		v.st.complex = true
		return nil
	}
	switch n.(type) {
	case *ast.AnchorNode, *ast.AliasNode, *ast.MergeKeyNode:
		v.st.unsafe = true
		return nil
	}
	return &safetyVisitor{st: v.st, depth: v.depth + 1, maxDepth: v.maxDepth}
}

// AsMap returns v as a string-keyed map, or false.
func AsMap(v any) (map[string]any, bool) {
	switch m := v.(type) {
	case map[string]any:
		return m, true
	case map[any]any:
		out := make(map[string]any, len(m))
		for k, x := range m {
			out[fmt.Sprint(k)] = x
		}
		return out, true
	}
	return nil, false
}

// AsList returns v as a list, or false.
func AsList(v any) ([]any, bool) {
	l, ok := v.([]any)
	return l, ok
}

// AsString returns a scalar as a string: strings as they are, numbers and booleans in their usual text form. Maps, lists and nil
// are not scalars.
func AsString(v any) (string, bool) {
	switch x := v.(type) {
	case string:
		return x, true
	case bool:
		return strconv.FormatBool(x), true
	case int:
		return strconv.Itoa(x), true
	case int64:
		return strconv.FormatInt(x, 10), true
	case uint64:
		return strconv.FormatUint(x, 10), true
	case float64:
		return strconv.FormatFloat(x, 'f', -1, 64), true
	}
	return "", false
}

// AsStrings returns a scalar as a one-element list, or a list of scalars as a list of strings; items that are not scalars are
// dropped and counted in bad.
func AsStrings(v any) (out []string, bad int) {
	if s, ok := AsString(v); ok {
		return []string{s}, 0
	}
	l, ok := AsList(v)
	if !ok {
		if v != nil {
			bad++
		}
		return nil, bad
	}
	for _, x := range l {
		s, ok := AsString(x)
		if !ok {
			bad++
			continue
		}
		out = append(out, s)
	}
	return out, bad
}
