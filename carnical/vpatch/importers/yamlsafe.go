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
	"github.com/goccy/go-yaml/lexer"
	"github.com/goccy/go-yaml/parser"
	"github.com/goccy/go-yaml/token"
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

// DecodeYAML reads one YAML document into plain Go values (map[string]any, []any, string, bool, Number, nil).
//
// The rule files this reads are untrusted, and the YAML library's cost is not linear in the size of its input: measured here, 64 KiB
// of nested "[" takes about 9 seconds and 64 KiB of "- " about 2 (four times as long for each doubling). So before the library
// sees a document it is refused if it is larger than lim.MaxDocBytes, is not UTF-8, holds a NUL byte, or has a line shaped like
// those inputs (see yamlPreScan). The library's tokens are then checked before its parser sees them (see yamlTokenScan), because
// the nesting that costs the parser its time can be spread over lines that a check of one line at a time does not connect. The
// parsed tree is refused, before anything is expanded, if it has more than one document, uses anchors, aliases or merge keys (the
// "billion laughs" shape), is nested more deeply than lim.MaxNesting*4 levels, or has more than 500,000 nodes. No rule feed this
// reads uses anchors. Last, decoding runs under a time limit, and no more than four decodes run at once. The same deadline bounds
// waiting for a parser slot and waiting for its result; workers that time out retain their slots until they finish, so
// outstanding parser work remains bounded.
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
	// Tokenizing takes time in proportion to the input; parsing does not. So the tokens are checked first, and parsed only then.
	tokens := lexer.Tokenize(string(data))
	if err := yamlTokenScan(tokens); err != nil {
		return nil, err
	}
	file, err := parser.Parse(tokens, 0)
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
	out, err := (&plainDecoder{lib: yaml.NewDecoder(&bytes.Buffer{})}).value(body)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrYAMLInvalid, firstLine(err.Error()))
	}
	return out, nil
}

// Number is a number in a decoded document. CrowdSec and nuclei read most fields into Go strings, which get the text as written
// (1.10, 010, 0x41); a field they read as an untyped value gets the number the YAML library reads (1.1, 8, 65).
type Number struct {
	Text  string
	Value any // int64, uint64 or float64
}

// plainDecoder converts a parsed tree as the library's NodeToValue does, except that a number becomes a Number.
type plainDecoder struct {
	lib *yaml.Decoder
}

func (d *plainDecoder) value(n ast.Node) (any, error) {
	switch x := n.(type) {
	case nil:
		return nil, nil
	case *ast.IntegerNode, *ast.FloatNode, *ast.InfinityNode, *ast.NanNode:
		v, err := d.libValue(x)
		if err != nil {
			return nil, err
		}
		return Number{Text: x.GetToken().Value, Value: v}, nil
	case *ast.MappingNode:
		m := make(map[string]any, len(x.Values))
		for _, kv := range x.Values {
			if err := d.setPair(m, kv); err != nil {
				return nil, err
			}
		}
		return m, nil
	case *ast.MappingValueNode:
		m := map[string]any{}
		if err := d.setPair(m, x); err != nil {
			return nil, err
		}
		return m, nil
	case *ast.SequenceNode:
		l := make([]any, 0, len(x.Values))
		for _, e := range x.Values {
			v, err := d.value(e)
			if err != nil {
				return nil, err
			}
			l = append(l, v)
		}
		return l, nil
	}
	return d.libValue(n) // strings, booleans, nulls, block scalars and tagged nodes, as the library reads them
}

// setPair adds one entry to m, with the key named as the library names it.
func (d *plainDecoder) setPair(m map[string]any, kv *ast.MappingValueNode) error {
	k, err := d.libValue(kv.Key)
	if err != nil {
		return err
	}
	v, err := d.value(kv.Value)
	if err != nil {
		return err
	}
	switch key := k.(type) {
	case nil:
		m["null"] = v
	case string:
		m[key] = v
	default:
		m[fmt.Sprint(key)] = v
	}
	return nil
}

func (d *plainDecoder) libValue(n ast.Node) (any, error) {
	if n == nil {
		return nil, nil
	}
	var v any
	err := d.lib.DecodeFromNode(n, &v)
	return v, err
}

// blockScalarHeader is a block scalar's header: "|" or ">", then at most an indentation digit and a chomping sign, in either order.
var blockScalarHeader = regexp.MustCompile(`^[|>](?:[1-9][+-]?|[+-][1-9]?)?$`)

// yamlPreScan refuses the line shapes that make the YAML library slow: deep indentation, a long run of "- " (nested sequences),
// deep or very many flow brackets, and thousands of quotes or ": " on one line. Real rule files have none of these. Lines inside a
// block scalar ("key: |") are free text and are not looked at, except that they count toward the size limit already applied.
//
// A line opens a block scalar only where YAML reads one: the header ends what the line says outside quotes and comments, and it
// stands alone or follows the line's one "key:". So "a: #: |" is the key a and a comment, as it is to the library, and does not
// stop the lines after it from being checked.
func yamlPreScan(data []byte) error {
	blockIndent := -1
	for len(data) > 0 {
		var line []byte
		if i := bytes.IndexAny(data, "\r\n"); i >= 0 {
			cr := data[i] == '\r'
			line, data = data[:i], data[i+1:]
			if cr && len(data) > 0 && data[0] == '\n' {
				data = data[1:] // CRLF is one YAML line break; CR and LF also stand alone.
			}
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
		depth, maxDepth, tokens := 0, 0, 0
		if bytes.Count(rest, []byte{byteDoubleQuote})+bytes.Count(rest, []byte{byteSingleQuote}) > yamlMaxQuotesPerLine {
			return fmt.Errorf("%w: quote characters", ErrYAMLUnsafe)
		}
		var quote byte
		code := len(rest) // where what the line says ends: the start of its comment, or its end
		keys := 0         // the ": " indicators outside quotes
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
				if i == 0 || isYAMLSpace(rest[i-1]) || rest[i-1] == '[' || rest[i-1] == '{' || rest[i-1] == ',' || rest[i-1] == ':' {
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
				if i+1 >= len(rest) || isYAMLSpace(rest[i+1]) {
					tokens++
					keys++
				}
			case '#':
				if i == 0 || isYAMLSpace(rest[i-1]) { // at 0 it follows a "- " marker
					code = i // a comment
					i = len(rest)
				}
			}
		}
		if maxDepth > yamlMaxFlowDepth || tokens > yamlMaxTokensPerLine {
			return fmt.Errorf("%w: flow nesting or token count", ErrYAMLUnsafe)
		}
		if quote == 0 && depth == 0 && opensBlockScalar(rest[:code], keys) {
			// The text is the lines indented more than the node the scalar belongs to: the sequence entry ("- |"), or the key, which
			// stands to the right of any "- " in front of it.
			blockIndent = indent
			if keys == 1 {
				blockIndent = len(line) - len(rest)
			}
		}
	}
	return nil
}

// opensBlockScalar reports whether code, a line's content outside its comment with the "- " markers taken off, ends in a block
// scalar header that YAML reads as one: alone, or after the line's only "key:".
func opensBlockScalar(code []byte, keys int) bool {
	end := len(code)
	for end > 0 && isYAMLSpace(code[end-1]) {
		end--
	}
	cut := end
	for cut > 0 && !isYAMLSpace(code[cut-1]) {
		cut--
	}
	if !blockScalarHeader.Match(code[cut:end]) {
		return false
	}
	for cut > 0 && isYAMLSpace(code[cut-1]) {
		cut--
	}
	if cut == 0 {
		return keys == 0
	}
	return keys == 1 && code[cut-1] == ':'
}

func isYAMLSpace(c byte) bool { return c == ' ' || c == byteTab }

// yamlTokenScan refuses a document whose tokens nest flow collections ("[", "{") more deeply than one line of the pre-scan may,
// counted over the whole document, or that open more than yamlMaxDashes block sequences on one line. These are what the parser
// takes more than linear time over, and the tokens are exactly what it will read, whatever comments, quotes and line breaks
// surround them.
func yamlTokenScan(tokens token.Tokens) error {
	depth := 0
	line, dashes := 0, 0
	for _, tk := range tokens {
		switch tk.Type {
		case token.SequenceStartType, token.MappingStartType:
			depth++
			if depth > yamlMaxFlowDepth {
				return fmt.Errorf("%w: flow nesting", ErrYAMLUnsafe)
			}
		case token.SequenceEndType, token.MappingEndType:
			if depth > 0 {
				depth--
			}
		case token.SequenceEntryType:
			if tk.Position == nil {
				continue
			}
			if tk.Position.Line != line {
				line, dashes = tk.Position.Line, 0
			}
			dashes++
			if dashes > yamlMaxDashes {
				return fmt.Errorf("%w: nested sequence markers", ErrYAMLUnsafe)
			}
		}
	}
	return nil
}

// Byte values written as numbers, so that no backslash escape is needed in this file.
const (
	byteTab         = 9
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

// AsString returns a scalar as a string: strings as they are, a Number as it is written, other numbers and booleans in their usual
// text form. Maps, lists and nil are not scalars.
func AsString(v any) (string, bool) {
	switch x := v.(type) {
	case string:
		return x, true
	case Number:
		return x.Text, true
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

// Untyped returns v as a source engine sees a field it reads as an untyped value: a Number, also one in a list, is its value.
func Untyped(v any) any {
	switch x := v.(type) {
	case Number:
		return x.Value
	case []any:
		out := make([]any, len(x))
		for i, e := range x {
			out[i] = Untyped(e)
		}
		return out
	}
	return v
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
