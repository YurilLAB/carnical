// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"unicode/utf8"
)

// scanLimits are what a JSON document is checked against before anything is decoded from it.
type scanLimits struct {
	maxDepth  int
	maxTokens int
	maxString int
	// keyOK, if not nil, says whether an object's name is acceptable.
	keyOK func(string) bool
	// nullOK, if not nil, says whether a null may stand at the path of names that leads to it (names of objects only;
	// an array adds nothing to the path). Without it, null is refused everywhere.
	nullOK func(path []string) bool
}

type scanFrame struct {
	object bool
	names  map[string]struct{}
	key    bool // the next string in this object is a name
	name   string
}

// scanJSON reads a document once and refuses what the typed decoder would let through quietly: invalid UTF-8 (which
// encoding/json replaces with U+FFFD), a repeated name in an object (it keeps the last, so two readers that keep different
// ones read different documents), nesting past a limit, an enormous number of tokens, a very long string or number, and
// null where the schema has a value (it leaves the field as it was). The messages say what is wrong and never repeat what
// the document holds. A document that passes is valid JSON with one top-level value.
func scanJSON(data []byte, lim scanLimits) error {
	if !utf8.Valid(data) {
		return errors.New("the text is not valid UTF-8")
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	var stack []scanFrame
	tokens, top := 0, 0
	for {
		t, err := dec.Token()
		if errors.Is(err, io.EOF) {
			if len(stack) != 0 || top == 0 {
				return errors.New("the document ends too early")
			}
			return nil
		}
		if err != nil {
			return errors.New("not valid JSON")
		}
		tokens++
		if tokens > lim.maxTokens {
			return fmt.Errorf("more than %d values", lim.maxTokens)
		}
		inObject := len(stack) > 0 && stack[len(stack)-1].object
		valueDone := func() {
			if inObject {
				stack[len(stack)-1].key = true
			}
		}
		if len(stack) == 0 {
			top++
			if top > 1 {
				return errors.New("more than one value in the document")
			}
		}
		switch tok := t.(type) {
		case json.Delim:
			switch tok {
			case '{', '[':
				if len(stack) >= lim.maxDepth {
					return fmt.Errorf("nested deeper than %d levels", lim.maxDepth)
				}
				stack = append(stack, scanFrame{object: tok == '{', names: map[string]struct{}{}, key: tok == '{'})
			default:
				stack = stack[:len(stack)-1]
				if len(stack) > 0 && stack[len(stack)-1].object {
					stack[len(stack)-1].key = true
				}
			}
		case string:
			if len(tok) > lim.maxString {
				return fmt.Errorf("a string longer than %d bytes", lim.maxString)
			}
			if inObject && stack[len(stack)-1].key {
				f := &stack[len(stack)-1]
				if _, dup := f.names[tok]; dup {
					return errors.New("a field is given twice")
				}
				if lim.keyOK != nil && !lim.keyOK(tok) {
					return errors.New("a field name that is not allowed here")
				}
				f.names[tok] = struct{}{}
				f.key, f.name = false, tok
				continue
			}
			valueDone()
		case json.Number:
			if len(tok) > 32 {
				return errors.New("a number with more than 32 characters")
			}
			valueDone()
		case nil:
			if lim.nullOK == nil || !lim.nullOK(framePath(stack)) {
				return errors.New("null where a value is needed")
			}
			valueDone()
		default: // true, false
			valueDone()
		}
	}
}

// framePath is the names of the objects that lead to the value being read.
func framePath(stack []scanFrame) []string {
	var p []string
	for _, f := range stack {
		if f.object {
			p = append(p, f.name)
		}
	}
	return p
}

// sectionKeyOK is the form of a field name inside a section another package owns: printable ASCII without a quote or a
// backslash, 1 to MaxSectionKeyBytes of it. Names such as "/api/v1/users" or "application/json" are fine; a name with a
// control character, a bidirectional override or invalid UTF-8 is how a name is made to look like another.
func sectionKeyOK(k string) bool {
	if len(k) == 0 || len(k) > MaxSectionKeyBytes {
		return false
	}
	for i := 0; i < len(k); i++ {
		if c := k[i]; c < 0x21 || c > 0x7e || c == '"' || c == '\\' {
			return false
		}
	}
	return true
}

// checkSection applies the checks every section another package owns gets from here.
func checkSection(raw json.RawMessage) error {
	if len(raw) > MaxSectionBytes {
		return fmt.Errorf("larger than %d KiB", MaxSectionBytes>>10)
	}
	err := scanJSON(raw, scanLimits{maxDepth: MaxSectionDepth, maxTokens: MaxSectionNodes, maxString: MaxStringBytes, keyOK: sectionKeyOK,
		nullOK: func([]string) bool { return true }})
	if err != nil {
		return err
	}
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || trimmed[0] != '{' {
		return errors.New("must be an object")
	}
	return nil
}

// canonicalJSON writes a JSON document in one fixed form: no white space, object names in byte order, strings as
// encoding/json writes them, numbers as they were spelled. The same data always gives the same bytes. The document must
// already have passed scanJSON, but it is limited again here, so that it cannot be made to recurse without end.
func canonicalJSON(raw []byte) ([]byte, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, errors.New("not valid JSON")
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, errors.New("more than one value")
	}
	var b bytes.Buffer
	if err := writeCanonical(&b, v, 0); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

func writeCanonical(b *bytes.Buffer, v any, depth int) error {
	if depth > 64 {
		return errors.New("nested too deeply")
	}
	switch x := v.(type) {
	case nil:
		b.WriteString("null")
	case bool:
		if x {
			b.WriteString("true")
		} else {
			b.WriteString("false")
		}
	case json.Number:
		b.WriteString(x.String())
	case string:
		out, err := json.Marshal(x)
		if err != nil {
			return err
		}
		b.Write(out)
	case []any:
		b.WriteByte('[')
		for i, e := range x {
			if i > 0 {
				b.WriteByte(',')
			}
			if err := writeCanonical(b, e, depth+1); err != nil {
				return err
			}
		}
		b.WriteByte(']')
	case map[string]any:
		names := make([]string, 0, len(x))
		for k := range x {
			names = append(names, k)
		}
		sort.Strings(names)
		b.WriteByte('{')
		for i, k := range names {
			if i > 0 {
				b.WriteByte(',')
			}
			out, err := json.Marshal(k)
			if err != nil {
				return err
			}
			b.Write(out)
			b.WriteByte(':')
			if err := writeCanonical(b, x[k], depth+1); err != nil {
				return err
			}
		}
		b.WriteByte('}')
	default:
		return fmt.Errorf("unexpected %T", v)
	}
	return nil
}

// safeName makes a field name from an error message fit to show: printable ASCII, cut to 40 characters.
func safeName(s string) string {
	var b strings.Builder
	for _, r := range s {
		if b.Len() >= 40 {
			b.WriteString("...")
			break
		}
		if r >= 0x21 && r <= 0x7e && r != '"' && r != '\\' {
			b.WriteRune(r)
		} else {
			b.WriteByte('?')
		}
	}
	return b.String()
}
