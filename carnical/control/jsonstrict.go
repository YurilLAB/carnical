// SPDX-License-Identifier: Apache-2.0

package control

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"reflect"
	"strings"
	"unicode/utf8"
)

// Two parsers can read the same JSON text differently when it has a repeated key, bad UTF-8 or a byte-order mark,
// and an attacker uses the difference. Everything this package reads, and every policy document it stores, goes
// through checkJSON first, so there is only one way to read it.

var (
	errJSONSyntax = errors.New("not valid JSON")
	errJSONUTF8   = errors.New("not valid UTF-8")
	errJSONDup    = errors.New("a key appears twice in one object")
	errJSONDepth  = errors.New("nested too deeply")
	errJSONRoot   = errors.New("not a JSON object")
	errJSONTrail  = errors.New("text after the JSON value")
)

// checkJSON verifies that b is exactly one JSON object, in valid UTF-8, with no repeated key in any object, nested no
// deeper than maxDepth, and nothing after it but white space. It does not interpret the content.
func checkJSON(b []byte, maxDepth int) error {
	if !utf8.Valid(b) {
		return errJSONUTF8
	}
	b = bytes.TrimLeft(b, " \t\r\n")
	if len(b) == 0 || b[0] != '{' {
		if len(b) == 0 || !json.Valid(b) {
			return errJSONSyntax
		}
		return errJSONRoot
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	type frame struct {
		keys    map[string]struct{} // non-nil for an object
		wantKey bool
	}
	var stack []frame
	started := false
	for {
		tok, err := dec.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return errJSONSyntax
		}
		isKey := false
		if n := len(stack); n > 0 && stack[n-1].keys != nil && stack[n-1].wantKey {
			isKey = true
		}
		switch v := tok.(type) {
		case json.Delim:
			switch v {
			case '{', '[':
				if len(stack) >= maxDepth {
					return errJSONDepth
				}
				if n := len(stack); n > 0 && stack[n-1].keys != nil {
					stack[n-1].wantKey = true // after the value this container is, the next token is a key
				}
				f := frame{}
				if v == '{' {
					f.keys, f.wantKey = map[string]struct{}{}, true
				}
				stack = append(stack, f)
				started = true
			case '}', ']':
				stack = stack[:len(stack)-1]
			}
		case string:
			if isKey {
				f := &stack[len(stack)-1]
				if _, dup := f.keys[v]; dup {
					return errJSONDup
				}
				f.keys[v] = struct{}{}
				f.wantKey = false
			} else if n := len(stack); n > 0 && stack[n-1].keys != nil {
				stack[n-1].wantKey = true
			}
		default: // number, bool, null
			if n := len(stack); n > 0 && stack[n-1].keys != nil {
				stack[n-1].wantKey = true
			}
		}
		if started && len(stack) == 0 {
			// the top-level value is complete: only white space may follow
			if _, err := dec.Token(); err != io.EOF {
				return errJSONTrail
			}
			return nil
		}
	}
	return errJSONSyntax
}

var errJSONField = errors.New("a field is not one this request has")

// decodeEnvelope reads one of the API's own request bodies into dst: it must pass checkJSON (depth 16), and then
// has no field dst does not name, spelled exactly as dst names it, and no trailing data.
//
// The exact spelling matters: encoding/json matches a key to a field without regard to case, so {"REVISION": 2} would be
// read as "revision" by Go and as an unknown field by another reader. The body is signed, so the UI's own reader is not
// in the way, but a request has one meaning only if every reader gives it that one.
func decodeEnvelope(b []byte, dst any) error {
	if err := checkJSON(b, 16); err != nil {
		return err
	}
	allowed := jsonFieldNames(dst)
	dec := json.NewDecoder(bytes.NewReader(b))
	if _, err := dec.Token(); err != nil { // the opening brace: checkJSON has shown there is one
		return errJSONSyntax
	}
	for dec.More() {
		k, err := dec.Token()
		key, isString := k.(string)
		if err != nil || !isString {
			return errJSONSyntax
		}
		if !allowed[key] {
			return errJSONField
		}
		var skip json.RawMessage
		if err := dec.Decode(&skip); err != nil {
			return errJSONSyntax
		}
	}
	dec = json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return errJSONSyntax
	}
	if dec.More() {
		return errJSONTrail
	}
	return nil
}

// jsonFieldNames lists the names dst's fields have in JSON.
func jsonFieldNames(dst any) map[string]bool {
	out := map[string]bool{}
	t := reflect.TypeOf(dst)
	for t != nil && t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	if t == nil || t.Kind() != reflect.Struct {
		return out
	}
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		name, _, _ := strings.Cut(f.Tag.Get("json"), ",")
		if name == "-" || !f.IsExported() {
			continue
		}
		if name == "" {
			name = f.Name
		}
		out[name] = true
	}
	return out
}
