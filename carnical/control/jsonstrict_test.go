// SPDX-License-Identifier: Apache-2.0

package control

import (
	"strings"
	"testing"
)

func TestCheckJSON(t *testing.T) {
	deep := func(n int) string { return strings.Repeat(`{"a":`, n) + "1" + strings.Repeat("}", n) }
	deepArr := func(n int) string { return `{"a":` + strings.Repeat("[", n) + strings.Repeat("]", n) + "}" }
	rows := []struct {
		name string
		in   string
		ok   bool
	}{
		{"empty object", `{}`, true},
		{"simple", `{"mode":"block","threshold":5}`, true},
		{"white space around", " \n\t{\"a\":1}\r\n ", true},
		{"nested objects and arrays", `{"a":{"b":[1,2,{"c":null}]},"d":[[],[{}]]}`, true},
		{"same key in different objects", `{"a":{"x":1},"b":{"x":2},"c":[{"x":3},{"x":4}]}`, true},
		{"same key as a string value", `{"a":"a","b":"a"}`, true},
		{"unicode and escaped surrogates", `{"é":"日本語","emoji":"` + esc + `ud83d` + esc + `ude00"}`, true},
		{"numbers", `{"a":-1.5e+10,"b":0,"c":123456789012345678901234567890}`, true},
		{"depth exactly 64", deep(64), true},
		{"depth 65", deep(65), false},
		{"depth through arrays 64", deepArr(63), true},
		{"depth through arrays 65", deepArr(65), false},
		{"empty", ``, false},
		{"only white space", "  \n", false},
		{"not JSON", `hello`, false},
		{"array root", `[1,2]`, false},
		{"string root", `"a"`, false},
		{"number root", `1`, false},
		{"null root", `null`, false},
		{"duplicate key", `{"a":1,"a":2}`, false},
		{"duplicate key, different values", `{"a":1,"b":2,"a":{"x":1}}`, false},
		{"duplicate key in a nested object", `{"o":{"k":1,"k":2}}`, false},
		{"duplicate key in an object in an array", `{"o":[{"k":1,"k":2}]}`, false},
		{"duplicate key after a nested value", `{"a":{"x":1},"a":3}`, false},
		{"duplicate key spelled with an escape", `{"a":1,"` + esc + `u0061":2}`, false},
		{"a lone surrogate escape is still one string", `{"a":"` + esc + `ud800"}`, true},
		{"trailing comma", `{"a":1,}`, false},
		{"missing comma", `{"a":1 "b":2}`, false},
		{"single quotes", `{'a':1}`, false},
		{"unquoted key", `{a:1}`, false},
		{"trailing garbage", `{"a":1} x`, false},
		{"two values", `{"a":1}{"b":2}`, false},
		{"two values with space", `{"a":1} {"b":2}`, false},
		{"unterminated", `{"a":1`, false},
		{"unterminated string", `{"a":"x}`, false},
		{"a byte-order mark", "\xef\xbb\xbf{\"a\":1}", false},
		{"invalid UTF-8 in a string", "{\"a\":\"\xff\"}", false},
		{"invalid UTF-8 outside strings", "\xff{\"a\":1}", false},
		{"overlong UTF-8", "{\"a\":\"\xc0\xaf\"}", false},
		{"a NUL byte", "{\"a\":\"\x00\"}", false},
		{"a comment", `{"a":1/*x*/}`, false},
		{"NaN", `{"a":NaN}`, false},
		{"leading zero number", `{"a":01}`, false},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			err := checkJSON([]byte(row.in), 64)
			if (err == nil) != row.ok {
				t.Fatalf("err = %v, want ok = %v", err, row.ok)
			}
		})
	}
}

func TestDecodeEnvelope(t *testing.T) {
	type env struct {
		Revision uint64 `json:"revision"`
		Name     string `json:"name"`
	}
	rows := []struct {
		name string
		in   string
		ok   bool
		want env
	}{
		{"exact", `{"revision":3}`, true, env{Revision: 3}},
		{"both fields", `{"revision":3,"name":"x"}`, true, env{3, "x"}},
		{"unknown field is refused", `{"revision":3,"admin":true}`, false, env{}},
		{"unknown field in different case is refused", `{"Revision":3,"extra":1}`, false, env{}},
		{"a known field in another case is refused (encoding/json would have taken it)", `{"REVISION":3}`, false, env{}},
		{"a known field in mixed case is refused", `{"revisioN":3}`, false, env{}},
		{"the same field in two cases is refused", `{"revision":1,"Revision":2}`, false, env{}},
		{"a field with a trailing space is refused", `{"revision ":3}`, false, env{}},
		{"wrong type", `{"revision":"3"}`, false, env{}},
		{"negative", `{"revision":-3}`, false, env{}},
		{"fraction", `{"revision":3.5}`, false, env{}},
		{"too big", `{"revision":99999999999999999999}`, false, env{}},
		{"null is a zero", `{"revision":null}`, true, env{}},
		{"duplicate field", `{"revision":3,"revision":4}`, false, env{}},
		{"array", `[3]`, false, env{}},
		{"string", `"x"`, false, env{}},
		{"trailing data", `{"revision":3} {}`, false, env{}},
		{"empty", ``, false, env{}},
		{"nested object where a number is expected", `{"revision":{"a":1}}`, false, env{}},
		{"deep nesting", strings.Repeat(`{"a":`, 20) + "1" + strings.Repeat("}", 20), false, env{}},
		{"invalid UTF-8", "{\"name\":\"\xff\"}", false, env{}},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			var got env
			err := decodeEnvelope([]byte(row.in), &got)
			if (err == nil) != row.ok {
				t.Fatalf("err = %v, want ok = %v", err, row.ok)
			}
			if row.ok && got != row.want {
				t.Fatalf("got %+v", got)
			}
		})
	}
}

// esc is a single backslash. Tests build JSON escapes from it, because a tool that rewrites spelled-out escapes would
// otherwise turn them into the characters they stand for and the test into one of something else.
var esc = string(rune(92))
