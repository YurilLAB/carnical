// SPDX-License-Identifier: Apache-2.0

package apiguard

import (
	"strings"
	"testing"
)

func TestParseJSONAcceptsRFC8259AndRefusesWhatIsNot(t *testing.T) {
	tests := []struct {
		name string
		in   string
		ok   bool
		dup  bool
	}{
		{"object", `{"a":1,"b":[true,false,null],"c":"x"}`, true, false},
		{"array of numbers", `[1, -2, 3.5, 1e3, 1E-2, 0]`, true, false},
		{"scalar top level", `"hello"`, true, false},
		{"white space around", " \t\r\n{ } \n", true, false},
		{"escapes", `"a\"b\\c\/d\b\f\n\r\té"`, true, false},
		{"surrogate pair", `"😀"`, true, false},
		{"lone surrogate is replaced, not refused", `"\ud83d"`, true, false},
		{"duplicate key is reported", `{"role":"user","role":"admin"}`, true, true},
		{"empty input", ``, false, false},
		{"trailing comma in array", `[1,2,]`, false, false},
		{"trailing comma in object", `{"a":1,}`, false, false},
		{"single quotes", `{'a':1}`, false, false},
		{"comment", `{"a":1} // x`, false, false},
		{"unquoted key", `{a:1}`, false, false},
		{"NaN", `[NaN]`, false, false},
		{"leading zero", `[01]`, false, false},
		{"bare minus", `[-]`, false, false},
		{"fraction without digits", `[1.]`, false, false},
		{"exponent without digits", `[1e]`, false, false},
		{"two values", `{} {}`, false, false},
		{"byte order mark", "\xef\xbb\xbf{}", false, false},
		{"raw control character in string", "\"a\x01b\"", false, false},
		{"invalid UTF-8 in string", "\"a\xffb\"", false, false},
		{"bad escape", `"\q"`, false, false},
		{"short unicode escape", `"\u12"`, false, false},
		{"unterminated string", `"abc`, false, false},
		{"unterminated object", `{"a":1`, false, false},
		{"missing colon", `{"a" 1}`, false, false},
		{"literal prefix", `tru`, false, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, dup, err := parseJSON([]byte(tt.in), jsonLimits{})
			if (err == nil) != tt.ok {
				t.Fatalf("err = %v, want ok=%v", err, tt.ok)
			}
			if err == nil && dup != tt.dup {
				t.Fatalf("dup = %v, want %v", dup, tt.dup)
			}
		})
	}
}

func TestParseJSONIsBoundedByDepthAndSize(t *testing.T) {
	tests := []struct {
		name string
		in   string
		lim  jsonLimits
		err  error
	}{
		{"nesting at the limit", strings.Repeat("[", 8) + strings.Repeat("]", 8), jsonLimits{depth: 8}, nil},
		{"nesting over the limit", strings.Repeat("[", 9) + strings.Repeat("]", 9), jsonLimits{depth: 8}, errTooDeep},
		{"a million brackets cost nothing", strings.Repeat("[", 1_000_000), jsonLimits{}, errTooDeep},
		{"objects nested over the limit", strings.Repeat(`{"a":`, 40) + "1" + strings.Repeat("}", 40), jsonLimits{}, errTooDeep},
		{"values at the limit", "[1,2,3]", jsonLimits{nodes: 4}, nil},
		{"values over the limit", "[1,2,3]", jsonLimits{nodes: 3}, errTooMany},
		{"keys count as values", `{"a":1,"b":2}`, jsonLimits{nodes: 4}, errTooMany},
		{"many small values", "[" + strings.Repeat("1,", 200_000) + "1]", jsonLimits{}, errTooMany},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, err := parseJSON([]byte(tt.in), tt.lim)
			if err != tt.err {
				t.Fatalf("err = %v, want %v", err, tt.err)
			}
		})
	}
}

func TestParseJSONValuesAreWhatTheyLookLike(t *testing.T) {
	v, _, err := parseJSON([]byte(`{"n":123456789012345678901234567890,"f":1.50,"s":"é","a":[1,{"k":null}]}`), jsonLimits{})
	if err != nil {
		t.Fatal(err)
	}
	m := v.(map[string]any)
	if m["n"] != Num("123456789012345678901234567890") || !m["n"].(Num).isInteger() {
		t.Fatalf("a big integer was not kept whole: %v", m["n"])
	}
	if m["f"] != Num("1.50") || m["f"].(Num).isInteger() {
		t.Fatalf("a fraction: %v", m["f"])
	}
	if m["s"] != "é" {
		t.Fatalf("escape: %q", m["s"])
	}
	back := string(appendJSON(nil, v, 0))
	if _, _, err := parseJSON([]byte(back), jsonLimits{}); err != nil {
		t.Fatalf("what appendJSON wrote does not parse: %v: %s", err, back)
	}
	if !equalValues(v, mustParse(t, back), 0) {
		t.Fatalf("a value did not survive being written and read: %s", back)
	}
}

func mustParse(t testing.TB, s string) any {
	t.Helper()
	v, _, err := parseJSON([]byte(s), jsonLimits{})
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func TestNumberKinds(t *testing.T) {
	tests := []struct {
		in  string
		int bool
		ok  bool
		isI int64
		okI bool
	}{
		{"3", true, true, 3, true},
		{"-3", true, true, -3, true},
		{"3.0", true, true, 3, true},
		{"3e2", true, true, 300, true},
		{"3.5", false, true, 0, false},
		{"1e400", false, false, 0, false},
		{"9223372036854775807", true, true, 9223372036854775807, true},
		{"9223372036854775808", true, true, 0, false},
		{"", false, false, 0, false},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			n := Num(tt.in)
			if n.isInteger() != tt.int {
				t.Errorf("isInteger = %v", n.isInteger())
			}
			if _, ok := n.float(); ok != tt.ok {
				t.Errorf("float ok = %v", ok)
			}
			if i, ok := n.int64(); ok != tt.okI || (ok && i != tt.isI) {
				t.Errorf("int64 = %d %v", i, ok)
			}
		})
	}
}
