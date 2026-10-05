package formats

import (
	"strings"
	"testing"
)

// u is a JSON \uXXXX escape. It is built from parts so that the source of this file holds no backslash-u sequence for an editor
// or a tool to expand.
func u(hex string) string { return string([]byte{92, 'u'}) + hex }

func nested(open, shut string, n int) string {
	return strings.Repeat(open, n) + strings.Repeat(shut, n)
}

const (
	idJSONSyntax   = 5002100
	idJSONTrailing = 5002101
	idJSONLimit    = 5002102
	idJSONDup      = 5002103
	idJSONProto    = 5002104
	idJSONNUL      = 5002105
	idJSONSurr     = 5002106
	idWide         = 5002020
	idBadUTF8      = 5002021
	idControl      = 5002022
	idBOM          = 5002023
)

var jsonRows = register("json", []row{
	// Accepted.
	{name: "object", ct: "application/json", body: `{"a":1,"b":[true,false,null],"c":{"d":"e"}}`},
	{name: "empty array", ct: "application/json", body: `[]`},
	{name: "empty object with space", ct: "application/json", body: ` { } `},
	{name: "top level string", ct: "application/json", body: `"hello"`},
	{name: "top level number", ct: "application/json", body: `-12.5e+3`},
	{name: "escapes", ct: "application/json", body: `{"k":"\"\\\/\b\f\n\r\t` + u("00e9") + `"}`},
	{name: "surrogate pair", ct: "application/json", body: `{"k":"` + u("d83d") + u("de00") + `"}`},
	{name: "utf-8 text", ct: "application/json", body: `{"name":"José 日本語 😀"}`},
	{name: "same key at different depths", ct: "application/json", body: `{"a":{"a":{"a":1}},"b":{"a":2}}`},
	{name: "constructor without prototype", ct: "application/json", body: `{"constructor":"x","prototype":1}`},
	{name: "plus json type", ct: "application/vnd.api+json", body: `{"data":{"type":"x"}}`},
	{name: "json with utf-8 charset", ct: "application/json; charset=utf-8", body: `{"a":1}`},
	{name: "depth at the limit", ct: "application/json", body: nested("[", "]", 64)},
	{name: "line breaks as whitespace", ct: "application/json", body: "{\r\n\t\"a\" : 1\r\n}\n"},
	{name: "numbers", ct: "application/json", body: `[0,-0,0.5,1e5,1E-5,123456789012345678901234567890]`},
	{name: "sixteen distinct keys then seventeen", ct: "application/json", body: `{"k1":1,"k2":1,"k3":1,"k4":1,"k5":1,"k6":1,"k7":1,"k8":1,"k9":1,"k10":1,"k11":1,"k12":1,"k13":1,"k14":1,"k15":1,"k16":1,"k17":1,"k18":1}`},

	// Duplicate keys: different parsers keep the first, the last, or merge.
	{name: "duplicate key", ct: "application/json", body: `{"a":1,"a":2}`, want: idJSONDup},
	{name: "duplicate key in nested object", ct: "application/json", body: `{"x":{"a":1,"b":2,"a":3}}`, want: idJSONDup},
	{name: "duplicate key differing in case", ct: "application/json", body: `{"admin":false,"Admin":true}`, want: idJSONDup},
	{name: "duplicate key hidden by an escape", ct: "application/json", body: `{"a":1,"` + u("0061") + `":2}`, want: idJSONDup},
	{name: "duplicate key hidden by an escaped capital", ct: "application/json", body: `{"role":"user","` + u("0052") + `OLE":"admin"}`, want: idJSONDup},
	{name: "duplicate key through the kelvin sign", ct: "application/json", body: `{"k":1,"` + u("212a") + `":2}`, want: idJSONDup},
	{name: "duplicate key through the long s", ct: "application/json", body: `{"s":1,"` + u("017f") + `":2}`, want: idJSONDup},
	{name: "duplicate key of an emoji, escaped and raw", ct: "application/json", body: `{"😀":1,"` + u("d83d") + u("de00") + `":2}`, want: idJSONDup},
	{name: "duplicate key among many", ct: "application/json", body: `{"k1":1,"k2":1,"k3":1,"k4":1,"k5":1,"k6":1,"k7":1,"k8":1,"k9":1,"k10":1,"k11":1,"k12":1,"k13":1,"k14":1,"k15":1,"k16":1,"k17":1,"K3":2}`, want: idJSONDup},
	{name: "duplicate key in an array element", ct: "application/json", body: `[{"a":1},{"a":1,"a":2}]`, want: idJSONDup},

	// Prototype pollution.
	{name: "__proto__ key", ct: "application/json", body: `{"__proto__":{"isAdmin":true}}`, want: idJSONProto},
	{name: "__proto__ key escaped", ct: "application/json", body: `{"` + u("005f") + `_proto__":{"x":1}}`, want: idJSONProto},
	{name: "__proto__ in a nested object", ct: "application/json", body: `{"a":{"b":{"__proto__":1}}}`, want: idJSONProto},
	{name: "constructor prototype", ct: "application/json", body: `{"constructor":{"prototype":{"isAdmin":true}}}`, want: idJSONProto},
	{name: "constructor prototype in capitals and escaped", ct: "application/json", body: `{"` + u("0043") + `onstructor":{"PROTOTYPE":1}}`, want: idJSONProto},

	// Encodings and byte-level tricks.
	{name: "byte order mark", ct: "application/json", body: "\xef\xbb\xbf{\"a\":1}", want: idBOM},
	{name: "utf-16le", ct: "application/json", body: "{\x00\"\x00a\x00\"\x00:\x001\x00}\x00", want: idWide},
	{name: "utf-16be", ct: "application/json", body: "\x00{\x00\"\x00a\x00\"\x00:\x001\x00}", want: idWide},
	{name: "utf-16 with byte order mark", ct: "application/json", body: "\xff\xfe{\x00}\x00", want: idWide},
	{name: "utf-32be", ct: "application/json", body: "\x00\x00\x00{\x00\x00\x00}", want: idWide},
	{name: "raw NUL in a string", ct: "application/json", body: "{\"a\":\"x\x00y\"}", want: idControl},
	{name: "raw control character in a string", ct: "application/json", body: "{\"a\":\"x\x01y\"}", want: idControl},
	{name: "raw line feed in a string", ct: "application/json", body: "{\"a\":\"x\ny\"}", want: idControl},
	{name: "escaped NUL", ct: "application/json", body: `{"a":"x` + u("0000") + `y"}`, want: idJSONNUL},
	{name: "lone high surrogate", ct: "application/json", body: `{"a":"` + u("d800") + `"}`, want: idJSONSurr},
	{name: "lone low surrogate", ct: "application/json", body: `{"a":"` + u("dc00") + `"}`, want: idJSONSurr},
	{name: "high surrogate then another high", ct: "application/json", body: `{"a":"` + u("d800") + u("d800") + `"}`, want: idJSONSurr},
	{name: "invalid utf-8 in a value", ct: "application/json", body: "{\"a\":\"\xff\"}", want: idBadUTF8},
	{name: "overlong utf-8", ct: "application/json", body: "{\"a\":\"\xc0\xaf\"}", want: idBadUTF8},
	{name: "utf-8 surrogate", ct: "application/json", body: "{\"a\":\"\xed\xa0\x80\"}", want: idBadUTF8},
	{name: "invalid utf-8 in a key", ct: "application/json", body: "{\"\xfe\":1}", want: idBadUTF8},
	{name: "latin-1 charset with accents", ct: "application/json; charset=iso-8859-1", body: "{\"a\":\"caf\xc3\xa9\"}", want: 5002006},

	// Syntax.
	{name: "trailing value", ct: "application/json", body: `{"a":1} {"b":2}`, want: idJSONTrailing},
	{name: "trailing characters", ct: "application/json", body: `{"a":1}x`, want: idJSONTrailing},
	{name: "trailing comma in array", ct: "application/json", body: `[1,2,]`, want: idJSONSyntax},
	{name: "trailing comma in object", ct: "application/json", body: `{"a":1,}`, want: idJSONSyntax},
	{name: "comment", ct: "application/json", body: `{"a":1/*x*/}`, want: idJSONSyntax},
	{name: "line comment", ct: "application/json", body: "{\"a\":1}//x", want: idJSONTrailing},
	{name: "single quotes", ct: "application/json", body: `{'a':1}`, want: idJSONSyntax},
	{name: "unquoted key", ct: "application/json", body: `{a:1}`, want: idJSONSyntax},
	{name: "leading zero", ct: "application/json", body: `{"a":01}`, want: idJSONSyntax},
	{name: "plus sign", ct: "application/json", body: `{"a":+1}`, want: idJSONSyntax},
	{name: "bare decimal point", ct: "application/json", body: `{"a":.5}`, want: idJSONSyntax},
	{name: "trailing decimal point", ct: "application/json", body: `{"a":1.}`, want: idJSONSyntax},
	{name: "hex number", ct: "application/json", body: `{"a":0x10}`, want: idJSONSyntax},
	{name: "a minus sign and nothing else", ct: "application/json", body: `[-]`, want: idJSONSyntax},
	{name: "a minus sign before a point", ct: "application/json", body: `{"a":-.5}`, want: idJSONSyntax},
	{name: "an exponent with no digits", ct: "application/json", body: `[1e]`, want: idJSONSyntax},
	{name: "an exponent sign with no digits", ct: "application/json", body: `[1E+]`, want: idJSONSyntax},
	{name: "NaN", ct: "application/json", body: `{"a":NaN}`, want: idJSONSyntax},
	{name: "Infinity", ct: "application/json", body: `[Infinity]`, want: idJSONSyntax},
	{name: "capital literal", ct: "application/json", body: `[True]`, want: idJSONSyntax},
	{name: "bad escape", ct: "application/json", body: `{"a":"\x41"}`, want: idJSONSyntax},
	{name: "short unicode escape", ct: "application/json", body: `{"a":"` + u("12") + `"}`, want: idJSONSyntax},
	{name: "unterminated string", ct: "application/json", body: `{"a":"x`, want: idJSONSyntax},
	{name: "unterminated object", ct: "application/json", body: `{"a":1`, want: idJSONSyntax},
	{name: "missing colon", ct: "application/json", body: `{"a" 1}`, want: idJSONSyntax},
	{name: "a semicolon for the colon", ct: "application/json", body: `{"a";1}`, want: idJSONSyntax},
	{name: "an equals sign for the colon", ct: "application/json", body: `{"a"=1}`, want: idJSONSyntax},
	{name: "a letter for the opening quote of a key", ct: "application/json", body: `{xa":1}`, want: idJSONSyntax},
	{name: "missing comma", ct: "application/json", body: `[1 2]`, want: idJSONSyntax},
	{name: "whitespace only", ct: "application/json", body: "  \n ", want: idJSONSyntax},
	{name: "form feed as whitespace", ct: "application/json", body: "{\f}", want: idJSONSyntax},

	// Limits.
	{name: "nested one past the limit", ct: "application/json", body: nested("[", "]", 65), want: idJSONLimit},
	{name: "nested a hundred thousand deep", ct: "application/json", body: nested("[", "", 100000), want: idJSONLimit},
	{name: "nested objects past the limit", ct: "application/json", body: strings.Repeat(`{"a":`, 70) + "1" + strings.Repeat("}", 70), want: idJSONLimit},
	{name: "too many values", ct: "application/json", body: "[" + strings.Repeat("1,", 20) + "1]", want: idJSONLimit,
		tweak: func(p *Policy) { p.JSON.MaxNodes = 20 }},
	{name: "too many keys", ct: "application/json", body: `{"a":1,"b":2,"c":3,"d":4}`, want: idJSONLimit,
		tweak: func(p *Policy) { p.JSON.MaxKeys = 3 }},
	{name: "string too long", ct: "application/json", body: `{"a":"` + strings.Repeat("x", 100) + `"}`, want: idJSONLimit,
		tweak: func(p *Policy) { p.JSON.MaxStringLen = 99 }},
	{name: "string at the limit", ct: "application/json", body: `{"a":"` + strings.Repeat("x", 99) + `"}`,
		tweak: func(p *Policy) { p.JSON.MaxStringLen = 99 }},
	{name: "key too long", ct: "application/json", body: `{"` + strings.Repeat("k", 40) + `":1}`, want: idJSONLimit,
		tweak: func(p *Policy) { p.JSON.MaxKeyLen = 39 }},
	{name: "number too long", ct: "application/json", body: `[` + strings.Repeat("9", 65) + `]`, want: idJSONLimit},
	{name: "exponent with many digits", ct: "application/json", body: `[1e1000]`, want: idJSONLimit},
	{name: "exponent with three digits", ct: "application/json", body: `[1e999,1E-999]`},

	// Declared as JSON.
	{name: "declared json but xml", ct: "application/json", body: `<a>1</a>`, want: 5002043},
	{name: "declared json but a form", ct: "application/json", body: `a=1&b=2`, want: 5002043},
	{name: "declared json but plain text", ct: "application/json", body: `hello`, want: 5002043},
})

func TestJSON(t *testing.T) { runTable(t, jsonRows) }

func TestJSONPolicyOffAndMonitorPerRule(t *testing.T) {
	dup := row{ct: "application/json", body: `{"a":1,"A":2}`}
	for _, tc := range []struct {
		name   string
		action Action
		block  bool
		found  bool
	}{{"block", Block, true, true}, {"monitor", Monitor, false, true}, {"off", Off, false, false}} {
		t.Run(tc.name, func(t *testing.T) {
			in := New(dup.policy(map[string]Action{"json-duplicate-key": tc.action}, false))
			res := in.Inspect(dup.request())
			found, blocked := false, false
			for _, v := range res.Verdicts {
				if v.ID == idJSONDup {
					found = true
					blocked = blocked || v.Block
				}
			}
			if found != tc.found || blocked != tc.block {
				t.Fatalf("found %v blocked %v, want %v %v: %v", found, blocked, tc.found, tc.block, res.Verdicts)
			}
		})
	}
}

// TestJSONMonitorKeepsReadingAfterARecoverableFinding shows that in monitor mode a finding that does not end the parse does not hide
// the ones after it.
func TestJSONMonitorKeepsReadingAfterARecoverableFinding(t *testing.T) {
	r := row{ct: "application/json", body: `{"a":1,"A":2,"__proto__":{"x":1},"s":"` + u("0000") + `"}`}
	in := New(r.policy(nil, true))
	got := ids(in.Inspect(r.request()).Verdicts)
	for _, want := range []int{idJSONDup, idJSONProto, idJSONNUL} {
		if !has(got, want) {
			t.Errorf("missing %d in %v", want, got)
		}
	}
}

func TestFoldRune(t *testing.T) {
	for _, tc := range []struct {
		a, b rune
		same bool
	}{
		{'a', 'A', true}, {'k', 0x212A, true}, {'K', 0x212A, true}, {'s', 0x17F, true}, {'é', 'É', true}, {'ǅ', 'ǆ', true},
		{'a', 'b', false}, {'i', 0x130, false}, {'ß', 's', false},
	} {
		if (foldRune(tc.a) == foldRune(tc.b)) != tc.same {
			t.Errorf("foldRune(%q) == foldRune(%q) is not %v", tc.a, tc.b, tc.same)
		}
	}
}

func FuzzJSON(f *testing.F) {
	for _, r := range jsonRows {
		f.Add(r.body)
	}
	f.Add(`{"query":"{a}","variables":{}}`)
	in := New(Policy{})
	f.Fuzz(func(t *testing.T, body string) {
		fuzzNoPanic(t, in, row{ct: "application/json", body: body})
		fuzzNoPanic(t, in, row{ct: "application/json", path: "/graphql", body: body})
	})
}

func BenchmarkJSON(b *testing.B) {
	var sb strings.Builder
	sb.WriteString(`{"users":[`)
	for i := 0; sb.Len() < 100<<10; i++ {
		if i > 0 {
			sb.WriteByte(',')
		}
		sb.WriteString(`{"id":12345,"name":"Alice Example","email":"alice@example.test","tags":["a","b","c"],"active":true,"score":98.6,"address":{"city":"Cairns","zip":"4870"}}`)
	}
	sb.WriteString(`]}`)
	benchBody(b, "application/json", sb.String())
}
