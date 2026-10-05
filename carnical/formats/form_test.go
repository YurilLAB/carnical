// SPDX-License-Identifier: Apache-2.0

package formats

import (
	"fmt"
	"strings"
	"testing"
)

const (
	idFormEscape  = 5002600
	idFormCtl     = 5002601
	idFormDup     = 5002602
	idFormLimit   = 5002603
	idFormBracket = 5002604
	idFormSemi    = 5002605
	idFormProto   = 5002606
	form          = "application/x-www-form-urlencoded"
)

func manyParams(n int) string {
	parts := make([]string, n)
	for i := range parts {
		parts[i] = fmt.Sprintf("p%d=v%d", i, i)
	}
	return strings.Join(parts, "&")
}

var formRows = register("form", []row{
	// Accepted.
	{name: "two parameters", ct: form, body: "a=1&b=2"},
	{name: "plus is a space", ct: form, body: "q=hello+world"},
	{name: "percent escapes", ct: form, body: "q=%41%42%43&r=%C3%A9%E6%97%A5"},
	{name: "array syntax repeats a name", ct: form, body: "tags[]=a&tags[]=b&tags[]=c"},
	{name: "nested brackets", ct: form, body: "user[name]=a&user[address][city]=b"},
	{name: "newline sent as escapes", ct: form, body: "comment=line1%0D%0Aline2%09tabbed"},
	{name: "empty value", ct: form, body: "a=&b=2"},
	{name: "name only", ct: form, body: "flag&a=1"},
	{name: "equals sign inside a value", ct: form, body: "a=b=c"},
	{name: "empty pair between ampersands", ct: form, body: "a=1&&b=2&"},
	{name: "a thousand parameters", ct: form, body: manyParams(1000)},
	{name: "raw utf-8", ct: form, body: "name=José"},
	{name: "latin-1 escape under a latin-1 charset", ct: form + "; charset=iso-8859-1", body: "name=caf%E9"},
	{name: "brackets at the depth limit", ct: form, body: "a[1][2][3][4][5][6][7][8]=x"},
	{name: "base name that merely contains proto", ct: form, body: "protocol=https&prototype_id=3"},
	{name: "a long but allowed value", ct: form, body: "a=" + strings.Repeat("x", 60000)},

	// Escapes.
	{name: "non-hex escape", ct: form, body: "a=%zz", want: idFormEscape},
	{name: "bare percent", ct: form, body: "a=100%", want: idFormEscape},
	{name: "percent and one digit", ct: form, body: "a=%4", want: idFormEscape},
	{name: "bad escape in a name", ct: form, body: "%g1=2", want: idFormEscape},
	{name: "escaped NUL", ct: form, body: "a=x%00y", want: idFormCtl},
	{name: "escaped control character", ct: form, body: "a=%01", want: idFormCtl},
	{name: "escaped delete", ct: form, body: "a=%7f", want: idFormCtl},
	{name: "escaped newline in a name", ct: form, body: "a%0Ab=1", want: idFormCtl},
	{name: "raw NUL", ct: form, body: "a=x\x00y", want: idFormCtl},
	{name: "raw line feed", ct: form, body: "a=1\nb=2", want: idFormCtl},
	{name: "raw carriage return", ct: form, body: "a=1\r\n", want: idFormCtl},
	{name: "invalid utf-8 by escape", ct: form, body: "a=%FF%FE", want: idBadUTF8},
	{name: "invalid utf-8 raw", ct: form, body: "a=\xc3(", want: idBadUTF8},
	{name: "truncated utf-8 sequence", ct: form, body: "a=%E6%97", want: idBadUTF8},

	// Separators and duplicates.
	{name: "semicolon separator", ct: form, body: "a=1;b=2", want: idFormSemi},
	{name: "semicolon in a name", ct: form, body: "a;b=1", want: idFormSemi},
	{name: "duplicate name is recorded", ct: form, body: "id=1&id=2", also: []int{idFormDup}},
	{name: "duplicate name differing in case is recorded", ct: form, body: "Id=1&id=2", also: []int{idFormDup}},
	{name: "duplicate name by escape is recorded", ct: form, body: "id=1&%69d=2", also: []int{idFormDup}},
	{name: "duplicate name refused when the rule is set to block", ct: form, body: "id=1&id=2", want: idFormDup,
		tweak: func(p *Policy) { p.Rules = map[string]Action{"form-duplicate-param": Block} }},

	// Limits.
	{name: "five thousand parameters", ct: form, body: manyParams(5000), want: idFormLimit},
	{name: "a thousand and one parameters", ct: form, body: manyParams(1001), want: idFormLimit},
	{name: "name too long", ct: form, body: strings.Repeat("n", 300) + "=1", want: idFormLimit},
	{name: "value too long", ct: form, body: "a=" + strings.Repeat("v", 65537), want: idFormLimit},
	{name: "value too long by escapes", ct: form, body: "a=" + strings.Repeat("%41", 30), want: idFormLimit,
		tweak: func(p *Policy) { p.Form.MaxValueLen = 29 }},
	{name: "brackets one past the limit", ct: form, body: "a[1][2][3][4][5][6][7][8][9]=x", want: idFormBracket},
	{name: "brackets by escape", ct: form, body: "a%5B1%5D%5B2%5D%5B3%5D=x", want: idFormBracket,
		tweak: func(p *Policy) { p.Form.MaxBracketDepth = 2 }},

	// Prototype pollution.
	{name: "__proto__ name", ct: form, body: "__proto__[admin]=1", want: idFormProto},
	{name: "__proto__ in brackets", ct: form, body: "user[__proto__][admin]=1", want: idFormProto},
	{name: "__proto__ with a dot", ct: form, body: "a.__proto__.admin=1", want: idFormProto},
	{name: "constructor prototype", ct: form, body: "constructor[prototype][admin]=1", want: idFormProto},
	{name: "__PROTO__ in capitals", ct: form, body: "__PROTO__[admin]=1", want: idFormProto},
	{name: "Constructor Prototype in mixed case", ct: form, body: "Constructor[PROTOTYPE][admin]=1", want: idFormProto},
	{name: "__proto__ by escape", ct: form, body: "%5F%5Fproto%5F%5F[x]=1", want: idFormProto},

	// A body that is not a form.
	{name: "json under a form type", ct: form, body: `{"a":1}`, want: 5002040},
	{name: "json array under a form type", ct: form, body: `["a","b"]`, want: 5002040},
	{name: "xml under a form type", ct: form, body: `<?xml version="1.0"?><a/>`, want: 5002041},
	{name: "multipart under a form type", ct: form, body: "--xyz\r\nContent-Disposition: form-data; name=\"a\"\r\n\r\n1\r\n--xyz--\r\n", want: 5002042},
})

func TestForm(t *testing.T) { runTable(t, formRows) }

var queryRows = register("query", []row{
	{name: "ordinary API parameters", method: "GET", path: "/api", query: "q=hello+world&tags%5B%5D=red&tags%5B%5D=blue&page=1"},
	{name: "encoded separators are values", method: "GET", query: "q=a%3Bb%26c%3Dd%25"},
	{name: "unicode query", method: "GET", query: "q=%E6%97%A5%E6%9C%AC&name=%C3%A9"},
	{name: "empty values and separators", method: "GET", query: "a=&flag&&b=2&"},
	{name: "bad query escape", method: "GET", query: "x=%zz", want: 5002800},
	{name: "bad escape in name", method: "GET", query: "%x=1", want: 5002800},
	{name: "truncated escape", method: "GET", query: "x=%", want: 5002800},
	{name: "query NUL", method: "GET", query: "x=%00", want: 5002801},
	{name: "control in query name", method: "GET", query: "x%0A=1", want: 5002801},
	{name: "invalid query UTF-8", method: "GET", query: "x=%ff", want: 5002807},
	{name: "semicolon query separator", method: "GET", query: "a=1;b=2", want: 5002805},
	{name: "query prototype", method: "GET", query: "user%5B__proto__%5D%5Badmin%5D=1", want: 5002806},
	{name: "nested constructor prototype", method: "GET", query: "constructor%5Bprototype%5D%5Badmin%5D=1", want: 5002806},
	{name: "query duplicates monitored", method: "GET", query: "id=1&%69D=2", also: []int{5002802}},
	{name: "query duplicates blocked", method: "GET", query: "id=1&id=2", want: 5002802, tweak: func(p *Policy) { p.Rules["query-duplicate-param"] = Block }},
	{name: "query parameter count", method: "GET", query: manyParams(1001), want: 5002803},
	{name: "query name length", method: "GET", query: strings.Repeat("a", 257) + "=1", want: 5002803},
	{name: "query value length", method: "GET", query: "x=%41%42%43", want: 5002803, tweak: func(p *Policy) { p.Query.MaxValueLen = 2 }},
	{name: "query bracket depth", method: "GET", query: "a[1][2][3]=x", want: 5002804, tweak: func(p *Policy) { p.Query.MaxBracketDepth = 2 }},
	{name: "query byte cap boundary", method: "GET", query: "a=12", tweak: func(p *Policy) { p.MaxQueryBytes = 4 }},
	{name: "query byte cap", method: "GET", query: "a=123", want: 5002808, tweak: func(p *Policy) { p.MaxQueryBytes = 4 }},
	{name: "POST query is inspected", query: "x=%zz", ct: appJSON, body: `{}`, want: 5002800},
	{name: "HEAD query is inspected", method: "HEAD", query: "x=%zz", want: 5002800},
	{name: "query monitor cap does not skip JSON body", query: "a=123", ct: appJSON, body: `{"a":1,"a":2}`, want: idJSONDup, tweak: func(p *Policy) { p.MaxQueryBytes = 4; p.Rules["query-too-large"] = Monitor }},
	{name: "query off cap does not skip JSON body", query: "a=123", ct: appJSON, body: `{"a":1,"a":2}`, want: idJSONDup, tweak: func(p *Policy) { p.MaxQueryBytes = 4; p.Rules["query-too-large"] = Off }},
	{name: "query count monitor does not skip JSON body", query: "a=1&b=2", ct: appJSON, body: `{"a":1,"a":2}`, want: idJSONDup, tweak: func(p *Policy) { p.Query.MaxParams = 1; p.Rules["query-limit"] = Monitor }},
})

func TestQueryParameters(t *testing.T) { runTable(t, queryRows) }

func FuzzForm(f *testing.F) {
	for _, r := range formRows {
		f.Add(r.body)
	}
	for _, r := range queryRows {
		f.Add(r.query)
	}
	in := New(Policy{})
	f.Fuzz(func(t *testing.T, body string) {
		fuzzNoPanic(t, in, row{ct: form, body: body})
		fuzzNoPanic(t, in, row{ct: form, path: "/graphql", body: body})
		fuzzNoPanic(t, in, row{method: "GET", path: "/graphql", query: body})
		fuzzNoPanic(t, in, row{method: "GET", path: "/api", query: body})
		fuzzNoPanic(t, in, row{path: "/api", query: body, ct: appJSON, body: `{}`})
	})
}

func BenchmarkForm(b *testing.B) {
	var sb strings.Builder
	for i := 0; sb.Len() < 100<<10; i++ {
		if i > 0 {
			sb.WriteByte('&')
		}
		fmt.Fprintf(&sb, "field%d=value+with+spaces%%20and%%C3%%A9&user[name%d]=Alice", i, i)
	}
	benchRow(b, row{ct: form, body: sb.String(), tweak: func(p *Policy) { p.Form.MaxParams = 1_000_000 }})
}
