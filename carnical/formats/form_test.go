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

func FuzzForm(f *testing.F) {
	for _, r := range formRows {
		f.Add(r.body)
	}
	in := New(Policy{})
	f.Fuzz(func(t *testing.T, body string) {
		fuzzNoPanic(t, in, row{ct: form, body: body})
		fuzzNoPanic(t, in, row{ct: form, path: "/graphql", body: body})
		fuzzNoPanic(t, in, row{method: "GET", path: "/graphql", query: body})
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
