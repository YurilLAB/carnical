package formats

import (
	"strings"
	"testing"
)

const (
	idNDLines = 5002400
	idNDBlank = 5002401
	ndjson    = "application/x-ndjson"
)

func lines(n int, line string) string {
	return strings.Repeat(line+"\n", n)
}

var ndjsonRows = register("ndjson", []row{
	// Accepted.
	{name: "three records", ct: ndjson, body: "{\"a\":1}\n{\"a\":2}\n{\"a\":3}\n"},
	{name: "no final line feed", ct: ndjson, body: "{\"a\":1}\n{\"a\":2}"},
	{name: "one record", ct: ndjson, body: `{"a":1}`},
	{name: "carriage returns before the line feeds", ct: ndjson, body: "{\"a\":1}\r\n{\"a\":2}\r\n"},
	{name: "records of every kind", ct: ndjson, body: "{\"a\":1}\n[1,2,3]\n\"text\"\n42\ntrue\nnull\n"},
	{name: "jsonl type", ct: "application/jsonl", body: "{\"a\":1}\n{\"a\":2}\n"},
	{name: "the same key in different records", ct: ndjson, body: "{\"a\":1}\n{\"a\":2}\n{\"a\":3}\n"},
	{name: "a thousand lines", ct: ndjson, body: lines(1000, `{"i":1}`)},
	{name: "whitespace around a record", ct: ndjson, body: "  {\"a\":1}  \n\t[1]\t\n"},
	{name: "utf-8 text", ct: ndjson, body: "{\"n\":\"日本語 😀\"}\n"},

	// Refused.
	{name: "a record that is not json", ct: ndjson, body: "{\"a\":1}\nhello there\n", want: 5002043},
	{name: "a record with a syntax error", ct: ndjson, body: "{\"a\":1}\n{\"a\":}\n", want: idJSONSyntax},
	{name: "two records on one line", ct: ndjson, body: "{\"a\":1}{\"a\":2}\n", want: idJSONTrailing},
	{name: "a carriage return between two records", ct: ndjson, body: "{\"a\":1}\r{\"a\":2}\n", want: idJSONTrailing},
	{name: "a record split across two lines", ct: ndjson, body: "{\"a\":\n1}\n", want: idJSONSyntax},
	{name: "blank line between records", ct: ndjson, body: "{\"a\":1}\n\n{\"a\":2}\n", want: idNDBlank},
	{name: "two final line feeds", ct: ndjson, body: "{\"a\":1}\n\n", want: idNDBlank},
	{name: "blank line first", ct: ndjson, body: "\n{\"a\":1}\n", want: idNDBlank},
	{name: "a thousand and one lines", ct: ndjson, body: lines(1001, `{"i":1}`), want: idNDLines},
	{name: "a million lines", ct: ndjson, body: lines(100000, `1`), want: idNDLines},
	{name: "duplicate key in a record", ct: ndjson, body: "{\"a\":1}\n{\"a\":1,\"A\":2}\n", want: idJSONDup},
	{name: "prototype key in a record", ct: ndjson, body: "{\"__proto__\":{}}\n", want: idJSONProto},
	{name: "record nested too deeply", ct: ndjson, body: "{\"a\":1}\n" + nested("[", "]", 65) + "\n", want: idJSONLimit},
	{name: "byte order mark", ct: ndjson, body: "\xef\xbb\xbf{\"a\":1}\n", want: idBOM},
	{name: "utf-16", ct: ndjson, body: utf16le("{\"a\":1}\n"), want: idWide},
	{name: "invalid utf-8", ct: ndjson, body: "{\"a\":\"\xff\"}\n", want: idBadUTF8},
	{name: "raw control character", ct: ndjson, body: "{\"a\":\"\x01\"}\n", want: idControl},
	{name: "nodes counted over the whole body", ct: ndjson, body: lines(30, `[1,2,3]`), want: idJSONLimit,
		tweak: func(p *Policy) { p.JSON.MaxNodes = 100 }},
	{name: "keys counted over the whole body", ct: ndjson, body: lines(30, `{"a":1,"b":2}`), want: idJSONLimit,
		tweak: func(p *Policy) { p.JSON.MaxKeys = 50 }},
	{name: "a lower line limit", ct: ndjson, body: lines(5, `{}`), want: idNDLines,
		tweak: func(p *Policy) { p.NDJSON.MaxLines = 4 }},
	{name: "latin-1 charset with accents", ct: ndjson + "; charset=iso-8859-1", body: "{\"a\":\"caf\xc3\xa9\"}\n", want: 5002006},
})

func TestNDJSON(t *testing.T) { runTable(t, ndjsonRows) }

func TestNDJSONMessageNamesTheLine(t *testing.T) {
	in := New(Policy{})
	res := in.Inspect(row{ct: ndjson, body: "{\"a\":1}\n{\"a\":2}\n{\"a\":}\n"}.request())
	if len(res.Verdicts) != 1 || !strings.Contains(res.Verdicts[0].Message, "in line 3") {
		t.Fatalf("%v", res.Verdicts)
	}
}

func FuzzNDJSON(f *testing.F) {
	for _, r := range ndjsonRows {
		f.Add(r.body)
	}
	in := New(Policy{})
	f.Fuzz(func(t *testing.T, body string) {
		fuzzNoPanic(t, in, row{ct: ndjson, body: body})
	})
}

func BenchmarkNDJSON(b *testing.B) {
	line := `{"id":12345,"name":"Alice Example","email":"alice@example.test","tags":["a","b","c"],"active":true,"score":98.6}` + "\n"
	benchRow(b, row{ct: ndjson, body: strings.Repeat(line, 900), tweak: func(p *Policy) { p.JSON.MaxNodes = 1_000_000; p.JSON.MaxKeys = 1_000_000 }})
}
