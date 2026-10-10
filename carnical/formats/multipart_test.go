package formats

import (
	"fmt"
	"strings"
	"testing"
)

const (
	idMPNoBoundary = 5002700
	idMPBadBound   = 5002701
	idMPLimit      = 5002702
	idMPHeader     = 5002703
	idMPDupHeader  = 5002704
	idMPDupName    = 5002705
	idMPFileMis    = 5002706
	idMPFileStar   = 5002707
	idMPNested     = 5002708
	idMPTransfer   = 5002709
	idMPBareLF     = 5002710
	idMPNoClose    = 5002711
	idMPEpilogue   = 5002712
	idMPPreamble   = 5002713
	idMPDelim      = 5002714
	idMPDisp       = 5002715
	idMPDupParam   = 5002716
	bnd            = "----WebKitFormBoundaryXyZ12345"
	mpType         = "multipart/form-data; boundary=" + bnd
)

// part is one part: its header lines (without line ends) and its content.
func part(content string, headers ...string) string {
	return "--" + bnd + "\r\n" + strings.Join(headers, "\r\n") + "\r\n\r\n" + content + "\r\n"
}

func field(name, value string) string {
	return part(value, `Content-Disposition: form-data; name="`+name+`"`)
}

func file(name, filename, content string) string {
	return part(content, `Content-Disposition: form-data; name="`+name+`"; filename="`+filename+`"`, "Content-Type: application/octet-stream")
}

func closing() string { return "--" + bnd + "--\r\n" }

func mp(parts ...string) string { return strings.Join(parts, "") + closing() }

func manyParts(n int) string {
	var sb strings.Builder
	for i := 0; i < n; i++ {
		sb.WriteString(field(fmt.Sprintf("f%d", i), "v"))
	}
	return sb.String() + closing()
}

var multipartRows = register("multipart", []row{
	// Accepted.
	{name: "one field", ct: mpType, body: mp(field("a", "1"))},
	{name: "fields and a file", ct: mpType, body: mp(field("a", "1"), field("b", "two"), file("up", "photo.jpg", "\xff\xd8\xff\xe0binary\r\n\x00data"))},
	{name: "quoted boundary", ct: `multipart/form-data; boundary="` + bnd + `"`, body: mp(field("a", "1"))},
	{name: "empty value", ct: mpType, body: mp(field("a", ""))},
	{name: "no trailing line break after the closing boundary", ct: mpType, body: strings.TrimSuffix(mp(field("a", "1")), "\r\n")},
	{name: "array names repeat", ct: mpType, body: mp(field("f[]", "1"), field("f[]", "2"))},
	{name: "content with dashes and line breaks", ct: mpType, body: mp(field("a", "line1\r\n--not-the-boundary\r\n-- \r\nline4"))},
	{name: "part with its own type and charset", ct: mpType, body: mp(part("x", `Content-Disposition: form-data; name="a"`, "Content-Type: text/plain; charset=utf-8"))},
	{name: "binary and 8bit transfer encodings", ct: mpType, body: mp(part("x", `Content-Disposition: form-data; name="a"`, "Content-Transfer-Encoding: binary"), part("y", `Content-Disposition: form-data; name="b"`, "Content-Transfer-Encoding: 8BIT"))},
	{name: "a hundred parts", ct: mpType, body: manyParts(100)},
	{name: "filename and filename* that agree", ct: mpType, body: mp(part("x", `Content-Disposition: form-data; name="a"; filename="résumé.txt"; filename*=UTF-8''r%C3%A9sum%C3%A9.txt`)),
		also: []int{idMPFileStar}},
	{name: "percent-encoded filename that agrees with filename*", ct: mpType, body: mp(part("x", `Content-Disposition: form-data; name="a"; filename="a%20b.txt"; filename*=UTF-8''a%20b.txt`)),
		also: []int{idMPFileStar}},
	{name: "repeated name is recorded", ct: mpType, body: mp(field("a", "1"), field("a", "2")), also: []int{idMPDupName}},
	{name: "repeated name refused when the rule is set to block", ct: mpType, body: mp(field("a", "1"), field("A", "2")), want: idMPDupName,
		tweak: func(p *Policy) { p.Rules = map[string]Action{"multipart-duplicate-name": Block} }},
	{name: "multipart/mixed when the site allows it", ct: "multipart/mixed; boundary=" + bnd, body: mp(part("x", "Content-Type: text/plain")),
		tweak: func(p *Policy) { p.AllowedTypes = []string{"multipart/mixed"} }},

	// The boundary.
	{name: "no boundary", ct: "multipart/form-data", body: mp(field("a", "1")), want: idMPNoBoundary},
	{name: "empty boundary", ct: `multipart/form-data; boundary=""`, body: mp(field("a", "1")), want: idMPNoBoundary},
	{name: "boundary with a forbidden character", ct: `multipart/form-data; boundary="a<b"`, body: "--a<b\r\nContent-Disposition: form-data; name=\"a\"\r\n\r\n1\r\n--a<b--\r\n", want: idMPBadBound},
	{name: "boundary of 71 characters", ct: "multipart/form-data; boundary=" + strings.Repeat("b", 71), body: "--" + strings.Repeat("b", 71) + "--\r\n", want: idMPBadBound},
	{name: "boundary ending in a space", ct: `multipart/form-data; boundary="abc "`, body: "--abc \r\nContent-Disposition: form-data; name=\"a\"\r\n\r\n1\r\n--abc --\r\n", want: idMPBadBound},
	{name: "boundary given twice", ct: "multipart/form-data; boundary=a; boundary=b", body: "--a--\r\n", want: 5002007},
	{name: "boundary that is not in the body", ct: "multipart/form-data; boundary=other", body: mp(field("a", "1")), want: idMPDelim},

	// Structure.
	{name: "no closing boundary", ct: mpType, body: field("a", "1"), want: idMPNoClose},
	{name: "body ends in the headers", ct: mpType, body: "--" + bnd + "\r\nContent-Disposition: form-data; name=\"a\"\r\n", want: idMPNoClose},
	{name: "the boundary and nothing else", ct: mpType, body: "--" + bnd, want: idMPNoClose},
	{name: "the first boundary is followed by more boundary text", ct: mpType, body: "--" + bnd + "xyz\r\nContent-Disposition: form-data; name=\"a\"\r\n\r\n1\r\n--" + bnd + "xyz--\r\n", want: idMPDelim},
	{name: "a bare line feed after a later boundary", ct: mpType, body: field("a", "1") + "--" + bnd + "\nContent-Disposition: form-data; name=\"b\"\r\n\r\n2\r\n" + closing(), want: idMPBareLF},
	{name: "the body ends after a later boundary", ct: mpType, body: field("a", "1") + "--" + bnd, want: idMPNoClose},
	{name: "the headers are cut off with no line break", ct: mpType, body: "--" + bnd + "\r\nContent-Disposition: form-data; name=\"a\"", want: idMPNoClose},
	{name: "the boundary line and nothing else", ct: mpType, body: "--" + bnd + "\r\n", want: idMPNoClose},
	{name: "truncated closing boundary", ct: mpType, body: field("a", "1") + "--" + bnd + "-", want: idMPDelim},
	{name: "data after the closing boundary", ct: mpType, body: mp(field("a", "1")) + "trailing data", want: idMPEpilogue},
	{name: "a part after the closing boundary", ct: mpType, body: mp(field("a", "1")) + field("evil", "x") + closing(), want: idMPEpilogue},
	{name: "data before the first boundary", ct: mpType, body: "preamble text\r\n" + mp(field("a", "1")), want: idMPPreamble},
	{name: "boundary after text on the same line", ct: mpType, body: "junk" + mp(field("a", "1")), want: idMPDelim},
	{name: "line that starts with the boundary and goes on", ct: mpType, body: mp(field("a", "x\r\n--"+bnd+"EVIL\r\ny")), want: idMPDelim},
	{name: "boundary with trailing space", ct: mpType, body: strings.Replace(mp(field("a", "1"), field("b", "2")), "--"+bnd+"\r\nContent-Disposition: form-data; name=\"b\"", "--"+bnd+" \r\nContent-Disposition: form-data; name=\"b\"", 1), want: idMPDelim},
	{name: "boundary in the middle of a line of content", ct: mpType, body: mp(field("a", "x--"+bnd+"y")), want: idMPDelim},
	{name: "boundary right after the headers", ct: mpType, body: "--" + bnd + "\r\nContent-Disposition: form-data; name=\"a\"\r\n\r\n--" + bnd + "--\r\n", want: idMPDelim},
	{name: "bare line feed after the headers", ct: mpType, body: "--" + bnd + "\r\nContent-Disposition: form-data; name=\"a\"\n\nvalue\r\n--" + bnd + "--\r\n", want: idMPBareLF},
	{name: "bare line feed after the boundary", ct: mpType, body: "--" + bnd + "\nContent-Disposition: form-data; name=\"a\"\r\n\r\nv\r\n--" + bnd + "--\r\n", want: idMPBareLF},
	{name: "bare line feed before a boundary", ct: mpType, body: "--" + bnd + "\r\nContent-Disposition: form-data; name=\"a\"\r\n\r\nv\n--" + bnd + "--\r\n", want: idMPBareLF},
	{name: "all line breaks bare", ct: mpType, body: strings.ReplaceAll(mp(field("a", "1")), "\r\n", "\n"), want: idMPBareLF},
	{name: "a hundred and one parts", ct: mpType, body: manyParts(101), want: idMPLimit},
	{name: "headers too large", ct: mpType, body: mp(part("x", `Content-Disposition: form-data; name="a"`, "X-Padding: "+strings.Repeat("p", 100))), want: idMPLimit,
		tweak: func(p *Policy) { p.Multipart.MaxHeaderBytes = 100 }},
	{name: "too many headers", ct: mpType, body: mp(part("x", `Content-Disposition: form-data; name="a"`, "X-A: 1", "X-B: 2")), want: idMPLimit,
		tweak: func(p *Policy) { p.Multipart.MaxHeaders = 2 }},
	{name: "part name too long", ct: mpType, body: mp(field(strings.Repeat("n", 30), "1")), want: idMPLimit,
		tweak: func(p *Policy) { p.Multipart.MaxNameLen = 29 }},

	// Part headers.
	{name: "header with no colon", ct: mpType, body: mp(part("x", "Content-Disposition form-data; name=\"a\"")), want: idMPHeader},
	{name: "space before the colon", ct: mpType, body: mp(part("x", `Content-Disposition : form-data; name="a"`)), want: idMPHeader},
	{name: "folded header line", ct: mpType, body: mp(part("x", `Content-Disposition: form-data;`, ` name="a"`)), want: idMPHeader},
	{name: "control character in a header", ct: mpType, body: mp(part("x", "Content-Disposition: form-data; name=\"a\"\x01")), want: idMPHeader},
	{name: "repeated Content-Disposition", ct: mpType, body: mp(part("x", `Content-Disposition: form-data; name="a"`, `Content-Disposition: form-data; name="b"`)), want: idMPDupHeader},
	{name: "repeated Content-Type", ct: mpType, body: mp(part("x", `Content-Disposition: form-data; name="a"`, "Content-Type: text/plain", "Content-Type: image/png")), want: idMPDupHeader},
	{name: "header names in different case", ct: mpType, body: mp(part("x", `Content-Disposition: form-data; name="a"`, "content-disposition: form-data; name=\"b\"")), want: idMPDupHeader},
	{name: "no Content-Disposition", ct: mpType, body: mp(part("x", "Content-Type: text/plain")), want: idMPDisp},
	{name: "disposition that is not form-data", ct: mpType, body: mp(part("x", `Content-Disposition: attachment; name="a"`)), want: idMPDisp},
	{name: "no name", ct: mpType, body: mp(part("x", `Content-Disposition: form-data; filename="a.txt"`)), want: idMPDisp},
	{name: "name given twice", ct: mpType, body: mp(part("x", `Content-Disposition: form-data; name="a"; name="b"`)), want: idMPDupParam},
	{name: "filename given twice", ct: mpType, body: mp(part("x", `Content-Disposition: form-data; name="a"; filename="a.jpg"; filename="a.php"`)), want: idMPDupParam},
	{name: "unterminated quote in the disposition", ct: mpType, body: mp(part("x", `Content-Disposition: form-data; name="a`)), want: idMPHeader},
	{name: "filename and filename* disagree", ct: mpType, body: mp(part("x", `Content-Disposition: form-data; name="a"; filename="image.jpg"; filename*=UTF-8''shell.php`)), want: idMPFileMis},
	{name: "filename* decoy after a harmless filename", ct: mpType, body: mp(part("x", `Content-Disposition: form-data; name="a"; filename*=UTF-8''evil.php; filename="ok.txt"`)), want: idMPFileMis},
	{name: "filename* that is not a valid extended value", ct: mpType, body: mp(part("x", `Content-Disposition: form-data; name="a"; filename="a.txt"; filename*=a.txt`)), want: idMPFileMis},
	{name: "filename* in an unsupported charset", ct: mpType, body: mp(part("x", `Content-Disposition: form-data; name="a"; filename="a.txt"; filename*=UTF-7''a.txt`)), want: idMPFileMis},
	// A file to a parser that reads filename*, so its content is not an argument, and a field to one that does not.
	{name: "lone filename*", ct: mpType, body: mp(part("x", `Content-Disposition: form-data; name="a"; filename*=UTF-8''a.txt`)), want: idMPFileMis},
	// Go's mime lets name* replace name; many backends ignore it, so the two see different field names.
	{name: "an extended name", ct: mpType, body: mp(part("x", `Content-Disposition: form-data; name="safe"; name*=UTF-8''admin`)), want: idMPDisp},
	{name: "a continued filename", ct: mpType, body: mp(part("x", `Content-Disposition: form-data; name="a"; filename="ok.txt"; filename*0="shell"; filename*1=".php"`)), want: idMPDisp},
	{name: "nested multipart", ct: mpType, body: mp(part("x", `Content-Disposition: form-data; name="a"`, "Content-Type: multipart/mixed; boundary=inner")), want: idMPNested},
	{name: "base64 transfer encoding", ct: mpType, body: mp(part("PHNjcmlwdD4=", `Content-Disposition: form-data; name="a"`, "Content-Transfer-Encoding: base64")), want: idMPTransfer},
	{name: "quoted-printable transfer encoding", ct: mpType, body: mp(part("=3Cscript=3E", `Content-Disposition: form-data; name="a"`, "Content-Transfer-Encoding: quoted-printable")), want: idMPTransfer},
	{name: "part in utf-16", ct: mpType, body: mp(part("x", `Content-Disposition: form-data; name="a"`, "Content-Type: text/plain; charset=utf-16")), want: 5002006},
	{name: "part type with a repeated parameter", ct: mpType, body: mp(part("x", `Content-Disposition: form-data; name="a"`, "Content-Type: text/plain; charset=utf-8; charset=utf-16")), want: 5002007},
	{name: "malformed part type", ct: mpType, body: mp(part("x", `Content-Disposition: form-data; name="a"`, "Content-Type: text")), want: idMPHeader},

	// A body that is not multipart.
	{name: "json under a multipart type", ct: mpType, body: `{"a":1}`, want: 5002040},
	{name: "xml under a multipart type", ct: mpType, body: `<a/>`, want: 5002041},
})

func TestMultipart(t *testing.T) { runTable(t, multipartRows) }

func FuzzMultipart(f *testing.F) {
	for _, r := range multipartRows {
		f.Add(r.body)
	}
	in := New(Policy{})
	f.Fuzz(func(t *testing.T, body string) {
		fuzzNoPanic(t, in, row{ct: mpType, body: body})
		fuzzNoPanic(t, in, row{ct: "multipart/form-data; boundary=a", body: body})
	})
}

func BenchmarkMultipart(b *testing.B) {
	var sb strings.Builder
	for i := 0; i < 20; i++ {
		sb.WriteString(field(fmt.Sprintf("field%d", i), "some value for the field"))
	}
	sb.WriteString(file("upload", "photo.jpg", strings.Repeat("\x89PNG binary\r\n content ", 4500)))
	sb.WriteString(closing())
	benchBody(b, mpType, sb.String())
}
