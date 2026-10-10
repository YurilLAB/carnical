package formats

import "bytes"

// A body that is JSON or XML under a Content-Type that says form, text/plain or multipart is the standard way to get a body past a
// filter that reads bodies by their declared type (a form filter that never looks inside "a=b&c=d"), to a back end that reads it by
// its content. It is also how a cross-site request is made to carry JSON with no preflight: a form can send text/plain, and
// a lenient JSON endpoint reads it. This looks at the first bytes of the body and says what it looks like; a real form, a real
// multipart body and a plain text body do not start like any of these.

type sniffed struct {
	json, xml, multipart bool
	at                   int
}

// sniff looks at how a body starts. For text/plain (strict is false) it also wants the body to end the way a document does, because
// plain text may well start with a bracket.
func sniff(b []byte, strict bool) sniffed {
	var s sniffed
	i := 0
	if bytes.HasPrefix(b, bomUTF8) {
		i = len(bomUTF8)
	}
	if len(b) >= 4 && b[0] == '-' && b[1] == '-' {
		// --boundary CRLF
		for j := 2; j < len(b) && j < 74; j++ {
			if b[j] == '\r' && j+1 < len(b) && b[j+1] == '\n' && j > 2 {
				s.multipart = true
				return s
			}
			if !boundaryChar(b[j]) {
				break
			}
		}
	}
	for i < len(b) && xmlSpace(b[i]) {
		i++
	}
	s.at = i
	if i >= len(b) {
		return s
	}
	end := len(b)
	for end > i && xmlSpace(b[end-1]) {
		end--
	}
	switch b[i] {
	case '{':
		j := skipSpaces(b, i+1)
		if j < len(b) && (b[j] == '"' || b[j] == '}') {
			s.json = !strict || b[end-1] == '}'
		}
	case '[':
		j := skipSpaces(b, i+1)
		if j < len(b) && bytes.IndexByte([]byte("{[\"]-0123456789tfn"), b[j]) >= 0 {
			s.json = !strict || b[end-1] == ']'
		}
	case '<':
		if i+1 < len(b) {
			c := b[i+1]
			if c == '?' || c == '!' || c == '_' || c == ':' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' {
				s.xml = !strict || b[end-1] == '>'
			}
		}
	}
	return s
}

// skipSpaces moves past the JSON whitespace from i. JSON allows any amount, so padding after the bracket must not hide a
// document; it is one pass over bytes the body holds anyway.
func skipSpaces(b []byte, i int) int {
	for i < len(b) && xmlSpace(b[i]) {
		i++
	}
	return i
}

// checkSniff reports a body whose first bytes do not match its declared type. It returns false when the caller should stop.
func (in *Inspector) checkSniff(f *finder, ci ctInfo, body []byte) bool {
	s := sniff(body, ci.kind == kindText)
	switch {
	case s.json && f.hit(rMismatchJSONBody, s.at, dNone):
		return false
	case s.xml && f.hit(rMismatchXMLBody, s.at, dNone):
		return false
	case s.multipart && ci.kind != kindMultipart && f.hit(rMismatchMPBody, 0, dNone):
		return false
	}
	return true
}
