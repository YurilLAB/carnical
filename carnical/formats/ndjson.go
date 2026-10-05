package formats

import "bytes"

// NDJSON (also called JSON Lines): one JSON document per line. Each line is read by the same strict parser as a JSON body, under
// the same limits, and the node and key counts are for the whole body, so a body cannot be split into many small documents to
// get past them. Parsers differ about what to do with a blank line and with a carriage return that is not part of a line break,
// so a blank line between records is refused, and a carriage return is only accepted just before a line feed.

// checkNDJSON checks a newline-delimited JSON body. It returns false when the caller should stop.
func (in *Inspector) checkNDJSON(f *finder, ci ctInfo, body []byte) bool {
	if !in.utf8Charset(f, ci, body) {
		return false
	}
	start, ok := f.textStart(body)
	if !ok {
		return false
	}
	lim := &in.pol.NDJSON
	p := newJSONParser(f, &in.pol.JSON, nil)
	p.declared = true
	defer func() { f.line = 0 }()
	line := 0
	for pos := start; pos < len(body); {
		var ln []byte
		next := len(body)
		if nl := bytes.IndexByte(body[pos:], '\n'); nl >= 0 {
			ln, next = body[pos:pos+nl], pos+nl+1
		} else {
			ln = body[pos:]
		}
		line++
		if line > lim.MaxLines {
			f.line = 0
			f.hitLimit(rNDLines, dNone, lim.MaxLines, pos)
			return false
		}
		f.line = line
		if n := len(ln); n > 0 && ln[n-1] == '\r' {
			ln = ln[:n-1]
		}
		if len(ln) == 0 {
			if f.hit(rNDBlank, 0, dNone) {
				return false
			}
		} else if !p.doc(ln, 0) {
			return false
		}
		pos = next
	}
	return true
}
