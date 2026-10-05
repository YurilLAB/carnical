package formats

import (
	"bytes"
	"strings"
	"unicode/utf8"
)

// This is the structural reader for multipart bodies. It does not decode them or look at what an uploaded file holds (the proxy
// does that), it checks that the body is laid out the way RFC 2046 and RFC 7578 say, because every parser repairs a different part
// of a body that is not: whether data before the first boundary is skipped or read, whether a part ends at a bare line feed,
// whether a body with no closing boundary is accepted, whether a second Content-Disposition replaces the first, whether a "filename*"
// overrides a "filename", whether a base64 transfer encoding is decoded. A body that needs any of those repairs is refused.

// boundaryChar is bchars of RFC 2046: the characters a boundary may hold (a space too, but not as the last one).
func boundaryChar(c byte) bool {
	switch {
	case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		return true
	}
	switch c {
	case '\'', '(', ')', '+', '_', ',', '-', '.', '/', ':', '=', '?', ' ':
		return true
	}
	return false
}

var (
	crlf  = []byte{'\r', '\n'}
	dashd = []byte{'-', '-'}
)

// hdrSlot remembers a part header that matters, and where it was.
type hdrSlot struct {
	seen bool
	val  string
	at   int
}

type mpScanner struct {
	f    *finder
	body []byte
	lim  *MultipartLimits
	in   *Inspector
	// formData is true for multipart/form-data, where every part must say it is form data and name itself.
	formData bool
	delim    []byte
	names    map[string]struct{}
	fold     []byte
}

// checkMultipart checks the structure of a multipart body. It returns false when the caller should stop.
func (in *Inspector) checkMultipart(f *finder, body []byte, boundary string, subtype string) bool {
	lim := &in.pol.Multipart
	if boundary == "" {
		f.hit(rMPNoBoundary, -1, dNone)
		return false
	}
	if len(boundary) > lim.MaxBoundaryLen {
		if f.hitLimit(rMPBadBound, dBoundaryTooLong, lim.MaxBoundaryLen, -1) {
			return false
		}
	}
	if boundary[len(boundary)-1] == ' ' {
		if f.hit(rMPBadBound, -1, dBoundaryTrailingSpace) {
			return false
		}
	}
	for i := 0; i < len(boundary); i++ {
		if !boundaryChar(boundary[i]) {
			if f.hit(rMPBadBound, -1, dBoundaryChar) {
				return false
			}
			break
		}
	}
	s := &mpScanner{f: f, body: body, lim: lim, in: in, formData: subtype == "form-data", delim: []byte("--" + boundary)}
	if f.active(rMPDupName) {
		s.names = map[string]struct{}{}
	}
	return s.run()
}

// run walks the body: preamble, then parts until the closing delimiter, then the epilogue.
func (s *mpScanner) run() bool {
	f, body, delim := s.f, s.body, s.delim
	L := len(delim)
	first := bytes.Index(body, delim)
	if first < 0 {
		f.hit(rMPDelim, -1, dNoBoundaryInBody)
		return false
	}
	if first > 0 {
		rl := rMPPreamble
		if first < 2 || !bytes.Equal(body[first-2:first], crlf) {
			rl = rMPDelim
		}
		if f.hit(rl, first, dNone) {
			return false
		}
	}
	d := first // the delimiter that starts the current part, found at the start of a line
	for parts := 1; ; parts++ {
		tail := body[d+L:]
		var start int // where this part's header block starts
		switch {
		case bytes.HasPrefix(tail, dashd):
			// The closing delimiter. A line break may follow it, and nothing else.
			rest := tail[2:]
			if len(rest) > 0 && !bytes.Equal(rest, crlf) {
				f.hit(rMPEpilogue, d+L+2, dNone)
				return false
			}
			return true
		case bytes.HasPrefix(tail, crlf):
			start = d + L + 2
		case len(tail) > 0 && tail[0] == '\n':
			if f.hit(rMPBareLF, d+L, dNone) {
				return false
			}
			start = d + L + 1
		case len(tail) == 0:
			f.hit(rMPNoClose, d+L, dNone)
			return false
		default:
			f.hit(rMPDelim, d+L, dBadBoundaryLine)
			return false
		}
		if parts > s.lim.MaxParts {
			f.hitLimit(rMPLimit, dTooManyParts, s.lim.MaxParts, d)
			return false
		}
		contentStart, ok := s.headers(start)
		if !ok {
			return false
		}
		if d, ok = s.nextDelimiter(contentStart); !ok {
			return false
		}
	}
}

// nextDelimiter finds the delimiter that ends the part whose content starts at from. It must be at the start of a line and be
// followed by "--" or a line break. Occurrences that are not are reported and read as content, as a strict parser would.
func (s *mpScanner) nextDelimiter(from int) (int, bool) {
	f, body, delim := s.f, s.body, s.delim
	L := len(delim)
	pos := from
	for {
		i := bytes.Index(body[pos:], delim)
		if i < 0 {
			f.hit(rMPNoClose, len(body), dNone)
			return 0, false
		}
		i += pos
		pos = i + L
		atLine := i >= 2 && bytes.Equal(body[i-2:i], crlf)
		if !atLine {
			rl, d := rMPDelim, dMidLine
			if i >= 1 && body[i-1] == '\n' {
				rl, d = rMPBareLF, dNone
			}
			if f.hit(rl, i, d) {
				return 0, false
			}
			continue
		}
		if i < from+2 {
			// The line break before the delimiter is the one that ends the headers: nothing separates the headers from the boundary.
			if f.hit(rMPDelim, i, dNoBlankLine) {
				return 0, false
			}
			continue
		}
		tail := body[pos:]
		switch {
		case bytes.HasPrefix(tail, dashd), bytes.HasPrefix(tail, crlf):
			return i, true
		case len(tail) > 0 && tail[0] == '\n':
			if f.hit(rMPBareLF, pos, dNone) {
				return 0, false
			}
			return i, true
		case len(tail) == 0:
			f.hit(rMPNoClose, pos, dNone)
			return 0, false
		}
		if f.hit(rMPDelim, pos, dBadBoundaryLine) {
			return 0, false
		}
	}
}

// headers reads and checks one part's header block that starts at start, and returns where its content starts.
func (s *mpScanner) headers(start int) (int, bool) {
	f, body := s.f, s.body
	pos := start
	var disp, ctype, cte hdrSlot
	count := 0
	for {
		if pos >= len(body) {
			f.hit(rMPNoClose, len(body), dNone)
			return 0, false
		}
		if pos-start > s.lim.MaxHeaderBytes {
			f.hitLimit(rMPLimit, dHeaderTooLarge, s.lim.MaxHeaderBytes, start)
			return 0, false
		}
		nl := bytes.IndexByte(body[pos:], '\n')
		if nl < 0 {
			f.hit(rMPNoClose, len(body), dNone)
			return 0, false
		}
		nl += pos
		line := body[pos:nl]
		if len(line) > 0 && line[len(line)-1] == '\r' {
			line = line[:len(line)-1]
		} else if f.hit(rMPBareLF, nl, dNone) {
			return 0, false
		}
		at := pos
		pos = nl + 1
		if len(line) == 0 {
			break // the blank line that ends the header block
		}
		count++
		if count > s.lim.MaxHeaders {
			f.hitLimit(rMPLimit, dTooManyHeaders, s.lim.MaxHeaders, at)
			return 0, false
		}
		name, value, ok := splitHeaderLine(line)
		if !ok {
			if f.hit(rMPHeader, at, dBadHeaderLine) {
				return 0, false
			}
			continue
		}
		var slot *hdrSlot
		switch name {
		case "content-disposition":
			slot = &disp
		case "content-type":
			slot = &ctype
		case "content-transfer-encoding":
			slot = &cte
		default:
			continue
		}
		if slot.seen {
			if f.hit(rMPDupHeader, at, dNone) {
				return 0, false
			}
			continue
		}
		slot.seen, slot.val, slot.at = true, value, at
	}
	if cte.seen {
		switch strings.ToLower(cte.val) {
		case "7bit", "8bit", "binary":
		default:
			if f.hit(rMPTransfer, cte.at, dNone) {
				return 0, false
			}
		}
	}
	if ctype.seen && !s.partType(ctype.val, ctype.at) {
		return 0, false
	}
	if disp.seen {
		if !s.disposition(disp.val, disp.at) {
			return 0, false
		}
	} else if s.formData && f.hit(rMPDisp, start, dNoDisposition) {
		return 0, false
	}
	return pos, true
}

// splitHeaderLine reads "Name: value". The name is a token directly followed by the colon (a space before it, or a line that starts
// with a space or tab, which continues the line before, is a way to hide a header from a parser that does not accept it), and the
// value has no control character.
func splitHeaderLine(line []byte) (name, value string, ok bool) {
	i := 0
	for i < len(line) && tchar(line[i]) {
		i++
	}
	if i == 0 || i >= len(line) || line[i] != ':' {
		return "", "", false
	}
	v := bytes.Trim(line[i+1:], " \t")
	for _, c := range v {
		if c < 0x20 && c != '\t' || c == 0x7f {
			return "", "", false
		}
	}
	return strings.ToLower(string(line[:i])), string(v), true
}

// partType checks a part's Content-Type: well formed, no repeated parameter, an accepted charset, and not itself multipart.
func (s *mpScanner) partType(value string, at int) bool {
	f := s.f
	mt, p := parseMediaType(value)
	if p != nil {
		rl := rMPHeader
		if p.kind == pkDuplicate {
			rl = rTypeDupParam
		}
		return !f.hit(rl, at, p.d)
	}
	if mt.typ == "multipart" && f.hit(rMPNested, at, dNone) {
		return false
	}
	if cs, ok := mt.param("charset"); ok && !s.in.charsets[strings.ToLower(cs)] {
		if f.hit(rCharset, at, dInPart) {
			return false
		}
	}
	return true
}

// disposition checks a part's Content-Disposition.
func (s *mpScanner) disposition(value string, at int) bool {
	f := s.f
	typ, params, p := splitDisposition(value)
	if p != nil {
		rl := rMPHeader
		if p.kind == pkDuplicate {
			rl = rMPDupParam
		}
		return !f.hit(rl, at, p.d)
	}
	if s.formData && typ != "form-data" {
		if f.hit(rMPDisp, at, dNotFormData) {
			return false
		}
	}
	var name, filename, star string
	var hasName, hasFile, hasStar bool
	for _, pr := range params {
		switch pr.name {
		case "name":
			name, hasName = pr.value, true
		case "filename":
			filename, hasFile = pr.value, true
		case "filename*":
			star, hasStar = pr.value, true
		}
	}
	if s.formData && !hasName && f.hit(rMPDisp, at, dNoName) {
		return false
	}
	if hasName {
		if len(name) > s.lim.MaxNameLen {
			f.hitLimit(rMPLimit, dNameTooLong, s.lim.MaxNameLen, at)
			return false
		}
		if s.names != nil && !strings.HasSuffix(name, "[]") {
			s.fold = appendFolded(s.fold[:0], []byte(name), false)
			if _, dup := s.names[string(s.fold)]; dup {
				if f.hit(rMPDupName, at, dNone) {
					return false
				}
			} else {
				s.names[string(s.fold)] = struct{}{}
			}
		}
	}
	if hasStar {
		if f.hit(rMPFileStar, at, dNone) {
			return false
		}
		if hasFile {
			dec, ok := decodeExtValue(star)
			if !ok {
				return !f.hit(rMPFileMis, at, dBadExtValue)
			}
			// A client may percent-encode the plain filename too; the two agree if either form matches.
			plain, _ := unescapeQuery(strings.ReplaceAll(filename, "+", "%2B"))
			if dec != filename && dec != plain {
				return !f.hit(rMPFileMis, at, dNone)
			}
		}
	}
	return true
}

// decodeExtValue decodes an RFC 5987 extended value, charset'language'percent-encoded-bytes, for UTF-8 and ISO-8859-1.
func decodeExtValue(v string) (string, bool) {
	first := strings.IndexByte(v, '\'')
	if first < 0 {
		return "", false
	}
	second := strings.IndexByte(v[first+1:], '\'')
	if second < 0 {
		return "", false
	}
	charset := strings.ToLower(v[:first])
	enc := v[first+1+second+1:]
	var out []byte
	for i := 0; i < len(enc); i++ {
		c := enc[i]
		if c == '%' {
			if i+2 >= len(enc) || !isHexDigit(enc[i+1]) || !isHexDigit(enc[i+2]) {
				return "", false
			}
			out = append(out, byte(hexVal(enc[i+1])<<4|hexVal(enc[i+2])))
			i += 2
			continue
		}
		if !tchar(c) || c == '*' || c == '\'' {
			return "", false
		}
		out = append(out, c)
	}
	switch charset {
	case "utf-8":
		if !utf8.Valid(out) {
			return "", false
		}
		return string(out), true
	case "iso-8859-1":
		r := make([]rune, len(out))
		for i, b := range out {
			r[i] = rune(b)
		}
		return string(r), true
	}
	return "", false
}
