package formats

import (
	"bytes"
	"strings"
	"unicode/utf8"
)

// A bounded XML scanner, not encoding/xml: Go's decoder has a non-strict mode, a configurable charset reader and its own ideas about
// what to do with odd input, and the point is that nothing here is left to a decoder's choice. The scanner reads the document once,
// from the first byte to the last, keeps only the names of the elements that are open, and refuses what no request body needs and
// what every XML attack uses: a DOCTYPE (and so every entity, external or not), XInclude, XSLT, processing instructions, entity
// references that are not the five predefined ones, text split by comments or CDATA sections to hide a keyword from a filter, and an
// encoding that is not the one the bytes are in.

const (
	xmlnsXInclude = "http://www.w3.org/2001/XInclude"
	xmlnsXSLT     = "http://www.w3.org/1999/XSL/Transform"
)

type xmlScanner struct {
	f   *finder
	b   []byte
	i   int
	lim *XMLLimits
	// stack holds the offsets of the names of the open elements.
	stack      []span
	elements   int
	pieces     int
	rootSeen   bool
	rootClosed bool
	attrs      []span // names of the attributes of the element being read
}

// checkXML checks an XML body (XML, SOAP, XML-RPC, any +xml type). It returns false when the caller should stop.
func (in *Inspector) checkXML(f *finder, ci ctInfo, body []byte) bool {
	start, ok := f.textStart(body)
	if !ok {
		return false
	}
	p := &xmlScanner{f: f, b: body, i: start, lim: &in.pol.XML}
	return p.run(in, ci)
}

func xmlSpace(c byte) bool { return c == ' ' || c == '\t' || c == '\n' || c == '\r' }

func (p *xmlScanner) syntax(d detail) bool {
	p.f.hit(rXMLSyntax, p.i, d)
	return false
}

func (p *xmlScanner) limit(d detail, n int) bool {
	p.f.hitLimit(rXMLLimit, d, n, p.i)
	return false
}

func (p *xmlScanner) skipSpace() int {
	n := 0
	for p.i < len(p.b) && xmlSpace(p.b[p.i]) {
		p.i++
		n++
	}
	return n
}

func (p *xmlScanner) run(in *Inspector, ci ctInfo) bool {
	f, b := p.f, p.b
	enc := ""
	if bytes.HasPrefix(b[p.i:], []byte("<?xml")) && p.i+5 < len(b) && xmlSpace(b[p.i+5]) {
		var ok bool
		if enc, ok = p.declaration(); !ok {
			return false
		}
	} else {
		at := p.i
		for at < len(b) && xmlSpace(b[at]) {
			at++
		}
		if at >= len(b) {
			p.i = at
			return p.syntax(dEmptyDocument)
		}
		if b[at] != '<' {
			f.hit(rMismatchDeclXML, at, dNotXMLStart)
			return false
		}
	}
	if !p.encoding(in, ci, enc) {
		return false
	}
	for p.i < len(b) {
		if b[p.i] != '<' {
			if !p.text() {
				return false
			}
			continue
		}
		if p.i+1 >= len(b) {
			return p.syntax(dUnexpectedEnd)
		}
		var ok bool
		switch c := b[p.i+1]; {
		case c == '/':
			ok = p.endTag()
		case c == '?':
			ok = p.instruction()
		case c == '!':
			ok = p.bang()
		default:
			ok = p.startTag()
		}
		if !ok {
			return false
		}
	}
	if len(p.stack) > 0 {
		return p.syntax(dUnexpectedEnd)
	}
	if !p.rootSeen {
		return p.syntax(dNoRoot)
	}
	return true
}

// declaration reads <?xml version="1.0" encoding="..." standalone="..."?> and returns the encoding it names, lower case ("" if none).
func (p *xmlScanner) declaration() (string, bool) {
	b := p.b
	end := bytes.Index(b[p.i:], []byte("?>"))
	if end < 0 {
		return "", p.syntax(dBadDeclaration)
	}
	end += p.i
	at := p.i + 5
	enc := ""
	order := 0 // 1 after version, 2 after encoding, 3 after standalone
	for {
		for at < end && xmlSpace(b[at]) {
			at++
		}
		if at >= end {
			break
		}
		ns := at
		for at < end && b[at] >= 'a' && b[at] <= 'z' {
			at++
		}
		name := string(b[ns:at])
		for at < end && xmlSpace(b[at]) {
			at++
		}
		if at >= end || b[at] != '=' || name == "" {
			p.i = ns
			return "", p.syntax(dBadDeclaration)
		}
		at++
		for at < end && xmlSpace(b[at]) {
			at++
		}
		if at >= end || b[at] != '"' && b[at] != '\'' {
			p.i = at
			return "", p.syntax(dBadDeclaration)
		}
		q := b[at]
		vs := at + 1
		ve := bytes.IndexByte(b[vs:end], q)
		if ve < 0 {
			p.i = at
			return "", p.syntax(dBadDeclaration)
		}
		ve += vs
		val := string(b[vs:ve])
		at = ve + 1
		switch {
		case name == "version" && order == 0 && (val == "1.0" || val == "1.1"):
			order = 1
		case name == "encoding" && order == 1 && validEncodingName(val):
			enc, order = strings.ToLower(val), 2
		case name == "standalone" && order >= 1 && order < 3 && (val == "yes" || val == "no"):
			order = 3
		default:
			p.i = ns
			return "", p.syntax(dBadDeclaration)
		}
		if at < end && !xmlSpace(b[at]) {
			p.i = at
			return "", p.syntax(dBadDeclaration)
		}
	}
	if order == 0 {
		return "", p.syntax(dBadDeclaration)
	}
	p.i = end + 2
	return enc, true
}

func validEncodingName(s string) bool {
	if s == "" || !(s[0] >= 'a' && s[0] <= 'z' || s[0] >= 'A' && s[0] <= 'Z') {
		return false
	}
	for i := 1; i < len(s); i++ {
		c := s[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '.' || c == '_' || c == '-') {
			return false
		}
	}
	return true
}

// normCharset reduces the common aliases of the accepted charsets to one name, for comparison.
func normCharset(s string) string {
	switch s {
	case "utf8":
		return "utf-8"
	case "ascii", "us_ascii", "ansi_x3.4-1968":
		return "us-ascii"
	case "latin1", "latin-1", "iso8859-1", "iso_8859-1", "l1":
		return "iso-8859-1"
	case "cp1252", "windows1252":
		return "windows-1252"
	}
	return s
}

func isWideName(s string) bool {
	for _, p := range []string{"utf-16", "utf16", "utf-32", "utf32", "ucs-2", "ucs2", "ucs-4", "ucs4", "ucs_2", "ucs_4", "unicode"} {
		if strings.HasPrefix(s, p) {
			return true
		}
	}
	return false
}

// encoding settles which encoding the bytes are in, from the declaration and the Content-Type charset, and checks the bytes against
// it. A declaration that disagrees with the header, or names an encoding the site does not take (UTF-16 above all), or does not
// describe the bytes, is how a body is made to be read one way by a filter and another by a parser.
func (p *xmlScanner) encoding(in *Inspector, ci ctInfo, decl string) bool {
	f, b := p.f, p.b
	eff := "utf-8"
	header := normCharset(ci.charset)
	if decl != "" {
		d := normCharset(decl)
		switch {
		case isWideName(d):
			if f.hit(rXMLEncWide, -1, dNone) {
				return false
			}
		case !in.charsets[d]:
			if f.hit(rXMLEncBad, -1, dNone) {
				return false
			}
		}
		if header != "" && header != d && f.hit(rXMLEncMis, -1, dHeaderDisagrees) {
			return false
		}
		eff = d
	} else if header != "" {
		eff = header
	}
	high := false
	for i := p.i; i < len(b); i++ {
		c := b[i]
		if c < 0x20 && c != '\t' && c != '\n' && c != '\r' {
			if f.hit(rControlChar, i, dNone) {
				return false
			}
			break
		}
		if c >= utf8.RuneSelf {
			high = true
		}
	}
	if !high {
		return true
	}
	switch eff {
	case "utf-8":
		if i := firstInvalidUTF8(b[p.i:]); i >= 0 && f.hit(rInvalidUTF8, p.i+i, dNone) {
			return false
		}
	case "us-ascii":
		if f.hit(rXMLEncMis, -1, dNonASCII) {
			return false
		}
	default:
		// A single-byte charset named only by the header: the XML default is UTF-8 and some parsers use it whatever the header says.
		if decl == "" && f.hit(rXMLEncMis, -1, dHeaderNoDeclaration) {
			return false
		}
	}
	return true
}

// ---- names, references ----

// xmlNameStart and xmlNameChar are the productions of XML 1.0 (fifth edition) for non-ASCII characters.
func xmlNameStart(r rune) bool {
	switch {
	case r >= 0xC0 && r <= 0xD6, r >= 0xD8 && r <= 0xF6, r >= 0xF8 && r <= 0x2FF, r >= 0x370 && r <= 0x37D,
		r >= 0x37F && r <= 0x1FFF, r >= 0x200C && r <= 0x200D, r >= 0x2070 && r <= 0x218F, r >= 0x2C00 && r <= 0x2FEF,
		r >= 0x3001 && r <= 0xD7FF, r >= 0xF900 && r <= 0xFDCF, r >= 0xFDF0 && r <= 0xFFFD, r >= 0x10000 && r <= 0xEFFFF:
		return true
	}
	return false
}

func xmlNameChar(r rune) bool {
	return xmlNameStart(r) || r == 0xB7 || r >= 0x300 && r <= 0x36F || r >= 0x203F && r <= 0x2040
}

// name reads an XML name at p.i and returns its span. It is refused if it is empty, not a name, or longer than the limit.
func (p *xmlScanner) name() (span, bool) {
	b := p.b
	start := p.i
	i := p.i
	first := true
	for i < len(b) {
		c := b[i]
		if c < utf8.RuneSelf {
			ok := c == '_' || c == ':' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z'
			if !first {
				ok = ok || c == '-' || c == '.' || c >= '0' && c <= '9'
			}
			if !ok {
				break
			}
			i++
		} else {
			r, n := utf8.DecodeRune(b[i:])
			if r == utf8.RuneError && n == 1 {
				break
			}
			if !(xmlNameStart(r) || !first && xmlNameChar(r)) {
				break
			}
			i += n
		}
		first = false
		if i-start > p.lim.MaxNameLen {
			p.i = start
			return span{}, p.limit(dNameTooLong, p.lim.MaxNameLen)
		}
	}
	if i == start {
		return span{}, p.syntax(dBadName)
	}
	p.i = i
	return span{start, i}, true
}

// reference checks the reference that starts with the "&" at b[at]: one of the five predefined entities or a character reference to
// a character XML allows. It returns the offset after the semicolon. A reference to any other entity can only mean a DOCTYPE
// declared it, and no DOCTYPE is accepted.
func (p *xmlScanner) reference(at int) (int, bool) {
	b := p.b
	// bad is what a bad reference does: refuse, or in monitor mode go on with the byte after the ampersand.
	bad := func(d detail) (int, bool) {
		if p.f.hit(rXMLEntRef, at, d) {
			return 0, false
		}
		return at + 1, true
	}
	j := at + 1
	if j >= len(b) {
		return bad(dBadReference)
	}
	if b[j] == '#' {
		j++
		base := 10
		if j < len(b) && b[j] == 'x' {
			base = 16
			j++
		}
		ds := j
		v := 0
		for ; j < len(b) && j-ds < 8; j++ {
			c := b[j]
			if c >= '0' && c <= '9' {
				v = v*base + int(c-'0')
			} else if base == 16 && isHexDigit(c) {
				v = v*16 + int(hexVal(c))
			} else {
				break
			}
		}
		if j == ds || j >= len(b) || b[j] != ';' || !xmlChar(v) {
			return bad(dBadCharRef)
		}
		return j + 1, true
	}
	ns := j
	for j < len(b) && j-ns < 8 && b[j] >= 'a' && b[j] <= 'z' {
		j++
	}
	if j >= len(b) || b[j] != ';' {
		return bad(dBadReference)
	}
	switch string(b[ns:j]) {
	case "lt", "gt", "amp", "quot", "apos":
		return j + 1, true
	}
	return bad(dUnknownEntity)
}

func xmlChar(v int) bool {
	return v == 0x9 || v == 0xA || v == 0xD || v >= 0x20 && v <= 0xD7FF || v >= 0xE000 && v <= 0xFFFD || v >= 0x10000 && v <= 0x10FFFF
}

// ---- content ----

// text reads a run of character data, up to the next "<".
func (p *xmlScanner) text() bool {
	b := p.b
	start := p.i
	end := bytes.IndexByte(b[start:], '<')
	if end < 0 {
		end = len(b)
	} else {
		end += start
	}
	if end-start > p.lim.MaxTextLen {
		p.i = start
		return p.limit(dTextTooLong, p.lim.MaxTextLen)
	}
	inRoot := len(p.stack) > 0
	solid := false
	for i := start; i < end; i++ {
		c := b[i]
		switch {
		case xmlSpace(c):
		case c == '&':
			if !inRoot {
				p.i = i
				return p.syntax(dTextOutsideRoot)
			}
			next, ok := p.reference(i)
			if !ok {
				return false
			}
			solid = true
			i = next - 1
		case c == ']':
			if i+2 < end && b[i+1] == ']' && b[i+2] == '>' {
				p.i = i
				return p.syntax(dCDATAEnd)
			}
			if !inRoot {
				p.i = i
				return p.syntax(dTextOutsideRoot)
			}
			solid = true
		default:
			if !inRoot {
				p.i = i
				return p.syntax(dTextOutsideRoot)
			}
			solid = true
		}
	}
	if solid {
		p.pieces++
		if p.pieces > 1 && p.f.hit(rXMLTextSplit, start, dNone) {
			return false
		}
	}
	p.i = end
	return true
}

func (p *xmlScanner) startTag() bool {
	f, b := p.f, p.b
	p.i++ // <
	nm, ok := p.name()
	if !ok {
		return false
	}
	if p.rootClosed {
		p.i = nm.a
		return p.syntax(dContentAfterRoot)
	}
	if len(p.stack)+1 > p.lim.MaxDepth {
		p.i = nm.a
		return p.limit(dTooDeep, p.lim.MaxDepth)
	}
	p.elements++
	if p.elements > p.lim.MaxElements {
		p.i = nm.a
		return p.limit(dTooManyElements, p.lim.MaxElements)
	}
	p.attrs = p.attrs[:0]
	for {
		spaces := p.skipSpace()
		if p.i >= len(b) {
			return p.syntax(dUnexpectedEnd)
		}
		c := b[p.i]
		if c == '>' {
			p.i++
			p.stack = append(p.stack, nm)
			p.rootSeen = true
			p.pieces = 0
			return true
		}
		if c == '/' {
			if p.i+1 >= len(b) || b[p.i+1] != '>' {
				return p.syntax(dBadTag)
			}
			p.i += 2
			p.rootSeen = true
			p.pieces = 0
			if len(p.stack) == 0 {
				p.rootClosed = true
			}
			return true
		}
		if spaces == 0 {
			return p.syntax(dMissingSpace)
		}
		an, ok := p.name()
		if !ok {
			return false
		}
		if len(p.attrs)+1 > p.lim.MaxAttributes {
			p.i = an.a
			return p.limit(dTooManyAttributes, p.lim.MaxAttributes)
		}
		for _, o := range p.attrs {
			if bytes.Equal(b[o.a:o.b], b[an.a:an.b]) {
				if f.hit(rXMLDupAttr, an.a, dNone) {
					return false
				}
				break
			}
		}
		p.attrs = append(p.attrs, an)
		p.skipSpace()
		if p.i >= len(b) || b[p.i] != '=' {
			return p.syntax(dExpectedEquals)
		}
		p.i++
		p.skipSpace()
		if p.i >= len(b) || b[p.i] != '"' && b[p.i] != '\'' {
			return p.syntax(dExpectedQuote)
		}
		if !p.attrValue(an) {
			return false
		}
	}
}

// attrValue reads a quoted attribute value, checks the references in it, and, for a namespace declaration, what it declares.
func (p *xmlScanner) attrValue(name span) bool {
	b := p.b
	q := b[p.i]
	vs := p.i + 1
	i := vs
	for i < len(b) && b[i] != q {
		switch b[i] {
		case '<':
			p.i = i
			return p.syntax(dLessThanInAttr)
		case '&':
			next, ok := p.reference(i)
			if !ok {
				return false
			}
			i = next - 1
		}
		i++
		if i-vs > p.lim.MaxAttrValueLen {
			p.i = vs
			return p.limit(dValueTooLong, p.lim.MaxAttrValueLen)
		}
	}
	if i >= len(b) {
		p.i = vs
		return p.syntax(dUnexpectedEnd)
	}
	n := b[name.a:name.b]
	if string(n) == "xmlns" || bytes.HasPrefix(n, []byte("xmlns:")) {
		uri := strings.TrimSpace(decodeRefs(b[vs:i]))
		switch uri {
		case xmlnsXInclude:
			if p.f.hit(rXMLXInclude, vs, dNone) {
				return false
			}
		case xmlnsXSLT:
			if p.f.hit(rXMLXSLT, vs, dNone) {
				return false
			}
		}
	}
	p.i = i + 1
	return true
}

// decodeRefs resolves the references in an attribute value that a namespace declaration could hide behind ("&#104;ttp").
func decodeRefs(v []byte) string {
	if bytes.IndexByte(v, '&') < 0 {
		return string(v)
	}
	var out []byte
	for i := 0; i < len(v); i++ {
		if v[i] != '&' {
			out = append(out, v[i])
			continue
		}
		end := bytes.IndexByte(v[i:], ';')
		if end < 0 || end > 12 {
			out = append(out, v[i])
			continue
		}
		ref := string(v[i+1 : i+end])
		switch {
		case ref == "lt":
			out = append(out, '<')
		case ref == "gt":
			out = append(out, '>')
		case ref == "amp":
			out = append(out, '&')
		case ref == "quot":
			out = append(out, '"')
		case ref == "apos":
			out = append(out, '\'')
		case strings.HasPrefix(ref, "#x"), strings.HasPrefix(ref, "#"):
			base, digits := 10, ref[1:]
			if strings.HasPrefix(ref, "#x") {
				base, digits = 16, ref[2:]
			}
			n := 0
			ok := digits != ""
			for k := 0; k < len(digits); k++ {
				c := digits[k]
				switch {
				case c >= '0' && c <= '9':
					n = n*base + int(c-'0')
				case base == 16 && isHexDigit(c):
					n = n*16 + int(hexVal(c))
				default:
					ok = false
				}
			}
			if !ok || !xmlChar(n) {
				out = append(out, v[i])
				continue
			}
			out = utf8.AppendRune(out, rune(n))
		default:
			out = append(out, v[i])
			continue
		}
		i += end
	}
	return string(out)
}

func (p *xmlScanner) endTag() bool {
	b := p.b
	p.i += 2 // </
	nm, ok := p.name()
	if !ok {
		return false
	}
	p.skipSpace()
	if p.i >= len(b) || b[p.i] != '>' {
		return p.syntax(dBadTag)
	}
	if len(p.stack) == 0 {
		p.i = nm.a
		return p.syntax(dMismatchedTag)
	}
	top := p.stack[len(p.stack)-1]
	if !bytes.Equal(b[top.a:top.b], b[nm.a:nm.b]) {
		p.i = nm.a
		return p.syntax(dMismatchedTag)
	}
	p.stack = p.stack[:len(p.stack)-1]
	p.i++
	p.pieces = 0
	if len(p.stack) == 0 {
		p.rootClosed = true
	}
	return true
}

// instruction handles <?...?>. The only one allowed is the XML declaration, at the very start, which run already took.
func (p *xmlScanner) instruction() bool {
	b := p.b
	end := bytes.Index(b[p.i:], []byte("?>"))
	if end < 0 {
		return p.syntax(dUnterminatedPI)
	}
	if rest := b[p.i+2:]; len(rest) > 3 && strings.EqualFold(string(rest[:3]), "xml") && (xmlSpace(rest[3]) || rest[3] == '?') {
		return p.syntax(dDeclNotFirst) // an XML declaration anywhere but the first bytes is an error, not a processing instruction
	}
	if p.f.hit(rXMLPI, p.i, dNone) {
		return false
	}
	p.i += end + 2
	return true
}

// bang handles <!--, <![CDATA[ and the declarations that start with <!.
func (p *xmlScanner) bang() bool {
	b := p.b
	rest := b[p.i:]
	switch {
	case bytes.HasPrefix(rest, []byte("<!--")):
		end := bytes.Index(rest[4:], []byte("-->"))
		if end < 0 {
			return p.syntax(dUnterminatedComment)
		}
		body := rest[4 : 4+end]
		if bytes.Contains(body, []byte("--")) || len(body) > 0 && body[len(body)-1] == '-' {
			return p.syntax(dBadComment)
		}
		p.i += 4 + end + 3
		return true
	case bytes.HasPrefix(rest, []byte("<![CDATA[")):
		if len(p.stack) == 0 {
			return p.syntax(dTextOutsideRoot)
		}
		end := bytes.Index(rest[9:], []byte("]]>"))
		if end < 0 {
			return p.syntax(dUnterminatedCDATA)
		}
		if end > p.lim.MaxTextLen {
			return p.limit(dTextTooLong, p.lim.MaxTextLen)
		}
		if end > 0 {
			p.pieces++
			if p.pieces > 1 && p.f.hit(rXMLTextSplit, p.i, dNone) {
				return false
			}
		}
		p.i += 9 + end + 3
		return true
	case len(rest) >= 9 && strings.EqualFold(string(rest[:9]), "<!DOCTYPE"):
		return p.doctype()
	}
	for _, decl := range []string{"<!ENTITY", "<!ELEMENT", "<!ATTLIST", "<!NOTATION"} {
		if bytes.HasPrefix(rest, []byte(decl)) {
			if p.f.hit(rXMLEntDecl, p.i, dNone) {
				return false
			}
			break
		}
	}
	return p.syntax(dBadMarkup)
}

// doctype reads a DOCTYPE declaration, including an internal subset, up to its closing ">", and reports it as the most serious thing
// it holds: an ENTITY declaration, then a reference to an external resource, then the DOCTYPE itself. The scan is one pass over
// what follows and stops at the end of the declaration.
func (p *xmlScanner) doctype() bool {
	b := p.b
	i := p.i + 9
	depth := 0
	var quote byte
	entity, external := false, false
	for i < len(b) {
		c := b[i]
		switch {
		case quote != 0:
			if c == quote {
				quote = 0
			}
		case c == '"' || c == '\'':
			quote = c
		case c == '<' && bytes.HasPrefix(b[i:], []byte("<!--")):
			end := bytes.Index(b[i+4:], []byte("-->"))
			if end < 0 {
				return p.syntax(dUnterminatedDoctype)
			}
			i += 4 + end + 2
		case c == '<' && bytes.HasPrefix(b[i:], []byte("<!ENTITY")):
			entity = true
		case c == '[':
			depth++
		case c == ']':
			depth--
		case c == 'S' && bytes.HasPrefix(b[i:], []byte("SYSTEM")), c == 'P' && bytes.HasPrefix(b[i:], []byte("PUBLIC")):
			external = true
		case c == '>' && depth <= 0:
			if entity && p.f.hit(rXMLEntDecl, p.i, dNone) {
				return false
			}
			if external && p.f.hit(rXMLExternal, p.i, dNone) {
				return false
			}
			if p.f.hit(rXMLDoctype, p.i, dNone) {
				return false
			}
			p.i = i + 1
			return true
		}
		i++
	}
	return p.syntax(dUnterminatedDoctype)
}
