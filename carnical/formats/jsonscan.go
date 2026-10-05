// SPDX-License-Identifier: Apache-2.0

package formats

import (
	"unicode/utf8"
)

// This is a JSON parser written for this package, not encoding/json, because the decision "is this body acceptable" must not
// depend on what a general-purpose decoder repairs or ignores: Go's keeps the last of two equal keys and matches keys with case
// folded, Python's keeps the last, JavaScript's the last, PHP's the last, some Java libraries the first or all of them. Here a
// body with two keys that any of those would treat as one is refused, so there is nothing for them to disagree about.
//
// It checks RFC 8259 and a little more (see jsonParser.str and the rules for JSON in rules.go), reads the bytes once from start to
// end, never builds a tree, and its memory is the keys of the objects that are open at that moment.

// jsonMember is a value the GraphQL check needs from the top of a document.
type jsonMember struct {
	key        string // decoded, exact
	kind       byte   // first byte of the value: '{', '[', '"' or something else
	start, end int    // the value's bytes in the parsed slice
}

type jsonElem struct {
	kind    byte
	members []jsonMember
}

// jsonCapture collects, from the root object (or from each object in a root array), the members that make up a GraphQL request:
// query, variables, operationName, extensions and reserved method-override metadata. Nothing else is kept.
type jsonCapture struct {
	kind    byte
	members []jsonMember
	// graphQLPossible observes query documents in every root-array object, even beyond retained elements.
	graphQLPossible bool
	// elems holds the first max elements of a root array, and nelems how many there were.
	elems  []jsonElem
	nelems int
	max    int
}

type span struct{ a, b int }

type jsonParser struct {
	f   *finder
	b   []byte
	i   int
	lim *JSONLimits
	// nodes and keys count across every document given to the same parser (an NDJSON body is one budget).
	nodes, keys int
	// fold holds the folded key of every key of every object that is open, one after the other, and spans says where each one is.
	fold  []byte
	spans []span
	// dup and proto say which key checks are on. They are fixed when the parser is made.
	dup, proto bool
	capture    *jsonCapture
	rootArray  bool
	curElem    int // index in capture.elems of the root array element being parsed, or -1
	// declared is true when the Content-Type said this body is JSON, so that a body that does not start like JSON is a mismatch.
	declared bool
}

func newJSONParser(f *finder, lim *JSONLimits, capture *jsonCapture) *jsonParser {
	return &jsonParser{f: f, lim: lim, capture: capture, dup: f.active(rJSONDupKey), proto: f.active(rJSONProto)}
}

// scanJSON checks b as one JSON document. It returns false when the caller should stop: the request is refused, or the document is
// unreadable so there is nothing more to learn from it.
func scanJSON(f *finder, b []byte, lim *JSONLimits, capture *jsonCapture, declared bool) bool {
	start, ok := f.textStart(b)
	if !ok {
		return false
	}
	p := newJSONParser(f, lim, capture)
	p.declared = declared
	return p.doc(b, start)
}

// jsonStart reports whether c can begin a JSON value.
func jsonStart(c byte) bool {
	return c == '{' || c == '[' || c == '"' || c == '-' || c >= '0' && c <= '9' || c == 't' || c == 'f' || c == 'n'
}

func (p *jsonParser) doc(b []byte, start int) bool {
	p.b, p.i = b, start
	p.rootArray = false
	p.curElem = -1
	p.skipWS()
	if p.i >= len(b) {
		return p.syntax(dEmptyDocument)
	}
	if p.declared && !jsonStart(b[p.i]) {
		p.f.hit(rMismatchDeclJSON, p.i, dNotJSONStart)
		return false
	}
	if p.capture != nil {
		p.capture.kind = b[p.i]
	}
	if !p.value(0, false) {
		return false
	}
	p.skipWS()
	if p.i < len(b) {
		p.f.hit(rJSONTrailing, p.i, dNone)
		return false
	}
	return true
}

// syntax reports a syntax error. A parser cannot carry on after one, so it always returns false.
func (p *jsonParser) syntax(d detail) bool {
	p.f.hit(rJSONSyntax, p.i, d)
	return false
}

// limit reports a limit that was reached and stops: past a limit nothing the parser did would be bounded by it.
func (p *jsonParser) limit(d detail, n, at int) bool {
	p.f.hitLimit(rJSONLimit, d, n, at)
	return false
}

func (p *jsonParser) skipWS() {
	for p.i < len(p.b) {
		switch p.b[p.i] {
		case ' ', '\t', '\n', '\r':
			p.i++
		default:
			return
		}
	}
}

// value parses one value. depth is the number of arrays and objects that enclose it. ctor is true if the value is the value of a
// "constructor" key, so that an object that follows can be checked for a "prototype" key.
func (p *jsonParser) value(depth int, ctor bool) bool {
	if p.i >= len(p.b) {
		return p.syntax(dUnexpectedEnd)
	}
	p.nodes++
	if p.nodes > p.lim.MaxNodes {
		return p.limit(dTooManyValues, p.lim.MaxNodes, p.i)
	}
	switch c := p.b[p.i]; {
	case c == '{':
		return p.object(depth+1, ctor)
	case c == '[':
		return p.array(depth + 1)
	case c == '"':
		_, _, _, ok := p.str(false)
		return ok
	case c == '-' || c >= '0' && c <= '9':
		return p.number()
	case c == 't':
		return p.literal("true")
	case c == 'f':
		return p.literal("false")
	case c == 'n':
		return p.literal("null")
	}
	return p.syntax(dUnexpectedChar)
}

func (p *jsonParser) literal(lit string) bool {
	if len(p.b)-p.i >= len(lit) && string(p.b[p.i:p.i+len(lit)]) == lit {
		p.i += len(lit)
		return true
	}
	return p.syntax(dBadLiteral)
}

// number accepts -?(0|[1-9][0-9]*)(.[0-9]+)?([eE][+-]?[0-9]+)? and nothing else: no leading zero, plus sign, bare point, hex, NaN
// or Infinity, which different parsers take differently. An exponent of more than three digits is refused as a limit: some decoders
// turn it into a number with that many digits.
func (p *jsonParser) number() bool {
	b, i := p.b, p.i
	start := i
	if b[i] == '-' {
		i++
	}
	if i >= len(b) {
		p.i = i
		return p.syntax(dBadNumber)
	}
	switch {
	case b[i] == '0':
		i++
	case b[i] >= '1' && b[i] <= '9':
		for i < len(b) && b[i] >= '0' && b[i] <= '9' {
			i++
		}
	default:
		p.i = i
		return p.syntax(dBadNumber)
	}
	if i < len(b) && b[i] == '.' {
		i++
		d := i
		for i < len(b) && b[i] >= '0' && b[i] <= '9' {
			i++
		}
		if i == d {
			p.i = i
			return p.syntax(dBadNumber)
		}
	}
	if i < len(b) && (b[i] == 'e' || b[i] == 'E') {
		i++
		if i < len(b) && (b[i] == '+' || b[i] == '-') {
			i++
		}
		d := i
		for i < len(b) && b[i] >= '0' && b[i] <= '9' {
			i++
		}
		if i == d {
			p.i = i
			return p.syntax(dBadNumber)
		}
		if i-d > 3 {
			return p.limit(dExponentTooLong, 3, d)
		}
	}
	if i-start > p.lim.MaxNumberLen {
		return p.limit(dNumberTooLong, p.lim.MaxNumberLen, start)
	}
	p.i = i
	return true
}

// str reads the string that starts at p.b[p.i] (a quote). It returns the bytes between the quotes, whether any escape was seen, and
// whether to go on. It refuses raw control characters (including NUL), invalid UTF-8, bad escapes, an escaped NUL and surrogate
// escapes that are not a valid pair; the first two and the last two can be set to monitor, and then the scan goes on.
func (p *jsonParser) str(isKey bool) (start, end int, esc, ok bool) {
	b := p.b
	i := p.i + 1
	start = i
	for i < len(b) {
		c := b[i]
		switch {
		case c == '"':
			p.i = i + 1
			if !isKey && i-start > p.lim.MaxStringLen {
				return 0, 0, false, p.limit(dStringTooLong, p.lim.MaxStringLen, start)
			}
			return start, i, esc, true
		case c == '\\':
			esc = true
			i++
			if i >= len(b) {
				p.i = i
				return 0, 0, false, p.syntax(dUnterminatedString)
			}
			switch b[i] {
			case '"', '\\', '/', 'b', 'f', 'n', 'r', 't':
				i++
			case 'u':
				r, good := hex4(b, i+1)
				if !good {
					p.i = i
					return 0, 0, false, p.syntax(dBadEscape)
				}
				at := i - 1
				i += 5
				switch {
				case r == 0:
					if p.f.hit(rJSONNUL, at, dNone) {
						return 0, 0, false, false
					}
				case r >= 0xD800 && r <= 0xDBFF:
					lo, good := hex4(b, i+2)
					if i+1 < len(b) && b[i] == '\\' && b[i+1] == 'u' && good && lo >= 0xDC00 && lo <= 0xDFFF {
						i += 6
					} else if p.f.hit(rJSONSurr, at, dNone) {
						return 0, 0, false, false
					}
				case r >= 0xDC00 && r <= 0xDFFF:
					if p.f.hit(rJSONSurr, at, dNone) {
						return 0, 0, false, false
					}
				}
			default:
				p.i = i
				return 0, 0, false, p.syntax(dBadEscape)
			}
		case c < 0x20:
			if p.f.hit(rControlChar, i, dInString) {
				return 0, 0, false, false
			}
			i++
		case c >= utf8.RuneSelf:
			r, n := utf8.DecodeRune(b[i:])
			if r == utf8.RuneError && n == 1 {
				if p.f.hit(rInvalidUTF8, i, dNone) {
					return 0, 0, false, false
				}
			}
			i += n
		default:
			i++
		}
	}
	p.i = i
	return 0, 0, false, p.syntax(dUnterminatedString)
}

func (p *jsonParser) array(depth int) bool {
	if depth > p.lim.MaxDepth {
		return p.limit(dTooDeep, p.lim.MaxDepth, p.i)
	}
	p.i++
	if depth == 1 && p.capture != nil {
		p.rootArray = true
	}
	p.skipWS()
	if p.i < len(p.b) && p.b[p.i] == ']' {
		p.i++
		return true
	}
	for {
		p.skipWS()
		if p.i >= len(p.b) {
			return p.syntax(dUnexpectedEnd)
		}
		if depth == 1 && p.capture != nil {
			p.capture.nelems++
			p.curElem = -1
			if len(p.capture.elems) < p.capture.max {
				p.capture.elems = append(p.capture.elems, jsonElem{kind: p.b[p.i]})
				p.curElem = len(p.capture.elems) - 1
			}
		}
		if !p.value(depth, false) {
			return false
		}
		p.skipWS()
		if p.i >= len(p.b) {
			return p.syntax(dUnexpectedEnd)
		}
		switch p.b[p.i] {
		case ',':
			p.i++
		case ']':
			p.i++
			return true
		default:
			return p.syntax(dExpectedCommaOrEnd)
		}
	}
}

func (p *jsonParser) object(depth int, ctor bool) bool {
	if depth > p.lim.MaxDepth {
		return p.limit(dTooDeep, p.lim.MaxDepth, p.i)
	}
	p.i++
	base, foldBase := len(p.spans), len(p.fold)
	var big map[string]struct{}
	rootObj := depth == 1 && p.capture != nil
	elemObj := depth == 2 && p.rootArray && p.capture != nil
	needFold := p.dup || p.proto || rootObj || elemObj
	p.skipWS()
	if p.i < len(p.b) && p.b[p.i] == '}' {
		p.i++
		return true
	}
	for {
		p.skipWS()
		if p.i >= len(p.b) {
			return p.syntax(dUnexpectedEnd)
		}
		if p.b[p.i] != '"' {
			return p.syntax(dExpectedKey)
		}
		ks, ke, esc, ok := p.str(true)
		if !ok {
			return false
		}
		if ke-ks > p.lim.MaxKeyLen {
			return p.limit(dKeyTooLong, p.lim.MaxKeyLen, ks)
		}
		p.keys++
		if p.keys > p.lim.MaxKeys {
			return p.limit(dTooManyKeys, p.lim.MaxKeys, ks)
		}
		nextCtor, isGQL := false, false
		if needFold {
			start := len(p.fold)
			p.fold = appendFolded(p.fold, p.b[ks:ke], esc)
			fk := p.fold[start:]
			if p.dup {
				if n := len(p.spans) - base; n < 16 {
					for _, s := range p.spans[base:] {
						if string(p.fold[s.a:s.b]) == string(fk) {
							if p.f.hit(rJSONDupKey, ks, dNone) {
								return false
							}
							break
						}
					}
				} else {
					if big == nil {
						big = make(map[string]struct{}, 2*n)
						for _, s := range p.spans[base:] {
							big[string(p.fold[s.a:s.b])] = struct{}{}
						}
					}
					if _, seen := big[string(fk)]; seen {
						if p.f.hit(rJSONDupKey, ks, dNone) {
							return false
						}
					}
					big[string(fk)] = struct{}{}
				}
				p.spans = append(p.spans, span{start, len(p.fold)})
			}
			if p.proto {
				switch string(fk) {
				case "__proto__":
					if p.f.hit(rJSONProto, ks, dNone) {
						return false
					}
				case "constructor":
					nextCtor = true
				case "prototype":
					if ctor && p.f.hit(rJSONProto, ks, dNone) {
						return false
					}
				}
			}
			if rootObj || elemObj {
				switch string(fk) {
				case "query", "variables", "operationname", "extensions":
					isGQL = true
				default:
					isGQL = methodOverrideParam(string(fk))
				}
			}
		}
		p.skipWS()
		if p.i >= len(p.b) || p.b[p.i] != ':' {
			return p.syntax(dExpectedColon)
		}
		p.i++
		p.skipWS()
		if p.i >= len(p.b) {
			return p.syntax(dUnexpectedEnd)
		}
		vstart, kind := p.i, p.b[p.i]
		if !p.value(depth, nextCtor) {
			return false
		}
		if isGQL {
			m := jsonMember{key: decodeJSONString(p.b[ks:ke], esc), kind: kind, start: vstart, end: p.i}
			if p.rootArray && graphQLParamName(m.key) == "query" && kind == '"' {
				p.capture.graphQLPossible = p.capture.graphQLPossible || looksLikeGraphQL([]byte(decodeJSONString(p.b[vstart+1:p.i-1], true)))
			}
			if rootObj {
				p.capture.members = append(p.capture.members, m)
			} else if p.curElem >= 0 {
				e := &p.capture.elems[p.curElem]
				e.members = append(e.members, m)
			}
		}
		p.skipWS()
		if p.i >= len(p.b) {
			return p.syntax(dUnexpectedEnd)
		}
		switch p.b[p.i] {
		case ',':
			p.i++
		case '}':
			p.i++
			p.spans, p.fold = p.spans[:base], p.fold[:foldBase]
			return true
		default:
			return p.syntax(dExpectedCommaOrEnd)
		}
	}
}

// appendFolded appends the key's characters, with escapes decoded and case folded, to dst. The key was checked by str already.
func appendFolded(dst, raw []byte, esc bool) []byte {
	for i := 0; i < len(raw); {
		c := raw[i]
		switch {
		case c == '\\' && esc:
			r, n := decodeEscape(raw[i:])
			dst = utf8.AppendRune(dst, foldRune(r))
			i += n
		case c < utf8.RuneSelf:
			if 'A' <= c && c <= 'Z' {
				c += 'a' - 'A'
			}
			dst = append(dst, c)
			i++
		default:
			r, n := utf8.DecodeRune(raw[i:])
			dst = utf8.AppendRune(dst, foldRune(r))
			i += n
		}
	}
	return dst
}

// decodeEscape decodes the escape at the start of raw, which is a backslash, and returns the character and the bytes it took. An
// unpaired surrogate (which str refuses unless that rule is on monitor) gives U+FFFD.
func decodeEscape(raw []byte) (rune, int) {
	if len(raw) < 2 {
		return utf8.RuneError, len(raw)
	}
	switch raw[1] {
	case 'b':
		return '\b', 2
	case 'f':
		return '\f', 2
	case 'n':
		return '\n', 2
	case 'r':
		return '\r', 2
	case 't':
		return '\t', 2
	case 'u':
		r, ok := hex4(raw, 2)
		if !ok {
			return utf8.RuneError, 2
		}
		if r >= 0xD800 && r <= 0xDBFF {
			if len(raw) >= 12 && raw[6] == '\\' && raw[7] == 'u' {
				if lo, ok := hex4(raw, 8); ok && lo >= 0xDC00 && lo <= 0xDFFF {
					return 0x10000 + (r-0xD800)<<10 + (lo - 0xDC00), 12
				}
			}
			return utf8.RuneError, 6
		}
		if r >= 0xDC00 && r <= 0xDFFF {
			return utf8.RuneError, 6
		}
		return r, 6
	}
	return rune(raw[1]), 2 // \" \\ \/
}

// decodeJSONString returns the characters of a string body whose escapes were already checked.
func decodeJSONString(raw []byte, esc bool) string {
	if !esc {
		return string(raw)
	}
	out := make([]byte, 0, len(raw))
	for i := 0; i < len(raw); {
		if raw[i] == '\\' {
			r, n := decodeEscape(raw[i:])
			out = utf8.AppendRune(out, r)
			i += n
			continue
		}
		out = append(out, raw[i])
		i++
	}
	return string(out)
}
