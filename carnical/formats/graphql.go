package formats

import (
	"unicode/utf8"
)

// This file is a GraphQL lexer, parser and analyser for executable documents (operations and fragments), written to answer one
// question: how much work would a server do for this query? It does not validate against a schema. It reads the whole document,
// builds a small tree, expands fragments by arithmetic (never by copying them, so a document that would expand to billions of
// fields is counted in microseconds) and compares depth, field, alias and directive counts with the policy.

const (
	// gqlNestCap bounds the recursion of the parser, whatever the policy says: selection sets (inline fragments included) inside one
	// another. A document nested this deep is refused as too deep.
	gqlNestCap = 128
	// gqlValueCap bounds nested lists and objects in an argument value, and nested list types.
	gqlValueCap = 32
	// gqlNameCap bounds a name.
	gqlNameCap = 255
	// gqlMaxDefs bounds the operations and fragments in one document, which bounds how deep a chain of fragments can recurse when
	// they are counted.
	gqlMaxDefs = 1000
	// gqlSat stops counts growing past the point where they are over every limit; counting expanded fragments could otherwise overflow.
	gqlSat = 1 << 40
)

type gtk uint8

const (
	gEOF gtk = iota
	gPunct
	gName
	gNumber
	gString
	gSpread
)

type gqlLexer struct {
	src        []byte
	pos        int
	kind       gtk
	start, end int
	punct      byte
}

func (l *gqlLexer) is(name string) bool {
	return l.kind == gName && string(l.src[l.start:l.end]) == name
}

func (l *gqlLexer) isPunct(c byte) bool { return l.kind == gPunct && l.punct == c }

func isNameStart(c byte) bool { return c == '_' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' }
func isNameChar(c byte) bool  { return isNameStart(c) || c >= '0' && c <= '9' }

// next reads the next token into the lexer. The result is dNone, or what is wrong.
func (l *gqlLexer) next() detail {
	src := l.src
skip:
	for l.pos < len(src) {
		switch c := src[l.pos]; {
		case c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == ',':
			l.pos++
		case c == '#':
			for l.pos < len(src) && src[l.pos] != '\n' && src[l.pos] != '\r' {
				l.pos++
			}
		case c == 0xEF && l.pos+2 < len(src) && src[l.pos+1] == 0xBB && src[l.pos+2] == 0xBF:
			l.pos += 3 // a byte order mark is an ignored token in GraphQL
		default:
			break skip
		}
	}
	l.start = l.pos
	if l.pos >= len(src) {
		l.kind, l.end = gEOF, l.pos
		return dNone
	}
	c := src[l.pos]
	switch {
	case c == '!' || c == '$' || c == '&' || c == '(' || c == ')' || c == ':' || c == '=' || c == '@' || c == '[' || c == ']' || c == '{' || c == '|' || c == '}':
		l.kind, l.punct = gPunct, c
		l.pos++
	case c == '.':
		if l.pos+2 < len(src) && src[l.pos+1] == '.' && src[l.pos+2] == '.' {
			l.kind = gSpread
			l.pos += 3
		} else {
			return dBadSpread
		}
	case isNameStart(c):
		i := l.pos + 1
		for i < len(src) && isNameChar(src[i]) {
			i++
		}
		if i-l.pos > gqlNameCap {
			return dNameTooLong
		}
		l.kind = gName
		l.pos = i
	case c == '-' || c >= '0' && c <= '9':
		if d := l.number(); d != dNone {
			return d
		}
		l.kind = gNumber
	case c == '"':
		if d := l.str(); d != dNone {
			return d
		}
		l.kind = gString
	default:
		return dUnexpectedChar
	}
	l.end = l.pos
	return dNone
}

func (l *gqlLexer) number() detail {
	src := l.src
	i := l.pos
	if src[i] == '-' {
		i++
	}
	if i >= len(src) {
		return dBadNumber
	}
	if src[i] == '0' {
		i++
	} else if src[i] >= '1' && src[i] <= '9' {
		for i < len(src) && src[i] >= '0' && src[i] <= '9' {
			i++
		}
	} else {
		return dBadNumber
	}
	if i < len(src) && src[i] == '.' {
		i++
		d := i
		for i < len(src) && src[i] >= '0' && src[i] <= '9' {
			i++
		}
		if i == d {
			return dBadNumber
		}
	}
	if i < len(src) && (src[i] == 'e' || src[i] == 'E') {
		i++
		if i < len(src) && (src[i] == '+' || src[i] == '-') {
			i++
		}
		d := i
		for i < len(src) && src[i] >= '0' && src[i] <= '9' {
			i++
		}
		if i == d {
			return dBadNumber
		}
	}
	// A number may not run into a name, a point or another digit (1a, 1.2.3, 01): graphql-js and others disagree on what those mean.
	if i < len(src) && (src[i] == '.' || isNameChar(src[i])) {
		return dBadNumber
	}
	l.pos = i
	return dNone
}

// str reads a string or block string starting at the quote.
func (l *gqlLexer) str() detail {
	src := l.src
	if l.pos+2 < len(src) && src[l.pos+1] == '"' && src[l.pos+2] == '"' {
		i := l.pos + 3
		for i < len(src) {
			if src[i] == '\\' && i+3 < len(src) && src[i+1] == '"' && src[i+2] == '"' && src[i+3] == '"' {
				i += 4
				continue
			}
			if src[i] == '"' && i+2 < len(src) && src[i+1] == '"' && src[i+2] == '"' {
				l.pos = i + 3
				return dNone
			}
			i++
		}
		return dUnterminatedString
	}
	i := l.pos + 1
	for i < len(src) {
		switch c := src[i]; {
		case c == '"':
			l.pos = i + 1
			return dNone
		case c == '\n' || c == '\r':
			return dUnterminatedString
		case c == '\\':
			i++
			if i >= len(src) {
				return dUnterminatedString
			}
			switch src[i] {
			case '"', '\\', '/', 'b', 'f', 'n', 'r', 't':
				i++
			case 'u':
				if i+1 < len(src) && src[i+1] == '{' {
					j := i + 2
					var r rune
					for j < len(src) && j-i-2 < 7 && isHexDigit(src[j]) {
						r = r<<4 | hexVal(src[j])
						j++
					}
					if j == i+2 || j >= len(src) || src[j] != '}' || r > 0x10FFFF || r >= 0xD800 && r <= 0xDFFF {
						return dBadEscape
					}
					i = j + 1
				} else {
					r, ok := hex4(src, i+1)
					if !ok {
						return dBadEscape
					}
					i += 5
					switch {
					case r >= 0xD800 && r <= 0xDBFF:
						lo, ok := hex4(src, i+2)
						if i+1 < len(src) && src[i] == '\\' && src[i+1] == 'u' && ok && lo >= 0xDC00 && lo <= 0xDFFF {
							i += 6
						} else {
							return dBadEscape
						}
					case r >= 0xDC00 && r <= 0xDFFF:
						return dBadEscape
					}
				}
			default:
				return dBadEscape
			}
		default:
			i++
		}
	}
	return dUnterminatedString
}

// gqlFail is why a document was not accepted: a syntax error, or a limit of the parser (rule rGQLSyntax means syntax).
type gqlFail struct {
	r     *rule
	d     detail
	limit int
	off   int
}

const (
	selField uint8 = iota
	selSpread
	selInline
)

type gqlSel struct {
	kind  uint8
	name  string
	alias bool
	dirs  int
	sub   []gqlSel
}

type gqlDef struct {
	fragment bool
	name     string
	dirs     int // on the definition and on its variable definitions
	sel      []gqlSel
}

type gqlDoc struct {
	defs  []gqlDef
	ops   int
	intro bool
}

type gqlParser struct {
	l       gqlLexer
	lim     *GraphQLLimits
	fail    *gqlFail
	doc     gqlDoc
	sels    int
	maxSels int
}

// parseGraphQL parses an executable document. It never panics and uses time and memory in proportion to len(src).
func parseGraphQL(src []byte, lim *GraphQLLimits) (*gqlDoc, *gqlFail) {
	p := &gqlParser{l: gqlLexer{src: src}, lim: lim}
	p.maxSels = lim.MaxFields * (lim.MaxOperations + 1)
	if p.maxSels > 1_000_000 || p.maxSels <= 0 {
		p.maxSels = 1_000_000
	}
	if !p.advance() {
		return nil, p.fail
	}
	for p.l.kind != gEOF {
		if !p.definition() {
			return nil, p.fail
		}
	}
	if len(p.doc.defs) == 0 {
		p.syntax(dEmptyDocument)
		return nil, p.fail
	}
	return &p.doc, nil
}

func (p *gqlParser) syntax(d detail) bool {
	if p.fail == nil {
		p.fail = &gqlFail{r: rGQLSyntax, d: d, limit: -1, off: p.l.start}
	}
	return false
}

func (p *gqlParser) limit(r *rule, d detail, n int) bool {
	if p.fail == nil {
		p.fail = &gqlFail{r: r, d: d, limit: n, off: p.l.start}
	}
	return false
}

func (p *gqlParser) advance() bool {
	if d := p.l.next(); d != dNone {
		return p.syntax(d)
	}
	return true
}

func (p *gqlParser) expectPunct(c byte, d detail) bool {
	if !p.l.isPunct(c) {
		return p.syntax(d)
	}
	return p.advance()
}

func (p *gqlParser) expectName(d detail) (string, bool) {
	if p.l.kind != gName {
		return "", p.syntax(d)
	}
	name := string(p.l.src[p.l.start:p.l.end])
	return name, p.advance()
}

func (p *gqlParser) definition() bool {
	if len(p.doc.defs) >= gqlMaxDefs {
		return p.limit(rGQLLimit, dTooManyDefinitions, gqlMaxDefs)
	}
	switch {
	case p.l.isPunct('{'):
		return p.operation(true)
	case p.l.kind == gName:
		switch string(p.l.src[p.l.start:p.l.end]) {
		case "query", "mutation", "subscription":
			return p.operation(false)
		case "fragment":
			return p.fragment()
		case "schema", "scalar", "type", "interface", "union", "enum", "input", "directive", "extend":
			return p.syntax(dNotExecutable)
		}
	case p.l.kind == gString:
		return p.syntax(dNotExecutable)
	}
	return p.syntax(dUnexpectedToken)
}

func (p *gqlParser) operation(shorthand bool) bool {
	p.doc.ops++
	if p.doc.ops > p.lim.MaxOperations {
		return p.limit(rGQLLimit, dTooManyOperations, p.lim.MaxOperations)
	}
	var def gqlDef
	if !shorthand {
		if !p.advance() {
			return false
		}
		if p.l.kind == gName {
			if !p.advance() {
				return false
			}
		}
		if p.l.isPunct('(') {
			n, ok := p.variableDefinitions()
			if !ok {
				return false
			}
			def.dirs += n
		}
		n, ok := p.directives()
		if !ok {
			return false
		}
		def.dirs += n
	}
	sel, ok := p.selectionSet(1)
	if !ok {
		return false
	}
	def.sel = sel
	p.doc.defs = append(p.doc.defs, def)
	return true
}

func (p *gqlParser) fragment() bool {
	if !p.advance() {
		return false
	}
	if p.l.is("on") {
		return p.syntax(dFragmentNamedOn)
	}
	name, ok := p.expectName(dExpectedName)
	if !ok {
		return false
	}
	if !p.l.is("on") {
		return p.syntax(dExpectedOn)
	}
	if !p.advance() {
		return false
	}
	if _, ok := p.expectName(dExpectedName); !ok {
		return false
	}
	n, ok := p.directives()
	if !ok {
		return false
	}
	sel, ok := p.selectionSet(1)
	if !ok {
		return false
	}
	p.doc.defs = append(p.doc.defs, gqlDef{fragment: true, name: name, dirs: n, sel: sel})
	return true
}

// variableDefinitions reads ($name: Type = default @directive, ...) and returns how many directives it held.
func (p *gqlParser) variableDefinitions() (dirs int, ok bool) {
	if !p.advance() { // (
		return 0, false
	}
	count := 0
	for !p.l.isPunct(')') {
		if !p.expectPunct('$', dExpectedVariable) {
			return 0, false
		}
		if _, ok := p.expectName(dExpectedName); !ok {
			return 0, false
		}
		if !p.expectPunct(':', dExpectedColon) {
			return 0, false
		}
		if !p.typeRef(0) {
			return 0, false
		}
		if p.l.isPunct('=') {
			if !p.advance() || !p.value(0) {
				return 0, false
			}
		}
		n, ok := p.directives()
		if !ok {
			return 0, false
		}
		dirs += n
		count++
	}
	if count == 0 {
		return 0, p.syntax(dEmptyList)
	}
	return dirs, p.advance()
}

func (p *gqlParser) typeRef(depth int) bool {
	if depth > gqlValueCap {
		return p.limit(rGQLLimit, dTooDeep, gqlValueCap)
	}
	if p.l.isPunct('[') {
		if !p.advance() || !p.typeRef(depth+1) || !p.expectPunct(']', dExpectedCloseBracket) {
			return false
		}
	} else if _, ok := p.expectName(dExpectedName); !ok {
		return false
	}
	if p.l.isPunct('!') {
		return p.advance()
	}
	return true
}

func (p *gqlParser) directives() (int, bool) {
	n := 0
	for p.l.isPunct('@') {
		if !p.advance() {
			return 0, false
		}
		if _, ok := p.expectName(dExpectedName); !ok {
			return 0, false
		}
		if p.l.isPunct('(') && !p.arguments() {
			return 0, false
		}
		n++
	}
	return n, true
}

func (p *gqlParser) arguments() bool {
	if !p.advance() { // (
		return false
	}
	count := 0
	for !p.l.isPunct(')') {
		if _, ok := p.expectName(dExpectedName); !ok {
			return false
		}
		if !p.expectPunct(':', dExpectedColon) || !p.value(0) {
			return false
		}
		count++
	}
	if count == 0 {
		return p.syntax(dEmptyList)
	}
	return p.advance()
}

func (p *gqlParser) value(depth int) bool {
	if depth > gqlValueCap {
		return p.limit(rGQLLimit, dTooDeep, gqlValueCap)
	}
	switch {
	case p.l.isPunct('$'):
		if !p.advance() {
			return false
		}
		_, ok := p.expectName(dExpectedName)
		return ok
	case p.l.kind == gNumber, p.l.kind == gString, p.l.kind == gName:
		return p.advance()
	case p.l.isPunct('['):
		if !p.advance() {
			return false
		}
		for !p.l.isPunct(']') {
			if p.l.kind == gEOF {
				return p.syntax(dUnexpectedEnd)
			}
			if !p.value(depth + 1) {
				return false
			}
		}
		return p.advance()
	case p.l.isPunct('{'):
		if !p.advance() {
			return false
		}
		for !p.l.isPunct('}') {
			if _, ok := p.expectName(dExpectedName); !ok {
				return false
			}
			if !p.expectPunct(':', dExpectedColon) || !p.value(depth+1) {
				return false
			}
		}
		return p.advance()
	}
	return p.syntax(dUnexpectedToken)
}

// selectionSet reads { ... }. nest counts the selection sets (inline fragments included) that enclose this one.
func (p *gqlParser) selectionSet(nest int) ([]gqlSel, bool) {
	if nest > gqlNestCap {
		return nil, p.limit(rGQLDepth, dTooDeep, gqlNestCap)
	}
	if !p.l.isPunct('{') {
		return nil, p.syntax(dExpectedSelection)
	}
	if !p.advance() {
		return nil, false
	}
	var out []gqlSel
	for !p.l.isPunct('}') {
		if p.l.kind == gEOF {
			return nil, p.syntax(dUnexpectedEnd)
		}
		p.sels++
		if p.sels > p.maxSels {
			return nil, p.limit(rGQLFields, dTooManySelections, p.maxSels)
		}
		s, ok := p.selection(nest)
		if !ok {
			return nil, false
		}
		out = append(out, s)
	}
	if len(out) == 0 {
		return nil, p.syntax(dEmptyList)
	}
	return out, p.advance()
}

func (p *gqlParser) selection(nest int) (gqlSel, bool) {
	var s gqlSel
	if p.l.kind == gSpread {
		if !p.advance() {
			return s, false
		}
		switch {
		case p.l.kind == gName && !p.l.is("on"):
			s.kind = selSpread
			name, ok := p.expectName(dExpectedName)
			if !ok {
				return s, false
			}
			s.name = name
			n, ok := p.directives()
			if !ok {
				return s, false
			}
			s.dirs = n
			return s, true
		default:
			s.kind = selInline
			if p.l.is("on") {
				if !p.advance() {
					return s, false
				}
				if _, ok := p.expectName(dExpectedName); !ok {
					return s, false
				}
			}
			n, ok := p.directives()
			if !ok {
				return s, false
			}
			s.dirs = n
			sub, ok := p.selectionSet(nest + 1)
			if !ok {
				return s, false
			}
			s.sub = sub
			return s, true
		}
	}
	s.kind = selField
	name, ok := p.expectName(dExpectedName)
	if !ok {
		return s, false
	}
	if p.l.isPunct(':') {
		if !p.advance() {
			return s, false
		}
		s.alias = true
		if name, ok = p.expectName(dExpectedName); !ok {
			return s, false
		}
	}
	if name == "__schema" || name == "__type" {
		p.doc.intro = true
	}
	s.name = name
	if p.l.isPunct('(') && !p.arguments() {
		return s, false
	}
	n, ok := p.directives()
	if !ok {
		return s, false
	}
	s.dirs = n
	if p.l.isPunct('{') {
		sub, ok := p.selectionSet(nest + 1)
		if !ok {
			return s, false
		}
		s.sub = sub
	}
	return s, true
}

// ---- analysis ----

type gqlStats struct{ depth, fields, aliases, dirs int }

func satAdd(a, b int) int {
	if s := a + b; s < gqlSat {
		return s
	}
	return gqlSat
}

func (s *gqlStats) add(o gqlStats) {
	s.fields = satAdd(s.fields, o.fields)
	s.aliases = satAdd(s.aliases, o.aliases)
	s.dirs = satAdd(s.dirs, o.dirs)
}

type fragState struct {
	def   *gqlDef
	state uint8 // 0 not visited, 1 in progress, 2 done
	stats gqlStats
}

// gqlReport is what analysis found: problems with fragments, and the cost of each operation.
type gqlReport struct {
	cycle, unknown, duplicate bool
	ops                       []gqlStats
}

type gqlAnalyzer struct {
	frags map[string]*fragState
	rep   gqlReport
}

// analyze counts depth, fields, aliases and directives of every operation with its fragments expanded, and finds fragment cycles,
// spreads of fragments that are not defined, and fragments defined twice. Each fragment is counted once however often it is
// spread, so the work is linear in the size of the document.
func analyze(doc *gqlDoc) gqlReport {
	a := &gqlAnalyzer{frags: map[string]*fragState{}}
	for i := range doc.defs {
		d := &doc.defs[i]
		if !d.fragment {
			continue
		}
		if _, dup := a.frags[d.name]; dup {
			a.rep.duplicate = true
			continue
		}
		a.frags[d.name] = &fragState{def: d}
	}
	for i := range doc.defs {
		d := &doc.defs[i]
		if d.fragment {
			if fs := a.frags[d.name]; fs != nil && fs.def == d {
				a.fragment(fs)
			}
			continue
		}
		st := a.selections(d.sel)
		st.dirs = satAdd(st.dirs, d.dirs)
		a.rep.ops = append(a.rep.ops, st)
	}
	return a.rep
}

func (a *gqlAnalyzer) fragment(fs *fragState) gqlStats {
	switch fs.state {
	case 1:
		a.rep.cycle = true
		return gqlStats{}
	case 2:
		return fs.stats
	}
	fs.state = 1
	st := a.selections(fs.def.sel)
	st.dirs = satAdd(st.dirs, fs.def.dirs)
	fs.stats, fs.state = st, 2
	return st
}

func (a *gqlAnalyzer) selections(sel []gqlSel) gqlStats {
	var st gqlStats
	for i := range sel {
		x := &sel[i]
		st.dirs = satAdd(st.dirs, x.dirs)
		switch x.kind {
		case selField:
			st.fields = satAdd(st.fields, 1)
			if x.alias {
				st.aliases = satAdd(st.aliases, 1)
			}
			c := a.selections(x.sub)
			if c.depth+1 > st.depth {
				st.depth = c.depth + 1
			}
			st.add(c)
		case selInline:
			c := a.selections(x.sub)
			if c.depth > st.depth {
				st.depth = c.depth
			}
			st.add(c)
		case selSpread:
			fs := a.frags[x.name]
			if fs == nil {
				a.rep.unknown = true
				continue
			}
			c := a.fragment(fs)
			if c.depth > st.depth {
				st.depth = c.depth
			}
			st.add(c)
		}
	}
	return st
}

// sourceProblem looks for what no GraphQL source can contain: a control character other than tab, line feed and carriage return,
// or bytes that are not UTF-8. It returns the offset and the rule, or nil.
func sourceProblem(src []byte) (*rule, int) {
	high := false
	for i, c := range src {
		if c < 0x20 && c != '\t' && c != '\n' && c != '\r' {
			return rControlChar, i
		}
		if c >= utf8.RuneSelf {
			high = true
		}
	}
	if high {
		if i := firstInvalidUTF8(src); i >= 0 {
			return rInvalidUTF8, i
		}
	}
	return nil, 0
}
