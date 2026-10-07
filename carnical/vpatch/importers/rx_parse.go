// SPDX-License-Identifier: Apache-2.0

package importers

// This file is a small parser for the part of PCRE syntax that matters to the translation in rx.go: where the groups, alternations
// and quantifiers are, and which characters an atom can match. It is not a full regular-expression engine and does not try to be.
// Anything it does not understand is an error, and an error means "do not translate", which means the rule is skipped with a reason.

import (
	"errors"
	"strconv"
	"strings"
	"unicode/utf8"
)

// cset is a set of code points: a bitmap for 0..255 and one flag for "some code point above 255".
type cset struct {
	b    [256]bool
	high bool
}

func (a *cset) add(r rune) {
	if r >= 0 && r < 256 {
		a.b[r] = true
	} else {
		a.high = true
	}
}

func (a *cset) addRange(lo, hi rune) {
	for r := lo; r <= hi && r < 256; r++ {
		if r >= 0 {
			a.b[r] = true
		}
	}
	if hi >= 256 {
		a.high = true
	}
}

func (a *cset) union(o cset) {
	for i := range a.b {
		if o.b[i] {
			a.b[i] = true
		}
	}
	if o.high {
		a.high = true
	}
}

func (a cset) negated() cset {
	var n cset
	for i := range a.b {
		n.b[i] = !a.b[i]
	}
	n.high = !a.high
	return n
}

func (a cset) intersects(o cset) bool {
	for i := range a.b {
		if a.b[i] && o.b[i] {
			return true
		}
	}
	return a.high && o.high
}

func (a cset) subsetOf(o cset) bool {
	for i := range a.b {
		if a.b[i] && !o.b[i] {
			return false
		}
	}
	return !a.high || o.high
}

func fullSet() cset { return cset{}.negated() }

func wordSet() cset {
	var s cset
	s.addRange('a', 'z')
	s.addRange('A', 'Z')
	s.addRange('0', '9')
	s.add('_')
	return s
}

func digitSet() cset {
	var s cset
	s.addRange('0', '9')
	return s
}

func spaceSet() cset {
	var s cset
	for _, r := range " \t\n\v\f\r" {
		s.add(r)
	}
	return s
}

// foldCase adds the other case of every ASCII letter in s. The letters whose Unicode case folding reaches outside ASCII
// (k and s) also set the high flag, so that a later disjointness test stays on the safe side.
func (a *cset) foldCase() {
	for r := 'a'; r <= 'z'; r++ {
		u := r - 'a' + 'A'
		if a.b[r] || a.b[u] {
			a.b[r], a.b[u] = true, true
			if r == 'k' || r == 's' {
				a.high = true
			}
		}
	}
}

type nkind uint8

const (
	nSet nkind = iota
	nAssert
	nGroup
	nRepeat
	nBackref
)

type gkind uint8

const (
	gCapture gkind = iota
	gNonCapture
	gAtomic
	gLook
	gFlags // (?i) with nothing to group
)

// rnode is one node of the parsed pattern. start and end are byte offsets into the source.
type rnode struct {
	kind   nkind
	set    cset   // nSet: the characters it can match
	assert string // nAssert: "^", "$", `\b`, `\B`, `\A`, `\z`, `\Z`, `\G`
	gk     gkind  // nGroup
	alts   [][]*rnode
	sub    *rnode // nRepeat: what is repeated
	min    int
	max    int // -1 means no upper bound
	// possessive and plusPos: a possessive quantifier, and where its trailing "+" is in the source.
	possessive bool
	plusPos    int
	// openPos is where an atomic group's "(?>" starts.
	openPos    int
	start, end int
	multiline  bool // the multi-line flag was on where an assertion was written
	foldI      bool
}

type edit struct {
	start, end int
	repl       string
}

type rparser struct {
	s     string
	i     int
	depth int
	edits []edit
	// flags in force for the group being parsed.
	fi, fs, fm bool
	sawM       bool
	nodesSeen  int
}

var (
	errUnparsable   = errors.New("unparsable")
	errExtended     = errors.New("x-flag")
	errBackref      = errors.New("backreference")
	errLook         = errors.New("lookaround")
	errRecursion    = errors.New("recursion")
	errNesting      = errors.New("nesting-too-deep")
	errTooManyNodes = errors.New("too-many-nodes")
)

const (
	maxParseDepth = 64
	maxParseNodes = 200000
)

func parsePCRE(s string) (alts [][]*rnode, p *rparser, err error) {
	p = &rparser{s: s}
	alts, err = p.parseAlts()
	if err != nil {
		return nil, p, err
	}
	if p.i < len(p.s) { // an unmatched ")"
		return nil, p, errUnparsable
	}
	return alts, p, nil
}

func (p *rparser) parseAlts() ([][]*rnode, error) {
	p.depth++
	defer func() { p.depth-- }()
	if p.depth > maxParseDepth {
		return nil, errNesting
	}
	// Flags set inside a group end with the group.
	fi, fs, fm := p.fi, p.fs, p.fm
	defer func() { p.fi, p.fs, p.fm = fi, fs, fm }()

	var alts [][]*rnode
	var cur []*rnode
	for p.i < len(p.s) {
		c := p.s[p.i]
		switch c {
		case ')':
			alts = append(alts, cur)
			return alts, nil
		case '|':
			alts = append(alts, cur)
			cur = nil
			p.i++
			continue
		}
		n, err := p.parseAtom()
		if err != nil {
			return nil, err
		}
		if n == nil { // a flag group such as (?i) changes state and has no node
			continue
		}
		p.nodesSeen++
		if p.nodesSeen > maxParseNodes {
			return nil, errTooManyNodes
		}
		n, err = p.parseQuantifiers(n)
		if err != nil {
			return nil, err
		}
		cur = append(cur, n)
	}
	alts = append(alts, cur)
	return alts, nil
}

// parseQuantifiers wraps n in a repeat for each quantifier that follows it.
func (p *rparser) parseQuantifiers(n *rnode) (*rnode, error) {
	for p.i < len(p.s) {
		c := p.s[p.i]
		min, max := 0, 0
		start := p.i
		switch c {
		case '*':
			min, max = 0, -1
			p.i++
		case '+':
			min, max = 1, -1
			p.i++
		case '?':
			min, max = 0, 1
			p.i++
		case '{':
			lo, hi, ok, next := parseBraces(p.s, p.i)
			if !ok {
				return n, nil // a literal "{"
			}
			min, max = lo, hi
			p.i = next
		default:
			return n, nil
		}
		if n.kind == nAssert {
			return nil, errUnparsable
		}
		r := &rnode{kind: nRepeat, sub: n, min: min, max: max, start: n.start}
		if p.i < len(p.s) && p.s[p.i] == '?' {
			p.i++
		} else if p.i < len(p.s) && p.s[p.i] == '+' {
			r.possessive = true
			r.plusPos = p.i
			p.i++
		}
		r.end = p.i
		_ = start
		n = r
		// "a**" is an error in every engine; the loop would accept it as a repeat of a repeat, so stop here.
		if p.i < len(p.s) && (p.s[p.i] == '*' || p.s[p.i] == '+' || p.s[p.i] == '?') {
			return nil, errUnparsable
		}
	}
	return n, nil
}

func parseBraces(s string, i int) (lo, hi int, ok bool, next int) {
	j := i + 1
	k := j
	for k < len(s) && s[k] >= '0' && s[k] <= '9' {
		k++
	}
	if k == j || k-j > 6 {
		return 0, 0, false, i
	}
	lo, _ = strconv.Atoi(s[j:k])
	if k < len(s) && s[k] == '}' {
		return lo, lo, true, k + 1
	}
	if k >= len(s) || s[k] != ',' {
		return 0, 0, false, i
	}
	k++
	m := k
	for k < len(s) && s[k] >= '0' && s[k] <= '9' {
		k++
	}
	if k >= len(s) || s[k] != '}' || k-m > 6 {
		return 0, 0, false, i
	}
	if k == m {
		return lo, -1, true, k + 1
	}
	hi, _ = strconv.Atoi(s[m:k])
	return lo, hi, true, k + 1
}

func (p *rparser) parseAtom() (*rnode, error) {
	start := p.i
	c := p.s[p.i]
	switch c {
	case '(':
		return p.parseGroup()
	case '[':
		return p.parseClass()
	case '\\':
		return p.parseEscape()
	case '.':
		p.i++
		return &rnode{kind: nSet, set: fullSet(), start: start, end: p.i}, nil
	case '^':
		p.i++
		return &rnode{kind: nAssert, assert: "^", multiline: p.fm, start: start, end: p.i}, nil
	case '$':
		p.i++
		if p.fm {
			p.sawM = true
		}
		return &rnode{kind: nAssert, assert: "$", multiline: p.fm, start: start, end: p.i}, nil
	case '*', '+', '?':
		return nil, errUnparsable // nothing to repeat
	}
	r, size := utf8.DecodeRuneInString(p.s[p.i:])
	if r == utf8.RuneError && size <= 1 {
		r = rune(p.s[p.i])
		size = 1
	}
	p.i += size
	var s cset
	s.add(r)
	if p.fi {
		s.foldCase()
	}
	return &rnode{kind: nSet, set: s, start: start, end: p.i}, nil
}

func (p *rparser) parseGroup() (*rnode, error) {
	start := p.i
	p.i++ // (
	n := &rnode{kind: nGroup, gk: gCapture, start: start}
	if p.i < len(p.s) && p.s[p.i] == '?' {
		rest := p.s[p.i:]
		switch {
		case strings.HasPrefix(rest, "?:"):
			n.gk = gNonCapture
			p.i += 2
		case strings.HasPrefix(rest, "?>"):
			n.gk = gAtomic
			n.openPos = start
			p.i += 2
		case strings.HasPrefix(rest, "?=") || strings.HasPrefix(rest, "?!") || strings.HasPrefix(rest, "?<=") || strings.HasPrefix(rest, "?<!"):
			return nil, errLook
		case strings.HasPrefix(rest, "?P<") || (strings.HasPrefix(rest, "?<") && len(rest) > 2):
			j := strings.IndexByte(rest, '>')
			if j < 0 {
				return nil, errUnparsable
			}
			p.i += j + 1
		case strings.HasPrefix(rest, "?'"):
			j := strings.IndexByte(rest[2:], '\'')
			if j < 0 {
				return nil, errUnparsable
			}
			p.i += 2 + j + 1
		case strings.HasPrefix(rest, "?#"):
			j := strings.IndexByte(rest, ')')
			if j < 0 {
				return nil, errUnparsable
			}
			p.i += j + 1
			return nil, nil
		case strings.HasPrefix(rest, "?P=") || strings.HasPrefix(rest, "?P>"):
			return nil, errBackref
		case strings.HasPrefix(rest, "?|") || strings.HasPrefix(rest, "?R") || strings.HasPrefix(rest, "?&") || strings.HasPrefix(rest, "?(") || (len(rest) > 1 && rest[1] >= '0' && rest[1] <= '9') || strings.HasPrefix(rest, "?+") || strings.HasPrefix(rest, "?-") && len(rest) > 2 && rest[2] >= '0' && rest[2] <= '9':
			return nil, errRecursion
		default:
			// (?flags) or (?flags:...)
			j := 1
			on := true
			fi, fs, fm := p.fi, p.fs, p.fm
			for j < len(rest) && rest[j] != ')' && rest[j] != ':' {
				switch rest[j] {
				case '-':
					on = false
				case 'i':
					fi = on
				case 's':
					fs = on
				case 'm':
					fm = on
					if on {
						p.sawM = true
					}
				case 'U', 'u', 'J', 'n':
					// ungreedy and friends change meaning in ways this parser does not model.
					return nil, errUnparsable
				case 'x':
					return nil, errExtended
				default:
					return nil, errUnparsable
				}
				j++
			}
			if j >= len(rest) {
				return nil, errUnparsable
			}
			if rest[j] == ')' { // flags for the rest of the enclosing group
				p.fi, p.fs, p.fm = fi, fs, fm
				p.i += j + 1
				return nil, nil
			}
			// (?flags:...)
			p.i += j + 1
			n.gk = gNonCapture
			saved := [3]bool{p.fi, p.fs, p.fm}
			p.fi, p.fs, p.fm = fi, fs, fm
			alts, err := p.parseAlts()
			p.fi, p.fs, p.fm = saved[0], saved[1], saved[2]
			if err != nil {
				return nil, err
			}
			if p.i >= len(p.s) || p.s[p.i] != ')' {
				return nil, errUnparsable
			}
			p.i++
			n.alts = alts
			n.end = p.i
			return n, nil
		}
	}
	alts, err := p.parseAlts()
	if err != nil {
		return nil, err
	}
	if p.i >= len(p.s) || p.s[p.i] != ')' {
		return nil, errUnparsable
	}
	p.i++
	n.alts = alts
	n.end = p.i
	return n, nil
}

var posixClasses = map[string]func() cset{
	"alpha": func() cset { var s cset; s.addRange('a', 'z'); s.addRange('A', 'Z'); return s },
	"digit": digitSet,
	"alnum": func() cset { s := digitSet(); s.addRange('a', 'z'); s.addRange('A', 'Z'); return s },
	"upper": func() cset { var s cset; s.addRange('A', 'Z'); return s },
	"lower": func() cset { var s cset; s.addRange('a', 'z'); return s },
	"space": spaceSet,
	"blank": func() cset { var s cset; s.add(' '); s.add('\t'); return s },
	"punct": func() cset {
		var s cset
		s.addRange('!', '/')
		s.addRange(':', '@')
		s.addRange('[', '`')
		s.addRange('{', '~')
		return s
	},
	"xdigit": func() cset { s := digitSet(); s.addRange('a', 'f'); s.addRange('A', 'F'); return s },
	"word":   wordSet,
	"cntrl":  func() cset { var s cset; s.addRange(0, 31); s.add(127); return s },
	"print":  func() cset { var s cset; s.addRange(32, 126); return s },
	"graph":  func() cset { var s cset; s.addRange(33, 126); return s },
	"ascii":  func() cset { var s cset; s.addRange(0, 127); return s },
}

// parseClass parses a bracketed class starting at "[". PCRE reads a "-" next to a class escape such as \w as a literal; Go does
// not and refuses the pattern. That one difference is rewritten here (the "-" gets a backslash), which means the same thing.
func (p *rparser) parseClass() (*rnode, error) {
	start := p.i
	p.i++ // [
	var set cset
	negate := false
	if p.i < len(p.s) && p.s[p.i] == '^' {
		negate = true
		p.i++
	}
	first := true
	// prev says what the previous item was, for reading ranges: 0 none, 1 a single character (prevRune), 2 a class escape.
	prev := 0
	var prevRune rune
	for {
		if p.i >= len(p.s) {
			return nil, errUnparsable
		}
		c := p.s[p.i]
		if c == ']' && !first {
			p.i++
			break
		}
		first = false
		if c == '[' && p.i+1 < len(p.s) && p.s[p.i+1] == ':' {
			j := strings.Index(p.s[p.i:], ":]")
			if j < 0 {
				return nil, errUnparsable
			}
			name := p.s[p.i+2 : p.i+j]
			neg := false
			if strings.HasPrefix(name, "^") {
				neg = true
				name = name[1:]
			}
			f, ok := posixClasses[name]
			if !ok {
				return nil, errUnparsable
			}
			cs := f()
			if neg {
				cs = cs.negated()
			}
			set.union(cs)
			p.i += j + 2
			prev = 2
			continue
		}
		var cur rune
		isClassEsc := false
		var escSet cset
		if c == '\\' {
			if p.i+1 >= len(p.s) {
				return nil, errUnparsable
			}
			e := p.s[p.i+1]
			switch e {
			case 'd', 'D', 'w', 'W', 's', 'S', 'h', 'H', 'v', 'V', 'p', 'P', 'R', 'N', 'X':
				isClassEsc = true
				switch e {
				case 'd':
					escSet = digitSet()
				case 'D':
					escSet = digitSet().negated()
				case 'w':
					escSet = wordSet()
				case 'W':
					escSet = wordSet().negated()
				case 's':
					escSet = spaceSet()
				case 'S':
					escSet = spaceSet().negated()
				default:
					escSet = fullSet() // not modelled; the widest set keeps later checks safe
				}
				p.i += 2
				if e == 'p' || e == 'P' {
					if p.i < len(p.s) && p.s[p.i] == '{' {
						j := strings.IndexByte(p.s[p.i:], '}')
						if j < 0 {
							return nil, errUnparsable
						}
						p.i += j + 1
					} else {
						p.i++
					}
				}
			default:
				r, n, err := decodeEscapeChar(p.s[p.i:])
				if err != nil {
					return nil, err
				}
				cur = r
				p.i += n
			}
		} else {
			r, size := utf8.DecodeRuneInString(p.s[p.i:])
			if r == utf8.RuneError && size <= 1 {
				r, size = rune(p.s[p.i]), 1
			}
			cur = r
			p.i += size
		}
		if isClassEsc {
			set.union(escSet)
			// A "-" right after a class escape is a literal "-" in PCRE.
			if p.i+1 < len(p.s) && p.s[p.i] == '-' && p.s[p.i+1] != ']' {
				p.edits = append(p.edits, edit{p.i, p.i + 1, `\-`})
				set.add('-')
				p.i++
				prev = 0
				continue
			}
			prev = 2
			continue
		}
		// A range "a-z"; "-" last or first is a literal.
		if p.i+1 < len(p.s) && p.s[p.i] == '-' && p.s[p.i+1] != ']' {
			// Look at the end of the range.
			save := p.i
			p.i++
			var hi rune
			if p.s[p.i] == '\\' {
				e := p.s[p.i+1:]
				if len(e) > 0 && strings.ContainsRune("dDwWsShHvVpPRNX", rune(e[0])) {
					// "[a-\w]": PCRE makes the "-" literal.
					p.edits = append(p.edits, edit{save, save + 1, `\-`})
					set.add(cur)
					set.add('-')
					prev = 0
					continue
				}
				r, n, err := decodeEscapeChar(p.s[p.i:])
				if err != nil {
					return nil, err
				}
				hi = r
				p.i += n
			} else if p.s[p.i] == '[' && p.i+1 < len(p.s) && p.s[p.i+1] == ':' {
				return nil, errUnparsable
			} else {
				r, size := utf8.DecodeRuneInString(p.s[p.i:])
				if r == utf8.RuneError && size <= 1 {
					r, size = rune(p.s[p.i]), 1
				}
				hi = r
				p.i += size
			}
			if hi < cur {
				return nil, errUnparsable
			}
			set.addRange(cur, hi)
			prev = 0
			continue
		}
		set.add(cur)
		prev = 1
		prevRune = cur
	}
	_ = prev
	_ = prevRune
	if p.fi {
		set.foldCase()
	}
	if negate {
		set = set.negated()
	}
	return &rnode{kind: nSet, set: set, start: start, end: p.i}, nil
}

// decodeEscapeChar reads a backslash escape that stands for one character, and returns it with its length in bytes.
func decodeEscapeChar(s string) (rune, int, error) {
	if len(s) < 2 || s[0] != '\\' {
		return 0, 0, errUnparsable
	}
	e := s[1]
	switch e {
	case 'n':
		return '\n', 2, nil
	case 'r':
		return '\r', 2, nil
	case 't':
		return '\t', 2, nil
	case 'f':
		return '\f', 2, nil
	case 'v':
		return '\v', 2, nil
	case 'a':
		return 7, 2, nil
	case 'e':
		return 27, 2, nil
	case 'b': // backspace inside a class
		return 8, 2, nil
	case 'x':
		if len(s) >= 3 && s[2] == '{' {
			j := strings.IndexByte(s, '}')
			if j < 0 || j > 12 {
				return 0, 0, errUnparsable
			}
			v, err := strconv.ParseUint(s[3:j], 16, 32)
			if err != nil || v > utf8.MaxRune || v >= 0xD800 && v <= 0xDFFF {
				return 0, 0, errUnparsable
			}
			return rune(v), j + 1, nil
		}
		n := 0
		var v uint64
		for n < 2 && 2+n < len(s) && isHex(s[2+n]) {
			d, _ := strconv.ParseUint(s[2+n:3+n], 16, 8)
			v = v*16 + d
			n++
		}
		return rune(v), 2 + n, nil
	case '0', '1', '2', '3', '4', '5', '6', '7':
		n := 1
		v := rune(e - '0')
		for n < 3 && 1+n < len(s) && s[1+n] >= '0' && s[1+n] <= '7' {
			v = v*8 + rune(s[1+n]-'0')
			n++
		}
		return v, 1 + n, nil
	case 'c':
		if len(s) >= 3 {
			return rune(s[2]) & 0x1f, 3, nil
		}
		return 0, 0, errUnparsable
	}
	if e < utf8.RuneSelf {
		if isAlnum(e) {
			// An unknown letter or digit escape: the engines disagree about it, so do not guess.
			return 0, 0, errUnparsable
		}
		return rune(e), 2, nil
	}
	r, size := utf8.DecodeRuneInString(s[1:])
	return r, 1 + size, nil
}

func isHex(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F'
}

func isAlnum(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z'
}

func (p *rparser) parseEscape() (*rnode, error) {
	start := p.i
	if p.i+1 >= len(p.s) {
		return nil, errUnparsable
	}
	e := p.s[p.i+1]
	mk := func(s cset, n int) (*rnode, error) {
		p.i += n
		return &rnode{kind: nSet, set: s, start: start, end: p.i}, nil
	}
	switch e {
	case 'd':
		return mk(digitSet(), 2)
	case 'D':
		return mk(digitSet().negated(), 2)
	case 'w':
		return mk(wordSet(), 2)
	case 'W':
		return mk(wordSet().negated(), 2)
	case 's':
		return mk(spaceSet(), 2)
	case 'S':
		return mk(spaceSet().negated(), 2)
	case 'h', 'H', 'v', 'V', 'R', 'N', 'X':
		return mk(fullSet(), 2) // not modelled; the widest set keeps later checks safe
	case 'p', 'P':
		n := 2
		if p.i+2 < len(p.s) && p.s[p.i+2] == '{' {
			j := strings.IndexByte(p.s[p.i:], '}')
			if j < 0 {
				return nil, errUnparsable
			}
			n = j + 1
		} else {
			n = 3
		}
		if p.i+n > len(p.s) {
			return nil, errUnparsable
		}
		return mk(fullSet(), n)
	case 'b', 'B', 'A', 'z', 'Z', 'G':
		p.i += 2
		if e == 'b' || e == 'B' {
			// word boundaries are modelled by name only
		}
		return &rnode{kind: nAssert, assert: `\` + string(e), start: start, end: p.i}, nil
	case 'K':
		return nil, errLook
	case 'Q':
		// Go reads \Q...\E itself, so a pattern that has one never needs this translation; do not try to model it here.
		return nil, errUnparsable
	case 'k', 'g':
		return nil, errBackref
	case '1', '2', '3', '4', '5', '6', '7', '8', '9':
		return nil, errBackref
	}
	r, n, err := decodeEscapeChar(p.s[p.i:])
	if err != nil {
		return nil, err
	}
	var s cset
	s.add(r)
	if p.fi {
		s.foldCase()
	}
	return mk(s, n)
}
