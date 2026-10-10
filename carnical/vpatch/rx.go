// SPDX-License-Identifier: Apache-2.0

package vpatch

import (
	"fmt"
	"regexp"
	"regexp/syntax"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Limits on what one regular expression may cost, enforced when it is compiled. The signatures come from feeds we do not write,
// so a pattern is checked for what it would cost before it is allowed near a request.
const (
	maxPatternLen = 32 << 10
	// maxProgInsts bounds one program, and so one expression run: Go's regexp has no DFA, and an alternation whose branches
	// stay alive together costs the whole program on every byte. The largest in the shipped feeds compiles to about 6,500.
	maxProgInsts = 8000
	// reMaxRepeat is the largest repeat count RE2 accepts.
	reMaxRepeat = 1000
	// rxWeightUnit is how many live NFA threads one byte of allowance pays for: an expression without large counted repeats is
	// charged one per byte, a repeat of a thousand some sixty.
	rxWeightUnit = 16
	// rxSmallRepeat is the largest count that is not charged for: \d{4} or [a-f]{1,8} keep few threads alive.
	rxSmallRepeat = 16
)

// repeatThreads estimates how many NFA threads an expression's counted repeats can keep alive at once. RE2 compiles x{0,990}
// as 990 copies of x, and on a value of the right shape every copy is live for every byte, so the time per byte grows with the
// count (and with the product of counts, when they are nested). A star is one loop and costs nothing extra, nor does a small
// count. It reads the expression before Simplify, which expands the counts away.
func repeatThreads(re *syntax.Regexp) int {
	inner := 0
	for _, s := range re.Sub {
		inner += repeatThreads(s)
	}
	if re.Op != syntax.OpRepeat {
		return inner
	}
	count := max(re.Min, re.Max)
	if count <= rxSmallRepeat {
		return inner
	}
	return min(count*max(inner, 1), maxProgInsts)
}

// rxProg is a compiled regular expression: the programs that must all match one value, whether the value is read as bytes, the
// literals a value must contain for it to match, and what had to be rewritten to get here.
type rxProg struct {
	res      []*regexp.Regexp
	byteMode bool
	// weight is what one byte of input costs against a request's work allowance: repeatThreads in units of rxWeightUnit, at
	// least 1. RE2's time per byte grows with the threads that can be live at once.
	weight int
	// anchors is the clause of lower-case ASCII literals, at least one of which must occur in any value the expression matches,
	// or nil if no safe one was found.
	anchors []string
	// notes names the PCRE constructs that were rewritten, each once.
	notes []string
}

// compileRx turns a PCRE-flavoured pattern (the form the rule feeds are written in) into RE2 programs, or says exactly why it
// cannot.
//
// What is translated, and why each is safe:
//
//   - A possessive quantifier (a*+, a++, a?+, a{2,3}+) and an atomic group ((?>x)) become the greedy form. They differ from it
//     only in not backing off, so the greedy form matches everything they do and, rarely, more. A signature's match is a yes or
//     no, so this can add a match, never lose one.
//   - \Z and a $ outside multi-line mode match at the end or before a final newline in PCRE, and only at the very end in RE2;
//     both become that exact PCRE condition.
//   - \e, \cX, \xH, a lone \b in a character class: spelled differently, same meaning.
//   - (?#comment) is dropped.
//   - A repeat bound above RE2's 1000 ({0,4096}) is widened to no bound. Exact for values shorter than the bound, which is the
//     only difference.
//   - A pattern that starts \A(?=A)(?=B)rest asserts that A, B and rest each match at the start; it becomes those expressions,
//     all required of the same value. Exact.
//   - A lookahead of one character class directly before something that cannot start with any other character, such as
//     (?=[a-z])(?:cat|curl|...), asserts nothing the next token does not already; it is removed after that has been proved on the
//     parsed expression. Exact.
//   - \xHH above 0x7F means a byte in PCRE and a code point in RE2. A pattern that uses one is matched against a copy of the
//     value in which each byte is its own code point, which is exactly PCRE's view.
//
// Everything else that has no RE2 equivalent is refused with its name: lookahead and lookbehind not covered above, back-references,
// recursion, conditionals, backtracking verbs, \G, \K, \R, \X, \h, \v and the extended (?x) mode.
func compileRx(pattern, flags string) (*rxProg, error) {
	if len(pattern) > maxPatternLen {
		return nil, fmt.Errorf("regular expression is %d bytes, over the limit of %d", len(pattern), maxPatternLen)
	}
	var fi, fs, fm bool
	for _, f := range flags {
		switch f {
		case 'i':
			fi = true
		case 's':
			fs = true
		case 'm':
			fm = true
		default:
			return nil, fmt.Errorf("unknown regular expression flag %q", string(f))
		}
	}
	multiline := fm || hasInlineFlag(pattern, 'm')
	prefix := ""
	if fi {
		prefix += "i"
	}
	if fs {
		prefix += "s"
	}
	if fm {
		prefix += "m"
	}
	if prefix != "" {
		prefix = "(?" + prefix + ")"
	}

	var tr translator
	parts, err := tr.translateAll(pattern, multiline, false)
	if err != nil {
		return nil, err
	}
	byteMode := false
	if tr.sawHighEscape {
		var tr2 translator
		parts, err = tr2.translateAll(pattern, multiline, true)
		if err != nil {
			return nil, err
		}
		tr = tr2
		byteMode = true
	}

	prog := &rxProg{byteMode: byteMode, notes: tr.notes()}
	threads := 0
	var clauses [][]string
	for _, part := range parts {
		src := prefix + part
		ast, err := syntax.Parse(src, syntax.Perl)
		if err != nil {
			return nil, fmt.Errorf("not valid for RE2: %s", cleanReErr(err))
		}
		if err := tr.verifyMarkers(ast); err != nil {
			return nil, err
		}
		threads += repeatThreads(ast)
		p, err := syntax.Compile(ast.Simplify())
		if err != nil {
			return nil, fmt.Errorf("not valid for RE2: %s", cleanReErr(err))
		}
		if len(p.Inst) > maxProgInsts {
			return nil, fmt.Errorf("regular expression compiles to %d instructions, over the limit of %d", len(p.Inst), maxProgInsts)
		}
		re, err := regexp.Compile(src)
		if err != nil {
			return nil, fmt.Errorf("not valid for RE2: %s", cleanReErr(err))
		}
		prog.res = append(prog.res, re)
		clauses = append(clauses, extractClauses(ast)...)
	}
	prog.anchors = bestClause(clauses)
	prog.weight = max(1, threads/rxWeightUnit)
	return prog, nil
}

func cleanReErr(err error) string {
	s := err.Error()
	s = strings.TrimPrefix(s, "error parsing regexp: ")
	if len(s) > 120 {
		s = s[:120]
	}
	return s
}

// hasInlineFlag reports whether the pattern switches flag f on anywhere with an inline group such as (?m) or (?im:...).
func hasInlineFlag(p string, f byte) bool {
	for i := 0; i+2 < len(p); i++ {
		if p[i] == '\\' {
			i++
			continue
		}
		if p[i] != '(' || p[i+1] != '?' {
			continue
		}
		for j := i + 2; j < len(p); j++ {
			c := p[j]
			if c == f {
				return true
			}
			if c == '-' {
				break
			}
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z') {
				break
			}
		}
	}
	return false
}

// A translator rewrites one pattern. It is used once.
type translator struct {
	byteMode      bool
	multiline     bool
	sawHighEscape bool
	counts        map[string]bool
	looks         []lookahead
}

// A lookahead is a (?=[class]) that was replaced by an empty named group so that it can be found again in the parsed expression
// and checked there.
type lookahead struct {
	ranges []rune // the class, as pairs of first and last rune
}

const lookMarkPrefix = "vplook"

func (t *translator) note(s string) {
	if t.counts == nil {
		t.counts = map[string]bool{}
	}
	t.counts[s] = true
}

func (t *translator) notes() []string {
	var out []string
	for k := range t.counts {
		out = append(out, k)
	}
	return out
}

// translateAll returns the expressions that together are the pattern: one, or several when the pattern is a conjunction of
// start-anchored lookaheads.
func (t *translator) translateAll(p string, multiline, byteMode bool) ([]string, error) {
	t.multiline, t.byteMode = multiline, byteMode
	pref, body := "", p
	if strings.HasPrefix(p, "(?") {
		if end := strings.IndexByte(p, ')'); end > 0 && isFlagGroup(p[2:end]) {
			for _, f := range p[2:end] {
				switch f {
				case 'i', 'm', 's', 'U', '-':
				case 'x':
					return nil, fmt.Errorf("extended mode (?x) has no RE2 equivalent")
				case 'R':
					return nil, fmt.Errorf("recursion (?R) has no RE2 equivalent")
				default:
					return nil, fmt.Errorf("inline flag %q has no RE2 equivalent", string(f))
				}
			}
			pref, body = p[:end+1], p[end+1:]
		}
	}
	anchor := ""
	switch {
	case strings.HasPrefix(body, `\A`):
		anchor = `\A`
	case strings.HasPrefix(body, "^") && !multiline:
		anchor = "^"
	}
	if anchor != "" && strings.HasPrefix(body[len(anchor):], "(?=") {
		rest := body[len(anchor):]
		var bodies []string
		for strings.HasPrefix(rest, "(?=") {
			end := matchingParen(rest, 0)
			if end < 0 {
				return nil, fmt.Errorf("unbalanced parenthesis")
			}
			bodies = append(bodies, rest[3:end])
			rest = rest[end+1:]
		}
		if topLevelAlternation(rest) {
			return nil, fmt.Errorf("lookahead in one branch of an alternation has no RE2 equivalent")
		}
		if rest != "" {
			bodies = append(bodies, rest)
		}
		t.note("start-anchored lookaheads split into required parts")
		var out []string
		for _, b := range bodies {
			s, err := t.run(b)
			if err != nil {
				return nil, err
			}
			out = append(out, pref+`\A`+s)
		}
		return out, nil
	}
	s, err := t.run(body)
	if err != nil {
		return nil, err
	}
	return []string{pref + s}, nil
}

func isFlagGroup(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c == '-') {
			return false
		}
	}
	return true
}

// scanClass returns the index just after the character class that starts at p[i], or -1 if it is not closed.
func scanClass(p string, i int) int {
	j := i + 1
	if j < len(p) && p[j] == '^' {
		j++
	}
	if j < len(p) && p[j] == ']' {
		j++
	}
	for j < len(p) {
		switch p[j] {
		case '\\':
			j += 2
		case '[':
			if j+1 < len(p) && p[j+1] == ':' {
				if k := strings.Index(p[j+2:], ":]"); k >= 0 {
					j += 2 + k + 2
					continue
				}
			}
			j++
		case ']':
			return j + 1
		default:
			j++
		}
	}
	return -1
}

// matchingParen returns the index of the ')' that closes the '(' at p[i], or -1.
func matchingParen(p string, i int) int {
	depth := 0
	for j := i; j < len(p); j++ {
		switch p[j] {
		case '\\':
			if j+1 < len(p) && p[j+1] == 'Q' {
				if k := strings.Index(p[j+2:], `\E`); k >= 0 {
					j += 2 + k + 1
				} else {
					return -1
				}
			} else {
				j++
			}
		case '[':
			end := scanClass(p, j)
			if end < 0 {
				return -1
			}
			j = end - 1
		case '(':
			depth++
		case ')':
			depth--
			if depth == 0 {
				return j
			}
		}
	}
	return -1
}

// topLevelAlternation reports whether p has a '|' outside every group and class.
func topLevelAlternation(p string) bool {
	depth := 0
	for j := 0; j < len(p); j++ {
		switch p[j] {
		case '\\':
			j++
		case '[':
			end := scanClass(p, j)
			if end < 0 {
				return false
			}
			j = end - 1
		case '(':
			depth++
		case ')':
			depth--
		case '|':
			if depth == 0 {
				return true
			}
		}
	}
	return false
}

// braceQuantifier parses {n}, {n,} or {n,m} at p[i] and returns its parts and length, or ok=false if it is not a quantifier (a
// literal brace, in PCRE and in RE2).
func braceQuantifier(p string, i int) (min, max int, hasMax bool, n int, ok bool) {
	j := i + 1
	k := j
	for k < len(p) && p[k] >= '0' && p[k] <= '9' {
		k++
	}
	if k == j || k-j > 9 {
		return
	}
	min, _ = strconv.Atoi(p[j:k])
	switch {
	case k < len(p) && p[k] == '}':
		return min, min, true, k + 1 - i, true
	case k < len(p) && p[k] == ',':
		k++
		m := k
		for k < len(p) && p[k] >= '0' && p[k] <= '9' {
			k++
		}
		if k >= len(p) || p[k] != '}' || k-m > 9 {
			return
		}
		if k == m {
			return min, 0, false, k + 1 - i, true
		}
		max, _ = strconv.Atoi(p[m:k])
		return min, max, true, k + 1 - i, true
	}
	return
}

func (t *translator) run(p string) (string, error) {
	var b strings.Builder
	b.Grow(len(p) + 16)
	lastQuant := false
	for i := 0; i < len(p); {
		c := p[i]
		switch {
		case c == '\\':
			n, err := t.escape(&b, p, i, false)
			if err != nil {
				return "", err
			}
			i += n
			lastQuant = false
		case c == '[':
			end := scanClass(p, i)
			if end < 0 {
				return "", fmt.Errorf("unterminated character class")
			}
			if err := t.class(&b, p[i:end]); err != nil {
				return "", err
			}
			i = end
			lastQuant = false
		case c == '(':
			n, err := t.group(&b, p, i)
			if err != nil {
				return "", err
			}
			i += n
			lastQuant = false
		case c == '*' || c == '+' || c == '?':
			switch {
			case lastQuant && c == '+':
				t.note("possessive quantifier made greedy")
				lastQuant = false
			case lastQuant && c == '?':
				b.WriteByte(c)
				lastQuant = false
			default:
				b.WriteByte(c)
				lastQuant = true
			}
			i++
		case c == '{':
			min, max, hasMax, n, ok := braceQuantifier(p, i)
			if !ok {
				b.WriteByte('{')
				i++
				lastQuant = false
				break
			}
			if min > reMaxRepeat {
				return "", fmt.Errorf("repeat count %d is above the RE2 limit of %d", min, reMaxRepeat)
			}
			if hasMax && max > reMaxRepeat {
				t.note("repeat bound above 1000 widened")
				fmt.Fprintf(&b, "{%d,}", min)
			} else {
				b.WriteString(p[i : i+n])
			}
			i += n
			lastQuant = true
		case c == '$' && !t.multiline:
			// PCRE: end of text, or before a final newline. RE2: end of text only.
			t.note("$ made to accept a final newline")
			b.WriteString(`(?:\n?\z)`)
			i++
			lastQuant = false
		case c >= 0x80 && t.byteMode:
			fmt.Fprintf(&b, `\x{%04x}`, c)
			i++
			lastQuant = false
		default:
			b.WriteByte(c)
			i++
			lastQuant = false
		}
	}
	return b.String(), nil
}

// escape translates the escape at p[i] (p[i] is a backslash) and returns how many bytes of p it used.
func (t *translator) escape(b *strings.Builder, p string, i int, inClass bool) (int, error) {
	if i+1 >= len(p) {
		return 0, fmt.Errorf("trailing backslash")
	}
	d := p[i+1]
	switch {
	case d == 'Q' && !inClass:
		end := strings.Index(p[i+2:], `\E`)
		if end < 0 {
			b.WriteString(p[i:])
			return len(p) - i, nil
		}
		b.WriteString(p[i : i+2+end+2])
		return 2 + end + 2, nil
	case d == 'Z' && !inClass:
		t.note(`\Z made to accept a final newline`)
		b.WriteString(`(?:\n?\z)`)
		return 2, nil
	case d == 'e':
		b.WriteString(`\x1b`)
		return 2, nil
	case d == 'c' && i+2 < len(p):
		x := p[i+2]
		if x >= 'a' && x <= 'z' {
			x -= 'a' - 'A'
		}
		fmt.Fprintf(b, `\x%02x`, x^0x40)
		return 3, nil
	case d == 'x':
		return t.hexEscape(b, p, i)
	case d == 'b' && inClass:
		b.WriteString(`\x08`)
		return 2, nil
	case d >= '1' && d <= '9' && !inClass:
		if i+2 < len(p) && p[i+2] >= '0' && p[i+2] <= '9' {
			b.WriteString(p[i : i+3]) // two digits: an octal escape if RE2 reads it as one
			return 3, nil
		}
		return 0, fmt.Errorf("back-reference \\%c has no RE2 equivalent", d)
	case d == 'k' || d == 'g':
		return 0, fmt.Errorf("named or relative back-reference \\%c has no RE2 equivalent", d)
	case d == 'G' || d == 'K' || d == 'R' || d == 'X' || d == 'h' || d == 'H' || d == 'v' || d == 'V' || d == 'N' || d == 'C':
		return 0, fmt.Errorf("PCRE escape \\%c has no RE2 equivalent", d)
	case d >= 0x80:
		// An escaped non-ASCII character is that character in PCRE; RE2 refuses the escape.
		_, size := utf8.DecodeRuneInString(p[i+1:])
		if t.byteMode {
			for k := 0; k < size; k++ {
				fmt.Fprintf(b, `\x{%04x}`, p[i+1+k])
			}
		} else {
			b.WriteString(p[i+1 : i+1+size])
		}
		return 1 + size, nil
	default:
		b.WriteString(p[i : i+2])
		return 2, nil
	}
}

// hexEscape handles \xHH, \xH, \x and \x{HHHH}.
func (t *translator) hexEscape(b *strings.Builder, p string, i int) (int, error) {
	j := i + 2
	if j < len(p) && p[j] == '{' {
		k := strings.IndexByte(p[j:], '}')
		if k < 0 {
			return 0, fmt.Errorf("unterminated \\x{...}")
		}
		v, err := strconv.ParseUint(strings.TrimLeft(p[j+1:j+k], "0"), 16, 32)
		if err != nil && strings.TrimLeft(p[j+1:j+k], "0") != "" {
			return 0, fmt.Errorf("invalid \\x{...} escape")
		}
		n := k + 1 + 2
		if t.byteMode {
			if v > 0xFF {
				return 0, fmt.Errorf("\\x{%x} is above one byte in a byte-oriented pattern", v)
			}
			fmt.Fprintf(b, `\x{%04x}`, v)
			return n, nil
		}
		if v >= 0x80 && v <= 0xFF {
			t.sawHighEscape = true
		}
		b.WriteString(p[i : i+n])
		return n, nil
	}
	digits := 0
	for digits < 2 && j+digits < len(p) && isHex(p[j+digits]) {
		digits++
	}
	var v byte
	for k := 0; k < digits; k++ {
		v = v<<4 | unhex(p[j+k])
	}
	if v >= 0x80 {
		t.sawHighEscape = true
		if t.byteMode {
			fmt.Fprintf(b, `\x{%04x}`, v)
			return 2 + digits, nil
		}
	}
	fmt.Fprintf(b, `\x%02x`, v)
	return 2 + digits, nil
}

// class translates a character class, p being exactly "[...]".
func (t *translator) class(b *strings.Builder, p string) error {
	b.WriteByte('[')
	i := 1
	if i < len(p) && p[i] == '^' {
		b.WriteByte('^')
		i++
	}
	if i < len(p) && p[i] == ']' {
		b.WriteString(`\]`)
		i++
	}
	for i < len(p)-1 {
		c := p[i]
		switch {
		case c == '\\':
			n, err := t.escape(b, p[:len(p)-1], i, true)
			if err != nil {
				return err
			}
			i += n
		case c == '[' && i+1 < len(p) && p[i+1] == ':':
			if k := strings.Index(p[i+2:], ":]"); k >= 0 {
				b.WriteString(p[i : i+2+k+2])
				i += 2 + k + 2
				continue
			}
			b.WriteString(`\[`)
			i++
		case c == '[':
			b.WriteString(`\[`)
			i++
		case c >= 0x80 && t.byteMode:
			fmt.Fprintf(b, `\x{%04x}`, c)
			i++
		default:
			b.WriteByte(c)
			i++
		}
	}
	b.WriteByte(']')
	return nil
}

// group handles a '(' and returns how many bytes it used. Only the opening is consumed: what is inside is translated by the
// caller's loop, which keeps going.
func (t *translator) group(b *strings.Builder, p string, i int) (int, error) {
	rest := p[i:]
	switch {
	case strings.HasPrefix(rest, "(*"):
		return 0, fmt.Errorf("PCRE backtracking verb has no RE2 equivalent")
	case !strings.HasPrefix(rest, "(?"):
		b.WriteByte('(')
		return 1, nil
	case strings.HasPrefix(rest, "(?:"):
		b.WriteString("(?:")
		return 3, nil
	case strings.HasPrefix(rest, "(?>"):
		t.note("atomic group made a plain group")
		b.WriteString("(?:")
		return 3, nil
	case strings.HasPrefix(rest, "(?#"):
		end := strings.IndexByte(rest, ')')
		if end < 0 {
			return 0, fmt.Errorf("unterminated comment group")
		}
		t.note("comment group removed")
		return end + 1, nil
	case strings.HasPrefix(rest, "(?!"):
		return 0, fmt.Errorf("negative lookahead has no RE2 equivalent")
	case strings.HasPrefix(rest, "(?<!") || strings.HasPrefix(rest, "(?<="):
		return 0, fmt.Errorf("lookbehind has no RE2 equivalent")
	case strings.HasPrefix(rest, "(?="):
		end := matchingParen(p, i)
		if end < 0 {
			return 0, fmt.Errorf("unbalanced parenthesis")
		}
		ranges, ok := lookaheadClass(p[i+3 : end])
		if !ok {
			return 0, fmt.Errorf("lookahead has no RE2 equivalent")
		}
		t.note("redundant one-class lookahead removed")
		fmt.Fprintf(b, "(?P<%s%d>)", lookMarkPrefix, len(t.looks))
		t.looks = append(t.looks, lookahead{ranges: ranges})
		return end + 1 - i, nil
	case strings.HasPrefix(rest, "(?P<") || strings.HasPrefix(rest, "(?<"):
		b.WriteString("(?")
		return 2, nil
	case strings.HasPrefix(rest, "(?P=") || strings.HasPrefix(rest, "(?P>") || strings.HasPrefix(rest, "(?&") || strings.HasPrefix(rest, "(?R"):
		return 0, fmt.Errorf("back-reference or recursion has no RE2 equivalent")
	case strings.HasPrefix(rest, "(?|") || strings.HasPrefix(rest, "(?("):
		return 0, fmt.Errorf("branch reset or conditional group has no RE2 equivalent")
	case strings.HasPrefix(rest, "(?'"):
		return 0, fmt.Errorf("quoted group name has no RE2 equivalent")
	}
	// (?flags) or (?flags:
	j := 2
	for j < len(rest) && (rest[j] >= 'a' && rest[j] <= 'z' || rest[j] >= 'A' && rest[j] <= 'Z' || rest[j] == '-') {
		j++
	}
	if j < len(rest) && (rest[j] == ')' || rest[j] == ':') && j > 2 {
		for _, f := range rest[2:j] {
			switch f {
			case 'i', 'm', 's', 'U', '-':
			case 'x':
				return 0, fmt.Errorf("extended mode (?x) has no RE2 equivalent")
			default:
				return 0, fmt.Errorf("inline flag %q has no RE2 equivalent", string(f))
			}
		}
		b.WriteString(rest[:j+1])
		return j + 1, nil
	}
	return 0, fmt.Errorf("group syntax %q has no RE2 equivalent", rest[:min(len(rest), 4)])
}

// lookaheadClass returns the ranges of a lookahead body that is one character class ([a-z], \w, \d, [^x]); ok is false for
// anything else.
func lookaheadClass(body string) ([]rune, bool) {
	if body == "" {
		return nil, false
	}
	if body[0] == '[' {
		if end := scanClass(body, 0); end != len(body) {
			return nil, false
		}
	} else if !(len(body) == 2 && body[0] == '\\' && strings.ContainsRune("wWdDsS", rune(body[1]))) {
		return nil, false
	}
	re, err := syntax.Parse(body, syntax.Perl)
	if err != nil || re.Op != syntax.OpCharClass {
		return nil, false
	}
	return append([]rune(nil), re.Rune...), true
}

// verifyMarkers checks, on the parsed expression, that every lookahead that was replaced by an empty group is redundant: what
// follows it in the same sequence cannot be empty and can only begin with characters the lookahead accepts.
func (t *translator) verifyMarkers(re *syntax.Regexp) error {
	if len(t.looks) == 0 {
		return nil
	}
	var walk func(n *syntax.Regexp, inConcat bool) error
	walk = func(n *syntax.Regexp, inConcat bool) error {
		if id, ok := markerID(n); ok && id < len(t.looks) && !inConcat {
			return fmt.Errorf("lookahead has no RE2 equivalent (nothing follows it)")
		}
		if n.Op == syntax.OpConcat {
			for i, sub := range n.Sub {
				if id, ok := markerID(sub); ok && id < len(t.looks) {
					first, nullable := firstSet(n.Sub[i+1:])
					if nullable {
						return fmt.Errorf("lookahead has no RE2 equivalent (what follows it can be empty)")
					}
					if !rangesContain(t.looks[id].ranges, first) {
						return fmt.Errorf("lookahead has no RE2 equivalent (what follows it can start with other characters)")
					}
				}
			}
		}
		for _, sub := range n.Sub {
			if err := walk(sub, n.Op == syntax.OpConcat); err != nil {
				return err
			}
		}
		return nil
	}
	return walk(re, false)
}

func markerID(n *syntax.Regexp) (int, bool) {
	if n.Op == syntax.OpCapture && strings.HasPrefix(n.Name, lookMarkPrefix) {
		id, err := strconv.Atoi(n.Name[len(lookMarkPrefix):])
		return id, err == nil
	}
	return 0, false
}

// firstSet returns the code points a match of the sequence can start with, as range pairs, and whether the sequence can match
// the empty string.
func firstSet(seq []*syntax.Regexp) ([]rune, bool) {
	var out []rune
	for _, n := range seq {
		f, nullable := firstOf(n)
		out = append(out, f...)
		if !nullable {
			return out, false
		}
	}
	return out, true
}

func firstOf(n *syntax.Regexp) ([]rune, bool) {
	switch n.Op {
	case syntax.OpLiteral:
		if len(n.Rune) == 0 {
			return nil, true
		}
		r := n.Rune[0]
		out := []rune{r, r}
		if n.Flags&syntax.FoldCase != 0 {
			for f := foldNext(r); f != r; f = foldNext(f) {
				out = append(out, f, f)
			}
		}
		return out, false
	case syntax.OpCharClass:
		return append([]rune(nil), n.Rune...), false
	case syntax.OpAnyChar, syntax.OpAnyCharNotNL:
		return []rune{0, 0x10FFFF}, false
	case syntax.OpCapture:
		return firstOf(n.Sub[0])
	case syntax.OpConcat:
		return firstSet(n.Sub)
	case syntax.OpAlternate:
		var out []rune
		nullable := false
		for _, s := range n.Sub {
			f, nl := firstOf(s)
			out = append(out, f...)
			nullable = nullable || nl
		}
		return out, nullable
	case syntax.OpStar, syntax.OpQuest:
		f, _ := firstOf(n.Sub[0])
		return f, true
	case syntax.OpPlus:
		return firstOf(n.Sub[0])
	case syntax.OpRepeat:
		f, nl := firstOf(n.Sub[0])
		return f, nl || n.Min == 0
	case syntax.OpNoMatch:
		return nil, false
	default: // empty match and the zero-width assertions
		return nil, true
	}
}

func foldNext(r rune) rune {
	return unicode.SimpleFold(r)
}

// rangesContain reports whether every code point of sub (range pairs) lies inside set (range pairs).
func rangesContain(set, sub []rune) bool {
	for i := 0; i+1 < len(sub); i += 2 {
		lo, hi := sub[i], sub[i+1]
		ok := false
		for j := 0; j+1 < len(set); j += 2 {
			if lo >= set[j] && hi <= set[j+1] {
				ok = true
				break
			}
		}
		if !ok {
			return false
		}
	}
	return true
}
