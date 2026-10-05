// SPDX-License-Identifier: Apache-2.0

package importers

import (
	"errors"
	"regexp"
	"regexp/syntax"
	"sort"
	"strings"
	"unicode/utf8"
)

// RegexError says why a pattern could not be used. Reason is a short stable code that goes into the report.
type RegexError struct {
	Reason string
}

func (e *RegexError) Error() string { return "regex: " + e.Reason }

// TranslatePCRE rewrites a PCRE pattern for Go's RE2 syntax, but only where the rewrite means exactly the same thing for the
// question a signature asks ("does this value contain a match?"). There are three rewrites:
//
//   - a possessive quantifier ("a*+") loses its "+" when the rest of the pattern cannot start with a character the repeated
//     atom could match, so that giving characters back could never let the rest match. At the end of the pattern, or before "$",
//     that is always so;
//   - an atomic group "(?>...)" becomes "(?:...)" when what is inside can only match one length, or nothing that has to match
//     follows it, or it is a repeat that passes the possessive test above;
//   - in a character class, a "-" next to a class escape ("[\w-.]") is a literal "-" in PCRE and a syntax error in Go, so it is
//     written "\-".
//
// Anything else that Go cannot read (lookaround, backreferences, recursion, the x flag, \K) is not translated and returns an
// error naming it: no approximation is made. The result is not compiled here; use Report.CheckRegex, which does.
func TranslatePCRE(pattern string) (string, error) {
	alts, p, err := parsePCRE(pattern)
	if err != nil {
		return "", &RegexError{Reason: translateReason(err)}
	}
	a := &analyzer{}
	a.walk(alts, nil, nil, false)
	if a.err != nil {
		return "", a.err
	}
	edits := append(append([]edit(nil), p.edits...), a.edits...)
	if len(edits) == 0 {
		return pattern, nil
	}
	sort.Slice(edits, func(i, j int) bool { return edits[i].start < edits[j].start })
	var b strings.Builder
	pos := 0
	for _, e := range edits {
		if e.start < pos || e.end > len(pattern) || e.start > e.end {
			return "", &RegexError{Reason: "unparsable"}
		}
		b.WriteString(pattern[pos:e.start])
		b.WriteString(e.repl)
		pos = e.end
	}
	b.WriteString(pattern[pos:])
	return b.String(), nil
}

func translateReason(err error) string {
	switch {
	case errors.Is(err, errExtended):
		return "x-flag"
	case errors.Is(err, errBackref):
		return "backreference"
	case errors.Is(err, errLook):
		return "lookaround"
	case errors.Is(err, errRecursion):
		return "recursion"
	case errors.Is(err, errNesting), errors.Is(err, errTooManyNodes):
		return "too-complex"
	}
	return "unparsable"
}

type frame struct {
	seq   []*rnode
	idx   int
	group *rnode // the group this sequence is an alternative of, nil at the top
	loop  bool   // the group may repeat, so after an iteration another may begin
}

type analyzer struct {
	edits []edit
	err   *RegexError
}

func (a *analyzer) fail(reason string) {
	if a.err == nil {
		a.err = &RegexError{Reason: reason}
	}
}

func (a *analyzer) walk(alts [][]*rnode, parent []frame, group *rnode, loop bool) {
	for _, seq := range alts {
		for i, n := range seq {
			frames := make([]frame, len(parent)+1)
			copy(frames, parent)
			frames[len(parent)] = frame{seq: seq, idx: i, group: group, loop: loop}
			a.visit(n, frames)
			if a.err != nil {
				return
			}
		}
	}
}

func (a *analyzer) visit(n *rnode, frames []frame) {
	switch n.kind {
	case nRepeat:
		if n.possessive {
			a.checkPossessive(n, frames)
		}
		if n.sub.kind == nGroup {
			a.visitGroup(n.sub, frames, n.max != 1)
		}
	case nGroup:
		a.visitGroup(n, frames, false)
	}
}

func (a *analyzer) visitGroup(g *rnode, frames []frame, repeated bool) {
	if g.gk == gAtomic {
		a.checkAtomic(g, frames, repeated)
	}
	if a.err != nil {
		return
	}
	a.walk(g.alts, frames, g, repeated)
}

func (a *analyzer) checkPossessive(r *rnode, frames []frame) {
	if r.min == r.max && r.min >= 0 {
		a.edits = append(a.edits, edit{r.plusPos, r.plusPos + 1, ""})
		return
	}
	if r.sub.kind != nSet {
		a.fail("possessive-not-exact")
		return
	}
	if !followDisjoint(r.sub.set, frames) {
		a.fail("possessive-not-exact")
		return
	}
	a.edits = append(a.edits, edit{r.plusPos, r.plusPos + 1, ""})
}

func (a *analyzer) checkAtomic(g *rnode, frames []frame, repeated bool) {
	exact := false
	if _, ok := fixedLenAlts(g.alts); ok {
		exact = true
	} else if len(g.alts) == 1 && len(g.alts[0]) == 1 && g.alts[0][0].kind == nRepeat && g.alts[0][0].sub.kind == nSet && !g.alts[0][0].possessive {
		r := g.alts[0][0]
		exact = r.min == r.max || (!repeated && followDisjoint(r.sub.set, frames))
	} else if !repeated {
		exact = endReachable(frames)
	}
	if !exact {
		a.fail("atomic-not-exact")
		return
	}
	a.edits = append(a.edits, edit{g.openPos, g.openPos + 3, "(?:"})
}

// followDisjoint reports whether, after an atom with character set x has been repeated, whatever must match next provably cannot
// begin with a character in x. Then giving back some of the repeated characters (which is all that differs between a greedy and
// a possessive quantifier) could never let the rest of the pattern match, and the two mean the same.
func followDisjoint(x cset, frames []frame) bool {
	for level := len(frames) - 1; level >= 0; level-- {
		f := frames[level]
		for j := f.idx + 1; j < len(f.seq); j++ {
			done, ok := stepFollow(f.seq[j], x)
			if done {
				return ok
			}
		}
		if f.loop && f.group != nil {
			s, _, bad := firstGroup(f.group)
			if bad || s.intersects(x) {
				return false
			}
		}
	}
	return true // the pattern ends: nothing that has to match remains
}

// stepFollow looks at one node that comes after the repeat. done says the question is settled; ok is the answer.
func stepFollow(n *rnode, x cset) (done, ok bool) {
	switch n.kind {
	case nSet:
		return true, !n.set.intersects(x)
	case nAssert:
		switch n.assert {
		case "$", `\z`, `\Z`:
			// After the repeat took every character it could, "end of text" holds there. A character given back would leave
			// one of x in front of it, so the assertion would fail. That reasoning is wrong for "$" in multi-line mode, where
			// "$" holds in front of a newline.
			return true, !n.multiline
		case `\b`:
			w := wordSet()
			return true, x.subsetOf(w) || x.subsetOf(w.negated())
		}
		return true, false
	case nRepeat:
		var s cset
		var nullable, bad bool
		if n.sub.kind == nSet {
			s = n.sub.set
		} else if n.sub.kind == nGroup {
			s, nullable, bad = firstGroup(n.sub)
		} else {
			return true, false
		}
		if bad || s.intersects(x) {
			return true, false
		}
		if n.min > 0 && !nullable {
			return true, true
		}
		return false, true
	case nGroup:
		s, nullable, bad := firstGroup(n)
		if bad || s.intersects(x) {
			return true, false
		}
		if !nullable {
			return true, true
		}
		return false, true
	}
	return true, false
}

// firstGroup returns the characters a group can begin with, whether it can match the empty string, and bad when it holds
// something this analysis does not model (an assertion).
func firstGroup(g *rnode) (s cset, nullable, bad bool) {
	for _, alt := range g.alts {
		as, an, ab := firstSeq(alt)
		if ab {
			return cset{}, false, true
		}
		s.union(as)
		if an {
			nullable = true
		}
	}
	if len(g.alts) == 0 {
		nullable = true
	}
	return s, nullable, false
}

func firstSeq(seq []*rnode) (s cset, nullable, bad bool) {
	for _, n := range seq {
		switch n.kind {
		case nSet:
			s.union(n.set)
			return s, false, false
		case nRepeat:
			var ns cset
			var nn, nb bool
			if n.sub.kind == nSet {
				ns = n.sub.set
			} else if n.sub.kind == nGroup {
				ns, nn, nb = firstGroup(n.sub)
			} else {
				return cset{}, false, true
			}
			if nb {
				return cset{}, false, true
			}
			s.union(ns)
			if n.min > 0 && !nn {
				return s, false, false
			}
		case nGroup:
			gs, gn, gb := firstGroup(n)
			if gb {
				return cset{}, false, true
			}
			s.union(gs)
			if !gn {
				return s, false, false
			}
		default:
			return cset{}, false, true
		}
	}
	return s, true, false
}

// fixedLenAlts reports the one length that every alternative has, when each is a plain run of single characters.
func fixedLenAlts(alts [][]*rnode) (int, bool) {
	length := -1
	for _, alt := range alts {
		n, ok := fixedLenSeq(alt)
		if !ok {
			return 0, false
		}
		if length >= 0 && n != length {
			return 0, false
		}
		length = n
	}
	if length < 0 {
		return 0, false
	}
	return length, true
}

func fixedLenSeq(seq []*rnode) (int, bool) {
	total := 0
	for _, n := range seq {
		switch n.kind {
		case nSet:
			total++
		case nRepeat:
			if n.min != n.max || n.min < 0 {
				return 0, false
			}
			switch n.sub.kind {
			case nSet:
				total += n.min
			case nGroup:
				l, ok := fixedLenAlts(n.sub.alts)
				if !ok || n.sub.gk == gAtomic {
					return 0, false
				}
				total += n.min * l
			default:
				return 0, false
			}
		case nGroup:
			l, ok := fixedLenAlts(n.alts)
			if !ok {
				return 0, false
			}
			total += l
		default:
			return 0, false
		}
	}
	return total, true
}

// endReachable reports whether everything after the node is optional, so that once the node has matched the pattern has
// matched, whatever else could have been tried.
func endReachable(frames []frame) bool {
	for level := len(frames) - 1; level >= 0; level-- {
		f := frames[level]
		for j := f.idx + 1; j < len(f.seq); j++ {
			n := f.seq[j]
			switch n.kind {
			case nRepeat:
				if n.min != 0 {
					return false
				}
			case nGroup:
				_, nullable, bad := firstGroup(n)
				if bad || !nullable {
					return false
				}
			default:
				return false
			}
		}
		if f.loop {
			return false
		}
	}
	return true
}

// CheckRegex makes sure a regular expression compiles in Go, translating PCRE-only syntax only where that is exact (see
// TranslatePCRE), and counts it in the report. It returns the pattern to use; when it returns an error the signature that
// holds the pattern must be skipped, and the error's Reason is already counted in the report.
//
// flags may hold "i", "s" and "m"; they are how the pattern is meant to be compiled.
func (r *Report) CheckRegex(pattern, flags string, maxBytes int) (string, error) {
	r.Regex.Seen++
	fail := func(reason string) (string, error) {
		r.Regex.Failed++
		r.Regex.FailReason[reason]++
		return "", &RegexError{Reason: reason}
	}
	if maxBytes > 0 && len(pattern) > maxBytes {
		return fail("too-long")
	}
	if !utf8.ValidString(pattern) {
		return fail("not-utf8")
	}
	prefix := flagPrefix(flags)
	if _, err := regexp.Compile(prefix + pattern); err == nil {
		r.Regex.Compiled++
		return pattern, nil
	} else if !mayTranslate(err) {
		return fail(classifyGoError(err))
	}
	t, terr := TranslatePCRE(pattern)
	if terr != nil {
		var re *RegexError
		if errors.As(terr, &re) {
			return fail(re.Reason)
		}
		return fail("unparsable")
	}
	if t == pattern {
		_, err := regexp.Compile(prefix + pattern)
		return fail(classifyGoError(err))
	}
	if _, err := regexp.Compile(prefix + t); err != nil {
		return fail(classifyGoError(err))
	}
	r.Regex.Translated++
	return t, nil
}

func flagPrefix(flags string) string {
	var b strings.Builder
	for _, c := range flags {
		if c == 'i' || c == 's' || c == 'm' {
			b.WriteRune(c)
		}
	}
	if b.Len() == 0 {
		return ""
	}
	return "(?" + b.String() + ")"
}

// mayTranslate says whether a compile error is one that TranslatePCRE can address.
func mayTranslate(err error) bool {
	var se *syntax.Error
	if !errors.As(err, &se) {
		return false
	}
	switch se.Code {
	case syntax.ErrInvalidRepeatOp, syntax.ErrMissingRepeatArgument, syntax.ErrInvalidPerlOp, syntax.ErrInvalidCharRange, syntax.ErrInvalidEscape:
		return true
	}
	return false
}

// classifyGoError turns a Go regexp error into a short stable code for the report.
func classifyGoError(err error) string {
	if err == nil {
		return "unparsable"
	}
	var se *syntax.Error
	if !errors.As(err, &se) {
		return "unparsable"
	}
	switch se.Code {
	case syntax.ErrInvalidPerlOp:
		switch {
		case strings.HasPrefix(se.Expr, "(?=") || strings.HasPrefix(se.Expr, "(?!"):
			return "lookaround"
		case strings.HasPrefix(se.Expr, "(?<=") || strings.HasPrefix(se.Expr, "(?<!"):
			return "lookaround"
		case strings.HasPrefix(se.Expr, "(?>"):
			return "atomic-not-exact"
		}
		return "perl-syntax"
	case syntax.ErrInvalidEscape:
		e := se.Expr
		if len(e) == 2 && e[0] == '\\' && e[1] >= '1' && e[1] <= '9' {
			return "backreference"
		}
		return "escape:" + e
	case syntax.ErrInvalidRepeatOp:
		if strings.Contains(se.Expr, "+") {
			return "possessive-not-exact"
		}
		return "repeat-operator"
	case syntax.ErrInvalidRepeatSize, syntax.ErrLarge, syntax.ErrNestingDepth:
		return "too-complex"
	case syntax.ErrMissingRepeatArgument:
		return "repeat-argument"
	case syntax.ErrInvalidCharRange:
		return "char-range"
	case syntax.ErrMissingParen, syntax.ErrUnexpectedParen:
		return "parentheses"
	case syntax.ErrMissingBracket:
		return "bracket"
	}
	return "unparsable"
}
