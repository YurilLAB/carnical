// SPDX-License-Identifier: Apache-2.0

package vpatch

import (
	"regexp/syntax"
	"strings"
	"unicode/utf8"
)

// Required literals.
//
// To decide quickly which of thousands of signatures a request could possibly match, each condition is given a set of literal
// strings, at least one of which must occur in any value the condition matches. If none occurs in a request's values the condition
// cannot hold and the signature is not looked at. The set is a necessary condition, never a sufficient one: a literal that is
// present only means the real operator has to run.
//
// A literal is only ever shorter or weaker than the truth. The rules that keep that so:
//
//   - Anything not understood contributes nothing (the empty requirement), never a guess.
//   - Literals are lower-cased ASCII. A text is scanned with ASCII case folded, so a case-sensitive pattern still finds its
//     lower-case form and a case-insensitive one finds every spelling. (Unicode simple folding makes two non-ASCII characters equal
//     to ASCII letters, the Kelvin sign and the long s; the scanner folds those too.)
//   - From a string with non-ASCII characters only an ASCII run is kept: any part of a required string is itself required.
//   - A set that has an empty member requires nothing and is dropped.

const (
	// maxExact is the largest set of whole strings kept while the pieces of a concatenation are multiplied out.
	maxExact = 16
	// maxExactLen is the longest such string.
	maxExactLen = 48
	// maxClauseLits is the most literals one requirement may offer; a longer alternation is not worth indexing.
	maxClauseLits = 2048
	// minAnchor is the shortest literal worth indexing. One byte is in nearly every request.
	minAnchor = 2
	// maxAnchor is the longest literal kept. A longer required string is cut: any part of it is still required.
	maxAnchor = 24
)

// info describes what a node of a regular expression requires.
//
// If exact is set, the node matches exactly one of the strings in set (the empty string among them if it can match nothing).
// Otherwise it matches something about which cnf says what is necessary: for every clause, at least one of its literals is in
// the text. An empty cnf says nothing.
type info struct {
	exact bool
	set   []string
	cnf   [][]string
}

func exactOf(s ...string) info { return info{exact: true, set: s} }

// asCNF is the necessary condition as clauses; nil if there is none worth having.
func (i info) asCNF() [][]string {
	if !i.exact {
		return i.cnf
	}
	for _, s := range i.set {
		if s == "" {
			return nil
		}
	}
	return [][]string{i.set}
}

// extractClauses returns the necessary clauses of a parsed expression, each already reduced to usable literals.
func extractClauses(re *syntax.Regexp) [][]string {
	var out [][]string
	for _, cl := range extract(re).asCNF() {
		if f := finalizeLits(cl); f != nil {
			out = append(out, f)
		}
	}
	return out
}

func extract(re *syntax.Regexp) info {
	switch re.Op {
	case syntax.OpEmptyMatch, syntax.OpBeginLine, syntax.OpEndLine, syntax.OpBeginText, syntax.OpEndText,
		syntax.OpWordBoundary, syntax.OpNoWordBoundary:
		return exactOf("")
	case syntax.OpLiteral:
		var b strings.Builder
		for _, r := range re.Rune {
			if r >= 'A' && r <= 'Z' {
				r += 'a' - 'A'
			}
			b.WriteRune(r)
		}
		return exactOf(b.String())
	case syntax.OpCharClass:
		return classLiterals(re)
	case syntax.OpCapture:
		return extract(re.Sub[0])
	case syntax.OpQuest:
		c := extract(re.Sub[0])
		if c.exact && len(c.set) < maxExact {
			return exactOf(dedupe(append([]string{""}, c.set...))...)
		}
		return info{}
	case syntax.OpPlus:
		return info{cnf: extract(re.Sub[0]).asCNF()}
	case syntax.OpRepeat:
		if re.Min == 0 {
			return info{}
		}
		if re.Min == 1 && re.Max == 1 {
			return extract(re.Sub[0])
		}
		c := extract(re.Sub[0])
		if c.exact && re.Min >= 2 {
			// x{2,3} contains xx: the first Min copies are one after the other.
			rep := []string{""}
			ok := true
			for i := 0; i < re.Min && ok; i++ {
				rep, ok = cross(rep, c.set)
			}
			if ok {
				if re.Min == re.Max {
					return exactOf(rep...)
				}
				return info{cnf: exactOf(rep...).asCNF()}
			}
		}
		return info{cnf: c.asCNF()}
	case syntax.OpConcat:
		return extractConcat(re.Sub)
	case syntax.OpAlternate:
		return extractAlternate(re.Sub)
	default: // star, any character, no match: nothing is required
		return info{}
	}
}

// classLiterals turns a small character class into the set of its characters.
func classLiterals(re *syntax.Regexp) info {
	n := 0
	for i := 0; i+1 < len(re.Rune); i += 2 {
		n += int(re.Rune[i+1]-re.Rune[i]) + 1
		if n > 4 {
			return info{}
		}
	}
	var set []string
	for i := 0; i+1 < len(re.Rune); i += 2 {
		for r := re.Rune[i]; r <= re.Rune[i+1]; r++ {
			if r >= 'A' && r <= 'Z' {
				r += 'a' - 'A'
			}
			set = append(set, string(r))
		}
	}
	return exactOf(dedupe(set)...)
}

func extractConcat(subs []*syntax.Regexp) info {
	cur := []string{""}
	var cnf [][]string
	allExact := true
	flush := func() {
		cnf = append(cnf, exactOf(cur...).asCNF()...)
	}
	for _, sub := range subs {
		x := extract(sub)
		if x.exact {
			if p, ok := cross(cur, x.set); ok {
				cur = p
				continue
			}
			allExact = false
			flush()
			cur = x.set
			continue
		}
		allExact = false
		flush()
		cnf = append(cnf, x.cnf...)
		cur = []string{""}
	}
	if allExact {
		return exactOf(cur...)
	}
	flush()
	return info{cnf: cnf}
}

func extractAlternate(subs []*syntax.Regexp) info {
	infos := make([]info, len(subs))
	allExact := true
	for i, s := range subs {
		infos[i] = extract(s)
		allExact = allExact && infos[i].exact
	}
	if allExact {
		var union []string
		for _, x := range infos {
			union = append(union, x.set...)
		}
		union = dedupe(union)
		if len(union) <= maxExact {
			return exactOf(union...)
		}
		return info{cnf: exactOf(union...).asCNF()}
	}
	// One branch is enough to match, so the requirement is that some branch's requirement holds: the union of one clause chosen
	// from each branch. A branch with nothing to offer makes the whole alternation require nothing.
	var union []string
	for _, x := range infos {
		cl := chooseClause(x.asCNF())
		if cl == nil {
			return info{}
		}
		union = append(union, cl...)
		if len(union) > maxClauseLits {
			return info{}
		}
	}
	return info{cnf: [][]string{dedupe(union)}}
}

func cross(a, b []string) ([]string, bool) {
	if len(a)*len(b) > maxExact {
		return nil, false
	}
	out := make([]string, 0, len(a)*len(b))
	for _, x := range a {
		for _, y := range b {
			s := x + y
			if len(s) > maxExactLen {
				return nil, false
			}
			out = append(out, s)
		}
	}
	return dedupe(out), true
}

func dedupe(in []string) []string {
	if len(in) < 2 {
		return in
	}
	seen := make(map[string]struct{}, len(in))
	out := in[:0:0]
	for _, s := range in {
		if _, ok := seen[s]; !ok {
			seen[s] = struct{}{}
			out = append(out, s)
		}
	}
	return out
}

// bestRun returns the longest run of ASCII bytes in s, cut to maxAnchor.
func bestRun(s string) string {
	best := ""
	for i := 0; i < len(s); {
		if s[i] >= utf8.RuneSelf {
			i++
			continue
		}
		j := i
		for j < len(s) && s[j] < utf8.RuneSelf {
			j++
		}
		if j-i > len(best) {
			best = s[i:j]
		}
		i = j
	}
	if len(best) > maxAnchor {
		best = best[:maxAnchor]
	}
	return best
}

// finalizeLits reduces every literal of a clause to its best ASCII run, lower case. It returns nil if any literal has no run of
// at least minAnchor bytes (that alternative could match without any usable literal, so the clause says nothing).
func finalizeLits(lits []string) []string {
	if len(lits) == 0 || len(lits) > maxClauseLits {
		return nil
	}
	out := make([]string, 0, len(lits))
	for _, l := range lits {
		r := strings.ToLower(bestRun(l))
		if len(r) < minAnchor {
			return nil
		}
		out = append(out, r)
	}
	return dropSuperstrings(dedupe(out))
}

// dropSuperstrings removes from a set of alternatives every one that contains another: if "bar" is in the text the clause holds,
// and "foobar" adds nothing. A smaller set is a cheaper index entry and a better key. Only done for sets small enough that the
// quadratic comparison is nothing.
func dropSuperstrings(lits []string) []string {
	if len(lits) < 2 || len(lits) > 64 {
		return lits
	}
	out := lits[:0:0]
	for i, a := range lits {
		redundant := false
		for j, b := range lits {
			if i != j && len(b) < len(a) && strings.Contains(a, b) {
				redundant = true
				break
			}
		}
		if !redundant {
			out = append(out, a)
		}
	}
	return out
}

// clauseQuality is the length of the shortest literal: a requirement is as selective as its weakest alternative.
func clauseQuality(cl []string) int {
	q := 1 << 30
	for _, l := range cl {
		if len(l) < q {
			q = len(l)
		}
	}
	return q
}

// chooseClause picks the most selective of the clauses (finalized), or nil if none is usable.
func chooseClause(cnf [][]string) []string {
	var best []string
	for _, cl := range cnf {
		f := finalizeLits(cl)
		if f == nil {
			continue
		}
		if best == nil || clauseQuality(f) > clauseQuality(best) || (clauseQuality(f) == clauseQuality(best) && len(f) < len(best)) {
			best = f
		}
	}
	return best
}

// bestClause picks the most selective of already finalized clauses.
func bestClause(clauses [][]string) []string {
	var best []string
	for _, f := range clauses {
		if best == nil || clauseQuality(f) > clauseQuality(best) || (clauseQuality(f) == clauseQuality(best) && len(f) < len(best)) {
			best = f
		}
	}
	return best
}
