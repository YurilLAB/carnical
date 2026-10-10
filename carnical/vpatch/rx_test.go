// SPDX-License-Identifier: Apache-2.0

package vpatch

import (
	"fmt"
	"math/rand"
	"regexp/syntax"
	"sort"
	"strings"
	"testing"
)

// matchRx compiles with compileRx and reports whether every program matches the input, as the engine does (including the byte
// view for patterns that need it).
func matchRx(t *testing.T, pattern, flags, input string) bool {
	t.Helper()
	p, err := compileRx(pattern, flags)
	if err != nil {
		t.Fatalf("compileRx(%q): %v", pattern, err)
	}
	in := input
	if p.byteMode {
		in = latin1ToUTF8(input)
	}
	for _, re := range p.res {
		if !re.MatchString(in) {
			return false
		}
	}
	return true
}

func TestRegexTranslation(t *testing.T) {
	tests := []struct {
		name    string
		pattern string
		flags   string
		input   string
		want    bool
	}{
		{"plain", `a+b`, "", "xaab", true},
		{"plain no", `a+b`, "", "xb", false},
		{"possessive plus", `a++b`, "", "aab", true},
		{"possessive star", `a*+b`, "", "b", true},
		{"possessive optional", `a?+b`, "", "ab", true},
		{"possessive braces", `a{2,3}+b`, "", "aab", true},
		{"possessive is a superset of PCRE (documented)", `a++a`, "", "aa", true},
		{"a literal plus after an escape is not possessive", `\++b`, "", "++b", true},
		{"lazy is kept", `a+?b`, "", "aab", true},
		{"atomic group", `(?>a+)b`, "", "aab", true},
		{"end of text with Z accepts a final newline", `abc\Z`, "", "abc\n", true},
		{"end of text with Z needs the end", `abc\Z`, "", "abcd", false},
		{"end of text with z is exact", `abc\z`, "", "abc\n", false},
		{"start of text", `\Aabc`, "", "abc", true},
		{"start of text no", `\Aabc`, "", "xabc", false},
		{"dollar accepts a final newline", `abc$`, "", "abc\n", true},
		{"dollar needs the end", `abc$`, "", "abc\nx", false},
		{"dollar in multi-line mode is the end of a line", `abc$`, "m", "abc\nx", true},
		{"dollar with an inline m flag", `(?m)abc$`, "", "abc\nx", true},
		{"dollar inside a class is a dollar", `[$]x`, "", "$x", true},
		{"escaped dollar", `a\$`, "", "a$", true},
		{"comment group", `a(?#note)b`, "", "ab", true},
		{"inline case flag", `(?i)abc`, "", "ABC", true},
		{"scoped case flag", `(?i:a)b`, "", "Ab", true},
		{"scoped case flag no", `(?i:a)b`, "", "AB", false},
		{"flag i", `abc`, "i", "ABC", true},
		{"flag s", `a.b`, "s", "a\nb", true},
		{"dot without s", `a.b`, "", "a\nb", false},
		{"named group", `(?<n>a)b`, "", "ab", true},
		{"python named group", `(?P<n>a)b`, "", "ab", true},
		{"hex escape", `\x41`, "", "A", true},
		{"short hex escape", `\x4`, "", "\x04", true},
		{"escape e", `\e`, "", "\x1b", true},
		{"control escape", `\cA`, "", "\x01", true},
		{"backspace in a class", `[\b]`, "", "\x08", true},
		{"quoted literal", `\Qa.b\E`, "", "a.b", true},
		{"quoted literal does not mean a dot", `\Qa.b\E`, "", "axb", false},
		{"repeat bound above 1000 is widened", `a{0,4096}b`, "", "b", true},
		{"repeat bound above 1000 widened keeps the minimum", `a{2,4096}b`, "", "ab", false},
		{"literal brace", `a{b`, "", "a{b", true},
		{"literal brace comma", `a{,3}`, "", "a{,3}", true},
		{"high byte escape is a byte", `\xc0\xaf`, "", "..\xc0\xaf..", true},
		{"high byte escape is not a code point", `\xc0\xaf`, "", "À¯", false},
		{"high byte range", `[\x80-\xff]{2}`, "", "a\x90\xa0", true},
		{"bytes in a pattern with a high byte escape", "é\\xc0", "", "\xc3\xa9\xc0", true},
		{"class with a leading bracket", `[]a]+`, "", "]a", true},
		{"posix class", `[[:digit:]]+`, "", "12", true},
		{"unicode property", `\p{L}+`, "", "ab", true},
		{"alternation", `foo|bar`, "", "xbar", true},
		// the lookahead idioms with an exact translation
		{"start-anchored lookaheads: all hold", `\A(?=[\s\S]*?foo)(?=[\s\S]*?bar)[\s\S]*?baz`, "", "barfoobaz", true},
		{"start-anchored lookaheads: one missing", `\A(?=[\s\S]*?foo)(?=[\s\S]*?bar)[\s\S]*?baz`, "", "foobaz", false},
		{"start-anchored lookaheads: the rest is missing", `\A(?=[\s\S]*?foo)[\s\S]*?baz`, "", "foobar", false},
		{"start-anchored length", `\A(?=[\s\S]{4}\z)[\s\S]*?x`, "", "abcx", true},
		{"start-anchored length wrong", `\A(?=[\s\S]{4}\z)[\s\S]*?x`, "", "abcdx", false},
		{"start-anchored with only lookaheads", `\A(?=[\s\S]*?foo)(?=[\s\S]*?bar)`, "", "foo bar", true},
		{"start-anchored with a flag prefix", `(?i)\A(?=[\s\S]*?foo)[\s\S]*?bar`, "", "FOO BAR", true},
		{"redundant one-class lookahead", `x(?=[a-z])(?:cat|curl)`, "", "xcat", true},
		{"redundant one-class lookahead no", `x(?=[a-z])(?:cat|curl)`, "", "xCAT", false},
		{"redundant one-class lookahead in a branch", `(?:a(?=[a-z])bc|zz)`, "", "abc", true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := matchRx(t, tc.pattern, tc.flags, tc.input); got != tc.want {
				t.Fatalf("%q on %q: %v, want %v", tc.pattern, tc.input, got, tc.want)
			}
		})
	}
}

func TestRegexRejections(t *testing.T) {
	tests := []struct {
		pattern string
		flags   string
		reason  string
	}{
		{`a(?=b)`, "", "lookahead"},
		{`a(?!b)`, "", "negative lookahead"},
		{`(?<=a)b`, "", "lookbehind"},
		{`(?<!a)b`, "", "lookbehind"},
		{`(a)\1`, "", "back-reference"},
		{`(?<n>a)\k<n>`, "", "back-reference"},
		{`(a)\g1`, "", "back-reference"},
		{`(?P<n>a)(?P=n)`, "", "back-reference"},
		{`(?R)`, "", "recursion"},
		{`(?|a|b)`, "", "branch reset"},
		{`(?(1)a|b)`, "", "conditional"},
		{`(?x) a b`, "", "extended"},
		{`(*SKIP)a`, "", "verb"},
		{`a\Gb`, "", "\\G"},
		{`a\Kb`, "", "\\K"},
		{`\R`, "", "\\R"},
		{`\h+`, "", "\\h"},
		{`a{2000}`, "", "RE2 limit"},
		{`x(?=[a-z])y*`, "", "can be empty"},
		{`x(?=[a-z])[a-z0-9]`, "", "other characters"},
		{`x(?=[a-z])`, "", "can be empty"},
		{`\A(?=a)b|c`, "", "alternation"},
		{`(`, "", "not valid"},
		{`a`, "z", "flag"},
		{strings.Repeat("a", maxPatternLen+1), "", "over the limit"},
		{`(?'n'a)`, "", "quoted group name"},
	}
	for _, tc := range tests {
		t.Run(tc.pattern[:min(len(tc.pattern), 30)]+tc.reason, func(t *testing.T) {
			_, err := compileRx(tc.pattern, tc.flags)
			if err == nil {
				t.Fatalf("%q compiled", tc.pattern)
			}
			if !strings.Contains(err.Error(), tc.reason) {
				t.Fatalf("%q: reason %q does not mention %q", tc.pattern, err, tc.reason)
			}
		})
	}
}

// TestRegexProgramSizeLimit: a pattern that compiles to a huge program is refused, not run.
func TestRegexProgramSizeLimit(t *testing.T) {
	if _, err := compileRx(`(?:(?:a{1000}){1000})`, ""); err == nil {
		t.Fatal("a million-instruction expression compiled")
	}
	// Go's regexp has no DFA: an alternation whose branches stay alive together costs its whole program on every byte. The
	// largest expression in the shipped feeds compiles to about 6,500 instructions; one past the limit is refused.
	var branches, shared []string
	for i := 0; i < 1000; i++ {
		branches = append(branches, fmt.Sprintf("x%dy%dz", i*7919%1000, i))
		shared = append(shared, fmt.Sprintf("a%04dz", i))
	}
	if _, err := compileRx(strings.Join(branches, "|"), ""); err == nil || !strings.Contains(err.Error(), "instructions") {
		t.Fatalf("a thousand-branch alternation of more than 8,000 instructions: %v", err)
	}
	// The parser factors branches that share their start, so the same number of words with common prefixes stays small.
	if _, err := compileRx(strings.Join(shared, "|"), ""); err != nil {
		t.Fatal(err)
	}
}

func clauseOf(t *testing.T, pattern, flags string) []string {
	t.Helper()
	p, err := compileRx(pattern, flags)
	if err != nil {
		t.Fatalf("%q: %v", pattern, err)
	}
	out := append([]string(nil), p.anchors...)
	sort.Strings(out)
	return out
}

func TestRequiredLiterals(t *testing.T) {
	tests := []struct {
		pattern string
		flags   string
		want    []string // nil: no usable literal
	}{
		{`abc`, "", []string{"abc"}},
		{`ABC`, "", []string{"abc"}},
		{`abc`, "i", []string{"abc"}},
		{`(?i)Abc`, "", []string{"abc"}},
		{`foo|bar`, "", []string{"bar", "foo"}},
		{`foo.*barbaz`, "", []string{"barbaz"}},
		{`^POST\z`, "", []string{"post"}},
		{`colou?r`, "", []string{"color", "colour"}},
		{`\.{2,3}/`, "", []string{".."}},
		{`a+bcd`, "", []string{"bcd"}},
		{`(?:ab|c)xyz`, "", []string{"abxyz", "cxyz"}},
		{`é\.php`, "", []string{".php"}},
		{`wp-content/plugins/[a-z]+/x\.php`, "", []string{"wp-content/plugins/"}},
		{`.*`, "", nil},
		{`[a-z]+`, "", nil},
		{`a`, "", nil},
		{`(?i)kk`, "", []string{"kk"}},
		{`x*abc`, "", []string{"abc"}},
		{`(?:foo)?bar`, "", []string{"bar"}},
		{`foo|foobar`, "", []string{"foo"}},
		{`foo|[a-z]+`, "", nil},
		{`\bunion\b.{0,40}?\bselect\b`, "", []string{"select"}}, // the longer of two required words is the better key
	}
	for _, tc := range tests {
		t.Run(tc.pattern+"/"+tc.flags, func(t *testing.T) {
			got := clauseOf(t, tc.pattern, tc.flags)
			if strings.Join(got, ",") != strings.Join(tc.want, ",") {
				t.Fatalf("got %v, want %v", got, tc.want)
			}
		})
	}
}

// randRegex builds a random expression over a tiny alphabet from the constructs the extractor understands, and some it does not.
func randRegex(r *rand.Rand, depth int) string {
	atoms := []string{"a", "b", "ab", "abc", "k", "s", "A", ".", "[ab]", "[a-c]", `\.`, "-", "ks", "é"}
	if depth <= 0 {
		return atoms[r.Intn(len(atoms))]
	}
	switch r.Intn(9) {
	case 0:
		return randRegex(r, depth-1) + randRegex(r, depth-1)
	case 1:
		return "(?:" + randRegex(r, depth-1) + "|" + randRegex(r, depth-1) + ")"
	case 2:
		return "(?:" + randRegex(r, depth-1) + ")?"
	case 3:
		return "(?:" + randRegex(r, depth-1) + ")*"
	case 4:
		return "(?:" + randRegex(r, depth-1) + ")+"
	case 5:
		return "(?:" + randRegex(r, depth-1) + "){2,3}"
	case 6:
		return "(" + randRegex(r, depth-1) + ")"
	case 7:
		return randRegex(r, depth-1) + randRegex(r, depth-1) + randRegex(r, depth-1)
	}
	return atoms[r.Intn(len(atoms))]
}

// TestRequiredLiteralsAreNecessary is the soundness property the index rests on: whenever an expression matches a text, every
// clause the extractor reports has one of its literals in the text (folded the way the scanner folds it). It is checked on random
// expressions and random texts over a small alphabet, so that matches are frequent, with case folding, the two non-ASCII
// characters that fold to ASCII letters, and non-ASCII text.
func TestRequiredLiteralsAreNecessary(t *testing.T) {
	r := rand.New(rand.NewSource(42))
	alphabet := []string{"a", "b", "c", "A", "B", "k", "K", "s", "S", "K", "ſ", ".", "-", "é", "É", "ab", "abc"}
	matches, anchored := 0, 0
	for i := 0; i < 4000; i++ {
		pat := randRegex(r, 3)
		flags := ""
		if r.Intn(2) == 0 {
			flags = "i"
		}
		p, err := compileRx(pat, flags)
		if err != nil {
			continue
		}
		// the full set of clauses, not only the chosen one
		ast, err := syntax.Parse(prefixFlags(flags)+pat, syntax.Perl)
		if err != nil {
			t.Fatalf("%q: %v", pat, err)
		}
		clauses := extractClauses(ast)
		if len(clauses) == 0 {
			continue
		}
		anchored++
		for j := 0; j < 60; j++ {
			var b strings.Builder
			for k, n := 0, 1+r.Intn(8); k < n; k++ {
				b.WriteString(alphabet[r.Intn(len(alphabet))])
			}
			text := b.String()
			if !p.res[0].MatchString(text) {
				continue
			}
			matches++
			for _, cl := range clauses {
				found := false
				for _, lit := range cl {
					if strings.Contains(foldedScan(text), lit) {
						found = true
					}
				}
				if !found {
					t.Fatalf("pattern %q (flags %q) matches %q but none of its required literals %v is in it", pat, flags, text, cl)
				}
			}
		}
	}
	if matches < 500 || anchored < 200 {
		t.Fatalf("the property was barely exercised: %d matches over %d anchored expressions", matches, anchored)
	}
	t.Logf("%d matching texts checked against %d anchored random expressions", matches, anchored)
}

func prefixFlags(f string) string {
	if f == "" {
		return ""
	}
	return "(?" + f + ")"
}

// foldedScan is the text as the automaton sees it: ASCII folded, and the Kelvin sign and long s read as k and s.
func foldedScan(s string) string { return foldNonASCII(lowerASCII(s)) }
