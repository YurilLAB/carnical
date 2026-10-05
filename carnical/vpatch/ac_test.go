// SPDX-License-Identifier: Apache-2.0

package vpatch

import (
	"math/rand"
	"sort"
	"strings"
	"testing"
)

func scanAll(a *automaton, text string, n int) []int {
	seen := make([]uint32, n)
	got := a.scan(text, 1, seen, nil)
	out := make([]int, len(got))
	for i, p := range got {
		out[i] = int(p)
	}
	sort.Ints(out)
	return out
}

// naive is the definition: which literals occur in the text, folded as the scanner folds it.
func naive(lits []string, text string) []int {
	t := foldNonASCII(lowerASCII(text))
	var out []int
	for i, l := range lits {
		if strings.Contains(t, l) {
			out = append(out, i)
		}
	}
	return out
}

func TestAutomatonAgainstTheDefinition(t *testing.T) {
	r := rand.New(rand.NewSource(7))
	alpha := []string{"a", "b", "c", "k", "s", "-", "/", "é"}
	for trial := 0; trial < 3000; trial++ {
		var lits []string
		seen := map[string]bool{}
		for i, n := 0, 1+r.Intn(25); i < n; i++ {
			var b strings.Builder
			for j, m := 0, 1+r.Intn(5); j < m; j++ {
				b.WriteString(alpha[r.Intn(len(alpha))])
			}
			if l := b.String(); !seen[l] {
				seen[l] = true
				lits = append(lits, l)
			}
		}
		a := newAutomaton(lits)
		for j := 0; j < 20; j++ {
			var b strings.Builder
			for k, m := 0, r.Intn(40); k < m; k++ {
				b.WriteString([]string{"a", "b", "c", "A", "B", "K", "S", "k", "s", "-", "/", "é", "K", "ſ", "x"}[r.Intn(15)])
			}
			text := b.String()
			got, want := scanAll(a, text, len(lits)), naive(lits, text)
			if len(got) != len(want) {
				t.Fatalf("literals %q, text %q: got %v, want %v", lits, text, got, want)
			}
			for i := range got {
				if got[i] != want[i] {
					t.Fatalf("literals %q, text %q: got %v, want %v", lits, text, got, want)
				}
			}
		}
	}
}

func TestAutomatonRows(t *testing.T) {
	tests := []struct {
		name string
		lits []string
		text string
		want []int
	}{
		{"nested literals are all found", []string{"he", "she", "his", "hers"}, "ushers", []int{0, 1, 3}},
		{"overlap", []string{"aaa"}, "aaaa", []int{0}},
		{"a literal that is a suffix of another", []string{"abcd", "bcd", "cd"}, "xabcd", []int{0, 1, 2}},
		{"none", []string{"abc"}, "ab", nil},
		{"folds the text", []string{"select"}, "UnIoN SeLeCt", []int{0}},
		{"Kelvin sign is k", []string{"kk"}, "KK", []int{0}},
		{"long s is s", []string{"ss"}, "ſſ", []int{0}},
		{"empty text", []string{"a"}, "", nil},
		{"no literals", nil, "abc", nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			a := newAutomaton(tc.lits)
			got := scanAll(a, tc.text, len(tc.lits))
			if len(got) != len(tc.want) {
				t.Fatalf("got %v, want %v", got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Fatalf("got %v, want %v", got, tc.want)
				}
			}
		})
	}
}

// A pattern is reported once per stamp, and again under a new stamp.
func TestAutomatonStamps(t *testing.T) {
	a := newAutomaton([]string{"ab"})
	seen := make([]uint32, 1)
	if got := a.scan("abab", 1, seen, nil); len(got) != 1 {
		t.Fatalf("%v", got)
	}
	if got := a.scan("ab", 1, seen, nil); len(got) != 0 {
		t.Fatalf("reported twice under one stamp: %v", got)
	}
	if got := a.scan("ab", 2, seen, nil); len(got) != 1 {
		t.Fatalf("not reported under a new stamp: %v", got)
	}
}

func FuzzAutomaton(f *testing.F) {
	f.Add("abc", "xxABCxx")
	f.Add("kk", "KK")
	f.Fuzz(func(t *testing.T, lit, text string) {
		lit = strings.ToLower(bestRun(lit))
		if lit == "" {
			return
		}
		a := newAutomaton([]string{lit, lit + "x"})
		got := scanAll(a, text, 2)
		want := naive([]string{lit, lit + "x"}, text)
		if len(got) != len(want) {
			t.Fatalf("%q in %q: %v vs %v", lit, text, got, want)
		}
	})
}
