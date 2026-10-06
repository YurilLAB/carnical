// SPDX-License-Identifier: Apache-2.0

package importers

import (
	"errors"
	"strings"
	"testing"
)

func TestTranslatePCRE(t *testing.T) {
	tests := []struct {
		name    string
		in      string
		want    string // the translation, when it is expected to succeed
		wantErr string // the reason code, when it is expected to be refused
	}{
		// Possessive quantifiers that mean the same as the greedy ones, because the rest cannot begin with what is repeated.
		{name: "possessive before a different literal", in: `a*+b`, want: `a*b`},
		{name: "possessive class escape before letters", in: `\s*+script`, want: `\s*script`},
		{name: "possessive at the end", in: `foo\s*+`, want: `foo\s*`},
		{name: "possessive before end anchor", in: `[^&]*+$`, want: `[^&]*$`},
		{name: "possessive plus before word boundary", in: `\w++\b`, want: `\w+\b`},
		{name: "possessive optional", in: `a?+b`, want: `a?b`},
		{name: "possessive with fixed count is a no-op", in: `a{3}+a`, want: `a{3}a`},
		{name: "possessive inside group followed by a different literal", in: `(?:a*+|b)c`, want: `(?:a*|b)c`},
		{name: "possessive in the library's own xss pattern", in: `<\s*+script\b|\bon(?:error|load)\s*+=`, want: `<\s*script\b|\bon(?:error|load)\s*=`},
		{name: "possessive class before alternation of literals", in: `[ \t]{0,8}+(?:id|whoami)`, want: `[ \t]{0,8}(?:id|whoami)`},
		// Atomic groups that cannot change the result.
		{name: "atomic group of fixed length", in: `(?>abc)d`, want: `(?:abc)d`},
		{name: "atomic alternation of one length", in: `(?>a|b)c`, want: `(?:a|b)c`},
		{name: "atomic group at the end", in: `x(?>a|ab)`, want: `x(?:a|ab)`},
		{name: "atomic repeat followed by different literal", in: `(?>a+)b`, want: `(?:a+)b`},
		// The class rewrite.
		{name: "dash after class escape", in: `[\w-.]+`, want: `[\w\-.]+`},
		{name: "dash after class escape then more", in: `[\d-_a]`, want: `[\d\-_a]`},
		{name: "plain class untouched", in: `[a-z0-9_.-]+`, want: `[a-z0-9_.-]+`},
		{name: "nothing to translate", in: `abc(d|e)+`, want: `abc(d|e)+`},

		// Cases that are NOT the same without the possessive quantifier, which must be refused.
		{name: "possessive before the same character", in: `a*+a`, wantErr: "possessive-not-exact"},
		{name: "possessive dot before a letter", in: `.*+x`, wantErr: "possessive-not-exact"},
		{name: "possessive space before space", in: `\s*+\s`, wantErr: "possessive-not-exact"},
		{name: "possessive class before overlapping class", in: `[a-f]++[d-z]`, wantErr: "possessive-not-exact"},
		{name: "possessive before optional overlap", in: `a*+a?b`, wantErr: "possessive-not-exact"},
		{name: "possessive before end anchor in multi-line mode", in: `(?m)a*+$`, wantErr: "possessive-not-exact"},
		{name: "possessive repeat of a group", in: `(?:ab)*+c`, wantErr: "possessive-not-exact"},
		{name: "possessive before group that may start the same", in: `a*+(?:a|b)`, wantErr: "possessive-not-exact"},
		{name: "possessive in a repeated group whose next round starts the same", in: `(?:a*+b?)*`, wantErr: "possessive-not-exact"},
		{name: "possessive before boundary when the atom spans both kinds", in: `.*+\b`, wantErr: "possessive-not-exact"},
		{name: "atomic alternation of different lengths", in: `(?>a|ab)c`, wantErr: "atomic-not-exact"},
		{name: "atomic repeat followed by the same character", in: `(?>a+)a`, wantErr: "atomic-not-exact"},
		// Syntax that has no exact translation at all.
		{name: "lookahead", in: `a(?=b)`, wantErr: "lookaround"},
		{name: "lookbehind", in: `(?<=a)b`, wantErr: "lookaround"},
		{name: "backreference", in: `(a)\1`, wantErr: "backreference"},
		{name: "extended flag", in: `(?x) a b`, wantErr: "x-flag"},
		{name: "recursion", in: `(?R)`, wantErr: "recursion"},
		{name: "unbalanced group", in: `(a`, wantErr: "unparsable"},
		{name: "Unicode escape beyond scalar range", in: `\x{110000}*+b`, wantErr: "unparsable"},
		{name: "Unicode escape overflowing rune", in: `\x{ffffffff}*+b`, wantErr: "unparsable"},
		{name: "Unicode surrogate escape", in: `\x{d800}*+b`, wantErr: "unparsable"},
		{name: "keep-out", in: `a\Kb`, wantErr: "lookaround"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := TranslatePCRE(tt.in)
			if tt.wantErr != "" {
				var re *RegexError
				if !errors.As(err, &re) {
					t.Fatalf("TranslatePCRE(%q) = %q, %v; want error %q", tt.in, got, err, tt.wantErr)
				}
				if re.Reason != tt.wantErr {
					t.Fatalf("TranslatePCRE(%q) reason = %q; want %q", tt.in, re.Reason, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("TranslatePCRE(%q) error: %v; want %q", tt.in, err, tt.want)
			}
			if got != tt.want {
				t.Fatalf("TranslatePCRE(%q) = %q; want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestCheckRegex(t *testing.T) {
	tests := []struct {
		name       string
		pattern    string
		flags      string
		max        int
		want       string
		wantReason string
		wantStat   string // "compiled", "translated" or "failed"
	}{
		{name: "plain", pattern: `^/wp-admin/[a-z]+\.php$`, wantStat: "compiled", want: `^/wp-admin/[a-z]+\.php$`},
		{name: "with flag", pattern: `select\s+from`, flags: "i", wantStat: "compiled", want: `select\s+from`},
		{name: "possessive translated", pattern: `<\s*+script`, wantStat: "translated", want: `<\s*script`},
		{name: "possessive not exact", pattern: `a*+a`, wantStat: "failed", wantReason: "possessive-not-exact"},
		{name: "lookahead", pattern: `a(?=b)`, wantStat: "failed", wantReason: "lookaround"},
		{name: "backreference", pattern: `(a)\1`, wantStat: "failed", wantReason: "backreference"},
		{name: "too long", pattern: strings.Repeat("a", 100), max: 50, wantStat: "failed", wantReason: "too-long"},
		{name: "not utf8", pattern: "a\xffb", wantStat: "failed", wantReason: "not-utf8"},
		{name: "unknown escape", pattern: `a\hb`, wantStat: "failed", wantReason: "escape:\\h"},
		{name: "unclosed bracket", pattern: `[a-z`, wantStat: "failed", wantReason: "bracket"},
		{name: "repeat too big", pattern: `a{2000}`, wantStat: "failed", wantReason: "too-complex"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := NewReport("test")
			got, err := r.CheckRegex(tt.pattern, tt.flags, tt.max)
			if r.Regex.Seen != 1 {
				t.Fatalf("Seen = %d, want 1", r.Regex.Seen)
			}
			switch tt.wantStat {
			case "compiled":
				if err != nil || got != tt.want || r.Regex.Compiled != 1 || r.Regex.Translated != 0 || r.Regex.Failed != 0 {
					t.Fatalf("got %q, %v, stats %+v", got, err, r.Regex)
				}
			case "translated":
				if err != nil || got != tt.want || r.Regex.Translated != 1 || r.Regex.Compiled != 0 {
					t.Fatalf("got %q, %v, stats %+v", got, err, r.Regex)
				}
			case "failed":
				var re *RegexError
				if !errors.As(err, &re) || re.Reason != tt.wantReason || r.Regex.Failed != 1 || r.Regex.FailReason[tt.wantReason] != 1 {
					t.Fatalf("got %q, %v, stats %+v; want reason %q", got, err, r.Regex, tt.wantReason)
				}
			}
		})
	}
}
