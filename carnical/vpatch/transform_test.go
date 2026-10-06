// SPDX-License-Identifier: Apache-2.0

package vpatch

import (
	"strings"
	"testing"
	"unicode"
)

func TestTransforms(t *testing.T) {
	t.Run("invalid scalar cannot alias a byte", func(t *testing.T) {
		for _, cp := range []rune{-1, -256, 0xD800, 0x110000} {
			if got := string(appendCP(nil, cp, false)); got != "\uFFFD" {
				t.Fatalf("appendCP(%d) = %q", cp, got)
			}
		}
	})
	bs := string(rune(92)) // a backslash, spelled so that no source tool turns "\u" followed by hex digits into the character
	tests := []struct {
		name string
		fn   string
		in   string
		want string
	}{
		// urldecode1: once, plus stays, bad escapes stay
		{"urldecode1 space", "urldecode1", "a%20b", "a b"},
		{"urldecode1 plus stays", "urldecode1", "a+b", "a+b"},
		{"urldecode1 once only", "urldecode1", "%2541", "%41"},
		{"urldecode1 bad escape", "urldecode1", "%zz%4", "%zz%4"},
		{"urldecode1 trailing percent", "urldecode1", "100%", "100%"},
		{"urldecode1 IIS unicode", "urldecode1", "%u0041%U0042", "AB"},
		{"urldecode1 IIS below 0x100 is one byte", "urldecode1", "%u00c0%u00af", "\xc0\xaf"},
		{"urldecode1 does not fold full width", "urldecode1", "%uff1c", "＜"},
		{"urldecode1 plain text", "urldecode1", "/a/b", "/a/b"},
		// urldecode: until it settles, plus is a space, overlong and full-width fold
		{"urldecode double", "urldecode", "%2541", "A"},
		{"urldecode plus", "urldecode", "a+b", "a b"},
		{"urldecode overlong slash", "urldecode", "..%c0%af..", "../.."},
		{"urldecode overlong via IIS", "urldecode", "%u00c0%u00af", "/"},
		{"urldecode full width folds", "urldecode", "%uff1cscript%uff1e", "<script>"},
		{"urldecode raw full width folds", "urldecode", "＜script＞", "<script>"},
		{"urldecode dot dot slash triple encoded", "urldecode", "%252e%252e%252f", "../"},
		{"urldecode is bounded at four rounds", "urldecode", "%2525252541", "%41"},
		{"urldecode bad escape", "urldecode", "%zz", "%zz"},
		{"urldecode plain", "urldecode", "/a/b.php", "/a/b.php"},
		// lowercase
		{"lowercase", "lowercase", "AbC/Σ", "abc/Σ"},
		{"lowercase no-op", "lowercase", "abc", "abc"},
		// normpath
		{"normpath collapses", "normpath", "/a/./b//c/../d", "/a/b/d"},
		{"normpath keeps a climb above the root", "normpath", "/../a", "/../a"},
		{"normpath two climbs", "normpath", "/a/../../b", "/../b"},
		{"normpath keeps a trailing slash", "normpath", "/a/b/", "/a/b/"},
		{"normpath trailing dot dot", "normpath", "/a/b/..", "/a/"},
		{"normpath relative", "normpath", "a/b", "a/b"},
		{"normpath leaves the query alone", "normpath", "/x/../y?p=../../z//q", "/y?p=../../z//q"},
		{"normpath empty", "normpath", "", ""},
		{"normpath root", "normpath", "/", "/"},
		{"normpath backslash is not a separator", "normpath", "/a\\..\\b", "/a\\..\\b"},
		{"normpathwin backslash", "normpathwin", "..\\..\\x", "../../x"},
		{"normpathwin mixed", "normpathwin", "/a\\b/../c", "/a/c"},
		// htmldecode
		{"htmldecode named", "htmldecode", "&lt;script&gt;", "<script>"},
		{"htmldecode decimal", "htmldecode", "&#60;&#0000060;", "<<"},
		{"htmldecode hex without semicolon", "htmldecode", "&#x3c&#X3C;", "<<"},
		{"htmldecode twice", "htmldecode", "&amp;lt;", "<"},
		{"htmldecode no code point zero", "htmldecode", "&#0;", "&#0;"},
		{"htmldecode no surrogate", "htmldecode", "&#xD800;", "&#xD800;"},
		{"htmldecode plain ampersand", "htmldecode", "a & b &x", "a & b &x"},
		// jsdecode
		{"jsdecode hex", "jsdecode", `\x3cscript\x3e`, "<script>"},
		{"jsdecode unicode", "jsdecode", bs + "u003c", "<"},
		{"jsdecode unicode full width folds", "jsdecode", bs + "uff1c", "<"},
		{"jsdecode octal", "jsdecode", `\074\0`, "<\x00"},
		{"jsdecode letters", "jsdecode", `a\nb\tc`, "a\nb\tc"},
		{"jsdecode other char", "jsdecode", `\q\/`, "q/"},
		{"jsdecode braces", "jsdecode", bs + "u{3c}", "<"},
		{"jsdecode surrogate pair", "jsdecode", bs + "uD83D" + bs + "uDE00", "\U0001F600"},
		{"jsdecode trailing backslash", "jsdecode", `abc\`, `abc\`},
		{"jsdecode no escape", "jsdecode", "abc", "abc"},
		// cssdecode
		{"cssdecode hex and space", "cssdecode", `\3c script`, "<script"},
		{"cssdecode six digits", "cssdecode", `\00003cx`, "<x"},
		{"cssdecode hex ends at a non-hex", "cssdecode", `\3cscript`, "<script"},
		{"cssdecode other char", "cssdecode", `\q`, "q"},
		{"cssdecode line continuation", "cssdecode", "a\\\nb", "ab"},
		{"cssdecode none", "cssdecode", "abc", "abc"},
		// utf8unicode
		{"utf8unicode two bytes", "utf8unicode", "é", "%u00e9"},
		{"utf8unicode four bytes", "utf8unicode", "\U0001F600", "%ud83d%ude00"},
		{"utf8unicode ascii", "utf8unicode", "abc", "abc"},
		{"utf8unicode invalid bytes pass", "utf8unicode", "a\xc0\xafb", "a\xc0\xafb"},
		// whitespace and nulls
		{"nulls", "nulls", "a\x00b\x00", "ab"},
		{"nulls none", "nulls", "ab", "ab"},
		{"compressspace", "compressspace", "a   b\t\nc", "a b c"},
		{"compressspace single spaces unchanged", "compressspace", " a b ", " a b "},
		{"compressspace no-break space byte", "compressspace", "a\xa0\xa0b", "a b"},
		{"removespace", "removespace", "a b\tc\n", "abc"},
		{"trim", "trim", " \t a b \n", "a b"},
		{"trim none", "trim", "ab", "ab"},
		// base64decode
		{"base64decode", "base64decode", "dW5pb24gc2VsZWN0", "union select"},
		{"base64decode unpadded", "base64decode", "YWJjZGVmZw", "abcdefg"},
		{"base64decode padded", "base64decode", "YWJjZGVmZw==", "abcdefg"},
		{"base64decode url alphabet", "base64decode", "PDw_Pz8-Pg", "<<???>>"},
		{"base64decode too short", "base64decode", "YWJj", "YWJj"},
		{"base64decode not base64", "base64decode", "not base64!!!!", "not base64!!!!"},
		{"base64decode wrong length", "base64decode", "YWJjZGVmZ", "YWJjZGVmZ"},
		// comments
		{"comments block", "comments", "sel/**/ect a/*x*/b", "select ab"},
		{"comments unterminated keeps the rest", "comments", "a /* b", "a  b"},
		{"comments dash dash needs a space", "comments", "a--b", "a--b"},
		{"comments dash dash comment", "comments", "a -- b\nc", "a \nc"},
		{"comments hash", "comments", "a # b\nc", "a \nc"},
		{"comments executable", "comments", "/*!50000union*/ select", "union select"},
		{"comments trailing dash dash", "comments", "1 or 1=1 --", "1 or 1=1 "},
		{"comments none", "comments", "plain", "plain"},
		{"replacecomments", "replacecomments", "sel/**/ect", "sel ect"},
		{"replacecomments leaves line comments", "replacecomments", "a -- b # c", "a -- b # c"},
		{"replacecomments unterminated", "replacecomments", "a/*", "a "},
		// cmdline
		{"cmdline quotes", "cmdline", `c"a"t /etc/passwd`, "cat/etc/passwd"},
		{"cmdline caret and case", "cmdline", "CA^T   /ETC/passwd", "cat/etc/passwd"},
		{"cmdline separators", "cmdline", "a,b;c\td", "a b c d"},
		{"cmdline space before slash and paren", "cmdline", "cat /x ( y", "cat/x( y"},
		{"cmdline backslash", "cmdline", `w\h\o\ami`, "whoami"},
		{"cmdline none", "cmdline", "cat", "cat"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			fn, ok := transforms[tc.fn]
			if !ok {
				t.Fatalf("no transform %q", tc.fn)
			}
			if got := fn(tc.in); got != tc.want {
				t.Fatalf("%s(%q) = %q, want %q", tc.fn, tc.in, got, tc.want)
			}
		})
	}
}

// TestEveryDocumentedTransformExists ties the table to signature.go's list.
func TestEveryDocumentedTransformExists(t *testing.T) {
	for _, name := range []string{"urldecode1", "urldecode", "lowercase", "normpath", "normpathwin", "htmldecode", "jsdecode", "cssdecode",
		"utf8unicode", "nulls", "compressspace", "removespace", "trim", "base64decode", "comments", "replacecomments", "cmdline"} {
		if transforms[name] == nil {
			t.Errorf("transform %q is documented and missing", name)
		}
	}
}

// A plain value must pass through every transform without a copy: that is what keeps an ordinary request cheap.
func TestTransformsDoNotAllocateForPlainValues(t *testing.T) {
	plain := "/wp-content/plugins/contact-form-7/includes/x.php"
	for name, fn := range transforms {
		allocs := testing.AllocsPerRun(100, func() { _ = fn(plain) })
		if allocs != 0 {
			t.Errorf("%s allocates %.0f times on a plain value", name, allocs)
		}
		if got := fn(plain); got != plain {
			t.Errorf("%s changed a plain value: %q", name, got)
		}
	}
}

// Transforms are bounded: their output is never more than a small multiple of their input, and none panics.
func TestTransformsAreBoundedOnHostileInput(t *testing.T) {
	inputs := []string{
		strings.Repeat("%", 1000), strings.Repeat("%u", 1000), strings.Repeat("&#", 1000), strings.Repeat(`\`, 1001), strings.Repeat("/*", 1000),
		strings.Repeat("../", 1000), strings.Repeat("\xc0", 1000), strings.Repeat("é", 1000), strings.Repeat("&amp;", 1000),
		strings.Repeat("%25", 1000), "\x00\xff\xfe", strings.Repeat("-", 1000), strings.Repeat("a b", 1000), strings.Repeat(`\u{`, 500),
	}
	for name, fn := range transforms {
		for _, in := range inputs {
			out := fn(in)
			if len(out) > 8*len(in)+16 {
				t.Errorf("%s: %d bytes in, %d out", name, len(in), len(out))
			}
		}
	}
}

// TestFoldingAssumption proves the one fact the literal index rests on for case folding: the only characters outside ASCII that
// Unicode simple folding makes equal to an ASCII letter are the Kelvin sign and the long s, which the scanner folds itself.
func TestFoldingAssumption(t *testing.T) {
	for r := rune(0); r <= unicode.MaxRune; r++ {
		if r < 0x80 {
			continue
		}
		for f := unicode.SimpleFold(r); f != r; f = unicode.SimpleFold(f) {
			if f < 0x80 && ((f >= 'a' && f <= 'z') || (f >= 'A' && f <= 'Z')) && r != 0x212A && r != 0x17F {
				t.Fatalf("U+%04X folds to ASCII %q and the scanner does not know it", r, f)
			}
		}
	}
	if !hasFoldingNonASCII("xKy") || foldNonASCII("Kſ") != "ks" {
		t.Fatal("the scanner's own folding is wrong")
	}
}
