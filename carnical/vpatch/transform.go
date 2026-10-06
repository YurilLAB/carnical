// SPDX-License-Identifier: Apache-2.0

package vpatch

import (
	"encoding/base64"
	"fmt"
	"html"
	"strings"
	"unicode/utf8"
)

// A transformFn rewrites one value before an operator looks at it. Every transform returns its argument unchanged (the same
// string, no copy) when there is nothing to do, so that the common case, a plain ASCII value, costs one scan and no allocation,
// and so that "did anything change" is a cheap comparison.
//
// The meanings follow the reference engine the signature library was built and verified against (the Site Firewall's
// Transforms class), because a signature is only as good as the agreement between the author's idea of "urldecode" and the
// engine's. Where that engine is stricter than ModSecurity, so is this one, and the differences are listed in docs/vpatch.md.
type transformFn func(string) string

// transforms is the table of every transform signature.go documents. A name that is not here makes the signature fail to load.
var transforms = map[string]transformFn{
	"urldecode1":      urlDecode1,
	"urldecode":       urlDecode,
	"lowercase":       lowerASCII,
	"normpath":        func(s string) string { return normPath(s, false) },
	"normpathwin":     func(s string) string { return normPath(s, true) },
	"htmldecode":      htmlDecode,
	"jsdecode":        jsDecode,
	"cssdecode":       cssDecode,
	"utf8unicode":     utf8Unicode,
	"nulls":           removeNulls,
	"compressspace":   compressSpace,
	"removespace":     removeSpace,
	"trim":            trimSpace,
	"base64decode":    base64Decode,
	"comments":        removeComments,
	"replacecomments": replaceComments,
	"cmdline":         cmdLine,
}

func isHex(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F'
}

func unhex(c byte) byte {
	switch {
	case c >= '0' && c <= '9':
		return c - '0'
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10
	default:
		return c - 'A' + 10
	}
}

func isHex4(s string) bool {
	return len(s) >= 4 && isHex(s[0]) && isHex(s[1]) && isHex(s[2]) && isHex(s[3])
}

func hexVal(s string) rune {
	var r rune
	for i := 0; i < len(s); i++ {
		r = r<<4 | rune(unhex(s[i]))
	}
	return r
}

// appendCP appends a code point as bytes. Below 0x80 it is the byte; a surrogate or a value past U+10FFFF is U+FFFD; the rest is
// UTF-8. With fold, the full-width ASCII forms (U+FF01 to U+FF5E) and the ideographic space fold to the ASCII they imitate, as
// Windows "best fit" conversion does, so that a back end on such a stack reading them as ASCII is not a way round a signature.
func appendCP(b []byte, cp rune, fold bool) []byte {
	if cp >= 0 && cp < 0x80 {
		return append(b, byte(cp))
	}
	if fold {
		if cp >= 0xFF01 && cp <= 0xFF5E {
			return append(b, byte(cp-0xFEE0))
		}
		if cp == 0x3000 {
			return append(b, ' ')
		}
	}
	if (cp >= 0xD800 && cp <= 0xDFFF) || cp > 0x10FFFF {
		return append(b, 0xEF, 0xBF, 0xBD)
	}
	return utf8.AppendRune(b, cp)
}

// foldOverlong rewrites the overlong UTF-8 forms of ASCII (C0 xx, C1 xx, E0 80 xx, E0 81 xx, F0 80 80 xx, F0 80 81 xx), which no
// honest client sends and some back ends (old IIS and Java stacks) still read as the ASCII character, and the raw UTF-8
// full-width ASCII forms and ideographic space, which Windows turns into ASCII. "%c0%af" is a slash.
func foldOverlong(s string) string {
	need := false
	for i := 0; i < len(s) && !need; i++ {
		switch s[i] {
		case 0xC0, 0xC1, 0xE0, 0xE3, 0xEF, 0xF0:
			need = true
		}
	}
	if !need {
		return s
	}
	var b []byte
	for i := 0; i < len(s); i++ {
		c := s[i]
		var out byte
		n := 0
		switch {
		case (c == 0xC0 || c == 0xC1) && i+1 < len(s) && s[i+1] >= 0x80 && s[i+1] <= 0xBF:
			out, n = (c-0xC0)<<6|s[i+1]&0x3F, 2
		case c == 0xE0 && i+2 < len(s) && (s[i+1] == 0x80 || s[i+1] == 0x81) && s[i+2] >= 0x80 && s[i+2] <= 0xBF:
			out, n = (s[i+1]-0x80)<<6|s[i+2]&0x3F, 3
		case c == 0xF0 && i+3 < len(s) && s[i+1] == 0x80 && (s[i+2] == 0x80 || s[i+2] == 0x81) && s[i+3] >= 0x80 && s[i+3] <= 0xBF:
			out, n = (s[i+2]-0x80)<<6|s[i+3]&0x3F, 4
		case c == 0xEF && i+2 < len(s) && s[i+1] == 0xBC && s[i+2] >= 0x81 && s[i+2] <= 0xBF:
			out, n = s[i+2]-0x60, 3
		case c == 0xEF && i+2 < len(s) && s[i+1] == 0xBD && s[i+2] >= 0x80 && s[i+2] <= 0x9E:
			out, n = s[i+2]-0x20, 3
		case c == 0xE3 && i+2 < len(s) && s[i+1] == 0x80 && s[i+2] == 0x80:
			out, n = ' ', 3
		}
		if n == 0 {
			if b != nil {
				b = append(b, c)
			}
			continue
		}
		if b == nil {
			b = make([]byte, 0, len(s))
			b = append(b, s[:i]...)
		}
		b = append(b, out)
		i += n - 1
	}
	if b == nil {
		return s
	}
	return string(b)
}

// percentU rewrites the IIS spelling %uHHHH (either case of u): a value below 0x100 is one byte, as IIS reads it (so %u00c0%u00af
// is a slash), a larger one is its UTF-8 bytes, with the full-width folding when fold is set.
func percentU(s string, fold bool) string {
	var b []byte
	for i := 0; i < len(s); i++ {
		if s[i] == '%' && i+5 < len(s) && (s[i+1] == 'u' || s[i+1] == 'U') && isHex4(s[i+2:]) {
			if b == nil {
				b = make([]byte, 0, len(s))
				b = append(b, s[:i]...)
			}
			if cp := hexVal(s[i+2 : i+6]); cp >= 0 && cp < 0x100 {
				b = append(b, byte(cp))
			} else {
				b = appendCP(b, cp, fold)
			}
			i += 5
			continue
		}
		if b != nil {
			b = append(b, s[i])
		}
	}
	if b == nil {
		return s
	}
	return string(b)
}

// percentDecode is one round of %HH decoding, with '+' read as a space if plus is set. A '%' that does not start a valid escape
// stays.
func percentDecode(s string, plus bool) string {
	i := 0
	for i < len(s) && s[i] != '%' && !(plus && s[i] == '+') {
		i++
	}
	if i == len(s) {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	b.WriteString(s[:i])
	for ; i < len(s); i++ {
		switch c := s[i]; {
		case c == '+' && plus:
			b.WriteByte(' ')
		case c == '%' && i+2 < len(s) && isHex(s[i+1]) && isHex(s[i+2]):
			b.WriteByte(unhex(s[i+1])<<4 | unhex(s[i+2]))
			i += 2
		default:
			b.WriteByte(c)
		}
	}
	return b.String()
}

// urlDecode1 decodes %HH and %uHHHH exactly once and never looks at the result again: the text as a server decodes it once.
// Where urlDecode erases an encoded percent sign on its second pass ("/%2577ebui" becomes "/webui"), this keeps what a
// signature written against the once-decoded form sees ("/%77ebui"). A '+' stays, overlong and full-width forms are not folded,
// and a bad escape such as "%zz" stays.
func urlDecode1(s string) string {
	i := strings.IndexByte(s, '%')
	if i < 0 {
		return s
	}
	if strings.IndexByte(s, 'u') < 0 && strings.IndexByte(s, 'U') < 0 {
		return percentDecode(s, false)
	}
	var b []byte
	for ; i < len(s); i++ {
		if s[i] != '%' {
			if b != nil {
				b = append(b, s[i])
			}
			continue
		}
		var out byte
		cp := rune(-1)
		n := 0
		switch {
		case i+5 < len(s) && (s[i+1] == 'u' || s[i+1] == 'U') && isHex4(s[i+2:]):
			cp, n = hexVal(s[i+2:i+6]), 6
		case i+2 < len(s) && isHex(s[i+1]) && isHex(s[i+2]):
			out, n = unhex(s[i+1])<<4|unhex(s[i+2]), 3
		}
		if n == 0 {
			if b != nil {
				b = append(b, '%')
			}
			continue
		}
		if b == nil {
			b = make([]byte, 0, len(s))
			b = append(b, s[:i]...)
		}
		switch {
		case cp < 0:
			b = append(b, out)
		case cp < 0x100:
			b = append(b, byte(cp))
		default:
			b = appendCP(b, cp, false)
		}
		i += n - 1
	}
	if b == nil {
		return s
	}
	return string(b)
}

// urlDecode decodes up to four passes while the text keeps changing, so double, triple and quadruple encoding are seen through.
// A pass reads the IIS %uHHHH spelling, then %HH and '+' (a space), then folds overlong and full-width forms to the ASCII they
// stand for.
func urlDecode(s string) string {
	if strings.IndexByte(s, '%') < 0 && strings.IndexByte(s, '+') < 0 {
		return foldOverlong(s)
	}
	for i := 0; i < 4; i++ {
		t := s
		if strings.IndexByte(t, '%') >= 0 && (strings.IndexByte(t, 'u') >= 0 || strings.IndexByte(t, 'U') >= 0) {
			t = percentU(t, true)
		}
		t = foldOverlong(percentDecode(t, true))
		if len(t) == len(s) && t == s {
			break
		}
		s = t
	}
	return s
}

// lowerASCII lower-cases A to Z and nothing else. Non-ASCII letters keep their case: the engine promises ASCII lower case, and
// anything wider would change the length of some values.
func lowerASCII(s string) string {
	for i := 0; i < len(s); i++ {
		if c := s[i]; c >= 'A' && c <= 'Z' {
			var b strings.Builder
			b.Grow(len(s))
			b.WriteString(s[:i])
			for ; i < len(s); i++ {
				c := s[i]
				if c >= 'A' && c <= 'Z' {
					c += 'a' - 'A'
				}
				b.WriteByte(c)
			}
			return b.String()
		}
	}
	return s
}

// normPath collapses repeated slashes, "." segments and ".." segments, the way a file system or a web server resolves a path. Only
// the part before the first '?' or '#' is touched, because a query string is not a path: "?file=../x" must reach the operator
// as written. A ".." that would climb above the root is kept, so that a signature for "../" still sees the attempt; a trailing
// slash is kept, since "/a/b/" and "/a/b" are different requests to many servers. win also treats '\' as a separator.
func normPath(s string, win bool) string {
	end := len(s)
	if q := strings.IndexAny(s, "?#"); q >= 0 {
		end = q
	}
	head, tail := s[:end], s[end:]
	if win && strings.IndexByte(head, '\\') >= 0 {
		head = strings.ReplaceAll(head, "\\", "/")
	} else if !needsNormPath(head) {
		return s
	}
	rooted := strings.HasPrefix(head, "/")
	last := head
	if i := strings.LastIndexByte(head, '/'); i >= 0 {
		last = head[i+1:]
	}
	trailing := last == "" || last == "." || last == ".."
	out := make([]string, 0, 8)
	for _, seg := range strings.Split(head, "/") {
		switch seg {
		case "", ".":
		case "..":
			if n := len(out); n > 0 && out[n-1] != ".." {
				out = out[:n-1]
			} else {
				out = append(out, "..")
			}
		default:
			out = append(out, seg)
		}
	}
	var b strings.Builder
	b.Grow(len(s))
	if rooted {
		b.WriteByte('/')
	}
	b.WriteString(strings.Join(out, "/"))
	if trailing && len(out) > 0 {
		b.WriteByte('/')
	}
	b.WriteString(tail)
	return b.String()
}

// needsNormPath is the cheap test that lets normPath return its argument untouched.
func needsNormPath(p string) bool {
	if strings.IndexByte(p, '/') < 0 {
		return false
	}
	if strings.Contains(p, "//") || strings.Contains(p, "/./") || strings.Contains(p, "/../") {
		return true
	}
	return strings.HasSuffix(p, "/.") || strings.HasSuffix(p, "/..") || strings.HasPrefix(p, "./") || strings.HasPrefix(p, "../")
}

// htmlDecode resolves HTML character references up to three times: numeric ones with or without the closing semicolon and any
// number of leading zeros, and the named ones of HTML5. A numeric reference to nothing real (zero, a surrogate, past U+10FFFF)
// is left as written.
func htmlDecode(s string) string {
	for i := 0; i < 3; i++ {
		if strings.IndexByte(s, '&') < 0 {
			return s
		}
		t := htmlNumeric(s)
		if strings.IndexByte(t, '&') >= 0 {
			t = htmlNamed(t)
		}
		if len(t) == len(s) && t == s {
			return s
		}
		s = t
	}
	return s
}

// htmlNamed resolves the named references (&lt; &amp; and the old ones that need no semicolon). A numeric reference is not touched
// here: htmlNumeric has decided which of those mean anything.
func htmlNamed(s string) string {
	var b strings.Builder
	changed := false
	for i := 0; i < len(s); i++ {
		if s[i] == '&' && i+1 < len(s) && (s[i+1] >= 'a' && s[i+1] <= 'z' || s[i+1] >= 'A' && s[i+1] <= 'Z') {
			j := i + 1
			for j < len(s) && j-i <= 32 && (s[j] >= 'a' && s[j] <= 'z' || s[j] >= 'A' && s[j] <= 'Z' || s[j] >= '0' && s[j] <= '9') {
				j++
			}
			if j < len(s) && s[j] == ';' {
				j++
			}
			if dec := html.UnescapeString(s[i:j]); dec != s[i:j] {
				if !changed {
					changed = true
					b.Grow(len(s))
					b.WriteString(s[:i])
				}
				b.WriteString(dec)
				i = j - 1
				continue
			}
		}
		if changed {
			b.WriteByte(s[i])
		}
	}
	if !changed {
		return s
	}
	return b.String()
}

// htmlNumeric resolves &#NNN; and &#xHHH; (the semicolon optional).
func htmlNumeric(s string) string {
	var b []byte
	for i := 0; i < len(s); i++ {
		if s[i] == '&' && i+2 < len(s) && s[i+1] == '#' {
			if end, cp, ok := numericRef(s, i); ok {
				if cp < 1 || cp > 0x10FFFF || (cp >= 0xD800 && cp <= 0xDFFF) {
					if b != nil {
						b = append(b, s[i:end]...)
					}
				} else {
					if b == nil {
						b = make([]byte, 0, len(s))
						b = append(b, s[:i]...)
					}
					b = appendCP(b, cp, false)
				}
				i = end - 1
				continue
			}
		}
		if b != nil {
			b = append(b, s[i])
		}
	}
	if b == nil {
		return s
	}
	return string(b)
}

// numericRef parses the character reference at s[i:] ("&#", an optional x, digits, an optional semicolon). cp is -1 if there are
// more digits than any code point has.
func numericRef(s string, i int) (end int, cp rune, ok bool) {
	j := i + 2
	hex := false
	if j < len(s) && (s[j] == 'x' || s[j] == 'X') {
		hex = true
		j++
	}
	start := j
	for j < len(s) && s[j] == '0' {
		j++
	}
	k := j
	for k < len(s) && (hex && isHex(s[k]) || !hex && s[k] >= '0' && s[k] <= '9') {
		k++
	}
	if k == start {
		return 0, 0, false
	}
	digits := s[j:k]
	switch {
	case len(digits) == 0:
		cp = 0
	case hex && len(digits) <= 6:
		cp = hexVal(digits)
	case !hex && len(digits) <= 7:
		for _, d := range []byte(digits) {
			cp = cp*10 + rune(d-'0')
		}
	default:
		cp = -1
	}
	end = k
	if end < len(s) && s[end] == ';' {
		end++
	}
	return end, cp, true
}

// jsDecode resolves JavaScript string escapes: \uHHHH (with surrogate pairs), \u{H...}, \xHH, octal (\0 to \377), the single
// letter escapes (\n \t and so on), and any other escaped character to itself. A code point written as \u is folded to ASCII if it
// is a full-width form. A lone backslash at the end stays.
func jsDecode(s string) string {
	i := strings.IndexByte(s, '\\')
	if i < 0 {
		return s
	}
	b := make([]byte, 0, len(s))
	b = append(b, s[:i]...)
	for ; i < len(s); i++ {
		c := s[i]
		if c != '\\' || i+1 >= len(s) {
			b = append(b, c)
			continue
		}
		d := s[i+1]
		rest := s[i+2:]
		switch {
		case d == 'u' && len(rest) >= 10 && (rest[0] == 'd' || rest[0] == 'D') && strings.IndexByte("89abAB", rest[1]) >= 0 &&
			isHex(rest[2]) && isHex(rest[3]) && rest[4] == '\\' && rest[5] == 'u' && (rest[6] == 'd' || rest[6] == 'D') &&
			strings.IndexByte("cdefCDEF", rest[7]) >= 0 && isHex(rest[8]) && isHex(rest[9]):
			hi, lo := hexVal(rest[:4]), hexVal(rest[6:10])
			b = appendCP(b, 0x10000+(hi-0xD800)<<10+(lo-0xDC00), false)
			i += 11
		case d == 'u' && len(rest) >= 3 && rest[0] == '{' && isHex(rest[1]):
			k := 1
			for k < len(rest) && k <= 6 && isHex(rest[k]) {
				k++
			}
			if k < len(rest) && rest[k] == '}' {
				b = appendCP(b, hexVal(rest[1:k]), true)
				i += 2 + k
				break
			}
			b = append(b, 'u')
			i++
		case d == 'u' && isHex4(rest):
			b = appendCP(b, hexVal(rest[:4]), true)
			i += 5
		case d == 'x' && len(rest) >= 2 && isHex(rest[0]) && isHex(rest[1]):
			b = append(b, unhex(rest[0])<<4|unhex(rest[1]))
			i += 3
		case d >= '0' && d <= '7':
			v := int(d - '0')
			n, more := 1, 2
			if d >= '4' {
				more = 1
			}
			for n <= more && n-1 < len(rest) && rest[n-1] >= '0' && rest[n-1] <= '7' {
				v = v*8 + int(rest[n-1]-'0')
				n++
			}
			b = append(b, byte(v))
			i += n
		default:
			switch d {
			case 'a':
				b = append(b, 7)
			case 'b':
				b = append(b, 8)
			case 'f':
				b = append(b, 12)
			case 'n':
				b = append(b, 10)
			case 'r':
				b = append(b, 13)
			case 't':
				b = append(b, 9)
			case 'v':
				b = append(b, 11)
			default:
				b = append(b, d)
			}
			i++
		}
	}
	return string(b)
}

// cssDecode resolves CSS escapes: a backslash and one to six hex digits (and one white-space character that ends them) is a code
// point, a backslash before a newline is a line continuation and vanishes, and a backslash before anything else is that character.
func cssDecode(s string) string {
	i := strings.IndexByte(s, '\\')
	if i < 0 {
		return s
	}
	b := make([]byte, 0, len(s))
	b = append(b, s[:i]...)
	for ; i < len(s); i++ {
		c := s[i]
		if c != '\\' || i+1 >= len(s) {
			b = append(b, c)
			continue
		}
		if isHex(s[i+1]) {
			j := i + 1
			var r rune
			for n := 0; n < 6 && j < len(s) && isHex(s[j]); n++ {
				r = r<<4 | rune(unhex(s[j]))
				j++
			}
			switch {
			case j+1 < len(s) && s[j] == '\r' && s[j+1] == '\n':
				j += 2
			case j < len(s) && (s[j] == ' ' || s[j] == '\t' || s[j] == '\r' || s[j] == '\n' || s[j] == '\f'):
				j++
			}
			b = appendCP(b, r, true)
			i = j - 1
			continue
		}
		switch s[i+1] {
		case '\r':
			i++
			if i+1 < len(s) && s[i+1] == '\n' {
				i++
			}
		case '\n', '\f':
			i++
		default:
			b = append(b, s[i+1])
			i++
		}
	}
	return string(b)
}

// utf8Unicode writes every multi-byte UTF-8 character as %uHHHH (lower-case hex, a surrogate pair above U+FFFF), the form
// urlDecode reads back, so that a character written as UTF-8, as %uHHHH and as full-width ASCII all arrive at the same text.
// ASCII and bytes that are not valid UTF-8 pass through (urlDecode folds the overlong forms).
func utf8Unicode(s string) string {
	high := false
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x80 {
			high = true
			break
		}
	}
	if !high {
		return s
	}
	var b []byte
	for i := 0; i < len(s); {
		c := s[i]
		if c < 0x80 {
			if b != nil {
				b = append(b, c)
			}
			i++
			continue
		}
		r, size := utf8.DecodeRuneInString(s[i:])
		if r == utf8.RuneError && size <= 1 {
			if b != nil {
				b = append(b, c)
			}
			i++
			continue
		}
		if b == nil {
			b = make([]byte, 0, len(s)+len(s)/2)
			b = append(b, s[:i]...)
		}
		if r > 0xFFFF {
			v := r - 0x10000
			b = fmt.Appendf(b, "%%u%04x%%u%04x", 0xD800+(v>>10), 0xDC00+(v&0x3FF))
		} else {
			b = fmt.Appendf(b, "%%u%04x", r)
		}
		i += size
	}
	if b == nil {
		return s
	}
	return string(b)
}

func removeNulls(s string) string {
	i := strings.IndexByte(s, 0)
	if i < 0 {
		return s
	}
	b := make([]byte, 0, len(s))
	for j := 0; j < len(s); j++ {
		if s[j] != 0 {
			b = append(b, s[j])
		}
	}
	return string(b)
}

// isWS is white space as SQL, shells and HTML parsers see it, plus the Latin-1 no-break space byte.
func isWS(c byte) bool {
	return c == ' ' || c == '\t' || c == '\n' || c == '\v' || c == '\f' || c == '\r' || c == 0xA0
}

// compressSpace turns every run of white space into one space.
func compressSpace(s string) string {
	need := false
	for i := 0; i < len(s); i++ {
		if isWS(s[i]) && (s[i] != ' ' || (i+1 < len(s) && isWS(s[i+1]))) {
			need = true
			break
		}
	}
	if !need {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	space := false
	for i := 0; i < len(s); i++ {
		if isWS(s[i]) {
			if !space {
				b.WriteByte(' ')
			}
			space = true
			continue
		}
		space = false
		b.WriteByte(s[i])
	}
	return b.String()
}

func removeSpace(s string) string {
	i := 0
	for i < len(s) && !isWS(s[i]) {
		i++
	}
	if i == len(s) {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	b.WriteString(s[:i])
	for ; i < len(s); i++ {
		if !isWS(s[i]) {
			b.WriteByte(s[i])
		}
	}
	return b.String()
}

func isTrim(c byte) bool {
	return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\v' || c == '\f'
}

func trimSpace(s string) string {
	i, j := 0, len(s)
	for i < j && isTrim(s[i]) {
		i++
	}
	for j > i && isTrim(s[j-1]) {
		j--
	}
	return s[i:j]
}

// base64Decode decodes a value that is entirely valid base64 (standard or URL alphabet, padding optional, white space ignored,
// at least eight characters) and returns anything else untouched. A value that is not base64 is not an error: most values are not.
func base64Decode(s string) string {
	t := removeSpace(s)
	if len(t) < 8 {
		return s
	}
	end := len(t)
	for end > 0 && t[end-1] == '=' {
		end--
	}
	if len(t)-end > 2 {
		return s
	}
	for i := 0; i < end; i++ {
		c := t[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '+' || c == '/' || c == '-' || c == '_') {
			return s
		}
	}
	core := strings.NewReplacer("-", "+", "_", "/").Replace(t[:end])
	if len(core)%4 == 1 {
		return s
	}
	out, err := base64.RawStdEncoding.DecodeString(core)
	if err != nil || len(out) == 0 {
		return s
	}
	return string(out)
}

// stripComments is the scanner shared by removeComments and replaceComments.
//
//   - A block comment is removed, or replaced by one space. An unterminated one is not trusted to swallow the rest: only its
//     opening marker goes, so the text after it is still inspected.
//   - A MySQL executable comment (slash star bang ...) runs as SQL, so its content is kept and only the markers go.
//   - "-- " and "#" comments run to the end of the line. A "--" that is not followed by white space is not a comment in MySQL,
//     so it is kept. Only removeComments (block false) treats these as comments.
func stripComments(s string, block bool, with string) string {
	if !strings.Contains(s, "/*") && (block || (!strings.Contains(s, "--") && !strings.Contains(s, "#"))) {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	closeAt, noClose := -1, false
	for i := 0; i < len(s); {
		c := s[i]
		switch {
		case c == '/' && i+1 < len(s) && s[i+1] == '*':
			end := -1
			if !noClose {
				if closeAt < i+2 {
					if f := strings.Index(s[i+2:], "*/"); f < 0 {
						noClose = true
					} else {
						closeAt = i + 2 + f
					}
				}
				if !noClose {
					end = closeAt
				}
			}
			if end < 0 {
				b.WriteString(with)
				i += 2
				continue
			}
			if i+2 < len(s) && s[i+2] == '!' {
				body := s[i+3 : end]
				k := 0
				for k < len(body) && k < 6 && body[k] >= '0' && body[k] <= '9' {
					k++
				}
				b.WriteString(with)
				b.WriteString(body[k:])
				b.WriteString(with)
			} else {
				b.WriteString(with)
			}
			i = end + 2
		case c == '-' && !block:
			run := 0
			for i+run < len(s) && s[i+run] == '-' {
				run++
			}
			after := i + run
			if run >= 2 && (after >= len(s) || s[after] == ' ' || s[after] == '\t' || s[after] == '\n' || s[after] == '\r' || s[after] == '\v' || s[after] == '\f' || s[after] == 0) {
				b.WriteString(strings.Repeat("-", run-2))
				i = after
				for i < len(s) && s[i] != '\r' && s[i] != '\n' {
					i++
				}
				continue
			}
			b.WriteString(s[i:after])
			i = after
		case c == '#' && !block:
			for i < len(s) && s[i] != '\r' && s[i] != '\n' {
				i++
			}
		default:
			b.WriteByte(c)
			i++
		}
	}
	return b.String()
}

// removeComments removes block, "--" and "#" comments (block comments leave nothing behind).
func removeComments(s string) string { return stripComments(s, false, "") }

// replaceComments replaces every block comment with one space, which is how a SQL parser sees it. Line comments are left alone.
func replaceComments(s string) string {
	if !strings.Contains(s, "/*") {
		return s
	}
	return stripComments(s, true, " ")
}

// cmdLine is the CRS transformation of the same name. It deletes backslashes, quotes and carets (c"a"t and ca^t are cat), turns
// commas, semicolons, spaces, tabs, carriage returns and newlines into one space, removes the space that comes right before
// '/' or '(', and lower-cases, so that the ways a shell tolerates a disguised command all give the plain command.
func cmdLine(s string) string {
	need := false
	for i := 0; i < len(s) && !need; i++ {
		switch c := s[i]; {
		case c == '"' || c == '\'' || c == '\\' || c == '^' || c == ',' || c == ';' || c == '\t' || c == '\r' || c == '\n' || c >= 'A' && c <= 'Z':
			need = true
		case c == ' ':
			if i+1 < len(s) && (s[i+1] == ' ' || s[i+1] == '/' || s[i+1] == '(' || s[i+1] == ',' || s[i+1] == ';' || s[i+1] == '\t' || s[i+1] == '\r' || s[i+1] == '\n') {
				need = true
			}
		}
	}
	if !need {
		return s
	}
	b := make([]byte, 0, len(s))
	pending := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '"' || c == '\'' || c == '\\' || c == '^':
		case c == ' ' || c == ',' || c == ';' || c == '\t' || c == '\r' || c == '\n':
			pending = true
		case c == '/' || c == '(':
			pending = false
			b = append(b, c)
		default:
			if pending {
				b = append(b, ' ')
				pending = false
			}
			if c >= 'A' && c <= 'Z' {
				c += 'a' - 'A'
			}
			b = append(b, c)
		}
	}
	if pending {
		b = append(b, ' ')
	}
	return string(b)
}
