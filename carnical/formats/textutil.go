package formats

import (
	"bytes"
	"unicode"
	"unicode/utf8"
)

var bomUTF8 = []byte{0xEF, 0xBB, 0xBF}

// wideEncoding reports whether b starts like UTF-16 or UTF-32: a byte order mark, or the pattern of zero bytes that the encoding of
// an ASCII character gives (RFC 4627 section 3). Every text format here starts with an ASCII byte in a legitimate document, so a
// zero in the first or second byte is a body in a wide encoding, which is how a filter that reads bytes is made to see nothing.
func wideEncoding(b []byte) bool {
	n := len(b)
	if n >= 2 && (b[0] == 0xFE && b[1] == 0xFF || b[0] == 0xFF && b[1] == 0xFE) {
		return true
	}
	if n >= 4 && b[0] == 0 && b[1] == 0 && b[2] == 0xFE && b[3] == 0xFF {
		return true
	}
	if n >= 2 && (b[0] == 0) != (b[1] == 0) {
		return true // 00 xx (UTF-16BE) or xx 00 (UTF-16LE, UTF-32LE)
	}
	if n >= 4 && b[0] == 0 && b[1] == 0 && b[2] == 0 && b[3] != 0 {
		return true // 00 00 00 xx (UTF-32BE)
	}
	return false
}

// textStart checks what every text format needs before it is parsed: it is not UTF-16 or UTF-32, and it has no byte order mark. It
// returns the offset at which the document starts, and false if the request is refused or the body cannot be read as text.
func (f *finder) textStart(b []byte) (int, bool) {
	if wideEncoding(b) {
		f.hit(rWideEncoding, 0, dNone)
		return 0, false
	}
	if bytes.HasPrefix(b, bomUTF8) {
		if f.hit(rBOM, 0, dNone) {
			return 0, false
		}
		return len(bomUTF8), true
	}
	return 0, true
}

// firstInvalidUTF8 returns the offset of the first byte that is not part of a valid UTF-8 sequence, or -1.
func firstInvalidUTF8(b []byte) int {
	if utf8.Valid(b) {
		return -1
	}
	for i := 0; i < len(b); {
		if b[i] < utf8.RuneSelf {
			i++
			continue
		}
		r, n := utf8.DecodeRune(b[i:])
		if r == utf8.RuneError && n == 1 {
			return i
		}
		i += n
	}
	return -1
}

// foldRune reduces a rune so that two runes which a case-insensitive comparison would match give the same result. ASCII becomes lower
// case, and the non-ASCII runes whose case folding reaches ASCII (the Kelvin sign, the long s) become that letter, which is what
// Go's own JSON decoder does; other runes become the smallest of their case orbit.
func foldRune(r rune) rune {
	if r < utf8.RuneSelf {
		if 'A' <= r && r <= 'Z' {
			return r + 'a' - 'A'
		}
		return r
	}
	least := r
	for f := unicode.SimpleFold(r); f != r; f = unicode.SimpleFold(f) {
		if f < utf8.RuneSelf {
			if 'A' <= f && f <= 'Z' {
				f += 'a' - 'A'
			}
			return f
		}
		if f < least {
			least = f
		}
	}
	return least
}

func isHexDigit(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F'
}

func hexVal(c byte) rune {
	switch {
	case c >= 'a':
		return rune(c-'a') + 10
	case c >= 'A':
		return rune(c-'A') + 10
	}
	return rune(c - '0')
}

// hex4 reads four hex digits at b[i:].
func hex4(b []byte, i int) (rune, bool) {
	if i < 0 || i+4 > len(b) {
		return 0, false
	}
	var r rune
	for k := 0; k < 4; k++ {
		if !isHexDigit(b[i+k]) {
			return 0, false
		}
		r = r<<4 | hexVal(b[i+k])
	}
	return r, true
}
