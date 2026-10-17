// SPDX-License-Identifier: Apache-2.0

package alert

import "unicode/utf8"

// cutMarker ends a string that Clean cut.
const cutMarker = "…"

// Clean makes a string that came from a visitor safe to write and to read back: invalid UTF-8 becomes U+FFFD; bytes
// below 0x20, 0x7f, the C1 controls, U+2028, U+2029 and the bidirectional controls become \xNN or \uNNNN escapes; a
// backslash becomes \\, so that an escape in the output cannot have come from the input. The result is at most max
// bytes: it is cut only when the whole of it does not fit, then on a rune and escape boundary and ended with "…".
// slog escapes JSON already; this defends a reader
// that decodes the line and writes the text somewhere else (OWASP Logging Cheat Sheet).
//
// A string that needs none of this and fits is returned as is, without allocating.
func Clean(s string, max int) string {
	if max <= 0 {
		return ""
	}
	if len(s) <= max && plain(s) {
		return s
	}
	b := make([]byte, 0, min(len(s), max)+8)
	// fit is the length of the output at the last piece boundary that leaves room for the marker: where a cut ends.
	fit := 0
	limit := max - len(cutMarker)
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		switch {
		case r == utf8.RuneError && size <= 1:
			b = append(b, "\uFFFD"...)
		case r == '\\':
			b = append(b, '\\', '\\')
		case r < 0x20 || r == 0x7f:
			b = append(b, '\\', 'x', hexDigit(r>>4), hexDigit(r))
		case r >= 0x80 && r <= 0x9f || r == 0x2028 || r == 0x2029 || isBidi(r):
			b = append(b, '\\', 'u', hexDigit(r>>12), hexDigit(r>>8), hexDigit(r>>4), hexDigit(r))
		default:
			b = append(b, s[i:i+size]...)
		}
		i += size
		if len(b) > max {
			// The whole output does not fit: end it at the last boundary with room for the marker.
			if limit < 0 {
				return "" // too small for even the marker
			}
			return string(append(b[:fit], cutMarker...))
		}
		if len(b) <= limit {
			fit = len(b)
		}
	}
	return string(b) // everything fits, so nothing is cut
}

// plain reports whether s is printable ASCII without a backslash.
func plain(s string) bool {
	for i := 0; i < len(s); i++ {
		if c := s[i]; c < 0x20 || c >= 0x7f || c == '\\' {
			return false
		}
	}
	return true
}

func isBidi(r rune) bool {
	switch {
	case r == 0x061c, r == 0x200e, r == 0x200f:
		return true
	case r >= 0x202a && r <= 0x202e:
		return true
	case r >= 0x2066 && r <= 0x2069:
		return true
	}
	return false
}

// hexDigit is the lower-case hex digit of the low four bits of v.
func hexDigit(v rune) byte { return "0123456789abcdef"[v&0xf] }
