// SPDX-License-Identifier: Apache-2.0

package apiguard

import (
	"strings"
)

// segClass is what a path segment looks like. A segment that looks like an identifier is a parameter however often it was seen;
// one that looks like a word is a literal, until enough different words have been seen in the same place.
type segClass uint8

const (
	scLiteral segClass = iota
	scInt
	scUUID
	scDate
	scHex
	scToken
	scID
)

var segClassName = [...]string{scLiteral: "", scInt: "{int}", scUUID: "{uuid}", scDate: "{date}", scHex: "{hex}", scToken: "{token}", scID: "{id}"}

// digitWords are the short words that contain a digit and are names, not identifiers (a path with /oauth2/ in it is not
// /{id}/).
var digitWords = map[string]bool{"oauth2": true, "oauth1": true, "2fa": true, "mfa2": true, "ipv4": true, "ipv6": true, "utf8": true,
	"http2": true, "http3": true, "sha1": true, "sha256": true, "sha512": true, "md5": true, "base64": true, "b2b": true, "b2c": true,
	"s3": true, "h264": true, "h265": true, "sso2": true, "webp2": true, "oidc1": true, "saml2": true, "p2p": true, "web3": true}

const maxLiteralSegment = 64

// classifySegment says what kind of thing a decoded path segment is. The order matters and is part of the format: the same path
// must be given the same template when a request is learned and when it is checked.
func classifySegment(s string) segClass {
	n := len(s)
	if n == 0 {
		return scLiteral
	}
	allDigits, allHex, hasDigit, hasUpper, hasLower, hasSep := true, true, false, false, false, false
	baseOK := true
	for i := 0; i < n; i++ {
		c := s[i]
		switch {
		case c >= '0' && c <= '9':
			hasDigit = true
		case c >= 'a' && c <= 'f':
			allDigits = false
			hasLower = true
		case c >= 'A' && c <= 'F':
			allDigits = false
			hasUpper = true
		case c >= 'g' && c <= 'z':
			allDigits, allHex = false, false
			hasLower = true
		case c >= 'G' && c <= 'Z':
			allDigits, allHex = false, false
			hasUpper = true
		case c == '-' || c == '_' || c == '.' || c == '+' || c == '=':
			allDigits, allHex = false, false
			hasSep = true
		default:
			allDigits, allHex, baseOK = false, false, false
		}
	}
	switch {
	case allDigits && n <= 19:
		return scInt
	case n == 36 && isUUID(s):
		return scUUID
	case n >= 10 && isDatePrefix(s):
		return scDate
	case allHex && n >= 8 && hasDigit:
		return scHex
	case baseOK && n >= 20 && hasUpper && hasLower && (hasDigit || hasSep):
		return scToken
	case baseOK && n >= 3 && hasDigit && !digitWords[strings.ToLower(s)] && !isVersionLike(s):
		return scID
	}
	return scLiteral
}

// isDatePrefix reports whether s is a date (2024-01-31) or starts like a date-time (2024-01-31T10:00:00Z).
func isDatePrefix(s string) bool {
	if len(s) < 10 || (len(s) > 10 && s[10] != 'T' && s[10] != 't') {
		return false
	}
	for i := 0; i < 10; i++ {
		switch i {
		case 4, 7:
			if s[i] != '-' {
				return false
			}
		default:
			if s[i] < '0' || s[i] > '9' {
				return false
			}
		}
	}
	return true
}

// isVersionLike reports whether s is a version such as v1, v2, v10 or v1.2.
func isVersionLike(s string) bool {
	if len(s) < 2 || (s[0] != 'v' && s[0] != 'V') {
		return false
	}
	for i := 1; i < len(s); i++ {
		if (s[i] < '0' || s[i] > '9') && s[i] != '.' {
			return false
		}
	}
	return true
}

// literalOK reports whether a segment can stand in a template as it is: short, printable ASCII, and without the characters that
// give a template its structure. Anything else is treated as an {id}, so a hostile segment can neither make a key that is too
// large nor one that reads as something else.
func literalOK(s string) bool {
	if len(s) > maxLiteralSegment {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c <= 0x20 || c >= 0x7f || c == '{' || c == '}' || c == '/' || c == '%' {
			return false
		}
	}
	return true
}

// collapsedSet is the set of path positions whose literals were so many and so seldom repeated that they are parameters.
type collapsedSet map[string]struct{}

// segmentClass is the class a segment takes in a template, given where it is. A literal at a collapsed position is an {id}.
func segmentClass(seg string, prefix []byte, collapsed collapsedSet) segClass {
	if c := classifySegment(seg); c != scLiteral {
		return c
	}
	if !literalOK(seg) {
		return scID
	}
	if len(collapsed) > 0 {
		if _, ok := collapsed[string(prefix)]; ok {
			return scID
		}
	}
	return scLiteral
}

// templateOf writes the template of a request path (the form it is learned and looked up in) after the method, into buf, and
// returns it. literals reports, for each literal segment, the prefix before it (as an offset into the template) and the segment,
// which is what the learner follows to see whether a position holds too many different words; it may be nil. ok is false for a
// path the learner does not follow (too many segments, an escape that does not decode).
func templateOf(method, path string, collapsed collapsedSet, buf []byte, visit func(prefix []byte, seg string)) (out []byte, ok bool) {
	var segs [MaxPathSegments]string
	n, ok := splitPath(path, segs[:])
	if !ok {
		return nil, false
	}
	buf = append(buf, method...)
	buf = append(buf, ' ')
	start := len(buf)
	if n == 0 {
		return append(buf, '/'), true
	}
	for i := 0; i < n; i++ {
		prefix := buf[start:]
		if len(prefix) == 0 {
			prefix = nil
		}
		c := segmentClass(segs[i], prefix, collapsed)
		buf = append(buf, '/')
		if c == scLiteral {
			if visit != nil {
				visit(buf[start:len(buf)-1], segs[i])
			}
			buf = append(buf, segs[i]...)
		} else {
			buf = append(buf, segClassName[c]...)
		}
	}
	return buf, true
}
