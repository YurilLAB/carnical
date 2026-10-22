// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"bytes"
	"errors"
	"net/http"
	"strings"

	"golang.org/x/net/http/httpguts"
)

// PHP2Shell (CVE-2026-109618, CVE-2026-109619) covers memory-safety failures in PHP's handling of out-of-memory and
// fatal errors and of request-owned state retained across requests. Some demonstrated paths use session upload
// progress and disclose worker memory through a session cookie; other paths do not need either indicator. A fixed
// PHP is the only complete fix. These checks reduce exposure to the demonstrated upload and cookie patterns:
//
//   - the request: a multipart body with the field that turns on PHP's session upload progress is refused (rule
//     5000013). Few sites use the feature; one that does turns the check off with UploadPolicy.AllowUploadProgress.
//   - the response: a session cookie whose value is not a session id PHP could have made, which is what the leak looks
//     like in the demonstrated cookie leak, is withheld and answered 403 (rule 5000080), unless
//     ResponsePolicy.AllowBadSessionIDs. The same check withholds trailers; after headers have been sent, it aborts
//     the response instead of replacing its status, and cannot recall an already streamed body.
//
// Neither check proves a PHP runtime safe: a leak can have another carrier or look like a valid session id, and
// different fatal-error producers and stale-state consumers can reach code execution without these patterns.

// uploadProgressName is the field PHP reads as the key of an upload's progress, its session.upload_progress.name, in
// lower case. The name is compared as PHP has read it from the part's Content-Disposition.
const uploadProgressName = "php_session_upload_progress"

// uploadProgressField reports the upload progress field in anything a multipart parser could read as a part's headers
// (see headerBlocks). Ordinary headers require a whole Content-Disposition name parameter, so a filename or another
// header mentioning the marker is harmless. Ambiguous headers retain the conservative squeezed match below: PHP
// joins continuation lines, truncates at NUL and splits overlong lines into buffer fragments. Overlapping blocks are
// merged before either scan, so even a body that is all headers costs linear time and constant storage.
func uploadProgressField(body, delim []byte) bool {
	blocks := newHeaderBlocks(body, delim)
	from, to := 0, 0 // the stretch of overlapping blocks taken in so far
	for blocks.start >= 0 {
		start, head, _ := blocks.next()
		if start > to {
			if progressHeaders(body[from:to], delim) {
				return true
			}
			from = start
		}
		to = max(to, head)
	}
	return progressHeaders(body[from:to], delim)
}

// progressHeaders narrows only unambiguous CRLF headers. Anything outside that grammar uses the old conservative
// scan over the entire stretch; an ordinary prefix must not hide a marker in an unusual suffix. The 4 KiB line cap
// is below PHP's 5 KiB multipart buffer, whose fragments can introduce another header interpretation.
func progressHeaders(text, delim []byte) bool {
	found := false
	first := true
	for rest := text; len(rest) > 0; first = false {
		line, after, lf := bytes.Cut(rest, []byte("\n"))
		rest = after
		if len(line) > 4096 || bytes.IndexByte(line, 0) >= 0 || lf && !bytes.HasSuffix(line, []byte("\r")) {
			return squeezedHolds(text)
		}
		line = bytes.TrimSuffix(line, []byte("\r"))
		if first && len(line) == 0 { // a block can start just after a delimiter, before its CRLF
			continue
		}
		if first && (bytes.Equal(line, delim) || bytes.Equal(bytes.TrimSuffix(line, []byte("--")), delim)) {
			continue
		}
		key, value, colon := bytes.Cut(line, []byte(":"))
		if !colon || !httpguts.ValidHeaderFieldName(string(key)) || bytes.Contains(line, delim) {
			return squeezedHolds(text)
		}
		if bytes.EqualFold(key, []byte("Content-Disposition")) {
			match, clean := progressDisposition(value)
			if !clean {
				return squeezedHolds(text)
			}
			found = found || match
		}
	}
	return found
}

// progressDisposition reads whole parameters only in an ordinary disposition: a token type followed by token keys
// and bare tokens or closed quoted values. Escapes, malformed quotes and separator ambiguities are left to the
// conservative scan. Duplicate names are all checked rather than guessing which an application's parser will use.
func progressDisposition(value []byte) (found, clean bool) {
	typ, rest, _ := bytes.Cut(value, []byte(";"))
	if !httpguts.ValidHeaderFieldName(string(bytes.TrimSpace(typ))) {
		return false, false
	}
	for len(rest) > 0 {
		rest = bytes.TrimLeft(rest, " \t")
		key, after, equals := bytes.Cut(rest, []byte("="))
		if !equals || !httpguts.ValidHeaderFieldName(string(key)) {
			return false, false
		}
		after = bytes.TrimLeft(after, " \t")
		var name []byte
		if len(after) > 0 && (after[0] == '"' || after[0] == '\'') {
			quote := after[0]
			end := bytes.IndexByte(after[1:], quote)
			if end < 0 {
				return false, false
			}
			name, rest = after[1:1+end], bytes.TrimLeft(after[2+end:], " \t")
			if bytes.IndexByte(name, '\\') >= 0 || len(rest) > 0 && rest[0] != ';' {
				return false, false
			}
			if len(rest) > 0 {
				rest = rest[1:]
			}
		} else {
			name, rest, _ = bytes.Cut(after, []byte(";"))
			name = bytes.TrimRight(name, " \t")
			if !httpguts.ValidHeaderFieldName(string(name)) {
				return false, false
			}
		}
		if bytes.EqualFold(key, []byte("name")) && len(name) == len(uploadProgressName) && bytes.EqualFold(name, []byte(uploadProgressName)) {
			found = true
		}
	}
	return found, true
}

// progressBorder is, for each prefix of uploadProgressName, the length of its longest proper prefix that is also its
// suffix: where a match that fails after that prefix may go on from (Knuth, Morris and Pratt).
var progressBorder = func() []int {
	w := uploadProgressName
	border := make([]int, len(w))
	for i, k := 1, 0; i < len(w); i++ {
		for k > 0 && w[i] != w[k] {
			k = border[k-1]
		}
		if w[i] == w[k] {
			k++
		}
		border[i] = k
	}
	return border
}()

// squeezedHolds reports whether text holds uploadProgressName after dropping quotes, backslashes and C whitespace,
// folding ASCII case and dropping the rest of each physical line after a NUL. It deliberately overmatches ambiguous
// headers, including spellings PHP would not take for the field.
func squeezedHolds(text []byte) bool {
	w := uploadProgressName
	k := 0 // how much of the name the squeezed text read so far ends with
	for i := 0; i < len(text); i++ {
		c := text[i]
		switch c {
		case 0:
			for i+1 < len(text) && text[i+1] != '\n' {
				i++
			}
			continue
		case '"', '\'', '\\', ' ', '\t', '\r', '\n', '\v', '\f':
			continue
		}
		if 'A' <= c && c <= 'Z' {
			c += 'a' - 'A'
		}
		for k > 0 && c != w[k] {
			k = progressBorder[k-1]
		}
		if c == w[k] {
			if k++; k == len(w) {
				return true
			}
		}
	}
	return false
}

// MaxSessionCookies is the most names ResponsePolicy.SessionCookies may hold.
const MaxSessionCookies = 16

// SessionCookieName reports whether name can name a session cookie: a token (RFC 6265) of at most 64 bytes.
func SessionCookieName(name string) bool {
	return len(name) <= 64 && httpguts.ValidHeaderFieldName(name)
}

// errPHP2Shell is returned for a response whose PHP session cookie is not a session id.
var errPHP2Shell = errors.New("the application set a session cookie that is not a session id")

// maxSessionID is the longest session id PHP makes or accepts (PS_MAX_SID_LENGTH).
const maxSessionID = 256

// badSessionCookie reports a Set-Cookie of a PHP session cookie (PHPSESSID, or one of names, in any case) whose value
// is neither empty nor a session id: up to 256 letters, digits, '-' and ',', which PHP sends escaped as %2C. PHP makes
// session ids of those characters only and refuses any other as a visitor's; "deleted", which it sends to end a
// session, is one.
func badSessionCookie(h http.Header, names []string) bool {
	for _, line := range h["Set-Cookie"] {
		name, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		name = strings.TrimSpace(name)
		if !strings.EqualFold(name, "PHPSESSID") && !containsFold(names, name) {
			continue
		}
		value, _, _ = strings.Cut(value, ";")
		if !sessionID(strings.TrimSpace(value)) {
			return true
		}
	}
	return false
}

// sessionID reports whether v is empty or a session id as PHP sends one in its cookie.
func sessionID(v string) bool {
	n := 0
	for i := 0; i < len(v); i++ {
		switch c := v[i]; {
		case 'a' <= c && c <= 'z', 'A' <= c && c <= 'Z', '0' <= c && c <= '9', c == '-', c == ',':
		case c == '%' && i+2 < len(v) && v[i+1] == '2' && (v[i+2] == 'C' || v[i+2] == 'c'):
			i += 2
		default:
			return false
		}
		n++
	}
	return n <= maxSessionID
}

func containsFold(list []string, s string) bool {
	for _, v := range list {
		if strings.EqualFold(v, s) {
			return true
		}
	}
	return false
}
