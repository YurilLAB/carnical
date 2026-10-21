// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"errors"
	"net/http"
	"strings"

	"golang.org/x/net/http/httpguts"
)

// PHP2Shell (CVE-2026-109618, CVE-2026-109619) is the name of two memory-safety bugs in PHP's handling of an upload
// that reports its progress to the session, which end in code execution. The published exploit reads the PHP
// process's memory back through the session cookie. A fixed PHP is the only complete fix; until the application runs
// one, the edge checks both sides of the exchange, as Cloudflare's managed rules for it do:
//
//   - the request: a multipart body with the field that turns on PHP's session upload progress is refused (rule
//     5000013). Few sites use the feature; one that does turns the check off with UploadPolicy.AllowUploadProgress.
//   - the response: a session cookie whose value is not a session id PHP could have made, which is what the leak looks
//     like whatever request caused it, is withheld and answered 403 (rule 5000080), unless
//     ResponsePolicy.AllowBadSessionIDs.

// uploadProgressName is the field PHP reads as the key of an upload's progress, its session.upload_progress.name, in
// lower case. The name is compared as PHP has read it from the part's Content-Disposition.
const uploadProgressName = "php_session_upload_progress"

// uploadProgressField reports the upload progress field in anything a multipart parser could read as a part's headers
// (see headerBlocks). The text is read as PHP reads a header line, the rest of a line after a NUL dropped, and then
// squeezed: quotes, backslashes and white space, line ends included, are left out and letters are put in lower case.
// So a name PHP reads in quotes or bare, with escapes, or across the header lines it joins, is found, and so are a few
// spellings PHP would not take for the field, which no form sends. Blocks that overlap are read as one stretch, so no
// byte is read twice, and nothing is copied: a body that is all headers costs one pass.
func uploadProgressField(body, delim []byte) bool {
	blocks := newHeaderBlocks(body, delim)
	from, to := 0, 0 // the stretch of overlapping blocks taken in so far
	for blocks.start >= 0 {
		start, head, _ := blocks.next()
		if start > to {
			if squeezedHolds(body[from:to]) {
				return true
			}
			from = start
		}
		to = max(to, head)
	}
	return squeezedHolds(body[from:to])
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

// squeezedHolds reports whether text, squeezed as uploadProgressField says, holds uploadProgressName.
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
