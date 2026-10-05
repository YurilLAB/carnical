// SPDX-License-Identifier: Apache-2.0

package shield

import (
	"crypto/tls"
	"net/http"
	"slices"
	"strconv"
	"strings"
)

// A botnet spread over thousands of addresses in many countries still runs one or a few programs, and those programs
// make requests that look alike: the same client software, the same set of headers, the same TLS settings, the same
// target. So the detector counts requests by what they look like as well as by where they come from. A fingerprint here
// is a hash of the parts of a request that a client program decides and that do not change from one request to the
// next; a path template is the target with its variable parts (numbers, identifiers, query values) taken out.

// fingerprint returns the request's fingerprint and a short readable label for reports.
func fingerprint(r *http.Request) (uint64, string) {
	var b strings.Builder
	b.Grow(256)
	b.WriteString(r.Method)
	b.WriteByte('|')
	b.WriteString(strconv.Itoa(r.ProtoMajor))
	b.WriteByte('|')
	if t := r.TLS; t != nil {
		b.WriteString(strconv.Itoa(int(t.Version)))
		b.WriteByte(',')
		b.WriteString(strconv.Itoa(int(t.CipherSuite)))
		b.WriteByte(',')
		b.WriteString(t.NegotiatedProtocol)
	}
	b.WriteByte('|')
	// Which headers are present (net/http does not keep their order), the first 32 in sorted order. The server's header
	// size limit bounds how many there can be.
	names := make([]string, 0, len(r.Header))
	for k := range r.Header {
		names = append(names, k)
	}
	slices.Sort(names)
	for _, n := range names[:min(len(names), 32)] {
		b.WriteString(n)
		b.WriteByte(',')
	}
	b.WriteByte('|')
	// The values that a client program fixes. Each is cut short: a fingerprint must not grow with what is sent.
	for _, h := range [...]string{"User-Agent", "Accept", "Accept-Encoding", "Sec-Fetch-Mode", "Sec-Ch-Ua", "Connection"} {
		b.WriteString(cut(r.Header.Get(h), 160))
		b.WriteByte('|')
	}
	// Only whether a language is asked for and the first one: the rest varies between real people.
	lang, _, _ := strings.Cut(r.Header.Get("Accept-Language"), ",")
	b.WriteString(cut(lang, 16))
	return hashString(b.String()), label(r)
}

func label(r *http.Request) string {
	ua := printable(cut(r.Header.Get("User-Agent"), 72))
	if ua == "" {
		ua = "(no user agent)"
	}
	proto := "HTTP/" + strconv.Itoa(r.ProtoMajor)
	if r.TLS != nil {
		proto += " " + tls.VersionName(r.TLS.Version)
	}
	return r.Method + " " + proto + " " + ua
}

// pathTemplate returns a hash of the request's target with its variable parts removed, and the template itself.
// "/product/1234/reviews?page=2" and "/product/98/reviews?page=7" are both "/product/9/reviews?"; a cache-busting flood
// of "/?r=<random>" is "/?" however the random part changes.
func pathTemplate(r *http.Request) (uint64, string) {
	path := r.URL.EscapedPath()
	var b strings.Builder
	b.Grow(len(path) + 2)
	n := 0
	for seg := range strings.SplitSeq(strings.TrimPrefix(path, "/"), "/") {
		if n == 6 {
			b.WriteString("/*")
			break
		}
		b.WriteByte('/')
		b.WriteString(segment(seg))
		n++
	}
	if b.Len() == 0 {
		b.WriteByte('/')
	}
	if r.URL.RawQuery != "" || r.URL.ForceQuery {
		b.WriteByte('?')
	}
	t := b.String()
	return hashString(t), printable(cut(t, 96))
}

// segment replaces a path segment that is an identifier with a placeholder: digits become "9", anything long that mixes
// letters and digits (a hash, a UUID, a token) becomes "x".
func segment(s string) string {
	if s == "" {
		return ""
	}
	digits, letters := 0, 0
	for i := 0; i < len(s); i++ {
		switch c := s[i]; {
		case c >= '0' && c <= '9':
			digits++
		case c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z':
			letters++
		}
	}
	switch {
	case digits == len(s):
		return "9"
	case len(s) >= 16 && digits > 0:
		return "x"
	case len(s) > 40:
		return "x"
	}
	return s
}

// isNavigation reports whether the request is a browser loading a page, the only kind of request a challenge page can be
// answered to: an API client or a script would only see an error it cannot act on.
func isNavigation(r *http.Request) bool {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		return false
	}
	if m := r.Header.Get("Sec-Fetch-Mode"); m != "" {
		return m == "navigate"
	}
	return strings.Contains(r.Header.Get("Accept"), "text/html")
}

func cut(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

// printable keeps what is safe to put in a log line: printable ASCII only.
func printable(s string) string {
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] > 0x7e {
			b := []byte(s)
			for j := i; j < len(b); j++ {
				if b[j] < 0x20 || b[j] > 0x7e {
					b[j] = '?'
				}
			}
			return string(b)
		}
	}
	return s
}
