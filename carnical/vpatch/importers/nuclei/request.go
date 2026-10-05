// SPDX-License-Identifier: Apache-2.0

package nuclei

import (
	"regexp"
	"strings"

	"github.com/YurilLAB/coraza/carnical/vpatch/importers"
)

// header is one request header as the template writes it.
type header struct {
	name string // lower case
	val  tpl
}

// request is one request a template sends, taken apart.
type request struct {
	method  string
	path    tpl // without the query
	query   tpl // the raw query, without "?"
	headers []header
	body    tpl
	rawBody bool // the request came from a raw block, so Content-Type is in headers
	// payloads are the inline payload lists of the block the request came from.
	payloads map[string][]string
}

// maxRequestsPerTemplate bounds how many requests of one template are converted.
const maxRequestsPerTemplate = 16

// extractor reads the request blocks of a template.
type extractor struct {
	res      resolver
	payloads map[string][]string // inline payload lists by variable name
}

var methodRe = regexp.MustCompile(`^[A-Z]{3,10}$`)

var dslRe = regexp.MustCompile(`^\s*(?:rand_[a-z_]+|base64(?:_decode)?|md5|sha1|sha256|to_lower|to_upper|url_encode|url_decode|html_escape|html_unescape|hex_encode|hex_decode|concat|replace|replace_regex|trim[a-z_]*|reverse|repeat|generate_[a-z_]+|date_time|unix_time|wait_for|regex|contains|len|compare_versions|gzip|zlib|aes_[a-z_]+|hmac|join|split|sort|uniq|toupper|tolower|template)\(`)

// templateVars returns the template-level variables that have a plain value.
func templateVars(v any) map[string]string {
	out := map[string]string{}
	m, ok := importers.AsMap(v)
	if !ok {
		return out
	}
	for k, x := range m {
		s, ok := importers.AsString(x)
		if !ok || strings.Contains(s, "{{") || dslRe.MatchString(s) || len(s) > 2048 || !identRe.MatchString(k) {
			continue
		}
		out[k] = s
	}
	return out
}

// inlinePayloads returns the payload lists a request block gives inline (a list of strings); a list kept in a file is not available.
func inlinePayloads(v any) map[string][]string {
	out := map[string][]string{}
	m, ok := importers.AsMap(v)
	if !ok {
		return out
	}
	for k, x := range m {
		if _, isList := importers.AsList(x); !isList {
			continue // a payload kept in a file is not available
		}
		l, bad := importers.AsStrings(x)
		if bad != 0 || len(l) == 0 {
			continue
		}
		if len(l) > 20 {
			l = l[:20]
		}
		for i := range l {
			if len(l[i]) > 500 {
				l[i] = l[i][:500]
			}
		}
		out[k] = l
	}
	return out
}

// fromBlock turns one entry of "http:" into requests. unsupported lists the reasons parts of it were left out.
func (x *extractor) fromBlock(block map[string]any) (reqs []request, unsupported []string) {
	if b, _ := block["unsafe"].(bool); b {
		return nil, []string{"unsafe-request"}
	}
	if b, _ := block["race"].(bool); b {
		return nil, []string{"race-request"}
	}
	x.payloads = inlinePayloads(block["payloads"])
	method := "GET"
	if m, ok := importers.AsString(block["method"]); ok && strings.TrimSpace(m) != "" {
		method = strings.ToUpper(strings.TrimSpace(m))
	}
	var hdrs []header
	if hm, ok := importers.AsMap(block["headers"]); ok {
		for k, v := range hm {
			s, ok := importers.AsString(v)
			if !ok {
				continue
			}
			hdrs = append(hdrs, header{name: strings.ToLower(strings.TrimSpace(k)), val: x.res.resolve(parseTpl(s))})
		}
	}
	var body tpl
	if s, ok := importers.AsString(block["body"]); ok {
		body = x.res.resolve(parseTpl(s))
	}
	if raws, ok := importers.AsList(block["raw"]); ok {
		for _, r := range raws {
			s, ok := importers.AsString(r)
			if !ok {
				unsupported = append(unsupported, "raw-not-text")
				continue
			}
			req, err := x.parseRaw(s)
			if err != "" {
				unsupported = append(unsupported, err)
				continue
			}
			reqs = append(reqs, req)
		}
		return reqs, unsupported
	}
	paths, bad := importers.AsStrings(block["path"])
	if bad > 0 {
		unsupported = append(unsupported, "path-not-text")
	}
	for _, p := range paths {
		path, query := x.splitTarget(x.res.resolve(parseTpl(p)))
		reqs = append(reqs, request{method: method, path: path, query: query, headers: hdrs, body: body})
	}
	return reqs, unsupported
}

// splitTarget cuts a request target (already stripped of {{BaseURL}}) into the path and the query, and makes the path start with "/".
func (x *extractor) splitTarget(t tpl) (path, query tpl) {
	if b, _, ok := t.splitAt('#'); ok {
		t = b
	}
	p, q, _ := t.splitAt('?')
	if len(p) == 0 || (p[0].v == "" && !strings.HasPrefix(p[0].lit, "/")) {
		p = append(tpl{{lit: "/"}}, p...)
	}
	return p, q
}

// parseRaw reads a raw HTTP request. Lines that start with "@" are nuclei's own annotations (@timeout, @Host) and are skipped.
func (x *extractor) parseRaw(s string) (request, string) {
	if len(s) > maxTplBytes {
		return request{}, "raw-too-long"
	}
	lines := strings.Split(strings.ReplaceAll(s, "\r\n", "\n"), "\n")
	i := 0
	for i < len(lines) && (strings.TrimSpace(lines[i]) == "" || strings.HasPrefix(strings.TrimSpace(lines[i]), "@")) {
		i++
	}
	if i >= len(lines) {
		return request{}, "raw-empty"
	}
	first := strings.Fields(lines[i])
	if len(first) < 2 {
		return request{}, "raw-unparsable"
	}
	method := strings.ToUpper(first[0])
	if !methodRe.MatchString(method) {
		return request{}, "raw-unparsable"
	}
	target := first[1]
	i++
	var hdrs []header
	for ; i < len(lines); i++ {
		l := lines[i]
		if strings.TrimSpace(l) == "" {
			i++
			break
		}
		name, val, ok := strings.Cut(l, ":")
		if !ok {
			continue
		}
		hdrs = append(hdrs, header{name: strings.ToLower(strings.TrimSpace(name)), val: x.res.resolve(parseTpl(strings.TrimSpace(val)))})
	}
	var body tpl
	if i < len(lines) {
		b := strings.TrimRight(strings.Join(lines[i:], "\n"), "\n ")
		if b != "" {
			body = x.res.resolve(parseTpl(b))
		}
	}
	path, query := x.splitTarget(x.res.resolve(parseTpl(target)))
	return request{method: method, path: path, query: query, headers: hdrs, body: body, rawBody: true}, ""
}

// contentType returns the request's Content-Type value, lower case, or "".
func (r request) contentType() string {
	for _, h := range r.headers {
		if h.name == "content-type" {
			s, _ := h.val.literalOr()
			return strings.ToLower(s)
		}
	}
	return ""
}

// literalOr returns the text with a placeholder-free rendering: the literal parts joined, variables dropped.
func (t tpl) literalOr() (string, bool) {
	s, ok := t.literal()
	if ok {
		return s, true
	}
	return t.text(""), false
}
