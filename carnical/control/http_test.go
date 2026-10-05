// SPDX-License-Identifier: Apache-2.0

package control

import (
	"bytes"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
)

func TestCheckTarget(t *testing.T) {
	long := "/" + strings.Repeat("a", 2048)
	rows := []struct {
		name string
		in   string
		ok   bool
	}{
		{"healthz", "/healthz", true},
		{"policy", "/v1/tenants/" + tenantA + "/policy", true},
		{"action with a colon", "/v1/tenants/" + tenantA + "/policy:validate", true},
		{"host with dots and a colon action", "/v1/tenants/" + tenantA + "/hosts/shop.example.com:verify", true},
		{"query", "/v1/tenants/" + tenantA + "/events?limit=10&cursor=abc_DEF-123", true},
		{"query with tilde and dot", "/x?a=b~c.d", true},
		{"empty", "", false},
		{"no leading slash", "v1/x", false},
		{"absolute form", "http://example.com/v1/x", false},
		{"star", "*", false},
		{"upper-case letter in path", "/V1/tenants", false},
		{"percent-encoded path", "/v1/%74enants", false},
		{"percent-encoded slash", "/v1/a%2fb", false},
		{"percent in query", "/x?a=%41", false},
		{"plus in path", "/v1/a+b", false},
		{"space", "/v1/a b", false},
		{"tab", "/v1/a\tb", false},
		{"newline", "/v1/a\nb", false},
		{"NUL", "/v1/a\x00b", false},
		{"backslash", "/v1/a\\b", false},
		{"semicolon", "/v1/a;b", false},
		{"semicolon in query", "/x?a=b;c=d", false},
		{"fragment", "/v1/a#b", false},
		{"unicode", "/v1/é", false},
		{"at sign", "/v1/a@b", false},
		{"underscore in path", "/v1/a_b", false},
		{"empty query", "/x?", false},
		{"two question marks", "/x?a=1?b=2", false},
		{"comma in query", "/x?a=1,2", false},
		{"huge target", long, false},
		{"huge query", "/x?" + strings.Repeat("a", 1025), false},
		{"query of exactly 1024", "/x?" + strings.Repeat("a", 1024), true},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			if err := checkTarget(row.in); (err == nil) != row.ok {
				t.Fatalf("err = %v, want ok = %v", err, row.ok)
			}
		})
	}
}

func TestJSONContentType(t *testing.T) {
	rows := []struct {
		name string
		in   []string
		ok   bool
	}{
		{"exact", []string{"application/json; charset=utf-8"}, true},
		{"upper case", []string{"Application/JSON; Charset=UTF-8"}, true},
		{"no space", []string{"application/json;charset=utf-8"}, true},
		{"spaces around", []string{"  application/json ;  charset = utf-8  "}, true},
		{"quoted charset", []string{`application/json; charset="utf-8"`}, true},
		{"missing", nil, false},
		{"empty", []string{""}, false},
		{"no charset", []string{"application/json"}, false},
		{"other charset", []string{"application/json; charset=latin1"}, false},
		{"utf-16", []string{"application/json; charset=utf-16"}, false},
		{"utf8 without the dash", []string{"application/json; charset=utf8"}, false},
		{"text/plain", []string{"text/plain; charset=utf-8"}, false},
		{"form", []string{"application/x-www-form-urlencoded"}, false},
		{"multipart", []string{"multipart/form-data; boundary=x"}, false},
		{"json with a suffix", []string{"application/json-patch+json; charset=utf-8"}, false},
		{"json with a prefix", []string{"xapplication/json; charset=utf-8"}, false},
		{"another subtype that starts the same", []string{"application/jsonx; charset=utf-8"}, false},
		{"an extra parameter", []string{"application/json; charset=utf-8; boundary=x"}, false},
		{"an extra parameter first", []string{"application/json; boundary=x; charset=utf-8"}, false},
		{"a parameter other than charset", []string{"application/json; version=1"}, false},
		{"two headers", []string{"application/json; charset=utf-8", "application/json; charset=utf-8"}, false},
		{"two headers, one wrong", []string{"application/json; charset=utf-8", "text/plain"}, false},
		{"a comma list", []string{"application/json; charset=utf-8, text/plain"}, false},
		{"no media type", []string{"; charset=utf-8"}, false},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			if got := jsonContentType(row.in); got != row.ok {
				t.Fatalf("got %v, want %v", got, row.ok)
			}
		})
	}
}

func TestValidHostname(t *testing.T) {
	label63 := strings.Repeat("a", 63)
	rows := []struct {
		in string
		ok bool
	}{
		{"example.com", true},
		{"shop.example.com", true},
		{"a-b.example.co.uk", true},
		{"xn--p1ai.example.com", true},
		{"example.xn--p1ai", true},
		{"123.example.com", true},
		{label63 + ".com", true},
		{"a.bc", true},
		{"", false},
		{"com", false},
		{"localhost", false},
		{"a.localhost", false},
		{"printer.local", false},
		{"db.internal", false},
		{"x.home.arpa", false},
		{"1.2.3.4", false},
		{"example.123", false},
		{"Example.com", false},
		{"example.com.", false},
		{".example.com", false},
		{"exa mple.com", false},
		{"exa_mple.com", false},
		{"*.example.com", false},
		{"example.com:443", false},
		{"example.com/path", false},
		{"example..com", false},
		{"-a.example.com", false},
		{"a-.example.com", false},
		{label63 + "a.com", false},
		{"пример.рф", false},
		{"example.c", false},
		{strings.Repeat("a.", 130) + "com", false},
		{"a.b", false},
		{"[::1]", false},
		{"example.com\n", false},
	}
	for _, row := range rows {
		t.Run(row.in, func(t *testing.T) {
			if got := validHostname(row.in); got != row.ok {
				t.Fatalf("validHostname(%q) = %v, want %v", row.in, got, row.ok)
			}
		})
	}
}

func TestValidUserID(t *testing.T) {
	rows := []struct {
		in string
		ok bool
	}{
		{"user-1", true}, {"a", true}, {"550e8400-e29b-41d4-a716-446655440000", true}, {"sam@example.com", true}, {"svc:billing", true},
		{"a.b_c+d-e", true}, {strings.Repeat("a", 128), true},
		{"", false}, {strings.Repeat("a", 129), false}, {"-user", false}, {".user", false}, {"user one", false}, {"user\n", false},
		{"zoë", false}, {"a/b", false}, {"a,b", false}, {"a;b", false}, {"a\"b", false}, {"a%41", false},
	}
	for _, row := range rows {
		t.Run(row.in, func(t *testing.T) {
			if got := validUserID(row.in); got != row.ok {
				t.Fatalf("got %v, want %v", got, row.ok)
			}
		})
	}
}

func TestParseIfMatch(t *testing.T) {
	rows := []struct {
		in   string
		want uint64
		code int
	}{
		{`"0"`, 0, 0}, {`"1"`, 1, 0}, {`"7"`, 7, 0}, {`"18446744073709551615"`, 18446744073709551615, 0},
		{``, 0, 428},
		{`7`, 0, 400}, {`"007"`, 0, 400}, {`""`, 0, 400}, {`"-1"`, 0, 400}, {`"+1"`, 0, 400}, {`"1.0"`, 0, 400}, {`W/"7"`, 0, 400},
		{`"7`, 0, 400}, {`7"`, 0, 400}, {`"18446744073709551616"`, 0, 400}, {`"a"`, 0, 400}, {`*`, 0, 400}, {`"7", "8"`, 0, 400},
		{`" 7"`, 0, 400}, {`"٧"`, 0, 400},
	}
	for _, row := range rows {
		t.Run(row.in, func(t *testing.T) {
			got, err := parseIfMatch(row.in)
			if row.code == 0 {
				if err != nil || got != row.want {
					t.Fatalf("got %d, %v", got, err)
				}
				return
			}
			if err == nil || err.status != row.code {
				t.Fatalf("err = %v, want status %d", err, row.code)
			}
		})
	}
}

func TestValidIdempotencyKey(t *testing.T) {
	rows := []struct {
		in string
		ok bool
	}{
		{"abcdefgh", true}, {"550e8400-e29b-41d4-a716-446655440000", true}, {strings.Repeat("a", 64), true}, {"a_b-c_d-e", true},
		{"", false}, {"short", false}, {strings.Repeat("a", 65), false}, {"has space1", false}, {"has.dot12", false}, {"-" + "abcdefg", true}, {"abcdefg\n", false},
	}
	for _, row := range rows {
		t.Run(row.in, func(t *testing.T) {
			if got := validIdempotencyKey(row.in); got != row.ok {
				t.Fatalf("got %v, want %v", got, row.ok)
			}
		})
	}
}

// ------------------------------------------------------------------------------------------------ the whole server

func TestOnlyDocumentedMethodsAreAllowed(t *testing.T) {
	h := newHarness(t)
	paths := map[string][]string{}
	for _, r := range h.srv.Routes() {
		p := strings.ReplaceAll(r.Pattern, "{tenant}", tenantA)
		p = strings.ReplaceAll(p, "{host}", "shop.example.com")
		p = strings.ReplaceAll(p, "{id}", "ui-a")
		paths[p] = append(paths[p], r.Method)
	}
	for path, allowed := range paths {
		for _, m := range []string{"GET", "PUT", "POST", "DELETE", "PATCH", "HEAD", "OPTIONS", "TRACE", "CONNECT", "PROPFIND", "get", ""} {
			t.Run(m+" "+path, func(t *testing.T) {
				req := httptest.NewRequest("GET", "https://control.test"+path, nil)
				req.Method, req.RequestURI = m, path
				w := h.serve(req)
				isAllowed := false
				for _, a := range allowed {
					if a == m {
						isAllowed = true
					}
				}
				if isAllowed {
					if w.Code == 405 || w.Code == 404 {
						t.Fatalf("documented method answered %d", w.Code)
					}
					return
				}
				if w.Code != 405 {
					t.Fatalf("status %d, want 405", w.Code)
				}
				allow := w.Header().Get("Allow")
				for _, a := range allowed {
					if !strings.Contains(allow, a) {
						t.Fatalf("Allow = %q, missing %s", allow, a)
					}
				}
				if strings.Contains(allow, "OPTIONS") || strings.Contains(allow, "HEAD") {
					t.Fatalf("Allow = %q lists an undocumented method", allow)
				}
				if e := errorOf(t, w); e.Code != "method_not_allowed" {
					t.Fatalf("code %s", e.Code)
				}
			})
		}
	}
}

func TestUnknownPathsAre404(t *testing.T) {
	h := newHarness(t)
	for _, p := range []string{"/", "/v1", "/v1/", "/v1/tenants", "/v1/tenants/", "/v1/tenants/" + tenantA, "/v1/tenants/" + tenantA + "/", "/v1/tenants/" + tenantA + "/policy/",
		"/v1/tenants/" + tenantA + "/policies", "/v1/tenants/" + tenantA + "/policy/history/x", "/v1/tenants/short/policy", "/v1/tenants/" + strings.Repeat("g", 32) + "/policy",
		"/v1/credentials/", "/v1/credentials/ui-a", "/v1/credentials/ui-a:other", "/admin", "/healthz/", "/v2/credentials", "/v1//credentials",
		"/v1/tenants/" + tenantA + "/hosts/localhost:verify", "/v1/tenants/" + tenantA + "/hosts/shop.example.com",
		"/v1/tenants/" + tenantA + "/./policy", "/v1/tenants/" + tenantA + "/../policy", "/v1/./credentials"} {
		t.Run(p, func(t *testing.T) {
			w := h.do(reqOpts{target: p})
			if w.Code != 404 {
				t.Fatalf("%q: status %d", p, w.Code)
			}
		})
	}
	if n := h.store.total(); n != 0 {
		t.Fatalf("a store was touched %d times", n)
	}
}

func TestMalformedTargetsAre400(t *testing.T) {
	h := newHarness(t)
	for _, p := range []string{"v1/credentials", "/V1/credentials", "/v1/%63redentials", "/v1/credentials?", "/v1/credentials?a=%41", "/v1/credentials#x", "/v1/cred entials",
		"http://control.test/v1/credentials", "*", "/v1/tenants/" + strings.ToUpper(tenantA) + "/policy"} {
		t.Run(p, func(t *testing.T) {
			req := httptest.NewRequest("GET", "https://control.test/healthz", nil)
			req.RequestURI = p
			if w := h.serve(req); w.Code != 400 {
				t.Fatalf("%q: status %d", p, w.Code)
			}
		})
	}
}

func TestQueryRules(t *testing.T) {
	h := newHarness(t)
	ev := "/v1/tenants/" + tenantA + "/events"
	rows := []struct {
		name   string
		target string
		code   int
	}{
		{"no query", ev, 200},
		{"limit", ev + "?limit=5", 200},
		{"cursor and limit", ev + "?cursor=c0&limit=5", 200},
		{"unknown key", ev + "?foo=1", 400},
		{"known and unknown key", ev + "?limit=5&foo=1", 400},
		{"duplicate key", ev + "?limit=5&limit=6", 400},
		{"empty value", ev + "?limit=", 400},
		{"no equals", ev + "?limit", 400},
		{"empty key", ev + "?=5", 400},
		{"trailing ampersand", ev + "?limit=5&", 400},
		{"leading ampersand", ev + "?&limit=5", 400},
		{"limit zero", ev + "?limit=0", 400},
		{"limit leading zero", ev + "?limit=05", 400},
		{"limit at the maximum", ev + "?limit=500", 200},
		{"limit over the maximum", ev + "?limit=501", 400},
		{"limit negative", ev + "?limit=-1", 400},
		{"limit not a number", ev + "?limit=abc", 400},
		{"limit huge", ev + "?limit=99999999999999999999", 400},
		{"cursor with a bad character", ev + "?cursor=a.b", 400},
		{"cursor too long", ev + "?cursor=" + strings.Repeat("a", 513), 400},
		{"cursor at the maximum", ev + "?cursor=" + strings.Repeat("a", 512), 200},
		{"a query on a route that takes none", "/v1/tenants/" + tenantA + "/policy?x=1", 400},
		{"a query on healthz", "/healthz?x=1", 400},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			if w := h.do(reqOpts{target: row.target}); w.Code != row.code {
				t.Fatalf("status %d, want %d: %s", w.Code, row.code, w.Body.String())
			}
		})
	}
}

func TestSmuggledAndDuplicateHeaders(t *testing.T) {
	h := newHarness(t)
	target := "/v1/tenants/" + tenantA + "/status"
	one := func(k, v string) func(r *http.Request) { return func(r *http.Request) { r.Header.Set(k, v) } }
	two := func(k, v1, v2 string) func(r *http.Request) {
		return func(r *http.Request) { r.Header[k] = []string{v1, v2} }
	}
	rows := []struct {
		name  string
		after func(r *http.Request)
		code  int
	}{
		{"clean request", func(r *http.Request) {}, 200},
		{"X-Forwarded-For", one("X-Forwarded-For", "203.0.113.9"), 400},
		{"X-Forwarded-Host", one("X-Forwarded-Host", "evil.example"), 400},
		{"X-Forwarded-Proto", one("X-Forwarded-Proto", "http"), 400},
		{"Forwarded", one("Forwarded", "for=203.0.113.9"), 400},
		{"X-Real-IP", one("X-Real-IP", "203.0.113.9"), 400},
		{"True-Client-IP", one("True-Client-IP", "203.0.113.9"), 400},
		{"X-Original-URL", one("X-Original-URL", "/v1/credentials"), 400},
		{"X-Rewrite-URL", one("X-Rewrite-URL", "/v1/credentials"), 400},
		{"X-HTTP-Method-Override", one("X-HTTP-Method-Override", "PUT"), 400},
		{"X-Method-Override", one("X-Method-Override", "PUT"), 400},
		{"Upgrade", one("Upgrade", "websocket"), 400},
		{"Trailer", one("Trailer", "Carnical-Acting-User"), 400},
		{"TE", one("Te", "trailers"), 400},
		{"Content-Encoding", one("Content-Encoding", "gzip"), 400},
		{"Proxy-Authorization", one("Proxy-Authorization", "Basic x"), 400},
		{"a name with an underscore", func(r *http.Request) { r.Header["X_Thing"] = []string{"1"} }, 400},
		{"an unknown Carnical header", one("Carnical-Admin", "yes"), 400},
		{"a second acting user", two("Carnical-Acting-User", "user-1", "root"), 400},
		{"a second Authorization", func(r *http.Request) { r.Header.Add("Authorization", "Bearer x") }, 400},
		{"a second If-Match", two("If-Match", `"1"`, `"2"`), 400},
		{"a second Idempotency-Key", two("Idempotency-Key", "abcdefgh", "abcdefgi"), 400},
		{"a second Step-Up", two("Carnical-Stepup-At", "1", "2"), 400},
		{"a second Content-Type", two("Content-Type", "application/json; charset=utf-8", "text/plain"), 400},
		{"a second Content-Length", two("Content-Length", "0", "0"), 400},
		{"a header value of 4097 bytes", one("X-Big", strings.Repeat("a", 4097)), 431},
		{"a header value of 4096 bytes", one("X-Big", strings.Repeat("a", 4096)), 200},
		{"a transfer encoding other than chunked", func(r *http.Request) { r.TransferEncoding = []string{"gzip", "chunked"} }, 400},
		{"HTTP/1.0", func(r *http.Request) { r.ProtoMajor, r.ProtoMinor = 1, 0 }, 400},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			w := h.do(reqOpts{target: target, after: row.after})
			if w.Code != row.code {
				t.Fatalf("status %d, want %d: %s", w.Code, row.code, w.Body.String())
			}
		})
	}
	t.Run("too many headers", func(t *testing.T) {
		w := h.do(reqOpts{target: target, after: func(r *http.Request) {
			for i := 0; i < 50; i++ {
				r.Header.Set("X-H"+strconv.Itoa(i), "v")
			}
		}})
		if w.Code != 431 {
			t.Fatalf("status %d", w.Code)
		}
	})
	t.Run("headers too large in total", func(t *testing.T) {
		w := h.do(reqOpts{target: target, after: func(r *http.Request) {
			for i := 0; i < 8; i++ {
				r.Header.Set("X-H"+strconv.Itoa(i), strings.Repeat("a", 3000))
			}
		}})
		if w.Code != 431 {
			t.Fatalf("status %d", w.Code)
		}
	})
}

func TestBodyRules(t *testing.T) {
	put := "/v1/tenants/" + tenantA + "/policy"
	doc := `{"mode":"block","threshold":5}`
	// a document of exactly the maximum size: valid JSON padded inside a string
	pad := func(total int) string {
		fill := total - len(`{"note":""}`)
		return `{"note":"` + strings.Repeat("x", fill) + `"}`
	}
	rows := []struct {
		name string
		o    reqOpts
		code int
		err  string
	}{
		{"a good document", reqOpts{method: "PUT", target: put, body: []byte(doc), ifMatch: `"0"`}, 200, ""},
		{"a document of exactly 256 KiB", reqOpts{method: "PUT", target: put, body: []byte(pad(256 << 10)), ifMatch: `"0"`}, 200, ""},
		{"a document one byte over", reqOpts{method: "PUT", target: put, body: []byte(pad(256<<10 + 1)), ifMatch: `"0"`}, 413, "payload_too_large"},
		{"a document of a megabyte", reqOpts{method: "PUT", target: put, body: []byte(pad(1 << 20)), ifMatch: `"0"`}, 413, "payload_too_large"},
		{"no content type", reqOpts{method: "PUT", target: put, body: []byte(doc), ctype: "-", ifMatch: `"0"`}, 415, "unsupported_media_type"},
		{"text/plain", reqOpts{method: "PUT", target: put, body: []byte(doc), ctype: "text/plain; charset=utf-8", ifMatch: `"0"`}, 415, "unsupported_media_type"},
		{"json without a charset", reqOpts{method: "PUT", target: put, body: []byte(doc), ctype: "application/json", ifMatch: `"0"`}, 415, "unsupported_media_type"},
		{"json in latin-1", reqOpts{method: "PUT", target: put, body: []byte(doc), ctype: "application/json; charset=iso-8859-1", ifMatch: `"0"`}, 415, "unsupported_media_type"},
		{"a form", reqOpts{method: "PUT", target: put, body: []byte("mode=off"), ctype: "application/x-www-form-urlencoded", ifMatch: `"0"`}, 415, "unsupported_media_type"},
		{"no body on a route that needs one", reqOpts{method: "PUT", target: put, ifMatch: `"0"`}, 400, "bad_request"},
		{"a body on a GET", reqOpts{method: "GET", target: put, body: []byte(doc)}, 400, "bad_request"},
		{"a body on a route that takes none", reqOpts{method: "POST", target: "/v1/tenants/" + tenantA + "/hosts/shop.example.com:verify", body: []byte("{}")}, 400, "bad_request"},
		{"not JSON", reqOpts{method: "PUT", target: put, body: []byte("not json"), ifMatch: `"0"`}, 400, "invalid_json"},
		{"an array", reqOpts{method: "PUT", target: put, body: []byte(`[1]`), ifMatch: `"0"`}, 400, "invalid_json"},
		{"a repeated key", reqOpts{method: "PUT", target: put, body: []byte(`{"mode":"off","mode":"block"}`), ifMatch: `"0"`}, 400, "invalid_json"},
		{"a byte-order mark", reqOpts{method: "PUT", target: put, body: []byte("\xef\xbb\xbf" + doc), ifMatch: `"0"`}, 400, "invalid_json"},
		{"invalid UTF-8", reqOpts{method: "PUT", target: put, body: []byte("{\"note\":\"\xff\"}"), ifMatch: `"0"`}, 400, "invalid_json"},
		{"two documents", reqOpts{method: "PUT", target: put, body: []byte(doc + doc), ifMatch: `"0"`}, 400, "invalid_json"},
		{"nested 65 deep", reqOpts{method: "PUT", target: put, body: []byte(strings.Repeat(`{"a":`, 65) + "1" + strings.Repeat("}", 65)), ifMatch: `"0"`}, 400, "invalid_json"},
		{"an envelope with an unknown field", reqOpts{method: "POST", target: "/v1/tenants/" + tenantA + "/publish", body: []byte(`{"revision":1,"force":true}`), idem: "abcdefgh"}, 400, "bad_request"},
		{"an envelope with the wrong type", reqOpts{method: "POST", target: "/v1/tenants/" + tenantA + "/publish", body: []byte(`{"revision":"1"}`), idem: "abcdefgh"}, 400, "bad_request"},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			h2 := newHarness(t) // a fresh store each time, so "0" is always the current revision
			w := h2.do(row.o)
			if w.Code != row.code {
				t.Fatalf("status %d, want %d: %.200s", w.Code, row.code, w.Body.String())
			}
			if row.err != "" {
				if e := errorOf(t, w); e.Code != row.err {
					t.Fatalf("code %q, want %q", e.Code, row.err)
				}
			}
			if row.code >= 400 && h2.store.revisions(tenantA) != 0 {
				t.Fatal("a refused request changed the policy")
			}
		})
	}
}

func TestAChunkedBodyOverTheLimitIsRefusedWithoutBeingBuffered(t *testing.T) {
	h := newHarness(t)
	big := bytes.Repeat([]byte("a"), 300<<10)
	req := h.build(reqOpts{method: "PUT", target: "/v1/tenants/" + tenantA + "/policy", body: big[:10], ifMatch: `"0"`})
	// the declared length is unknown (chunked) and the body is over the limit
	req.Body = readerCloser{bytes.NewReader(big)}
	req.ContentLength = -1
	req.TransferEncoding = []string{"chunked"}
	w := h.serve(req)
	if w.Code != 413 {
		t.Fatalf("status %d: %s", w.Code, w.Body.String())
	}
}

type readerCloser struct{ *bytes.Reader }

func (readerCloser) Close() error { return nil }

func TestTrailersAreRefused(t *testing.T) {
	h := newHarness(t)
	req := h.build(reqOpts{method: "PUT", target: "/v1/tenants/" + tenantA + "/policy", body: []byte(`{"mode":"block"}`), ifMatch: `"0"`})
	req.Trailer = http.Header{"X-Late": {"1"}}
	if w := h.serve(req); w.Code != 400 {
		t.Fatalf("status %d", w.Code)
	}
}

func TestEveryResponseHasTheSecurityHeadersAndNoCORS(t *testing.T) {
	h := newHarness(t)
	h.seed(tenantA, `{"mode":"block"}`)
	var responses []*httptest.ResponseRecorder
	add := func(w *httptest.ResponseRecorder) { responses = append(responses, w) }
	// every route, with success, every kind of failure, and the requests that never reach a route
	for _, r := range h.srv.Routes() {
		p := strings.ReplaceAll(strings.ReplaceAll(strings.ReplaceAll(r.Pattern, "{tenant}", tenantA), "{host}", "shop.example.com"), "{id}", "reader-a")
		add(h.do(reqOpts{method: r.Method, target: p}))
		add(h.do(reqOpts{as: "ui-b", method: r.Method, target: p}))
		add(h.do(reqOpts{as: "reader-a", method: r.Method, target: p, ts: 1}))
		add(h.do(reqOpts{method: "OPTIONS", target: p, extra: http.Header{"Origin": {"https://evil.example"}, "Access-Control-Request-Method": {"PUT"}}}))
	}
	add(h.do(reqOpts{target: "/nothing"}))
	add(h.do(reqOpts{target: "/v1/tenants/" + tenantA + "/policy", extra: http.Header{"Origin": {"https://evil.example"}}}))
	add(h.do(reqOpts{target: "/healthz"}))
	add(h.do(reqOpts{target: "/v1/tenants/" + tenantA + "/policy", noTLS: true}))
	req := httptest.NewRequest("GET", "https://control.test/x", nil)
	req.RequestURI = "x"
	add(h.serve(req))
	codes := map[int]bool{}
	for i, w := range responses {
		codes[w.Code] = true
		hd := w.Header()
		if hd.Get("Cache-Control") != "no-store" || hd.Get("X-Content-Type-Options") != "nosniff" || hd.Get("Content-Security-Policy") != "default-src 'none'" {
			t.Fatalf("response %d (%d) lacks a security header: %v", i, w.Code, hd)
		}
		if !strings.HasPrefix(hd.Get(HeaderRequestID), "req_") {
			t.Fatalf("response %d has no request id", i)
		}
		for k := range hd {
			if strings.HasPrefix(strings.ToLower(k), "access-control-") || strings.EqualFold(k, "Vary") && strings.Contains(strings.ToLower(hd.Get(k)), "origin") {
				t.Fatalf("response %d carries CORS header %s", i, k)
			}
		}
		if w.Code != 200 && w.Code != 201 && w.Code != 204 {
			if ct := hd.Get("Content-Type"); ct != "application/json; charset=utf-8" {
				t.Fatalf("response %d: content type %q", i, ct)
			}
			e := errorOf(t, w)
			if e.RequestID != hd.Get(HeaderRequestID) {
				t.Fatalf("response %d: the body's request id %q is not the header's %q", i, e.RequestID, hd.Get(HeaderRequestID))
			}
		}
	}
	for _, want := range []int{200, 400, 401, 403, 404, 405} {
		if !codes[want] {
			t.Errorf("the sweep never produced a %d, so it did not test that kind of response", want)
		}
	}
}

func TestErrorBodiesNeverEchoInput(t *testing.T) {
	h := newHarness(t)
	const marker = "zzMARKERzz"
	targets := []string{
		"/v1/tenants/" + marker + "/policy", "/v1/" + marker, "/v1/tenants/" + tenantA + "/events?" + marker + "=1", "/v1/tenants/" + tenantA + "/events?cursor=" + marker + "." + marker,
		"/v1/tenants/" + tenantA + "/events?limit=" + marker, "/v1/tenants/" + tenantA + "/hosts/" + marker + ".com:verify",
	}
	var all []*httptest.ResponseRecorder
	for _, p := range targets {
		req := httptest.NewRequest("GET", "https://control.test/healthz", nil)
		req.RequestURI = p
		all = append(all, h.serve(req))
		all = append(all, h.do(reqOpts{target: p}))
	}
	bad := func(o reqOpts) { all = append(all, h.do(o)) }
	bad(reqOpts{method: "PUT", target: "/v1/tenants/" + tenantA + "/policy", body: []byte(`{"` + marker + `":1,"` + marker + `":2}`), ifMatch: `"0"`})
	bad(reqOpts{method: "PUT", target: "/v1/tenants/" + tenantA + "/policy", body: []byte(`{"mode":"` + marker + `"}`), ifMatch: `"0"`})
	bad(reqOpts{method: "PUT", target: "/v1/tenants/" + tenantA + "/policy", body: []byte(`{"mode":"block"}`), ifMatch: `"` + marker + `"`})
	bad(reqOpts{method: "PUT", target: "/v1/tenants/" + tenantA + "/policy", body: []byte(`{"mode":"block"}`), ifMatch: `"0"`, ctype: "text/" + marker})
	bad(reqOpts{method: "POST", target: "/v1/tenants/" + tenantA + "/publish", body: []byte(`{"` + marker + `":1}`), idem: "abcdefgh"})
	bad(reqOpts{method: "POST", target: "/v1/tenants/" + tenantA + "/publish", body: []byte(`{"revision":1}`), idem: marker + marker})
	bad(reqOpts{method: "POST", target: "/v1/tenants/" + tenantA + "/hosts", body: []byte(`{"hostname":"` + marker + `"}`)})
	bad(reqOpts{target: "/v1/tenants/" + tenantA + "/status", after: func(r *http.Request) { r.Header.Set(HeaderActingUser, marker+" bad") }})
	bad(reqOpts{target: "/v1/tenants/" + tenantA + "/status", extra: http.Header{"X-Forwarded-For": {marker}}})
	bad(reqOpts{target: "/v1/tenants/" + tenantA + "/status", extra: http.Header{marker: {"x"}}, after: func(r *http.Request) { r.Header["Authorization"] = []string{marker} }})
	bad(reqOpts{as: "nobody-" + strings.ToLower(marker), target: "/v1/tenants/" + tenantA + "/status"})
	bad(reqOpts{target: "/v1/tenants/" + tenantA + "/status", host: strings.ToLower(marker) + ".test"})
	for i, w := range all {
		if strings.Contains(w.Body.String(), marker) || strings.Contains(strings.ToLower(w.Body.String()), strings.ToLower(marker)) {
			t.Fatalf("response %d (%d) echoes input: %s", i, w.Code, w.Body.String())
		}
		for k, vs := range w.Header() {
			for _, v := range vs {
				if strings.Contains(strings.ToLower(v), strings.ToLower(marker)) {
					t.Fatalf("response %d header %s echoes input: %s", i, k, v)
				}
			}
		}
	}
	// Nor does the audit log hold the marker, with one exception: a credential id that has the form of an id is logged as
	// it was claimed, because that is what the operator needs to see.
	low := strings.ToLower(marker)
	for _, e := range h.audit.all() {
		if strings.Contains(strings.ToLower(e.Tenant+e.User+e.Action+e.Detail+e.Outcome+e.Source+e.RequestID), low) {
			t.Fatalf("audit entry echoes input: %+v", e)
		}
		if strings.Contains(strings.ToLower(e.Credential), low) && e.Credential != "nobody-"+low {
			t.Fatalf("audit entry echoes input in the credential: %+v", e)
		}
	}
}

func TestAPanicInAStoreIsAUniformError(t *testing.T) {
	h := newHarness(t)
	w := h.putPolicy("ui-a", tenantA, `{"mode":"block","panic":true}`, 0, 0)
	if w.Code != 500 {
		t.Fatalf("status %d", w.Code)
	}
	e := errorOf(t, w)
	if e.Code != "internal" || strings.Contains(w.Body.String(), "exploded") || strings.Contains(w.Body.String(), "customer content") {
		t.Fatalf("panic text reached the client: %s", w.Body.String())
	}
	if w.Header().Get("Cache-Control") != "no-store" || w.Header().Get(HeaderRequestID) == "" {
		t.Fatal("headers missing on a recovered panic")
	}
	if h.srv.Stats().Panics != 1 {
		t.Fatalf("panics counted: %d", h.srv.Stats().Panics)
	}
	// and the server keeps working
	if w := h.do(reqOpts{target: "/v1/tenants/" + tenantA + "/status"}); w.Code != 200 {
		t.Fatalf("after a panic: %d", w.Code)
	}
	if got := h.internalErrors(); len(got) != 1 || !strings.HasSuffix(got[0], " panic") {
		t.Fatalf("hook calls: %v", got)
	}
}

func TestStoreErrorsAreUniformAndNeverShowTheirText(t *testing.T) {
	h := newHarness(t)
	h.store.fail = errors.New("connection to db-7.internal failed: password=hunter2")
	for _, tc := range []struct{ method, target, body string }{
		{"GET", "/v1/tenants/" + tenantA + "/policy", ""},
		{"GET", "/v1/tenants/" + tenantA + "/policy/history", ""},
	} {
		w := h.do(reqOpts{method: tc.method, target: tc.target})
		if w.Code != 500 || strings.Contains(w.Body.String(), "hunter2") || strings.Contains(w.Body.String(), "db-7") {
			t.Fatalf("%s: %d %s", tc.target, w.Code, w.Body.String())
		}
	}
	h.store.fail = ErrUnavailable
	w := h.do(reqOpts{target: "/v1/tenants/" + tenantA + "/policy"})
	if w.Code != 503 || errorOf(t, w).Code != "unavailable" || w.Header().Get("Retry-After") == "" {
		t.Fatalf("an unavailable store: %d %s", w.Code, w.Body.String())
	}
}

func TestHealthz(t *testing.T) {
	h := newHarness(t)
	w := h.do(reqOpts{target: "/healthz"})
	if w.Code != 200 || strings.TrimSpace(w.Body.String()) != `{"status":"ok"}` {
		t.Fatalf("%d %q", w.Code, w.Body.String())
	}
	// no authentication, so a request with no credential at all gets it
	req := httptest.NewRequest("GET", "https://control.test/healthz", nil)
	req.RequestURI = "/healthz"
	w = h.serve(req)
	if w.Code != 200 || w.Body.Len() != 15 {
		t.Fatalf("%d %q", w.Code, w.Body.String())
	}
	// no information: nothing varies with the state of the server
	h.audit.setFailing(true)
	w2 := h.serve(req)
	if w2.Body.String() != w.Body.String() || w2.Code != 200 {
		t.Fatal("the answer changed with the audit log's state")
	}
	// the stand-alone handler for a load balancer
	hh := HealthHandler()
	w3 := httptest.NewRecorder()
	hh.ServeHTTP(w3, httptest.NewRequest("GET", "/healthz", nil))
	if w3.Code != 200 || w3.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("health handler: %d", w3.Code)
	}
	w4 := httptest.NewRecorder()
	hh.ServeHTTP(w4, httptest.NewRequest("GET", "/v1/credentials", nil))
	if w4.Code != 404 {
		t.Fatalf("health handler served another path: %d", w4.Code)
	}
}

func TestGlobalInFlightLimit(t *testing.T) {
	h := newHarness(t, func(c *Config) { c.Limits.MaxInFlight = 2 })
	gate := make(chan struct{})
	h.pub.gate, h.pub.in = gate, make(chan struct{}, 4)
	h.seed(tenantA, `{"mode":"block"}`)
	done := make(chan *httptest.ResponseRecorder, 2)
	for i := 0; i < 2; i++ {
		i := i
		go func() {
			done <- h.do(reqOpts{method: "POST", target: "/v1/tenants/" + tenantA + "/publish", body: []byte(`{"revision":1}`), idem: "abcdefg" + strconv.Itoa(i)})
		}()
	}
	<-h.pub.in
	<-h.pub.in
	w := h.do(reqOpts{target: "/v1/tenants/" + tenantA + "/status"})
	if w.Code != 503 || errorOf(t, w).Code != "overloaded" || w.Header().Get("Retry-After") == "" {
		t.Fatalf("over the limit: %d %s", w.Code, w.Body.String())
	}
	close(gate)
	for i := 0; i < 2; i++ {
		if w := <-done; w.Code != 200 {
			t.Fatalf("held request: %d %s", w.Code, w.Body.String())
		}
	}
	if w := h.do(reqOpts{target: "/v1/tenants/" + tenantA + "/status"}); w.Code != 200 {
		t.Fatalf("after the others finished: %d", w.Code)
	}
}

func TestPerCredentialInFlightLimit(t *testing.T) {
	h := newHarness(t, func(c *Config) { c.Limits.MaxInFlightPerCredential = 1 })
	gate := make(chan struct{})
	h.pub.gate, h.pub.in = gate, make(chan struct{}, 4)
	h.seed(tenantA, `{"mode":"block"}`)
	h.seed(tenantB, `{"mode":"block"}`)
	done := make(chan *httptest.ResponseRecorder, 2)
	go func() {
		done <- h.do(reqOpts{method: "POST", target: "/v1/tenants/" + tenantA + "/publish", body: []byte(`{"revision":1}`), idem: "abcdefgh"})
	}()
	<-h.pub.in
	w := h.do(reqOpts{target: "/v1/tenants/" + tenantA + "/status"})
	if w.Code != 429 || errorOf(t, w).Code != "too_many_requests" {
		t.Fatalf("second request of the same credential: %d %s", w.Code, w.Body.String())
	}
	// another credential is not held up by it
	if w := h.do(reqOpts{as: "ui-b", target: "/v1/tenants/" + tenantB + "/status"}); w.Code != 200 {
		t.Fatalf("another credential: %d %s", w.Code, w.Body.String())
	}
	close(gate)
	if w := <-done; w.Code != 200 {
		t.Fatalf("held request: %d", w.Code)
	}
}
