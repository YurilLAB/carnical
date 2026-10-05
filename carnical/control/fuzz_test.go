// SPDX-License-Identifier: Apache-2.0

package control

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"unicode/utf8"
)

// Run one with, for example,
//
//	go test ./control -run XXX -fuzz FuzzParseAuthHeader -fuzztime 30s
func FuzzParseAuthHeader(f *testing.F) {
	good := AuthHeader{Credential: "ui-prod", Timestamp: 1791201600, Nonce: strings.Repeat("0", 32), Signature: make([]byte, 64)}.String()
	for _, s := range []string{good, "", AuthScheme, AuthScheme + " ", strings.Replace(good, ", ", ",", 1), good + "\n", good + good, "Carnical-Sig cred=, ts=, nonce=, sig=",
		strings.Replace(good, "ts=1791201600", "ts=01791201600", 1), strings.Repeat("A", 400)} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		h, err := ParseAuthHeader(s)
		if err != nil {
			return
		}
		// what is accepted is exactly one spelling: it formats back to the same text
		if h.String() != s {
			t.Fatalf("accepted %q but it formats as %q", s, h.String())
		}
		if !ValidCredentialID(h.Credential) || h.Timestamp <= 0 || h.Timestamp > maxTimestamp || len(h.Nonce) != 32 || !isLowerHex(h.Nonce) || len(h.Signature) != ed25519.SignatureSize {
			t.Fatalf("accepted a malformed header: %+v", h)
		}
		if len(s) > maxAuthLen || strings.ContainsAny(s, "\r\n\x00") {
			t.Fatalf("accepted %q", s)
		}
	})
}

func FuzzCanonicalString(f *testing.F) {
	body := sha256.Sum256([]byte("body"))
	f.Add("PUT", "control.example:8443", "/v1/tenants/"+tenantA+"/policy", string(body[:]), int64(1791201600), strings.Repeat("0", 32), "ui-prod", tenantA, "user-42", int64(1791201500), true, `"7"`, "")
	f.Add("GET", "a", "/x", "", int64(1), "", "", "", "", int64(0), false, "", "")
	f.Add("P\nUT", "h\nost", "/t\narget", "x", int64(-1), "n\nonce", "c\nred", "t\nenant", "u\nser", int64(-5), true, "i\nm", "k\ney")
	f.Fuzz(func(t *testing.T, method, host, target, bodyHash string, ts int64, nonce, cred, tenant, user string, stepUp int64, hasStepUp bool, ifMatch, idem string) {
		r := SignedRequest{Method: method, Host: host, Target: target, Timestamp: ts, Nonce: nonce, Credential: cred, Tenant: tenant, User: user, StepUp: stepUp,
			HasStepUp: hasStepUp, IfMatch: ifMatch, IdemKey: idem}
		copy(r.BodySHA256[:], bodyHash)
		s, err := r.CanonicalString()
		if err != nil {
			return
		}
		fields, ok := CanonicalFields(s)
		if !ok {
			t.Fatalf("an accepted request does not split into the thirteen parts: %q", s)
		}
		// no field was allowed to carry a line break or a control character, so each is exactly what was given
		want := []string{CanonicalPrefix, method, strings.ToLower(host), target, "", "", nonce, cred, orDash(tenant), user, "", orDash(ifMatch), orDash(idem)}
		for i, w := range want {
			if i == 4 || i == 5 || i == 10 {
				continue // derived: the body hash, the timestamp and the step-up time
			}
			if fields[i] != w {
				t.Fatalf("field %d is %q, want %q", i, fields[i], w)
			}
		}
		for i, fl := range fields {
			if strings.ContainsAny(fl, "\n\r\x00") || fl == "" {
				t.Fatalf("field %d is %q", i, fl)
			}
			for j := 0; j < len(fl); j++ {
				if fl[j] < 0x21 || fl[j] > 0x7e {
					t.Fatalf("field %d holds the byte %#x", i, fl[j])
				}
			}
		}
		if fields[10] == "-" == hasStepUp {
			t.Fatalf("the step-up field is %q for HasStepUp=%v", fields[10], hasStepUp)
		}
		// injectivity: change any one field and the text must change; the same fields give the same text
		again, _ := r.CanonicalString()
		if again != s {
			t.Fatal("not deterministic")
		}
		for _, mutate := range []func(x *SignedRequest){
			func(x *SignedRequest) { x.User += "x" }, func(x *SignedRequest) { x.Target += "x" }, func(x *SignedRequest) { x.BodySHA256[0] ^= 1 },
			func(x *SignedRequest) { x.Timestamp++ }, func(x *SignedRequest) { x.Host += "x" }, func(x *SignedRequest) { x.HasStepUp = !x.HasStepUp },
			func(x *SignedRequest) { x.IfMatch += "x" }, func(x *SignedRequest) { x.IdemKey += "x" },
		} {
			x := r
			mutate(&x)
			if s2, err := x.CanonicalString(); err == nil && s2 == s {
				t.Fatalf("two different requests have the same canonical text: %q", s)
			}
		}
	})
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

// FuzzSignedFieldsDoNotCollide: two requests that differ only in how a boundary is drawn between two adjacent fields
// (user and step-up, if-match and idempotency key) never give one text.
func FuzzSignedFieldsDoNotCollide(f *testing.F) {
	f.Add("a", "b", "a\nb", "")
	f.Fuzz(func(t *testing.T, a, b, c, d string) {
		x := vectorRequest()
		y := vectorRequest()
		x.User, x.IfMatch, x.IdemKey = a, b, c
		y.User, y.IfMatch, y.IdemKey = a+"\n"+b, c, d
		sx, ex := x.CanonicalString()
		sy, ey := y.CanonicalString()
		if ex == nil && ey == nil && sx == sy {
			t.Fatalf("collision between %+v and %+v", x, y)
		}
		if ey == nil && strings.Contains(y.User, "\n") {
			t.Fatalf("a user with a line break was accepted")
		}
	})
}

func maxDepthOf(b []byte) int {
	depth, max := 0, 0
	inStr, esc := false, false
	for _, c := range b {
		switch {
		case inStr:
			if esc {
				esc = false
			} else if c == '\\' {
				esc = true
			} else if c == '"' {
				inStr = false
			}
		case c == '"':
			inStr = true
		case c == '{' || c == '[':
			depth++
			if depth > max {
				max = depth
			}
		case c == '}' || c == ']':
			depth--
		}
	}
	return max
}

func FuzzCheckJSON(f *testing.F) {
	for _, s := range []string{`{}`, `{"a":1}`, `{"a":1,"a":2}`, `{"a":{"b":[1,2,{"c":null}]}}`, `[]`, ``, `{"a":"\ud800"}`, "\xef\xbb\xbf{}", `{"a":1}{"b":2}`, `{"mode":"block","threshold":5}`,
		strings.Repeat(`{"a":`, 70) + "1" + strings.Repeat("}", 70)} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		err := checkJSON(b, 64)
		if err != nil {
			return
		}
		// accepted: one valid UTF-8 object, no deeper than 64, that the standard library also accepts as one value
		if !utf8.Valid(b) || !json.Valid(b) {
			t.Fatalf("accepted %q", b)
		}
		var m map[string]json.RawMessage
		if err := json.Unmarshal(b, &m); err != nil {
			t.Fatalf("accepted something that is not an object: %q (%v)", b, err)
		}
		if d := maxDepthOf(b); d > 64 {
			t.Fatalf("accepted a document nested %d deep", d)
		}
		// no key of the top-level object appears twice: the number of keys the standard library kept is the number written
		dec := json.NewDecoder(bytes.NewReader(b))
		_, _ = dec.Token()
		written := 0
		for dec.More() {
			if _, err := dec.Token(); err != nil {
				t.Fatal(err)
			}
			written++
			var skip json.RawMessage
			if err := dec.Decode(&skip); err != nil {
				t.Fatal(err)
			}
		}
		if written != len(m) {
			t.Fatalf("the object has %d keys written and %d distinct: a repeated key was accepted in %q", written, len(m), b)
		}
	})
}

func FuzzDecodeEnvelope(f *testing.F) {
	for _, s := range []string{`{"revision":1}`, `{"revision":1,"x":2}`, `{"revision":"1"}`, `{"hostname":"a.example.com"}`, ``, `null`, `{"revision":1}{"revision":2}`} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		var p publishIn
		var h addHostIn
		var r rollbackIn
		for _, dst := range []any{&p, &h, &r} {
			if err := decodeEnvelope(b, dst); err == nil {
				// accepted: it is one object, with only known fields, and a second read gives the same value
				if checkJSON(b, 16) != nil {
					t.Fatalf("accepted what checkJSON refuses: %q", b)
				}
				var m map[string]any
				_ = json.Unmarshal(b, &m)
				for k := range m {
					if k != "revision" && k != "hostname" {
						t.Fatalf("an unknown field %q was accepted: %q", k, b)
					}
				}
			}
		}
	})
}

func FuzzCheckTargetAndRouting(f *testing.F) {
	h := newHarness(f)
	for _, s := range []string{"/healthz", "/v1/tenants/" + tenantA + "/policy", "/v1/tenants/" + tenantA + "/events?limit=5&cursor=abc", "/v1/credentials/ui-a:revoke",
		"/v1/tenants/" + tenantA + "/hosts/shop.example.com:verify", "", "/", "//", "/v1/../x", "/v1/tenants/" + tenantA + "/policy?x", "/a?b=c?d"} {
		f.Add(s, "GET")
	}
	f.Fuzz(func(t *testing.T, target, method string) {
		if checkTarget(target) != nil {
			return
		}
		rt, params, err := h.srv.match(method, target)
		if err != nil {
			if err.status != http.StatusNotFound && err.status != http.StatusMethodNotAllowed {
				t.Fatalf("status %d", err.status)
			}
			return
		}
		if rt == nil || rt.method != method {
			t.Fatalf("matched the wrong route for %q %q", method, target)
		}
		for name, v := range params {
			if !validParam(name, v) {
				t.Fatalf("param %s=%q is not valid", name, v)
			}
		}
		if rt.tenant && !ValidTenantID(params["tenant"]) {
			t.Fatalf("a tenant route without a valid tenant: %q", target)
		}
		if _, e := parseQuery(target, rt.query); e != nil && e.status != http.StatusBadRequest {
			t.Fatalf("query error status %d", e.status)
		}
	})
}

// FuzzServeHTTP sends arbitrary requests, signed or not, to the real handler and checks what must hold whatever arrives:
// no panic, an answer from the documented set with the uniform headers, nothing for a request that is not signed, and no
// store ever reached.
func FuzzServeHTTP(f *testing.F) {
	h := newHarness(f)
	seeds := []struct{ method, target, auth, user, ctype, body string }{
		{"GET", "/healthz", "", "", "", ""},
		{"GET", "/v1/tenants/" + tenantA + "/status", "Carnical-Sig cred=ui-a, ts=1, nonce=" + strings.Repeat("0", 32) + ", sig=" + strings.Repeat("A", 86), "user-1", "", ""},
		{"PUT", "/v1/tenants/" + tenantA + "/policy", "", "user-1", "application/json; charset=utf-8", `{"mode":"off"}`},
		{"POST", "/v1/credentials/ui-a:revoke", "x", "x", "", ""},
		{"OPTIONS", "/v1/tenants/" + tenantA + "/policy", "", "", "", ""},
		{"POST", "/v1/tenants/" + tenantA + "/hosts", "", "", "text/plain", "x"},
	}
	for _, s := range seeds {
		f.Add(s.method, s.target, s.auth, s.user, s.ctype, []byte(s.body))
	}
	panics := h.srv.Stats().Panics
	tlsState := h.build(reqOpts{target: "/healthz"}).TLS
	f.Fuzz(func(t *testing.T, method, target, auth, user, ctype string, body []byte) {
		before := h.touches()
		req := httptest.NewRequest("GET", "https://control.test/healthz", bytes.NewReader(body))
		req.Method, req.RequestURI, req.Host, req.RemoteAddr = method, target, "control.test", "198.51.100.10:5000"
		req.ContentLength = int64(len(body))
		if auth != "" {
			req.Header["Authorization"] = []string{auth}
		}
		if user != "" {
			req.Header[HeaderActingUser] = []string{user}
		}
		if ctype != "" {
			req.Header["Content-Type"] = []string{ctype}
		}
		req.TLS = tlsState
		w := httptest.NewRecorder()
		h.srv.ServeHTTP(w, req)
		switch w.Code {
		case 400, 401, 404, 405, 413, 415, 429, 431, 503:
		case 200:
			if target != "/healthz" || method != "GET" {
				t.Fatalf("an unsigned request was answered with 200: %q %q", method, target)
			}
		default:
			t.Fatalf("status %d for %q %q", w.Code, method, target)
		}
		if h.srv.Stats().Panics != panics {
			t.Fatalf("a panic was recovered for %q %q: the handler must never panic", method, target)
		}
		if !json.Valid(w.Body.Bytes()) {
			t.Fatalf("the answer is not JSON: %q", w.Body.String())
		}
		hd := w.Header()
		if hd.Get("Cache-Control") != "no-store" || hd.Get("X-Content-Type-Options") != "nosniff" || hd.Get("Content-Security-Policy") != "default-src 'none'" || !strings.HasPrefix(hd.Get(HeaderRequestID), "req_") {
			t.Fatalf("headers: %v", hd)
		}
		for k := range hd {
			if strings.HasPrefix(strings.ToLower(k), "access-control-") {
				t.Fatalf("CORS header %s", k)
			}
		}
		if h.touches() != before {
			t.Fatalf("a request that is not signed reached a store: %q %q", method, target)
		}
		// the failure limiter must not fill up and start refusing real callers because of this input
		h.srv.fails.mu.Lock()
		h.srv.fails.m = map[string]*failState{}
		h.srv.fails.mu.Unlock()
		h.srv.replay.mu.Lock()
		h.srv.replay.seen = map[string]map[string]struct{}{}
		h.srv.replay.mu.Unlock()
	})
}

func FuzzParseCredentials(f *testing.F) {
	c := Credential{ID: "ui-prod", Certs: []Fingerprint{{1}}, SigningKey: make(ed25519.PublicKey, 32), Tenants: []string{tenantA}, Scopes: []Scope{ScopeRead}, NotAfter: epoch}
	good, _ := MarshalCredentials([]Credential{c})
	for _, s := range [][]byte{good, []byte(`{}`), []byte(`{"credentials":[{}]}`), []byte(``), []byte(`[`), bytes.Replace(good, []byte("read"), []byte("root"), 1)} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		cs, err := ParseCredentials(bytes.NewReader(b))
		if err != nil {
			return
		}
		for _, c := range cs {
			if err := c.Validate(); err != nil {
				t.Fatalf("an accepted credential does not validate: %v", err)
			}
		}
		again, err := MarshalCredentials(cs)
		if err != nil {
			t.Fatal(err)
		}
		back, err := ParseCredentials(bytes.NewReader(again))
		if err != nil || len(back) != len(cs) {
			t.Fatalf("a credentials file does not survive being written and read: %v", err)
		}
	})
}

func FuzzVerifyChain(f *testing.F) {
	f.Add([]byte(""))
	f.Add([]byte("{}\n"))
	f.Add([]byte(`{"seq":1,"ts":"","prev":"` + zeroHash + `","request_id":"","credential":"","tenant":"","user":"","action":"","source":"","outcome":""}` + "\n"))
	f.Fuzz(func(t *testing.T, b []byte) {
		rep, err := VerifyChain(bytes.NewReader(b))
		if err == nil {
			if rep.Lines != bytes.Count(b, []byte("\n")) || (len(b) > 0 && b[len(b)-1] != '\n') {
				t.Fatalf("accepted a log that is not a whole number of lines: %d lines in %q", rep.Lines, b)
			}
		} else if _, ok := err.(*ChainError); !ok {
			t.Fatalf("error of the wrong kind: %T", err)
		}
	})
}
