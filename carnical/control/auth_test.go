// SPDX-License-Identifier: Apache-2.0

package control

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"
)

var ridRE = regexp.MustCompile(`req_[0-9a-f]{16}`)

// lastFailure returns the reason the most recent authentication failure was audited with.
func lastFailure(h *harness) (string, bool) {
	all := h.audit.all()
	for i := len(all) - 1; i >= 0; i-- {
		if all[i].Action == "authenticate" {
			return all[i].Detail, true
		}
	}
	return "", false
}

func body(doc string) []byte { return []byte(doc) }

func swapBody(r *http.Request, b []byte) {
	r.Body = io.NopCloser(bytes.NewReader(b))
	r.ContentLength = int64(len(b))
}

func editAuth(from, to string) func(r *http.Request) {
	return func(r *http.Request) {
		r.Header.Set("Authorization", strings.Replace(r.Header.Get("Authorization"), from, to, 1))
	}
}

func TestSignatureVerification(t *testing.T) {
	put := "/v1/tenants/" + tenantA + "/policy"
	status := "/v1/tenants/" + tenantA + "/status"
	events := "/v1/tenants/" + tenantA + "/events?limit=5"
	publish := "/v1/tenants/" + tenantA + "/publish"
	doc := `{"mode":"block","threshold":5}`
	okPut := func() reqOpts { return reqOpts{method: "PUT", target: put, body: body(doc), ifMatch: `"0"`} }
	okPublish := func() reqOpts {
		return reqOpts{method: "POST", target: publish, body: body(`{"revision":1}`), idem: "abcdefgh"}
	}
	nowSec := epoch.Unix()
	headerNonce := func(r *http.Request) string {
		m := regexp.MustCompile(`nonce=([0-9a-f]{32})`).FindStringSubmatch(r.Header.Get("Authorization"))
		return m[1]
	}
	_ = headerNonce

	rows := []struct {
		name   string
		o      func() reqOpts
		setup  func(h *harness)
		status int
		code   string // the error code
		reason string // the reason in the audit log, for authentication failures
	}{
		{name: "an untouched request", o: okPut, status: 200},
		{name: "an untouched GET", o: func() reqOpts { return reqOpts{target: status} }, status: 200},

		// each signed field changed after signing
		{name: "body: one byte changed", o: func() reqOpts {
			o := okPut()
			o.after = func(r *http.Request) { swapBody(r, body(strings.Replace(doc, "block", "BLOCK", 1))) }
			return o
		}, status: 401, code: "unauthenticated", reason: "bad_signature"},
		{name: "body: replaced by a weaker document of the same length", o: func() reqOpts {
			o := okPut()
			o.body = body(`{"mode":"block","threshold":5}`)
			o.after = func(r *http.Request) { swapBody(r, body(`{"mode":"off  ","threshold":5}`)) }
			return o
		}, status: 401, code: "unauthenticated", reason: "bad_signature"},
		{name: "body: a space added", o: func() reqOpts {
			o := okPut()
			o.after = func(r *http.Request) { swapBody(r, body(doc+" ")) }
			return o
		}, status: 401, reason: "bad_signature"},
		{name: "body: signed empty, sent full", o: func() reqOpts {
			o := okPut()
			o.hasSigned, o.signedBody = true, nil
			return o
		}, status: 401, reason: "bad_signature"},
		{name: "target: query value changed", o: func() reqOpts {
			return reqOpts{target: events, after: func(r *http.Request) { r.RequestURI = strings.Replace(r.RequestURI, "limit=5", "limit=6", 1) }}
		}, status: 401, reason: "bad_signature"},
		{name: "target: query removed", o: func() reqOpts {
			return reqOpts{target: events, after: func(r *http.Request) { r.RequestURI = "/v1/tenants/" + tenantA + "/events" }}
		}, status: 401, reason: "bad_signature"},
		{name: "target: query added", o: func() reqOpts {
			return reqOpts{target: "/v1/tenants/" + tenantA + "/events", after: func(r *http.Request) { r.RequestURI += "?limit=500" }}
		}, status: 401, reason: "bad_signature"},
		{name: "target: another route of the same tenant", o: func() reqOpts {
			return reqOpts{target: status, after: func(r *http.Request) { r.RequestURI = "/v1/tenants/" + tenantA + "/events" }}
		}, status: 401, reason: "bad_signature"},
		{name: "tenant: the path names another tenant the credential may also use", setup: func(h *harness) {
			h.addIdentity("multi", []string{tenantA, tenantB}, false, ScopeRead)
		}, o: func() reqOpts {
			return reqOpts{as: "multi", target: status, after: func(r *http.Request) { r.RequestURI = "/v1/tenants/" + tenantB + "/status" }}
		}, status: 401, reason: "bad_signature"},
		{name: "host: another host", o: func() reqOpts {
			return reqOpts{target: status, after: func(r *http.Request) { r.Host = "other.test" }}
		}, status: 401, reason: "bad_signature"},
		{name: "timestamp: moved by a second in the header", o: func() reqOpts {
			return reqOpts{target: status, after: editAuth("ts="+strconv.FormatInt(nowSec, 10), "ts="+strconv.FormatInt(nowSec+1, 10))}
		}, status: 401, reason: "bad_signature"},
		{name: "nonce: one digit changed", o: func() reqOpts {
			return reqOpts{target: status, nonce: "00000000000000000000000000000001", after: editAuth("nonce=00000000000000000000000000000001", "nonce=00000000000000000000000000000002")}
		}, status: 401, reason: "bad_signature"},
		{name: "credential: another existing credential, with this credential's certificate", o: func() reqOpts {
			return reqOpts{target: status, after: editAuth("cred=ui-a", "cred=ui-b")}
		}, status: 401, reason: "certificate_mismatch"},
		{name: "credential: one that does not exist", o: func() reqOpts {
			return reqOpts{target: status, after: editAuth("cred=ui-a", "cred=nobody-here")}
		}, status: 401, reason: "unknown_credential"},
		{name: "acting user: changed", o: func() reqOpts {
			return reqOpts{target: status, after: func(r *http.Request) { r.Header.Set(HeaderActingUser, "someone-else") }}
		}, status: 401, reason: "bad_signature"},
		{name: "acting user: removed", o: func() reqOpts {
			return reqOpts{target: status, after: func(r *http.Request) { r.Header.Del(HeaderActingUser) }}
		}, status: 401, reason: "malformed"},
		{name: "step-up: added after signing", o: func() reqOpts {
			return reqOpts{target: status, after: func(r *http.Request) { r.Header.Set(HeaderStepUp, strconv.FormatInt(nowSec, 10)) }}
		}, status: 401, reason: "bad_signature"},
		{name: "step-up: removed after signing", o: func() reqOpts {
			o := okPut()
			o.stepUp = nowSec
			o.after = func(r *http.Request) { r.Header.Del(HeaderStepUp) }
			return o
		}, status: 401, reason: "bad_signature"},
		{name: "step-up: made newer after signing", o: func() reqOpts {
			o := okPut()
			o.stepUp = nowSec - 1000
			o.after = func(r *http.Request) { r.Header.Set(HeaderStepUp, strconv.FormatInt(nowSec, 10)) }
			return o
		}, status: 401, reason: "bad_signature"},
		{name: "step-up: not a number", o: func() reqOpts {
			return reqOpts{target: status, after: func(r *http.Request) { r.Header.Set(HeaderStepUp, "yesterday") }}
		}, status: 401, reason: "malformed"},
		{name: "if-match: changed", o: func() reqOpts {
			o := okPut()
			o.after = func(r *http.Request) { r.Header.Set("If-Match", `"1"`) }
			return o
		}, status: 401, reason: "bad_signature"},
		{name: "if-match: removed", o: func() reqOpts {
			o := okPut()
			o.after = func(r *http.Request) { r.Header.Del("If-Match") }
			return o
		}, status: 401, reason: "bad_signature"},
		{name: "idempotency key: changed", setup: func(h *harness) { h.seed(tenantA, doc) }, o: func() reqOpts {
			o := okPublish()
			o.after = func(r *http.Request) { r.Header.Set("Idempotency-Key", "abcdefgi") }
			return o
		}, status: 401, reason: "bad_signature"},
		{name: "idempotency key: removed", setup: func(h *harness) { h.seed(tenantA, doc) }, o: func() reqOpts {
			o := okPublish()
			o.after = func(r *http.Request) { r.Header.Del("Idempotency-Key") }
			return o
		}, status: 401, reason: "bad_signature"},
		{name: "signature: one bit flipped", o: func() reqOpts {
			return reqOpts{target: status, after: func(r *http.Request) {
				a := r.Header.Get("Authorization")
				i := strings.Index(a, "sig=") + 4
				c := a[i]
				flip := byte('B')
				if c == 'B' {
					flip = 'C'
				}
				r.Header.Set("Authorization", a[:i]+string(flip)+a[i+1:])
			}}
		}, status: 401, reason: "bad_signature"},
		{name: "signature: truncated", o: func() reqOpts {
			return reqOpts{target: status, after: func(r *http.Request) {
				a := r.Header.Get("Authorization")
				r.Header.Set("Authorization", a[:len(a)-1])
			}}
		}, status: 401, reason: "malformed"},

		// the two halves of a credential, each alone
		{name: "a stolen certificate alone: the right certificate, another credential's key", o: func() reqOpts {
			return reqOpts{target: status, keyAs: "ui-b"}
		}, status: 401, reason: "bad_signature"},
		{name: "a stolen signing key alone: the right key, another credential's certificate", o: func() reqOpts {
			return reqOpts{target: status, certAs: "ui-b"}
		}, status: 401, reason: "certificate_mismatch"},
		{name: "no client certificate (a proxy that ended TLS)", o: func() reqOpts { return reqOpts{target: status, noTLS: true} }, status: 401, reason: "no_certificate"},
		{name: "TLS 1.2", o: func() reqOpts { return reqOpts{target: status, tlsVersion: tls.VersionTLS12} }, status: 401, reason: "no_certificate"},
		{name: "a certificate that was not verified against the CA", o: func() reqOpts { return reqOpts{target: status, noChain: true} }, status: 401, reason: "no_certificate"},

		// the credential's own state
		{name: "revoked", setup: func(h *harness) { h.setCred("ui-a", func(c *Credential) { c.Revoked = true }) }, o: func() reqOpts { return reqOpts{target: status} },
			status: 401, reason: "revoked"},
		{name: "expired a second ago", setup: func(h *harness) {
			h.setCred("ui-a", func(c *Credential) { c.NotAfter = epoch.Add(-time.Second) })
		}, o: func() reqOpts { return reqOpts{target: status} }, status: 401, reason: "expired"},
		{name: "expires at this very second", setup: func(h *harness) { h.setCred("ui-a", func(c *Credential) { c.NotAfter = epoch }) },
			o: func() reqOpts { return reqOpts{target: status} }, status: 401, reason: "expired"},
		{name: "expires in a second", setup: func(h *harness) { h.setCred("ui-a", func(c *Credential) { c.NotAfter = epoch.Add(time.Second) }) },
			o: func() reqOpts { return reqOpts{target: status} }, status: 200},
		{name: "source not in the allow-list", setup: func(h *harness) {
			h.setCred("ui-a", func(c *Credential) { c.Sources = []netipPrefix{mustPrefix("203.0.113.0/24")} })
		}, o: func() reqOpts { return reqOpts{target: status} }, status: 401, reason: "source_not_allowed"},
		{name: "source in the allow-list", setup: func(h *harness) {
			h.setCred("ui-a", func(c *Credential) { c.Sources = []netipPrefix{mustPrefix("198.51.100.0/24")} })
		}, o: func() reqOpts { return reqOpts{target: status} }, status: 200},
		{name: "an IPv6 source in an IPv6 allow-list", setup: func(h *harness) {
			h.setCred("ui-a", func(c *Credential) { c.Sources = []netipPrefix{mustPrefix("2001:db8::/32")} })
		}, o: func() reqOpts { return reqOpts{target: status, remote: "[2001:db8::7]:5000"} }, status: 200},
		{name: "a source that does not parse, with an allow-list", setup: func(h *harness) {
			h.setCred("ui-a", func(c *Credential) { c.Sources = []netipPrefix{mustPrefix("198.51.100.0/24")} })
		}, o: func() reqOpts { return reqOpts{target: status, remote: "pipe"} }, status: 401, reason: "source_not_allowed"},

		// time
		{name: "60 seconds fast", o: func() reqOpts { return reqOpts{target: status, ts: nowSec + 60} }, status: 200},
		{name: "61 seconds fast", o: func() reqOpts { return reqOpts{target: status, ts: nowSec + 61} }, status: 401, reason: "skew"},
		{name: "60 seconds slow", o: func() reqOpts { return reqOpts{target: status, ts: nowSec - 60} }, status: 200},
		{name: "61 seconds slow", o: func() reqOpts { return reqOpts{target: status, ts: nowSec - 61} }, status: 401, reason: "skew"},
		{name: "a year slow", o: func() reqOpts { return reqOpts{target: status, ts: nowSec - 365*86400} }, status: 401, reason: "skew"},

		// authorisation, after authentication
		{name: "wrong tenant: a credential for B on A", o: func() reqOpts { return reqOpts{as: "ui-b", target: status} }, status: 403, code: "forbidden"},
		{name: "wrong scope: read-only writing", o: func() reqOpts {
			return reqOpts{as: "reader-a", method: "PUT", target: put, body: body(doc), ifMatch: `"0"`}
		}, status: 403, code: "forbidden"},
		{name: "missing step-up on a weakening change", setup: func(h *harness) { h.seed(tenantA, doc) }, o: func() reqOpts {
			return reqOpts{method: "PUT", target: put, body: body(`{"mode":"off","threshold":5}`), ifMatch: `"1"`}
		}, status: 403, code: "step_up_required"},
		{name: "expired step-up (301 s)", setup: func(h *harness) { h.seed(tenantA, doc) }, o: func() reqOpts {
			return reqOpts{method: "PUT", target: put, body: body(`{"mode":"off","threshold":5}`), ifMatch: `"1"`, stepUp: nowSec - 301}
		}, status: 403, code: "step_up_required"},
		{name: "step-up of 300 s is fresh", setup: func(h *harness) { h.seed(tenantA, doc) }, o: func() reqOpts {
			return reqOpts{method: "PUT", target: put, body: body(`{"mode":"off","threshold":5}`), ifMatch: `"1"`, stepUp: nowSec - 300}
		}, status: 200},

		// the shape of the request
		{name: "oversized body", o: func() reqOpts {
			return reqOpts{method: "PUT", target: put, body: bytes.Repeat([]byte(" "), 256<<10+1), ifMatch: `"0"`}
		}, status: 413, code: "payload_too_large"},
		{name: "wrong content type", o: func() reqOpts {
			o := okPut()
			o.ctype = "text/plain"
			return o
		}, status: 415, code: "unsupported_media_type"},
		{name: "a smuggled header", o: func() reqOpts {
			return reqOpts{target: status, extra: http.Header{"X-Forwarded-For": {"203.0.113.9"}}}
		}, status: 400, code: "bad_request"},
		{name: "a duplicated acting-user header", o: func() reqOpts {
			return reqOpts{target: status, after: func(r *http.Request) { r.Header.Add(HeaderActingUser, "root") }}
		}, status: 400, code: "bad_request"},
		{name: "a duplicated Authorization header", o: func() reqOpts {
			return reqOpts{target: status, after: func(r *http.Request) { r.Header.Add("Authorization", r.Header.Get("Authorization")) }}
		}, status: 400, code: "bad_request"},
	}
	if len(rows) < 15 {
		t.Fatal("the table has shrunk")
	}
	var uniform []*httptest.ResponseRecorder
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			h := newHarness(t)
			if row.setup != nil {
				row.setup(h)
			}
			touchedBefore := h.touches()
			revBefore := h.store.revisions(tenantA)
			w := h.do(row.o())
			if w.Code != row.status {
				t.Fatalf("status %d, want %d: %.300s", w.Code, row.status, w.Body.String())
			}
			if row.status >= 400 {
				e := errorOf(t, w)
				want := row.code
				if row.status == 401 {
					want = "unauthenticated"
				}
				if want != "" && e.Code != want {
					t.Fatalf("code %q, want %q", e.Code, want)
				}
			}
			if row.status == 401 {
				reason, ok := lastFailure(h)
				if !ok {
					t.Fatal("an authentication failure was not audited")
				}
				if row.reason != "" && reason != row.reason {
					t.Fatalf("audited reason %q, want %q", reason, row.reason)
				}
				uniform = append(uniform, w)
			}
			// whatever is refused before the policy is looked at must not have reached any store or the validator
			if row.status == 401 || row.status == 400 || row.status == 413 || row.status == 415 || row.code == "forbidden" {
				if h.touches() != touchedBefore {
					t.Fatalf("a request that was refused as %d (%s) reached a store", row.status, row.code)
				}
			}
			if row.status >= 400 && h.store.revisions(tenantA) != revBefore {
				t.Fatal("a refused request changed the policy")
			}
		})
	}

	// Every authentication failure looks the same from outside: same status, same body but for the request id, same
	// headers but for the request id. That is what keeps "no such credential" from being told apart from "bad signature".
	t.Run("every authentication failure looks the same", func(t *testing.T) {
		if len(uniform) < 15 {
			t.Fatalf("only %d failures compared", len(uniform))
		}
		ref := uniform[0]
		refBody := ridRE.ReplaceAllString(ref.Body.String(), "RID")
		for i, w := range uniform {
			if w.Code != 401 {
				t.Fatalf("%d: status %d", i, w.Code)
			}
			if got := ridRE.ReplaceAllString(w.Body.String(), "RID"); got != refBody {
				t.Fatalf("failure %d has a different body:\n%s\n%s", i, got, refBody)
			}
			a, b := w.Header().Clone(), ref.Header().Clone()
			a.Del(HeaderRequestID)
			b.Del(HeaderRequestID)
			if !equalHeaders(a, b) {
				t.Fatalf("failure %d has different headers: %v vs %v", i, a, b)
			}
		}
	})
}

func equalHeaders(a, b http.Header) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if strings.Join(v, "\x00") != strings.Join(b[k], "\x00") {
			return false
		}
	}
	return true
}

func (h *harness) touches() int {
	n := h.store.total() + h.hosts.calls + h.events.calls + len(h.verify.calls) + h.pub.count()
	h.val.mu.Lock()
	n += h.val.calls
	h.val.mu.Unlock()
	return n
}

func TestAValidRequestIsAuditedAndNoneOfItsContentIsLogged(t *testing.T) {
	h := newHarness(t)
	h.putPolicy("ui-a", tenantA, `{"mode":"block","threshold":5,"note":"customer secret text"}`, 0, 0)
	h.do(reqOpts{target: "/v1/tenants/" + tenantA + "/policy"})
	for _, e := range h.audit.all() {
		if strings.Contains(e.Detail+e.Action+e.User+e.Tenant+e.Credential, "customer secret") {
			t.Fatalf("content in the audit log: %+v", e)
		}
		if e.RequestID == "" || e.Source != "198.51.100.10" || e.Credential != "ui-a" || e.User != "user-1" || e.Tenant != tenantA {
			t.Fatalf("entry lacks what it should carry: %+v", e)
		}
	}
	all := h.audit.all()
	if len(all) != 3 || all[0].Outcome != "started" || all[1].Outcome != "ok" || all[2].Action != "policy.get" {
		t.Fatalf("entries: %+v", all)
	}
	if all[1].RevBefore == nil || *all[1].RevBefore != 0 || all[1].RevAfter == nil || *all[1].RevAfter != 1 {
		t.Fatalf("revisions before and after: %+v", all[1])
	}
}

func TestReplay(t *testing.T) {
	h := newHarness(t)
	status := "/v1/tenants/" + tenantA + "/status"
	first := h.build(reqOpts{target: status})
	if w := h.serve(first); w.Code != 200 {
		t.Fatalf("first: %d", w.Code)
	}
	// the very same bytes, again
	again := h.build(reqOpts{target: status, nonce: nonceOf(first), ts: tsOf(first)})
	if w := h.serve(again); w.Code != 401 {
		t.Fatalf("an exact replay: %d", w.Code)
	}
	if r, _ := lastFailure(h); r != "replay" {
		t.Fatalf("reason %q", r)
	}
	// the same nonce with a fresh signature is also a replay: the nonce is what is remembered
	same := h.build(reqOpts{target: status, nonce: nonceOf(first), ts: tsOf(first) + 1})
	if w := h.serve(same); w.Code != 401 {
		t.Fatalf("a reused nonce: %d", w.Code)
	}
	// another credential may use the same nonce: nonces are per credential
	other := h.build(reqOpts{as: "reader-a", target: status, nonce: nonceOf(first), ts: tsOf(first)})
	if w := h.serve(other); w.Code != 200 {
		t.Fatalf("the same nonce for another credential: %d", w.Code)
	}
	// once the request is too old to be accepted anyway, its nonce has been forgotten and costs no memory
	if n := h.srv.replay.size(); n != 2 {
		t.Fatalf("%d nonces remembered", n)
	}
	h.clock.advance(2 * time.Minute)
	h.do(reqOpts{target: status}) // any request purges
	if n := h.srv.replay.size(); n != 1 {
		t.Fatalf("%d nonces remembered after the window", n)
	}
}

func nonceOf(r *http.Request) string {
	return regexp.MustCompile(`nonce=([0-9a-f]{32})`).FindStringSubmatch(r.Header.Get("Authorization"))[1]
}

func tsOf(r *http.Request) int64 {
	n, _ := strconv.ParseInt(regexp.MustCompile(`ts=(\d+)`).FindStringSubmatch(r.Header.Get("Authorization"))[1], 10, 64)
	return n
}

func TestAFailedRequestDoesNotBurnItsNonce(t *testing.T) {
	// a nonce is remembered only once the signature has been verified, so nobody without a key can use up nonces
	h := newHarness(t)
	status := "/v1/tenants/" + tenantA + "/status"
	r := h.build(reqOpts{target: status, keyAs: "ui-b"}) // wrong key
	if w := h.serve(r); w.Code != 401 {
		t.Fatalf("%d", w.Code)
	}
	if n := h.srv.replay.size(); n != 0 {
		t.Fatalf("a failed request left %d nonces", n)
	}
	if w := h.do(reqOpts{target: status, nonce: nonceOf(r)}); w.Code != 200 {
		t.Fatalf("the nonce of a failed request was burnt: %d", w.Code)
	}
}

func TestReplayCacheFullRefusesAndSaysSo(t *testing.T) {
	h := newHarness(t, func(c *Config) { c.Limits.ReplayMax = 5; c.Limits.ReplayMaxPerCredential = 3 })
	status := "/v1/tenants/" + tenantA + "/status"
	nonces := make([]string, 0, 3)
	for i := 0; i < 3; i++ {
		r := h.build(reqOpts{target: status})
		nonces = append(nonces, nonceOf(r))
		if w := h.serve(r); w.Code != 200 {
			t.Fatalf("request %d: %d", i, w.Code)
		}
	}
	w := h.do(reqOpts{target: status})
	if w.Code != 503 || errorOf(t, w).Code != "replay_cache_full" || w.Header().Get("Retry-After") == "" {
		t.Fatalf("a full cache: %d %s", w.Code, w.Body.String())
	}
	if h.srv.Stats().ReplayFull != 1 {
		t.Fatalf("stats: %+v", h.srv.Stats())
	}
	if r, _ := lastFailure(h); r != "replay_cache_full" {
		t.Fatalf("audited reason %q", r)
	}
	// it did not forget: the three nonces are still refused
	for i, n := range nonces {
		if w := h.do(reqOpts{target: status, nonce: n}); w.Code == 200 {
			t.Fatalf("nonce %d was forgotten to make room", i)
		}
	}
	// another credential is not starved by this one
	if w := h.do(reqOpts{as: "reader-a", target: status}); w.Code != 200 {
		t.Fatalf("another credential: %d", w.Code)
	}
	// and once the window has passed the cache drains and accepts requests again
	h.clock.advance(2 * time.Minute)
	if w := h.do(reqOpts{target: status}); w.Code != 200 {
		t.Fatalf("after the window: %d", w.Code)
	}
}

func TestTheServerRefusesAnUnusableCredentialStore(t *testing.T) {
	// a store that hands back a credential with no key must not make the signature check panic
	h := newHarness(t, func(c *Config) { c.Credentials = brokenCreds{c.Credentials} })
	w := h.do(reqOpts{target: "/v1/tenants/" + tenantA + "/status"})
	if w.Code != 401 || h.srv.Stats().Panics != 0 {
		t.Fatalf("%d, panics %d", w.Code, h.srv.Stats().Panics)
	}
	if r, _ := lastFailure(h); r != "bad_credential" {
		t.Fatalf("reason %q", r)
	}
}

type brokenCreds struct{ CredentialStore }

func (b brokenCreds) Lookup(id string) (Credential, bool) {
	c, ok := b.CredentialStore.Lookup(id)
	c.SigningKey = nil
	return c, ok
}

func TestCertificatesOutsideTheirValidityAreRefused(t *testing.T) {
	status := "/v1/tenants/" + tenantA + "/status"
	for _, tc := range []struct {
		name       string
		notBefore  time.Time
		notAfter   time.Time
		wantStatus int
	}{
		{"valid", epoch.Add(-time.Hour), epoch.Add(time.Hour), 200},
		{"expired a second ago", epoch.Add(-48 * time.Hour), epoch.Add(-time.Second), 401},
		{"not yet valid", epoch.Add(time.Second), epoch.Add(time.Hour), 401},
		{"expires this second", epoch.Add(-time.Hour), epoch, 200}, // NotAfter is inclusive in x509
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t)
			// a connection can outlive the certificate it began with, so the validity is checked on every request
			id := h.ids["ui-a"]
			id.cert = h.pki.issue(issueOpts{cn: "stale", notBefore: tc.notBefore, notAfter: tc.notAfter})
			id.cred.Certs = []Fingerprint{SPKIFingerprint(id.cert.cert)}
			h.refreshCreds()
			if w := h.do(reqOpts{target: status}); w.Code != tc.wantStatus {
				t.Fatalf("status %d, want %d", w.Code, tc.wantStatus)
			}
		})
	}
}

func TestSeveralCertificatesPerCredential(t *testing.T) {
	h := newHarness(t)
	second := h.addIdentity("ui-a-second", []string{tenantB}, false, ScopeRead).cert
	h.setCred("ui-a", func(c *Credential) { c.Certs = append(c.Certs, SPKIFingerprint(second.cert)) })
	status := "/v1/tenants/" + tenantA + "/status"
	if w := h.do(reqOpts{target: status}); w.Code != 200 {
		t.Fatalf("first certificate: %d", w.Code)
	}
	if w := h.do(reqOpts{as: "ui-a", certAs: "ui-a-second", target: status}); w.Code != 200 {
		t.Fatalf("second certificate: %d", w.Code)
	}
	h.setCred("ui-a", func(c *Credential) { c.Certs = c.Certs[1:] })
	if w := h.do(reqOpts{target: status}); w.Code != 401 {
		t.Fatalf("a certificate that was removed from the credential: %d", w.Code)
	}
}

func TestAllTenantsCredentialsAreOffUnlessEnabled(t *testing.T) {
	h := newHarness(t, func(c *Config) { c.AllowAllTenants = false })
	if w := h.do(reqOpts{as: "admin", target: "/v1/tenants/" + tenantC + "/status"}); w.Code != 403 {
		t.Fatalf("an all-tenants credential on a server that does not allow them: %d", w.Code)
	}
	if w := h.do(reqOpts{as: "admin", target: "/v1/credentials"}); w.Code != 403 {
		t.Fatalf("credential management without AllowAllTenants: %d", w.Code)
	}
	h2 := newHarness(t)
	if w := h2.do(reqOpts{as: "admin", target: "/v1/tenants/" + tenantC + "/status"}); w.Code != 200 {
		t.Fatalf("an all-tenants credential on a server that allows them: %d", w.Code)
	}
}

func TestParseTLSStateHelpers(t *testing.T) {
	// peerFingerprint on its own: the pieces a request must carry
	h := newHarness(t)
	req := h.build(reqOpts{target: "/healthz"})
	if _, ok := peerFingerprint(req, epoch); !ok {
		t.Fatal("a good connection was refused")
	}
	req.TLS.PeerCertificates = []*x509.Certificate{}
	if _, ok := peerFingerprint(req, epoch); ok {
		t.Fatal("a connection with no certificate was accepted")
	}
	req.TLS = &tls.ConnectionState{}
	if _, ok := peerFingerprint(req, epoch); ok {
		t.Fatal("an unfinished handshake was accepted")
	}
}
