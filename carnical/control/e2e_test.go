// SPDX-License-Identifier: Apache-2.0

package control

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// e2e is the whole thing over a real TLS listener: the server from TLSConfig, the HTTP server from HTTPServer, the
// harness's fakes behind it, and the Go client in front. The clock is the real one.
type e2e struct {
	*harness
	addr   string
	port   string
	base   string
	srv    *http.Server
	tlsr   *TLSReloader
	server *issued
	dir    string

	hookMu sync.Mutex
	hook   func(r *http.Request)
}

func newE2E(t *testing.T, tweak ...func(*Config)) *e2e {
	t.Helper()
	return newE2EWith(t, nil, tweak...)
}

// newE2EWith is newE2E with a say in how the HTTP server is set up before it starts serving.
func newE2EWith(t *testing.T, httpTweak func(*http.Server), tweak ...func(*Config)) *e2e {
	t.Helper()
	tweak = append([]func(*Config){func(c *Config) { c.Now = nil }}, tweak...)
	h := newHarness(t, tweak...)
	server := h.pki.server()
	dir := t.TempDir()
	certFile, keyFile, caFile := h.pki.files(dir, server)
	r, err := NewTLSReloader(TLSOptions{CertFile: certFile, KeyFile: keyFile, ClientCAFile: caFile})
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	e := &e2e{harness: h, addr: ln.Addr().String(), server: server, dir: dir, tlsr: r}
	hs := h.srv.HTTPServer(r.Config())
	inner := hs.Handler
	// a test can look at each request before the server does, without touching the server while it runs
	hs.Handler = http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		e.hookMu.Lock()
		f := e.hook
		e.hookMu.Unlock()
		if f != nil {
			f(req)
		}
		inner.ServeHTTP(w, req)
	})
	if httpTweak != nil {
		httpTweak(hs)
	}
	go func() { _ = hs.ServeTLS(ln, "", "") }()
	t.Cleanup(func() { hs.Close() })
	_, e.port, _ = net.SplitHostPort(e.addr)
	e.base, e.srv = "https://localhost:"+e.port, hs
	return e
}

func (e *e2e) onRequest(f func(r *http.Request)) {
	e.hookMu.Lock()
	e.hook = f
	e.hookMu.Unlock()
}

func (e *e2e) client(name string, tweak ...func(*ClientConfig)) *Client {
	e.t.Helper()
	id := e.ids[name]
	cfg := ClientConfig{BaseURL: e.base, CredentialID: id.cred.ID, SigningKey: id.priv, Certificate: &id.cert.tls, RootCAs: e.pki.pool(), Timeout: 10 * time.Second}
	for _, f := range tweak {
		f(&cfg)
	}
	c, err := NewClient(cfg)
	if err != nil {
		e.t.Fatal(err)
	}
	e.t.Cleanup(c.CloseIdleConnections)
	return c
}

func TestEndToEndOverRealTLS(t *testing.T) {
	t.Run("publish retry lifetime", func(t *testing.T) {
		clock := &fakeClock{t: time.Now()}
		e := newE2E(t, func(c *Config) {
			c.Now = clock.now
			c.Limits.IdempotencyTTL = 100 * time.Millisecond
		})
		e.seed(tenantA, `{"mode":"block"}`)
		c := e.client("ui-a", func(c *ClientConfig) { c.Now = clock.now })
		gate := make(chan struct{})
		e.pub.gate, e.pub.in = gate, make(chan struct{}, 2)
		type reply struct {
			seq uint64
			err error
		}
		publish := func(ch chan reply) {
			seq, err := c.Publish(context.Background(), tenantA, 1, "slow-retry-1", Actor{User: "user-1"})
			ch <- reply{seq, err}
		}
		first, retry := make(chan reply, 1), make(chan reply, 1)
		go publish(first)
		select {
		case <-e.pub.in:
		case <-time.After(5 * time.Second):
			close(gate)
			t.Fatal("publish did not start")
		}
		clock.advance(2 * time.Second)
		go publish(retry)
		var retryReply reply
		var duplicate bool
		select {
		case retryReply = <-retry:
			var ae *APIError
			if !errors.As(retryReply.err, &ae) || ae.Status != 409 || ae.Code != "in_progress" {
				t.Errorf("retry while unfinished: %+v", retryReply)
			}
		case <-e.pub.in:
			duplicate = true
			t.Error("retry invoked the publisher again while the first publish was unfinished")
		case <-time.After(5 * time.Second):
			t.Error("retry did not answer")
		}
		close(gate)
		firstReply := <-first
		if duplicate {
			retryReply = <-retry
		}
		if firstReply.err != nil || firstReply.seq != 1001 {
			t.Errorf("first publish: %+v", firstReply)
		}
		if n := e.pub.count(); n != 1 {
			t.Errorf("publisher ran %d times, want one", n)
		}
		// Successful completion starts a full retention period, even when the
		// operation took longer than that period to finish.
		seq, err := c.Publish(context.Background(), tenantA, 1, "slow-retry-1", Actor{User: "user-1"})
		if err != nil || seq != firstReply.seq || e.pub.count() != 1 {
			t.Errorf("completed publish was not replayed: sequence=%d err=%v calls=%d", seq, err, e.pub.count())
		}
		clock.advance(100 * time.Millisecond)
		seq, err = c.Publish(context.Background(), tenantA, 1, "slow-retry-1", Actor{User: "user-1"})
		if err != nil || seq != 1002 || e.pub.count() != 2 {
			t.Errorf("completed key did not expire: sequence=%d err=%v calls=%d", seq, err, e.pub.count())
		}
	})
	e := newE2E(t)
	c := e.client("ui-a")
	ctx := context.Background()
	actor := Actor{User: "user-1"}

	// nothing yet
	_, _, err := c.GetPolicy(ctx, tenantA, actor)
	var ae *APIError
	if !errors.As(err, &ae) || ae.Status != 404 || ae.Code != "no_policy" || !strings.HasPrefix(ae.RequestID, "req_") {
		t.Fatalf("no policy: %v", err)
	}
	// write, read back, publish
	rev, err := c.PutPolicy(ctx, tenantA, 0, []byte(`{"mode":"block","threshold":5}`), actor)
	if err != nil || rev != 1 {
		t.Fatalf("put: %d %v", rev, err)
	}
	got, doc, err := c.GetPolicy(ctx, tenantA, actor)
	if err != nil || got != 1 || !strings.Contains(string(doc), `"threshold":5`) {
		t.Fatalf("get: %d %s %v", got, doc, err)
	}
	seq, err := c.Publish(ctx, tenantA, 1, "e2e-publish-1", actor)
	if err != nil || seq != 1001 {
		t.Fatalf("publish: %d %v", seq, err)
	}
	// a stale write is a precondition failure, with the revision to ask for
	_, err = c.PutPolicy(ctx, tenantA, 0, []byte(`{"mode":"block","threshold":4}`), actor)
	if !errors.As(err, &ae) || ae.Status != 412 {
		t.Fatalf("stale: %v", err)
	}
	// a weakening change: refused with the changes named, then accepted with a step-up
	_, err = c.PutPolicy(ctx, tenantA, 1, []byte(`{"mode":"off","threshold":5}`), actor)
	if !errors.As(err, &ae) || ae.Status != 403 || ae.Code != "step_up_required" || len(ae.Weakening) != 1 || ae.Weakening[0].Code != "mode_lowered" {
		t.Fatalf("weakening: %v", err)
	}
	rev, err = c.PutPolicy(ctx, tenantA, 1, []byte(`{"mode":"off","threshold":5}`), Actor{User: "user-1", StepUp: time.Now()})
	if err != nil || rev != 2 {
		t.Fatalf("with a step-up: %d %v", rev, err)
	}
	// another tenant is refused
	if _, _, err := c.GetPolicy(ctx, tenantB, actor); !errors.As(err, &ae) || ae.Status != 403 {
		t.Fatalf("another tenant: %v", err)
	}
	// the audit log has all of it, from the real remote address
	var sawSource bool
	for _, a := range e.audit.all() {
		if a.Source == "127.0.0.1" && a.Credential == "ui-a" {
			sawSource = true
		}
	}
	if !sawSource {
		t.Fatalf("the audit log has no entry from 127.0.0.1: %+v", e.audit.all())
	}
	if e.srv.TLSConfig.MinVersion != tls.VersionTLS13 || e.srv.ReadHeaderTimeout == 0 || e.srv.ReadTimeout == 0 || e.srv.WriteTimeout == 0 || e.srv.IdleTimeout == 0 || e.srv.MaxHeaderBytes != 16<<10 {
		t.Fatalf("the HTTP server has no timeouts or limits: %+v", e.srv)
	}
}

func TestBothHTTPVersionsWork(t *testing.T) {
	e := newE2E(t)
	h2 := e.client("ui-a")
	h1 := e.client("ui-a")
	h1.hc.Transport.(*http.Transport).TLSClientConfig.NextProtos = []string{"http/1.1"}
	h1.hc.Transport.(*http.Transport).ForceAttemptHTTP2 = false
	for name, c := range map[string]*Client{"HTTP/2.0": h2, "HTTP/1.1": h1} {
		for i := 0; i < 3; i++ {
			r, err := c.Do(context.Background(), Call{Method: "GET", Target: "/v1/tenants/" + tenantA + "/status", ActingUser: "user-1"})
			if err != nil || r.Status != 200 || r.Proto != name {
				t.Fatalf("%s: %+v %v", name, r, err)
			}
		}
	}
}

func TestTheTwoHalvesOfACredentialAreBothNeeded(t *testing.T) {
	e := newE2E(t)
	status := Call{Method: "GET", Target: "/v1/tenants/" + tenantA + "/status", ActingUser: "user-1"}
	do := func(c *Client) (int, string) {
		r, err := c.Do(context.Background(), status)
		if err != nil {
			t.Fatal(err)
		}
		if e := r.Err(); e != nil {
			return r.Status, e.Code
		}
		return r.Status, ""
	}
	t.Run("both", func(t *testing.T) {
		if s, _ := do(e.client("ui-a")); s != 200 {
			t.Fatalf("%d", s)
		}
	})
	t.Run("the right certificate, another credential's key", func(t *testing.T) {
		c := e.client("ui-a", func(cfg *ClientConfig) { cfg.SigningKey = e.ids["ui-b"].priv })
		if s, _ := do(c); s != 401 {
			t.Fatalf("%d", s)
		}
	})
	t.Run("the right key, a valid certificate that is not the credential's", func(t *testing.T) {
		c := e.client("ui-a", func(cfg *ClientConfig) { cfg.Certificate = &e.ids["ui-b"].cert.tls })
		if s, _ := do(c); s != 401 {
			t.Fatalf("%d", s)
		}
	})
	t.Run("a valid certificate and no signature at all (a proxy that holds the certificate)", func(t *testing.T) {
		hc := e.rawClient("ui-a")
		resp, err := hc.Get(e.base + "/v1/tenants/" + tenantA + "/status")
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		if resp.StatusCode != 401 || !strings.Contains(string(b), `"unauthenticated"`) {
			t.Fatalf("%d %s", resp.StatusCode, b)
		}
	})
	t.Run("a signature and no certificate (a TLS-terminating proxy in the middle)", func(t *testing.T) {
		hc := e.rawClient("")
		resp, err := hc.Get(e.base + "/healthz")
		if err == nil {
			resp.Body.Close()
			t.Fatalf("the handshake succeeded without a client certificate: %d", resp.StatusCode)
		}
	})
	t.Run("a certificate that chains to the CA but is not the credential's", func(t *testing.T) {
		stranger := e.pki.client("stranger")
		hc := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: e.pki.pool(), Certificates: []tls.Certificate{stranger.tls}}}}
		resp, err := hc.Get(e.base + "/v1/tenants/" + tenantA + "/status")
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != 401 {
			t.Fatalf("%d", resp.StatusCode)
		}
	})
}

// rawClient is a plain HTTP client with the identity's certificate (or none), for requests the Client would never make.
func (e *e2e) rawClient(name string) *http.Client {
	cfg := &tls.Config{RootCAs: e.pki.pool(), MinVersion: tls.VersionTLS13}
	if name != "" {
		cfg.Certificates = []tls.Certificate{e.ids[name].cert.tls}
	}
	return &http.Client{Transport: &http.Transport{TLSClientConfig: cfg, ForceAttemptHTTP2: true}, Timeout: 10 * time.Second}
}

func TestSourceAddressAllowListOverRealConnections(t *testing.T) {
	e := newE2E(t)
	call := Call{Method: "GET", Target: "/v1/tenants/" + tenantA + "/status", ActingUser: "user-1"}
	for _, tc := range []struct {
		name    string
		sources []string
		want    int
	}{
		{"the loopback address is listed", []string{"127.0.0.1/32"}, 200},
		{"a range that includes it", []string{"127.0.0.0/8"}, 200},
		{"another network only", []string{"203.0.113.0/24"}, 401},
		{"IPv6 only", []string{"2001:db8::/32"}, 401},
		{"no list", nil, 200},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e.setCred("ui-a", func(c *Credential) {
				c.Sources = nil
				for _, s := range tc.sources {
					c.Sources = append(c.Sources, mustPrefix(s))
				}
			})
			r, err := e.client("ui-a").Do(context.Background(), call)
			if err != nil || r.Status != tc.want {
				t.Fatalf("%+v %v", r, err)
			}
		})
	}
}

func TestClientPinsAndChecksTheServer(t *testing.T) {
	e := newE2E(t)
	call := Call{Method: "GET", Target: "/v1/tenants/" + tenantA + "/status", ActingUser: "user-1"}
	t.Run("the right pin", func(t *testing.T) {
		c := e.client("ui-a", func(cfg *ClientConfig) { cfg.PinnedSPKI = []Fingerprint{SPKIFingerprint(e.server.cert)} })
		if r, err := c.Do(context.Background(), call); err != nil || r.Status != 200 {
			t.Fatalf("%v", err)
		}
	})
	t.Run("one of several pins", func(t *testing.T) {
		c := e.client("ui-a", func(cfg *ClientConfig) {
			cfg.PinnedSPKI = []Fingerprint{{1}, SPKIFingerprint(e.server.cert), {2}}
		})
		if _, err := c.Do(context.Background(), call); err != nil {
			t.Fatalf("%v", err)
		}
	})
	t.Run("a pin that is not the server's key", func(t *testing.T) {
		c := e.client("ui-a", func(cfg *ClientConfig) { cfg.PinnedSPKI = []Fingerprint{{1}} })
		if _, err := c.Do(context.Background(), call); !errors.Is(err, ErrPin) {
			t.Fatalf("%v", err)
		}
	})
	t.Run("the pin of another certificate from the same CA", func(t *testing.T) {
		other := e.pki.server()
		c := e.client("ui-a", func(cfg *ClientConfig) { cfg.PinnedSPKI = []Fingerprint{SPKIFingerprint(other.cert)} })
		if _, err := c.Do(context.Background(), call); !errors.Is(err, ErrPin) {
			t.Fatalf("%v", err)
		}
	})
	t.Run("a pin does not replace the normal checks", func(t *testing.T) {
		c := e.client("ui-a", func(cfg *ClientConfig) {
			cfg.PinnedSPKI = []Fingerprint{SPKIFingerprint(e.server.cert)}
			cfg.RootCAs = newPKI(t).pool() // a CA that did not issue the server's certificate
		})
		if _, err := c.Do(context.Background(), call); err == nil {
			t.Fatal("a pinned key was trusted although its certificate does not chain to the CA")
		}
	})
	t.Run("a server the client does not trust", func(t *testing.T) {
		c := e.client("ui-a", func(cfg *ClientConfig) { cfg.RootCAs = newPKI(t).pool() })
		if _, err := c.Do(context.Background(), call); err == nil {
			t.Fatal("trusted a server of another CA")
		}
	})
	t.Run("the wrong name", func(t *testing.T) {
		c := e.client("ui-a", func(cfg *ClientConfig) { cfg.ServerName = "other.test" })
		if _, err := c.Do(context.Background(), call); err == nil {
			t.Fatal("accepted a certificate for another name")
		}
	})
	t.Run("a server that only speaks TLS 1.2", func(t *testing.T) {
		ln, _ := net.Listen("tcp", "127.0.0.1:0")
		cfg := &tls.Config{Certificates: []tls.Certificate{e.server.tls}, MaxVersion: tls.VersionTLS12}
		hs := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}), TLSConfig: cfg}
		go func() { _ = hs.ServeTLS(ln, "", "") }()
		defer hs.Close()
		_, port, _ := net.SplitHostPort(ln.Addr().String())
		c := e.client("ui-a", func(cfg *ClientConfig) { cfg.BaseURL = "https://localhost:" + port })
		if _, err := c.Do(context.Background(), call); err == nil {
			t.Fatal("spoke TLS 1.2")
		}
	})
}

func TestClientLimits(t *testing.T) {
	e := newE2E(t)
	serve := func(h http.HandlerFunc) string {
		ln, _ := net.Listen("tcp", "127.0.0.1:0")
		hs := &http.Server{Handler: h, TLSConfig: &tls.Config{Certificates: []tls.Certificate{e.server.tls}}}
		go func() { _ = hs.ServeTLS(ln, "", "") }()
		t.Cleanup(func() { hs.Close() })
		_, port, _ := net.SplitHostPort(ln.Addr().String())
		return "https://localhost:" + port
	}
	call := Call{Method: "GET", Target: "/v1/tenants/" + tenantA + "/status", ActingUser: "user-1"}
	t.Run("a redirect is never followed", func(t *testing.T) {
		var followed atomic.Bool
		for _, code := range []int{301, 302, 303, 307, 308} {
			target := serve(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/elsewhere" {
					followed.Store(true)
				}
				http.Redirect(w, r, "/elsewhere", code)
			})
			c := e.client("ui-a", func(cfg *ClientConfig) { cfg.BaseURL = target })
			if _, err := c.Do(context.Background(), call); !errors.Is(err, ErrRedirect) {
				t.Fatalf("%d: %v", code, err)
			}
		}
		if followed.Load() {
			t.Fatal("the redirect was followed, and the signed request with it")
		}
	})
	t.Run("a response over the limit", func(t *testing.T) {
		big := bytes.Repeat([]byte("a"), 2000)
		known := serve(func(w http.ResponseWriter, r *http.Request) { w.Write(big) })
		chunked := serve(func(w http.ResponseWriter, r *http.Request) {
			f := w.(http.Flusher)
			for i := 0; i < 5; i++ {
				w.Write(big)
				f.Flush()
			}
		})
		for name, u := range map[string]string{"declared": known, "chunked": chunked} {
			c := e.client("ui-a", func(cfg *ClientConfig) { cfg.BaseURL = u; cfg.MaxResponse = 1000 })
			if _, err := c.Do(context.Background(), call); !errors.Is(err, ErrResponseTooLarge) {
				t.Fatalf("%s: %v", name, err)
			}
		}
		// exactly at the limit is fine
		c := e.client("ui-a", func(cfg *ClientConfig) { cfg.BaseURL = known; cfg.MaxResponse = 2000 })
		if r, err := c.Do(context.Background(), call); err != nil || len(r.Body) != 2000 {
			t.Fatalf("%v", err)
		}
	})
	t.Run("a server that does not answer in time", func(t *testing.T) {
		stop := make(chan struct{})
		t.Cleanup(func() { close(stop) })
		slow := serve(func(w http.ResponseWriter, r *http.Request) {
			select {
			case <-stop:
			case <-time.After(5 * time.Second):
			}
		})
		c := e.client("ui-a", func(cfg *ClientConfig) { cfg.BaseURL = slow; cfg.Timeout = 300 * time.Millisecond })
		start := time.Now()
		if _, err := c.Do(context.Background(), call); err == nil {
			t.Fatal("no error")
		}
		if d := time.Since(start); d > 3*time.Second {
			t.Fatalf("took %v", d)
		}
	})
	t.Run("a server that drips its answer", func(t *testing.T) {
		stop := make(chan struct{})
		t.Cleanup(func() { close(stop) })
		drip := serve(func(w http.ResponseWriter, r *http.Request) {
			f := w.(http.Flusher)
			w.WriteHeader(200)
			for i := 0; i < 100; i++ {
				select {
				case <-stop:
					return
				case <-time.After(100 * time.Millisecond):
				}
				w.Write([]byte("x"))
				f.Flush()
			}
		})
		c := e.client("ui-a", func(cfg *ClientConfig) { cfg.BaseURL = drip; cfg.Timeout = 500 * time.Millisecond })
		start := time.Now()
		if _, err := c.Do(context.Background(), call); err == nil {
			t.Fatal("no error")
		}
		if d := time.Since(start); d > 3*time.Second {
			t.Fatalf("took %v: the overall timeout does not cover reading the answer", d)
		}
	})
	t.Run("the environment's proxy is not used", func(t *testing.T) {
		t.Setenv("HTTPS_PROXY", "http://127.0.0.1:1")
		t.Setenv("https_proxy", "http://127.0.0.1:1")
		t.Setenv("ALL_PROXY", "http://127.0.0.1:1")
		if r, err := e.client("ui-a").Do(context.Background(), call); err != nil || r.Status != 200 {
			t.Fatalf("%v", err)
		}
	})
	t.Run("the context cancels a call", func(t *testing.T) {
		stop := make(chan struct{})
		t.Cleanup(func() { close(stop) })
		slow := serve(func(w http.ResponseWriter, r *http.Request) { <-stop })
		ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
		defer cancel()
		c := e.client("ui-a", func(cfg *ClientConfig) { cfg.BaseURL = slow })
		if _, err := c.Do(ctx, call); err == nil {
			t.Fatal("no error")
		}
	})
}

func TestClientConfigIsChecked(t *testing.T) {
	e := newE2E(t)
	id := e.ids["ui-a"]
	base := func() ClientConfig {
		return ClientConfig{BaseURL: e.base, CredentialID: "ui-a", SigningKey: id.priv, Certificate: &id.cert.tls, RootCAs: e.pki.pool()}
	}
	rows := []struct {
		name   string
		change func(c *ClientConfig)
		ok     bool
	}{
		{"good", func(c *ClientConfig) {}, true},
		{"plain http", func(c *ClientConfig) { c.BaseURL = "http://localhost:1" }, false},
		{"a user name in the address", func(c *ClientConfig) { c.BaseURL = "https://user:pw@localhost:1" }, false},
		{"a path in the address", func(c *ClientConfig) { c.BaseURL = "https://localhost:1/v1" }, false},
		{"a query in the address", func(c *ClientConfig) { c.BaseURL = "https://localhost:1?x=1" }, false},
		{"a fragment", func(c *ClientConfig) { c.BaseURL = "https://localhost:1#x" }, false},
		{"no host", func(c *ClientConfig) { c.BaseURL = "https://" }, false},
		{"a bare slash is fine", func(c *ClientConfig) { c.BaseURL = e.base + "/" }, true},
		{"a bad credential id", func(c *ClientConfig) { c.CredentialID = "UI A" }, false},
		{"no key", func(c *ClientConfig) { c.SigningKey = nil }, false},
		{"a short key", func(c *ClientConfig) { c.SigningKey = id.priv[:10] }, false},
		{"no certificate", func(c *ClientConfig) { c.Certificate = nil }, false},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			cfg := base()
			row.change(&cfg)
			if _, err := NewClient(cfg); (err == nil) != row.ok {
				t.Fatalf("err = %v, want ok = %v", err, row.ok)
			}
		})
	}
	c := e.client("ui-a")
	for _, call := range []Call{
		{Method: "DELETE", Target: "/v1/credentials", ActingUser: "u"},
		{Method: "GET", Target: "v1/credentials", ActingUser: "u"},
		{Method: "GET", Target: "/v1/Credentials", ActingUser: "u"},
		{Method: "GET", Target: "/v1/credentials?q=a b", ActingUser: "u"},
		{Method: "GET", Target: "/v1/credentials", ActingUser: ""},
		{Method: "GET", Target: "/v1/credentials", ActingUser: "a b"},
		{Method: "PUT", Target: "/v1/x", ActingUser: "u", Body: bytes.Repeat([]byte("a"), 256<<10+1)},
		{Method: "PUT", Target: "/v1/x", ActingUser: "u", IdempotencyKey: "-"},
	} {
		if _, err := c.Do(context.Background(), call); err == nil {
			t.Fatalf("the client sent %+v", call)
		}
	}
}

func TestReplayOverRealTLS(t *testing.T) {
	e := newE2E(t)
	id := e.ids["ui-a"]
	hc := e.rawClient("ui-a")
	hc.Transport.(*http.Transport).TLSClientConfig.NextProtos = []string{"http/1.1"}
	target := "/v1/tenants/" + tenantA + "/status"
	nonce := "0123456789abcdef0123456789abcdef"
	ts := time.Now().Unix()
	sr := SignedRequest{Method: "GET", Host: "localhost:" + e.port, Target: target, BodySHA256: sha256.Sum256(nil), Timestamp: ts, Nonce: nonce, Credential: "ui-a", Tenant: tenantA, User: "user-1"}
	sig, err := Sign(id.priv, sr)
	if err != nil {
		t.Fatal(err)
	}
	send := func() int {
		req, _ := http.NewRequest("GET", e.base+target, nil)
		req.Header.Set("Authorization", AuthHeader{Credential: "ui-a", Timestamp: ts, Nonce: nonce, Signature: sig}.String())
		req.Header.Set(HeaderActingUser, "user-1")
		resp, err := hc.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	if c := send(); c != 200 {
		t.Fatalf("the signed request: %d", c)
	}
	if c := send(); c != 401 {
		t.Fatalf("the same bytes again: %d", c)
	}
}

func TestConcurrentClients(t *testing.T) {
	e := newE2E(t)
	c := e.client("ui-a")
	var wg sync.WaitGroup
	var mu sync.Mutex
	counts := map[int]int{}
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 25; i++ {
				r, err := c.Do(context.Background(), Call{Method: "GET", Target: "/v1/tenants/" + tenantA + "/status", ActingUser: "user-" + strconv.Itoa(g)})
				mu.Lock()
				if err != nil {
					counts[-1]++
				} else {
					counts[r.Status]++
				}
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if counts[200] != 200 {
		t.Fatalf("%v", counts)
	}
	if e.srv.TLSConfig == nil {
		t.Fatal("no TLS config")
	}
	if e.stats().ReplayEntries != 200 {
		t.Fatalf("the replay cache holds %d nonces", e.stats().ReplayEntries)
	}
}

func (e *e2e) stats() Stats { return e.harness.srv.Stats() }

func TestClientCertificateIsReloadedFromDisk(t *testing.T) {
	e := newE2E(t)
	id := e.ids["ui-a"]
	dir := t.TempDir()
	certFile, keyFile := filepath.Join(dir, "client.pem"), filepath.Join(dir, "client.key")
	writeFile(t, certFile, id.cert.certPEM)
	writeFile(t, keyFile, id.cert.keyPEM)
	c, err := NewClient(ClientConfig{BaseURL: e.base, CredentialID: "ui-a", SigningKey: id.priv, CertFile: certFile, KeyFile: keyFile, RootCAs: e.pki.pool()})
	if err != nil {
		t.Fatal(err)
	}
	defer c.CloseIdleConnections()
	call := Call{Method: "GET", Target: "/v1/tenants/" + tenantA + "/status", ActingUser: "user-1"}
	if r, err := c.Do(context.Background(), call); err != nil || r.Status != 200 {
		t.Fatalf("%v", err)
	}
	// the certificate is renewed on the same key: the credential pins the key, so nothing else needs to change
	renewed := e.pki.issue(issueOpts{cn: "ui-a-renewed", key: id.cert.key})
	if SPKIFingerprint(renewed.cert) != SPKIFingerprint(id.cert.cert) {
		t.Fatal("a renewed certificate on the same key has another fingerprint")
	}
	writeFile(t, certFile, renewed.certPEM)
	when := time.Now().Add(time.Minute)
	_ = os.Chtimes(certFile, when, when)
	time.Sleep(2100 * time.Millisecond) // the files are looked at every two seconds
	c.CloseIdleConnections()
	var sawNew atomic.Bool
	e.onRequest(func(r *http.Request) {
		if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 && r.TLS.PeerCertificates[0].Subject.CommonName == "ui-a-renewed" {
			sawNew.Store(true)
		}
	})
	if r, err := c.Do(context.Background(), call); err != nil || r.Status != 200 {
		t.Fatalf("after renewal: %v", err)
	}
	if !sawNew.Load() {
		t.Fatal("the renewed certificate was not presented to the server")
	}
	// a damaged file does not take the client down
	writeFile(t, certFile, []byte("damaged"))
	when = time.Now().Add(2 * time.Minute)
	_ = os.Chtimes(certFile, when, when)
	time.Sleep(2100 * time.Millisecond)
	c.CloseIdleConnections()
	if r, err := c.Do(context.Background(), call); err != nil || r.Status != 200 {
		t.Fatalf("with a damaged file: %v", err)
	}
}

// ------------------------------------------------------------------------------------------------ the wire

func (e *e2e) raw(t *testing.T, name string, payload string) (*http.Response, string) {
	t.Helper()
	cfg := &tls.Config{RootCAs: e.pki.pool(), ServerName: "localhost", Certificates: []tls.Certificate{e.ids[name].cert.tls}, MinVersion: tls.VersionTLS13}
	conn, err := tls.Dial("tcp", e.addr, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.WriteString(conn, payload); err != nil {
		t.Fatal(err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		return nil, err.Error()
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp, string(b)
}

func TestMalformedRequestsOnTheWire(t *testing.T) {
	e := newE2E(t)
	target := "/v1/tenants/" + tenantA + "/status"
	rows := []struct {
		name    string
		payload string
		want    []int // acceptable statuses; 0 means the connection was closed with no answer
	}{
		{"two different Content-Length headers", "GET " + target + " HTTP/1.1\r\nHost: localhost\r\nContent-Length: 5\r\nContent-Length: 6\r\n\r\nhello!", []int{400}},
		{"Content-Length and chunked together", "GET " + target + " HTTP/1.1\r\nHost: localhost\r\nContent-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n", []int{400}},
		{"an unknown transfer encoding", "GET " + target + " HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: gzip, chunked\r\n\r\n", []int{400, 501}},
		{"a space before the colon", "GET " + target + " HTTP/1.1\r\nHost : localhost\r\n\r\n", []int{400}},
		// Go replaces an obsolete line fold with a space, which RFC 7230 allows; the request is then just unsigned
		{"a folded header", "GET " + target + " HTTP/1.1\r\nHost: localhost\r\nX-Folded: a\r\n b\r\n\r\n", []int{400, 401}},
		{"an absolute-form target", "GET https://evil.example" + target + " HTTP/1.1\r\nHost: localhost\r\n\r\n", []int{400}},
		{"a lower-case method", "get " + target + " HTTP/1.1\r\nHost: localhost\r\n\r\n", []int{405, 400}},
		{"HTTP/1.0", "GET " + target + " HTTP/1.0\r\n\r\n", []int{400}},
		{"two Host headers", "GET " + target + " HTTP/1.1\r\nHost: localhost\r\nHost: evil.example\r\n\r\n", []int{400}},
		{"an enormous request line", "GET /" + strings.Repeat("a", 20000) + " HTTP/1.1\r\nHost: localhost\r\n\r\n", []int{431, 414, 400, 0}},
		{"an enormous header", "GET " + target + " HTTP/1.1\r\nHost: localhost\r\nX-Big: " + strings.Repeat("a", 20000) + "\r\n\r\n", []int{431, 400, 0}},
		{"a null byte in a header", "GET " + target + " HTTP/1.1\r\nHost: localhost\r\nX-Null: a\x00b\r\n\r\n", []int{400}},
		{"a smuggled method override", "GET " + target + " HTTP/1.1\r\nHost: localhost\r\nX-HTTP-Method-Override: DELETE\r\n\r\n", []int{400}},
		{"a header name with an underscore", "GET " + target + " HTTP/1.1\r\nHost: localhost\r\nCarnical_Acting_User: root\r\n\r\n", []int{400}},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			before := e.touches()
			resp, body := e.raw(t, "ui-a", row.payload)
			if resp == nil {
				for _, w := range row.want {
					if w == 0 {
						return
					}
				}
				t.Fatalf("no answer: %s", body)
			}
			ok := false
			for _, w := range row.want {
				if resp.StatusCode == w {
					ok = true
				}
			}
			if !ok {
				t.Fatalf("status %d, want one of %v: %.200s", resp.StatusCode, row.want, body)
			}
			if e.touches() != before {
				t.Fatal("a store was touched")
			}
		})
	}
}

func TestSlowHeadersAreCutOff(t *testing.T) {
	e := newE2EWith(t, func(s *http.Server) { s.ReadHeaderTimeout = 300 * time.Millisecond })
	cfg := &tls.Config{RootCAs: e.pki.pool(), ServerName: "localhost", Certificates: []tls.Certificate{e.ids["ui-a"].cert.tls}, MinVersion: tls.VersionTLS13}
	conn, err := tls.Dial("tcp", e.addr, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_, _ = io.WriteString(conn, "GET /healthz HTTP/1.1\r\nHost: localhost\r\n")
	start := time.Now()
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	_, err = io.ReadAll(conn)
	_ = err
	if d := time.Since(start); d > 3*time.Second {
		t.Fatalf("a client that never finished its headers held the connection for %v", d)
	}
}

func TestHealthzOverTLSNeedsAClientCertificate(t *testing.T) {
	e := newE2E(t)
	resp, err := e.rawClient("ui-a").Get(e.base + "/healthz")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 || strings.TrimSpace(string(b)) != `{"status":"ok"}` {
		t.Fatalf("%d %s", resp.StatusCode, b)
	}
	if resp.Header.Get("Content-Security-Policy") != "default-src 'none'" {
		t.Fatal("no CSP")
	}
	// the plain handler for a load balancer
	ps := httptest.NewServer(HealthHandler())
	defer ps.Close()
	r2, err := http.Get(ps.URL + "/healthz")
	if err != nil || r2.StatusCode != 200 {
		t.Fatalf("%v", err)
	}
	r2.Body.Close()
}

func TestJSONFromTheServerIsAlwaysValid(t *testing.T) {
	e := newE2E(t)
	c := e.client("ui-a")
	for _, call := range []Call{
		{Method: "GET", Target: "/v1/tenants/" + tenantA + "/status", ActingUser: "u"},
		{Method: "GET", Target: "/v1/tenants/" + tenantA + "/policy", ActingUser: "u"},
		{Method: "GET", Target: "/v1/tenants/" + tenantB + "/policy", ActingUser: "u"},
		{Method: "GET", Target: "/v1/nothing", ActingUser: "u"},
	} {
		r, err := c.Do(context.Background(), call)
		if err != nil {
			t.Fatal(err)
		}
		if !json.Valid(r.Body) || !strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
			t.Fatalf("%s: %q", call.Target, r.Body)
		}
		if r.Header.Get("Content-Length") != "" && r.Header.Get("Content-Length") != strconv.Itoa(len(r.Body)) {
			t.Fatalf("content length %s for %d bytes", r.Header.Get("Content-Length"), len(r.Body))
		}
	}
}
