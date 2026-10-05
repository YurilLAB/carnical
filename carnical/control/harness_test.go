// SPDX-License-Identifier: Apache-2.0

package control

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

const (
	tenantA = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	tenantB = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	tenantC = "0123456789abcdef0123456789abcdef"
)

type identity struct {
	name string
	cred Credential
	priv ed25519.PrivateKey
	cert *issued
}

type harness struct {
	t      testing.TB
	pki    *testPKI
	clock  *fakeClock
	srv    *Server
	creds  *CredentialSet
	store  *memPolicyStore
	val    *fakeValidator
	pub    *fakePublisher
	status *fakeStatus
	events *fakeEvents
	hosts  *memHosts
	verify *fakeVerifier
	audit  *memAudit
	ids    map[string]*identity

	mu     sync.Mutex
	nonce  int
	errors []string
}

var epoch = time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)

// newHarness builds a server over the fakes, with these identities (all with a unique key and certificate):
//
//	ui-a     tenant A: read, write, publish
//	ui-b     tenant B: read, write, publish
//	reader-a tenant A: read only
//	raw-a    tenant A: read, raw-addresses
//	admin-a  tenant A: read, write, publish, admin
//	admin    every tenant: read, write, publish, admin (needs Config.AllowAllTenants)
func newHarness(t testing.TB, tweak ...func(*Config)) *harness {
	t.Helper()
	h := &harness{t: t, pki: newPKI(t), clock: &fakeClock{t: epoch}, store: newMemPolicyStore(), val: &fakeValidator{}, pub: &fakePublisher{},
		status: &fakeStatus{}, events: newFakeEvents(), hosts: newMemHosts(), verify: &fakeVerifier{result: map[string]bool{}}, audit: &memAudit{}, ids: map[string]*identity{}}
	h.status.status = TenantStatus{Health: "ok", Notes: []string{"all edges are current"}, LastPublish: &PublishInfo{Sequence: 7, Revision: 3, At: epoch.Add(-time.Hour), Actor: "user-1"},
		Edges: []EdgeAck{{Edge: "edge-1", Sequence: 7, At: epoch.Add(-time.Minute)}}}
	h.addIdentity("ui-a", []string{tenantA}, false, ScopeRead, ScopeWrite, ScopePublish)
	h.addIdentity("ui-b", []string{tenantB}, false, ScopeRead, ScopeWrite, ScopePublish)
	h.addIdentity("reader-a", []string{tenantA}, false, ScopeRead)
	h.addIdentity("raw-a", []string{tenantA}, false, ScopeRead, ScopeRawAddresses)
	h.addIdentity("admin-a", []string{tenantA}, false, ScopeRead, ScopeWrite, ScopePublish, ScopeAdmin)
	h.addIdentity("admin", nil, true, ScopeRead, ScopeWrite, ScopePublish, ScopeAdmin)
	cfg := Config{Credentials: h.creds, Audit: h.audit, Policies: h.store, Validator: h.val, Publisher: h.pub, Status: h.status, Events: h.events,
		Hosts: h.hosts, Verifier: h.verify, Now: h.clock.now, AllowAllTenants: true, Limits: Limits{FailureThreshold: 1000},
		OnInternalError: func(id, step string, err error) {
			h.mu.Lock()
			defer h.mu.Unlock()
			h.errors = append(h.errors, id+" "+step)
		}}
	for _, f := range tweak {
		f(&cfg)
	}
	srv, err := NewServer(cfg)
	if err != nil {
		t.Fatal(err)
	}
	h.srv = srv
	return h
}

func (h *harness) addIdentity(name string, tenants []string, all bool, scopes ...Scope) *identity {
	h.t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		h.t.Fatal(err)
	}
	cert := h.pki.client(name)
	id := &identity{name: name, priv: priv, cert: cert, cred: Credential{ID: name, Label: name, Certs: []Fingerprint{SPKIFingerprint(cert.cert)}, SigningKey: pub,
		Tenants: tenants, AllTenants: all, Scopes: scopes, NotAfter: epoch.Add(365 * 24 * time.Hour)}}
	h.ids[name] = id
	h.refreshCreds()
	return id
}

func (h *harness) refreshCreds() {
	var list []Credential
	for _, id := range h.ids {
		list = append(list, id.cred)
	}
	if h.creds == nil {
		h.creds = &CredentialSet{}
	}
	if err := h.creds.Replace(list); err != nil {
		h.t.Fatal(err)
	}
}

// setCred changes a credential in the store (not the identity's keys).
func (h *harness) setCred(name string, f func(c *Credential)) {
	id := h.ids[name]
	f(&id.cred)
	h.refreshCreds()
}

func (h *harness) freshNonce() string {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.nonce++
	var b [8]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:]) + strings.Repeat("0", 16-len(strconv.FormatInt(int64(h.nonce), 16))) + strconv.FormatInt(int64(h.nonce), 16)
}

// reqOpts describes a request. The zero value of each field is the sensible default.
type reqOpts struct {
	as      string // the identity whose credential id is claimed and whose key signs (default ui-a)
	certAs  string // the identity whose client certificate is presented (default: as)
	keyAs   string // the identity whose private key signs (default: as)
	method  string // default GET
	target  string
	body    []byte
	user    string // default user-1; "-" omits the header
	stepUp  int64  // unix seconds; 0 sends none
	ifMatch string // the header value as sent, e.g. "\"3\""
	idem    string
	ctype   string // default application/json; charset=utf-8 when there is a body; "-" omits
	ts      int64  // default: now
	nonce   string
	host    string // default control.test
	remote  string // default 198.51.100.10:50000
	extra   http.Header
	// after is called on the request after it is signed, to damage it
	after func(r *http.Request)
	// noTLS sends no TLS state at all
	noTLS bool
	// tlsVersion overrides the version in the fake TLS state
	tlsVersion uint16
	// chain leaves VerifiedChains empty
	noChain bool
	// signedBody is hashed for the signature instead of the real body
	signedBody []byte
	hasSigned  bool
}

func (h *harness) build(o reqOpts) *http.Request {
	h.t.Helper()
	if o.as == "" {
		o.as = "ui-a"
	}
	if o.method == "" {
		o.method = "GET"
	}
	if o.user == "" {
		o.user = "user-1"
	}
	if o.host == "" {
		o.host = "control.test"
	}
	if o.remote == "" {
		o.remote = "198.51.100.10:50000"
	}
	if o.ts == 0 {
		o.ts = h.clock.now().Unix()
	}
	if o.nonce == "" {
		o.nonce = h.freshNonce()
	}
	certAs, keyAs := o.certAs, o.keyAs
	if certAs == "" {
		certAs = o.as
	}
	if keyAs == "" {
		keyAs = o.as
	}
	// a claimed credential that does not exist is signed and presented with ui-a's key and certificate
	if h.ids[certAs] == nil {
		certAs = "ui-a"
	}
	if h.ids[keyAs] == nil {
		keyAs = "ui-a"
	}
	var body io.Reader
	if len(o.body) > 0 {
		body = bytes.NewReader(o.body)
	}
	req := httptest.NewRequest(o.method, "https://"+o.host+o.target, body)
	req.RequestURI = o.target
	req.Host = o.host
	req.RemoteAddr = o.remote
	if len(o.body) > 0 {
		req.ContentLength = int64(len(o.body))
	}

	hashed := o.body
	if o.hasSigned {
		hashed = o.signedBody
	}
	sr := SignedRequest{Method: o.method, Host: o.host, Target: o.target, BodySHA256: sha256.Sum256(hashed), Timestamp: o.ts, Nonce: o.nonce,
		Credential: o.as, Tenant: TenantFromTarget(o.target), User: o.user, IfMatch: o.ifMatch, IdemKey: o.idem}
	if o.stepUp != 0 {
		sr.StepUp, sr.HasStepUp = o.stepUp, true
	}
	if o.user == "-" {
		sr.User = "-"
	}
	sig, err := Sign(h.ids[keyAs].priv, sr)
	if err != nil {
		h.t.Fatalf("sign: %v", err)
	}
	req.Header.Set("Authorization", AuthHeader{Credential: o.as, Timestamp: o.ts, Nonce: o.nonce, Signature: sig}.String())
	if o.user != "-" {
		req.Header.Set(HeaderActingUser, o.user)
	}
	if o.stepUp != 0 {
		req.Header.Set(HeaderStepUp, strconv.FormatInt(o.stepUp, 10))
	}
	if o.ifMatch != "" {
		req.Header.Set("If-Match", o.ifMatch)
	}
	if o.idem != "" {
		req.Header.Set("Idempotency-Key", o.idem)
	}
	ct := o.ctype
	if ct == "" && len(o.body) > 0 {
		ct = "application/json; charset=utf-8"
	}
	if ct != "" && ct != "-" {
		req.Header.Set("Content-Type", ct)
	}
	for k, vs := range o.extra {
		for i, v := range vs {
			if i == 0 {
				req.Header.Set(k, v)
			} else {
				req.Header.Add(k, v)
			}
		}
	}
	if !o.noTLS {
		ver := o.tlsVersion
		if ver == 0 {
			ver = tls.VersionTLS13
		}
		c := h.ids[certAs].cert.cert
		st := &tls.ConnectionState{Version: ver, HandshakeComplete: true, PeerCertificates: []*x509.Certificate{c}}
		if !o.noChain {
			st.VerifiedChains = [][]*x509.Certificate{{c, h.pki.ca}}
		}
		req.TLS = st
	}
	if o.after != nil {
		o.after(req)
	}
	return req
}

func (h *harness) serve(req *http.Request) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	h.srv.ServeHTTP(w, req)
	return w
}

func (h *harness) do(o reqOpts) *httptest.ResponseRecorder { return h.serve(h.build(o)) }

type apiErr struct {
	Code, Message, RequestID string
	Problems                 []problemJSON
	Weakening                []changeJSON
}

func errorOf(t testing.TB, w *httptest.ResponseRecorder) apiErr {
	t.Helper()
	var b struct {
		Error struct {
			Code      string        `json:"code"`
			Message   string        `json:"message"`
			RequestID string        `json:"request_id"`
			Problems  []problemJSON `json:"problems"`
			Weakening []changeJSON  `json:"weakening"`
		} `json:"error"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &b); err != nil {
		t.Fatalf("not an error body (status %d): %v\n%s", w.Code, err, w.Body.String())
	}
	return apiErr{b.Error.Code, b.Error.Message, b.Error.RequestID, b.Error.Problems, b.Error.Weakening}
}

func decodeBody(t testing.TB, w *httptest.ResponseRecorder, v any) {
	t.Helper()
	if err := json.Unmarshal(w.Body.Bytes(), v); err != nil {
		t.Fatalf("bad body (status %d): %v\n%s", w.Code, err, w.Body.String())
	}
}

func (h *harness) putPolicy(as, tenant string, doc string, ifMatch uint64, stepUp int64) *httptest.ResponseRecorder {
	return h.do(reqOpts{as: as, method: "PUT", target: "/v1/tenants/" + tenant + "/policy", body: []byte(doc), ifMatch: etag(ifMatch), stepUp: stepUp})
}

// seed stores a first revision of a tenant's policy directly, and returns its revision.
func (h *harness) seed(tenant, doc string) uint64 {
	h.t.Helper()
	rev, err := h.store.Put(context.Background(), tenant, []byte(doc), uint64(h.store.revisions(tenant)), PutMeta{Actor: "seed", Credential: "seed", Kind: "put"})
	if err != nil {
		h.t.Fatal(err)
	}
	return rev
}

func (h *harness) internalErrors() []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]string(nil), h.errors...)
}

func ip(s string) netip.Addr { return netip.MustParseAddr(s) }

type netipPrefix = netip.Prefix

func mustPrefix(s string) netip.Prefix { return netip.MustParsePrefix(s) }
