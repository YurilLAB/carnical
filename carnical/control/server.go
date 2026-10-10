// SPDX-License-Identifier: Apache-2.0

package control

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

// Limits are the numbers the API holds itself to. The zero value of a field means "the default"
// (DefaultLimits has them all).
type Limits struct {
	// MaxBody is the largest request body; default 256 KiB.
	MaxBody int64
	// MaxHeaders and MaxHeaderBytes bound the number of header lines and their total size; defaults 40 and 16 KiB.
	MaxHeaders     int
	MaxHeaderBytes int
	// MaxInFlight and MaxInFlightPerCredential bound concurrent requests; defaults 128 and 16.
	MaxInFlight              int
	MaxInFlightPerCredential int
	// Skew is how far a request's timestamp may be from the server's clock; default 60 seconds.
	Skew time.Duration
	// StepUpMaxAge is how old a step-up assertion may be; default 5 minutes.
	StepUpMaxAge time.Duration
	// ReplayMax and ReplayMaxPerCredential cap the nonces remembered; defaults 200,000 and 50,000.
	ReplayMax              int
	ReplayMaxPerCredential int
	// FailureThreshold failures from one source or for one credential id start the waiting; default 3.
	FailureThreshold int
	// BackoffBase doubles with each further failure up to BackoffMax; defaults 1 second and 15 minutes.
	BackoffBase time.Duration
	BackoffMax  time.Duration
	// FailureDecay is how long without a failure before a key starts again; default 15 minutes.
	FailureDecay time.Duration
	// FailureKeys caps the table of failing keys; default 50,000.
	FailureKeys int
	// IdempotencyTTL, IdempotencyMax and IdempotencyPerCredential bound the publish idempotency keys; defaults 24
	// hours, 50,000 and 10,000.
	IdempotencyTTL           time.Duration
	IdempotencyMax           int
	IdempotencyPerCredential int
	// OperationTimeout bounds the calls to the stores for one request; default 10 seconds.
	OperationTimeout time.Duration
	// PageDefault and PageMax are the page sizes for lists; defaults 100 and 500.
	PageDefault int
	PageMax     int
	// HostCheckEvery is the least time between two verification attempts of one hostname; default 10 seconds.
	HostCheckEvery time.Duration
}

// DefaultLimits returns the defaults.
func DefaultLimits() Limits {
	return Limits{}.withDefaults()
}

func (l Limits) withDefaults() Limits {
	def := func(v *int64, d int64) {
		if *v <= 0 {
			*v = d
		}
	}
	defI := func(v *int, d int) {
		if *v <= 0 {
			*v = d
		}
	}
	defD := func(v *time.Duration, d time.Duration) {
		if *v <= 0 {
			*v = d
		}
	}
	def(&l.MaxBody, 256<<10)
	defI(&l.MaxHeaders, 40)
	defI(&l.MaxHeaderBytes, 16<<10)
	defI(&l.MaxInFlight, 128)
	defI(&l.MaxInFlightPerCredential, 16)
	defD(&l.Skew, 60*time.Second)
	defD(&l.StepUpMaxAge, 5*time.Minute)
	defI(&l.ReplayMax, 200_000)
	defI(&l.ReplayMaxPerCredential, 50_000)
	defI(&l.FailureThreshold, 3)
	defD(&l.BackoffBase, time.Second)
	defD(&l.BackoffMax, 15*time.Minute)
	defD(&l.FailureDecay, 15*time.Minute)
	defI(&l.FailureKeys, 50_000)
	defD(&l.IdempotencyTTL, 24*time.Hour)
	defI(&l.IdempotencyMax, 50_000)
	defI(&l.IdempotencyPerCredential, 10_000)
	defD(&l.OperationTimeout, 10*time.Second)
	defI(&l.PageDefault, 100)
	defI(&l.PageMax, 500)
	defD(&l.HostCheckEvery, 10*time.Second)
	return l
}

// Config makes a Server.
type Config struct {
	// Credentials and Audit are required. The others may be left nil, and the routes that need them then answer 501.
	Credentials CredentialStore
	Audit       Auditor
	Policies    PolicyStore
	Validator   PolicyValidator
	Publisher   Publisher
	Status      StatusSource
	Events      EventSource
	Hosts       HostRegistry
	Verifier    HostVerifier

	// AllowAllTenants honours credentials marked "all tenants". Leave it off except on the listener the owner's own
	// tooling uses.
	AllowAllTenants bool
	// Authority, if set, is the host (and port, as clients write it in Host) this server is reached at. A request signed
	// for another one is refused, so a request captured at one server that trusts the same credential cannot be sent to
	// this one. Give each server its own; replay protection is per process, so servers that share an Authority must not
	// share traffic.
	Authority string
	// Limits are the numbers the API holds itself to.
	Limits Limits
	// Now is the clock; default time.Now.
	Now func() time.Time
	// OnInternalError, when set, is told when a store or a panic made a request fail. It gets the request id, the
	// name of the step, and the error (nil for a panic). The error may hold anything the store put in it, so a hook
	// that logs it should decide what to keep; the server never logs it.
	OnInternalError func(requestID, step string, err error)
}

// Server is the control API.
type Server struct {
	cfg    Config
	lim    Limits
	now    func() time.Time
	routes []*route

	sem     chan struct{}
	perCred *counter
	replay  *replayCache
	fails   *failureLimiter
	idem    *idempotency
	hosts   *gate

	dummyKey ed25519.PublicKey
	dummySig []byte
	dummyFP  Fingerprint

	stats struct {
		authFailures, replayFull, panics, auditFailures atomic.Uint64
	}
	// auditGap is set when a change's closing line could not be written. Changes are refused from then on, until the log
	// has been checked and the server started again: a log that has silently lost a line is not one to write more to.
	auditGap atomic.Bool
}

// Stats are counters for the operator.
type Stats struct {
	AuthFailures  uint64 // requests refused for failing to authenticate
	ReplayFull    uint64 // requests refused because the replay cache was full
	Panics        uint64 // handler panics recovered
	AuditFailures uint64 // audit lines that could not be written
	ReplayEntries int    // nonces remembered now
	FailingKeys   int    // sources and credential ids in the failure table now
}

// Stats returns the counters.
func (s *Server) Stats() Stats {
	return Stats{AuthFailures: s.stats.authFailures.Load(), ReplayFull: s.stats.replayFull.Load(), Panics: s.stats.panics.Load(),
		AuditFailures: s.stats.auditFailures.Load(), ReplayEntries: s.replay.size(), FailingKeys: s.fails.size()}
}

// NewServer checks the configuration and builds the server.
func NewServer(cfg Config) (*Server, error) {
	if cfg.Credentials == nil || cfg.Audit == nil {
		return nil, errors.New("control: Credentials and Audit are required")
	}
	if a := cfg.Authority; a != "" && (len(a) > 261 || strings.ContainsAny(a, "/?#@ \t\\") || strings.HasPrefix(a, ":")) {
		return nil, errors.New("control: Authority must be a host name, with an optional :port")
	}
	s := &Server{cfg: cfg, lim: cfg.Limits.withDefaults(), now: cfg.Now}
	if s.now == nil {
		s.now = time.Now
	}
	s.sem = make(chan struct{}, s.lim.MaxInFlight)
	s.perCred = newCounter(s.lim.MaxInFlightPerCredential)
	s.replay = newReplayCache(s.lim.ReplayMax, s.lim.ReplayMaxPerCredential, s.lim.Skew)
	s.fails = newFailureLimiter(s.lim.FailureKeys, s.lim.FailureThreshold, s.lim.BackoffBase, s.lim.BackoffMax, s.lim.FailureDecay)
	s.idem = newIdempotency(s.lim.IdempotencyMax, s.lim.IdempotencyPerCredential, s.lim.IdempotencyTTL)
	s.hosts = newGate(50_000)
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	s.dummyKey = pub
	s.dummySig = ed25519.Sign(priv, []byte("carnical dummy"))
	if _, err := rand.Read(s.dummyFP[:]); err != nil {
		return nil, err
	}
	s.routes = s.buildRoutes()
	return s, nil
}

// Handler returns the server as an http.Handler. It must be served over TLS with the config from TLSConfig; it
// refuses any request that did not come with a verified TLS 1.3 client certificate.
func (s *Server) Handler() http.Handler { return s }

// HTTPServer returns an http.Server for the handler with the timeouts and limits a public listener needs. Serve it with
// ServeTLS("", "") on a listener, so the certificate comes from tlsCfg.
func (s *Server) HTTPServer(tlsCfg *tls.Config) *http.Server {
	return &http.Server{
		Handler:           s,
		TLSConfig:         tlsCfg,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    s.lim.MaxHeaderBytes,
		HTTP2:             &http.HTTP2Config{MaxConcurrentStreams: 32, MaxReadFrameSize: 64 << 10},
	}
}

// HealthHandler answers 200 to GET /healthz with nothing but "ok". It is for a load balancer that cannot present a
// client certificate: serve it on a separate plain listener bound to a private address. The main handler answers
// /healthz too, but only to a client that has passed TLS.
func HealthHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		setSecurityHeaders(w.Header())
		if r.URL.Path != "/healthz" || r.Method != http.MethodGet {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		_, _ = io.WriteString(w, `{"status":"ok"}`)
	})
}

func setSecurityHeaders(h http.Header) {
	h.Set("Cache-Control", "no-store")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Content-Security-Policy", "default-src 'none'")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("Strict-Transport-Security", "max-age=63072000")
}

// ------------------------------------------------------------------------------------------------------ the request

// reqCtx is what a handler gets: the request after every check, with the caller known.
type reqCtx struct {
	s      *Server
	r      *http.Request
	ctx    context.Context
	id     string
	now    time.Time
	route  *route
	params map[string]string
	body   []byte
	query  map[string]string

	cred      Credential
	user      string
	stepUp    int64
	hasStepUp bool
	tenant    string
	ifMatch   string
	idemKey   string
	source    string

	// filled in by the handler for the audit line
	revBefore, revAfter *uint64
	changes             []string
	detail              string
}

// result is what a handler returns on success.
type result struct {
	status  int
	body    any
	headers map[string]string
}

func (rc *reqCtx) setBefore(v uint64) { rc.revBefore = &v }
func (rc *reqCtx) setAfter(v uint64)  { rc.revAfter = &v }

func (rc *reqCtx) stepUpFresh() bool {
	if !rc.hasStepUp {
		return false
	}
	age := rc.now.Unix() - rc.stepUp
	return age <= int64(rc.s.lim.StepUpMaxAge/time.Second) && age >= -int64(rc.s.lim.Skew/time.Second)
}

func (s *Server) internal(requestID, step string, err error) {
	if s.cfg.OnInternalError != nil {
		s.cfg.OnInternalError(requestID, step, err)
	}
}

func newRequestID() string {
	var b [8]byte
	_, _ = rand.Read(b[:])
	return "req_" + hex.EncodeToString(b[:])
}

type countingWriter struct {
	http.ResponseWriter
	wrote bool
}

func (c *countingWriter) WriteHeader(code int) { c.wrote = true; c.ResponseWriter.WriteHeader(code) }
func (c *countingWriter) Write(b []byte) (int, error) {
	c.wrote = true
	return c.ResponseWriter.Write(b)
}

// ServeHTTP implements http.Handler. The order of the steps is the design: nothing that costs more than a table lookup
// happens before a request is known to be well formed, nothing reads the body of a source that is waiting out its
// failures, and nothing reaches a store before the caller is authenticated, allowed this scope and this tenant.
func (s *Server) ServeHTTP(rw http.ResponseWriter, r *http.Request) {
	rid := newRequestID()
	w := &countingWriter{ResponseWriter: rw}
	setSecurityHeaders(w.Header())
	w.Header().Set(HeaderRequestID, rid)
	defer func() {
		if rec := recover(); rec != nil {
			if rec == http.ErrAbortHandler {
				panic(rec)
			}
			s.stats.panics.Add(1)
			s.internal(rid, "panic", nil)
			if !w.wrote {
				writeError(w, rid, errInternal())
			}
		}
	}()

	select {
	case s.sem <- struct{}{}:
		defer func() { <-s.sem }()
	default:
		writeError(w, rid, &apiError{status: http.StatusServiceUnavailable, code: "overloaded", msg: "the service is busy; try again shortly", retry: 1})
		return
	}

	if e := checkTarget(r.RequestURI); e != nil {
		writeError(w, rid, e)
		return
	}
	if e := s.checkHeaders(r); e != nil {
		writeError(w, rid, e)
		return
	}
	rt, params, e := s.match(r.Method, r.RequestURI)
	if e != nil {
		writeError(w, rid, e)
		return
	}
	query, e := parseQuery(r.RequestURI, rt.query)
	if e != nil {
		writeError(w, rid, e)
		return
	}
	now := s.now()
	if rt.public {
		s.serveHealthz(w, rid)
		return
	}
	src, srcKey := sourceOf(r)

	// A source that keeps failing waits, before any of its bytes are read.
	if wait := s.fails.wait(srcKey, now); wait > 0 {
		if s.fails.firstBlocked(srcKey) {
			s.auditFailure(rid, "", src, "source_blocked", now, "refused")
		}
		writeError(w, rid, &apiError{status: http.StatusTooManyRequests, code: "too_many_failures", msg: "too many failed attempts; wait before trying again", retry: ceilSeconds(wait)})
		return
	}

	body, e := s.readBody(w, r, rt)
	if e != nil {
		writeError(w, rid, e)
		return
	}
	tenant := params["tenant"]
	ar := s.authenticate(r, rt, tenant, body, now, src)
	if !ar.ok {
		if ar.cacheFull {
			// The request was authentic; the server is out of room to remember it. That is not a failure by the caller, so it
			// does not count against the source or the credential, and it says what is wrong.
			s.stats.replayFull.Add(1)
			s.auditFailure(rid, ar.claimed, src, ar.reason, now, "refused")
			writeError(w, rid, &apiError{status: http.StatusServiceUnavailable, code: "replay_cache_full", msg: "the replay cache is full, so new requests are refused until it drains; try again shortly", retry: 2})
			return
		}
		s.stats.authFailures.Add(1)
		s.fails.fail(srcKey, now)
		var credWait time.Duration
		if ar.claimed != "" {
			s.fails.fail("cred:"+ar.claimed, now)
			credWait = s.fails.wait("cred:"+ar.claimed, now)
		}
		s.auditFailure(rid, ar.claimed, src, ar.reason, now, "auth_failed")
		if credWait > 0 {
			writeError(w, rid, &apiError{status: http.StatusTooManyRequests, code: "too_many_failures", msg: "too many failed attempts; wait before trying again", retry: ceilSeconds(credWait)})
			return
		}
		writeError(w, rid, &apiError{status: http.StatusUnauthorized, code: "unauthenticated", msg: "authentication failed"})
		return
	}
	s.fails.succeed(srcKey)

	if !s.perCred.acquire(ar.cred.ID) {
		writeError(w, rid, &apiError{status: http.StatusTooManyRequests, code: "too_many_requests", msg: "too many requests in flight for this credential", retry: 1})
		return
	}
	defer s.perCred.release(ar.cred.ID)

	ctx, cancel := context.WithTimeout(r.Context(), s.lim.OperationTimeout)
	defer cancel()
	rc := &reqCtx{s: s, r: r, ctx: ctx, id: rid, now: now, route: rt, params: params, body: body, query: query, cred: ar.cred, user: ar.user,
		stepUp: ar.stepUp, hasStepUp: ar.hasStepUp, tenant: tenant, source: src}

	res, aerr := s.run(rc)
	if aerr != nil {
		s.finishAudit(rc, outcomeOf(aerr), aerr.code)
		writeError(w, rid, aerr)
		return
	}
	if rt.mutating {
		s.finishAudit(rc, "ok", rc.detail)
		writeResult(w, rid, res)
		return
	}
	// A read is audited before its answer leaves: if the line cannot be written, the data is not sent.
	if err := s.cfg.Audit.Append(s.entry(rc, "ok", rc.detail)); err != nil {
		s.stats.auditFailures.Add(1)
		s.internal(rid, "audit", err)
		writeError(w, rid, &apiError{status: http.StatusServiceUnavailable, code: "audit_unavailable", msg: "the audit log is unavailable, so the request was not served", retry: 5})
		return
	}
	writeResult(w, rid, res)
}

func outcomeOf(e *apiError) string {
	switch e.status {
	case http.StatusForbidden:
		return "denied"
	case http.StatusConflict, http.StatusPreconditionFailed:
		return "conflict"
	case http.StatusBadRequest, http.StatusUnprocessableEntity, http.StatusPreconditionRequired, http.StatusNotFound, http.StatusUnsupportedMediaType, http.StatusRequestEntityTooLarge:
		return "invalid"
	}
	return "error"
}

// run checks scope and tenant, writes the "started" line of a change, and calls the handler.
func (s *Server) run(rc *reqCtx) (*result, *apiError) {
	rt := rc.route
	// the same answer for a missing scope and for another tenant's tenant, and neither touches a store
	allowed := rc.cred.HasScope(rt.scope)
	if rt.tenant {
		allowed = allowed && rc.cred.AllowsTenant(rc.tenant, s.cfg.AllowAllTenants)
	}
	if rt.allTenants {
		allowed = allowed && rc.cred.AllTenants && s.cfg.AllowAllTenants
	}
	if !allowed {
		return nil, &apiError{status: http.StatusForbidden, code: "forbidden", msg: "this credential may not do that"}
	}
	if e := s.checkActor(rc); e != nil {
		return nil, e
	}
	if rt.mutating {
		if s.auditGap.Load() {
			return nil, &apiError{status: http.StatusServiceUnavailable, code: "audit_unavailable", msg: "an earlier change's closing audit line was lost; check the log and restart the server", retry: 60}
		}
		// A change is written down before it is made. If the log cannot take the line, nothing is changed.
		if err := s.cfg.Audit.Append(s.entry(rc, "started", "")); err != nil {
			s.stats.auditFailures.Add(1)
			s.internal(rc.id, "audit", err)
			return nil, &apiError{status: http.StatusServiceUnavailable, code: "audit_unavailable", msg: "the audit log is unavailable, so nothing was changed", retry: 5}
		}
	}
	return rt.handle(rc)
}

// checkActor validates what the signature already covers but whose meaning is the API's: the acting user's form and
// the If-Match and Idempotency-Key values.
func (s *Server) checkActor(rc *reqCtx) *apiError {
	if !validUserID(rc.user) {
		return errBadRequest("the acting user id is not valid")
	}
	rc.ifMatch = rc.r.Header.Get("If-Match")
	rc.idemKey = rc.r.Header.Get("Idempotency-Key")
	return nil
}

func (s *Server) entry(rc *reqCtx, outcome, detail string) AuditEntry {
	return AuditEntry{Time: rc.now.UTC().Format(time.RFC3339), RequestID: rc.id, Credential: rc.cred.ID, Tenant: rc.tenant, User: rc.user,
		Action: rc.route.action, RevBefore: rc.revBefore, RevAfter: rc.revAfter, Changes: rc.changes, Source: rc.source, Outcome: outcome, Detail: detail}
}

// finishAudit writes the closing line of a change, or the only line of a read that failed. A failure to write it is
// counted and reported, not turned into an error: the change has been made.
func (s *Server) finishAudit(rc *reqCtx, outcome, detail string) {
	if err := s.cfg.Audit.Append(s.entry(rc, outcome, detail)); err != nil {
		s.stats.auditFailures.Add(1)
		s.internal(rc.id, "audit", err)
		if rc.route != nil && rc.route.mutating && outcome == "ok" { // a change was made and its record is incomplete
			s.auditGap.Store(true)
		}
	}
}

func (s *Server) auditFailure(rid, claimed, src, reason string, now time.Time, outcome string) {
	e := AuditEntry{Time: now.UTC().Format(time.RFC3339), RequestID: rid, Credential: claimed, Tenant: "", User: "", Action: "authenticate",
		Source: src, Outcome: outcome, Detail: reason}
	if claimed == "" {
		e.Credential = "-"
	}
	if err := s.cfg.Audit.Append(e); err != nil {
		s.stats.auditFailures.Add(1)
		s.internal(rid, "audit", err)
	}
}

func (s *Server) serveHealthz(w http.ResponseWriter, rid string) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Content-Length", "15")
	w.WriteHeader(http.StatusOK)
	_, _ = io.WriteString(w, `{"status":"ok"}`)
}

// ------------------------------------------------------------------------------------------------ authentication

type authResult struct {
	ok        bool
	reason    string // for the audit log only; never sent
	claimed   string // the credential id the request named, if it has the form of one
	cred      Credential
	user      string
	stepUp    int64
	hasStepUp bool
	cacheFull bool
}

// authenticate decides whether the request carries a valid credential. A request has to show a client certificate whose
// key the credential lists AND a signature, made with the credential's key, over everything that matters in the
// request. Every check is made, in the same order and with the same work, whatever the outcome of the ones before: an
// unknown credential, a bad signature, a wrong certificate and an expired credential take the same steps (including one
// full signature verification), and only the audit log is told which it was.
func (s *Server) authenticate(r *http.Request, rt *route, tenant string, body []byte, now time.Time, src string) authResult {
	var res authResult
	bad := false
	fail := func(cond bool, why string) {
		if cond {
			if !bad {
				res.reason = why
			}
			bad = true
		}
	}

	var hdr AuthHeader
	var perr error = errAuth
	if vals := r.Header.Values("Authorization"); len(vals) == 1 {
		hdr, perr = ParseAuthHeader(vals[0])
	}
	if perr != nil {
		hdr = AuthHeader{Credential: "unknown-credential", Timestamp: 1, Nonce: strings.Repeat("0", 32), Signature: s.dummySig}
	} else {
		res.claimed = hdr.Credential
	}
	fail(perr != nil, "malformed")

	cred, found := s.cfg.Credentials.Lookup(hdr.Credential)
	if !found {
		cred = Credential{ID: "unknown-credential", Certs: []Fingerprint{s.dummyFP}, SigningKey: s.dummyKey, NotAfter: now.Add(-time.Hour)}
	}
	fail(!found, "unknown_credential")
	if len(cred.SigningKey) != ed25519.PublicKeySize {
		// a store that returns a credential without its key would make Verify panic; treat it as unusable
		cred.SigningKey = s.dummyKey
		fail(true, "bad_credential")
	}

	fp, haveCert := peerFingerprint(r, now)
	fail(!haveCert, "no_certificate")
	fail(!cred.MatchesCert(fp), "certificate_mismatch")
	// The Host is signed; it must also be this server's, or a request captured at another one is good here too.
	fail(s.cfg.Authority != "" && !strings.EqualFold(r.Host, s.cfg.Authority), "wrong_authority")

	user := r.Header.Values(HeaderActingUser)
	step := r.Header.Values(HeaderStepUp)
	sr := SignedRequest{Method: r.Method, Host: r.Host, Target: r.RequestURI, BodySHA256: sha256.Sum256(body), Timestamp: hdr.Timestamp,
		Nonce: hdr.Nonce, Credential: hdr.Credential, Tenant: tenant, IfMatch: joinSingle(r.Header.Values("If-Match")),
		IdemKey: joinSingle(r.Header.Values("Idempotency-Key"))}
	if len(user) == 1 {
		sr.User = user[0]
	}
	fail(len(user) != 1, "malformed")
	if len(step) == 1 {
		if n, ok := parseTimestamp(step[0]); ok {
			sr.StepUp, sr.HasStepUp = n, true
		} else {
			fail(true, "malformed")
		}
	} else if len(step) > 1 {
		fail(true, "malformed")
	}
	canon, cerr := sr.CanonicalString()
	if cerr != nil {
		canon = "carnical-control-v1"
		fail(true, "malformed")
	}
	sig := hdr.Signature
	if len(sig) != ed25519.SignatureSize || sig[63]&224 != 0 {
		// Verify would return at once for a signature like this, which would be faster than the rest. Use a
		// well-formed dummy so there is one verification either way.
		sig = s.dummySig
		fail(true, "bad_signature")
	}
	fail(!ed25519.Verify(cred.SigningKey, []byte(canon), sig), "bad_signature")

	skew := now.Unix() - hdr.Timestamp
	if skew < 0 {
		skew = -skew
	}
	fail(skew > int64(s.lim.Skew/time.Second), "skew")
	fail(cred.Revoked, "revoked")
	fail(!now.Before(cred.NotAfter), "expired")
	addr, _ := netip.ParseAddr(src)
	fail(!cred.AllowsSource(addr), "source_not_allowed")
	fail(s.replay.peek(cred.ID, hdr.Nonce), "replay")

	if bad {
		return res
	}
	// Everything checks out. Only now is the nonce remembered, so only requests that hold a valid signature can fill the
	// cache.
	switch s.replay.use(cred.ID, hdr.Nonce, hdr.Timestamp, now.Unix()) {
	case replayRepeat:
		res.reason = "replay"
		return res
	case replayFull:
		res.reason, res.cacheFull = "replay_cache_full", true
		return res
	}
	res.ok, res.cred, res.user, res.stepUp, res.hasStepUp = true, cred, sr.User, sr.StepUp, sr.HasStepUp
	return res
}

func joinSingle(v []string) string {
	if len(v) == 1 {
		return v[0]
	}
	if len(v) == 0 {
		return ""
	}
	return strings.Join(v, "\x00") // not signable: the canonical string refuses it, so a duplicate header fails
}

// peerFingerprint returns the fingerprint of the client certificate's key, if the connection is TLS 1.3 with a client
// certificate that was verified and is inside its validity period now (a connection can outlive the certificate it
// began with).
func peerFingerprint(r *http.Request, now time.Time) (Fingerprint, bool) {
	st := r.TLS
	if st == nil || !st.HandshakeComplete || st.Version < tls.VersionTLS13 || len(st.PeerCertificates) == 0 || len(st.VerifiedChains) == 0 {
		return Fingerprint{}, false
	}
	c := st.PeerCertificates[0]
	if now.Before(c.NotBefore) || now.After(c.NotAfter) {
		return Fingerprint{}, false
	}
	return SPKIFingerprint(c), true
}

// sourceOf returns the connection's address as text and as a key for the failure limiter. An IPv6 address is keyed by its
// /64, because a single host controls that much.
func sourceOf(r *http.Request) (string, string) {
	ap, err := netip.ParseAddrPort(r.RemoteAddr)
	if err != nil {
		return "-", "src:-"
	}
	a := ap.Addr().Unmap().WithZone("")
	if a.Is6() {
		return a.String(), "src:" + netip.PrefixFrom(a, 64).Masked().Addr().String()
	}
	return a.String(), "src:" + a.String()
}

func ceilSeconds(d time.Duration) int {
	n := int((d + time.Second - 1) / time.Second)
	if n < 1 {
		n = 1
	}
	return n
}

// ------------------------------------------------------------------------------------------------ reading the request

// readBody enforces the content type and the size, reads the body (at most MaxBody bytes) and checks that nothing
// follows it that the signature would not cover.
func (s *Server) readBody(w http.ResponseWriter, r *http.Request, rt *route) ([]byte, *apiError) {
	switch rt.body {
	case bodyNone:
		if r.ContentLength != 0 || len(r.TransferEncoding) != 0 {
			return nil, errBadRequest("this request takes no body")
		}
		return nil, nil
	}
	if r.ContentLength == 0 && len(r.TransferEncoding) == 0 {
		return nil, errBadRequest("this request needs a JSON body")
	}
	if !jsonContentType(r.Header.Values("Content-Type")) {
		return nil, &apiError{status: http.StatusUnsupportedMediaType, code: "unsupported_media_type", msg: "the body must be application/json; charset=utf-8"}
	}
	if r.ContentLength > s.lim.MaxBody {
		return nil, errTooLarge()
	}
	r.Body = http.MaxBytesReader(w, r.Body, s.lim.MaxBody)
	b, err := io.ReadAll(r.Body)
	if err != nil {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			return nil, errTooLarge()
		}
		return nil, errBadRequest("the body could not be read")
	}
	if len(r.Trailer) != 0 {
		return nil, errBadRequest("trailers are not accepted")
	}
	if len(b) == 0 {
		return nil, errBadRequest("this request needs a JSON body")
	}
	return b, nil
}

// jsonContentType accepts exactly one Content-Type header whose value is application/json with the parameter
// charset=utf-8 and nothing else, in any case and with the usual spacing.
func jsonContentType(v []string) bool {
	if len(v) != 1 {
		return false
	}
	s := strings.ToLower(strings.TrimSpace(v[0]))
	mt, rest, _ := strings.Cut(s, ";")
	if strings.TrimSpace(mt) != "application/json" {
		return false
	}
	rest = strings.TrimSpace(rest)
	name, val, ok := strings.Cut(rest, "=")
	if !ok || strings.TrimSpace(name) != "charset" {
		return false
	}
	val = strings.TrimSpace(val)
	if len(val) >= 2 && val[0] == '"' && val[len(val)-1] == '"' {
		val = val[1 : len(val)-1]
	}
	return val == "utf-8"
}

// ------------------------------------------------------------------------------------------------ writing the answer

type errorBody struct {
	Error struct {
		Code      string        `json:"code"`
		Message   string        `json:"message"`
		RequestID string        `json:"request_id"`
		Problems  []problemJSON `json:"problems,omitempty"`
		Weakening []changeJSON  `json:"weakening,omitempty"`
	} `json:"error"`
}

type problemJSON struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

type changeJSON struct {
	Code    string `json:"code"`
	Summary string `json:"summary"`
}

type apiError struct {
	status    int
	code      string
	msg       string // fixed text, never built from the request
	retry     int
	allow     string
	etag      string // the current revision, for a failed precondition
	problems  []problemJSON
	weakening []changeJSON
}

func (e *apiError) Error() string { return e.code }

func errBadRequest(msg string) *apiError {
	return &apiError{status: http.StatusBadRequest, code: "bad_request", msg: msg}
}
func errTooLarge() *apiError {
	return &apiError{status: http.StatusRequestEntityTooLarge, code: "payload_too_large", msg: "the request body is too large"}
}
func errInternal() *apiError {
	return &apiError{status: http.StatusInternalServerError, code: "internal", msg: "an internal error occurred"}
}
func errNotImplemented() *apiError {
	return &apiError{status: http.StatusNotImplemented, code: "not_implemented", msg: "this server is not set up for that"}
}

func writeError(w http.ResponseWriter, rid string, e *apiError) {
	var b errorBody
	b.Error.Code, b.Error.Message, b.Error.RequestID = e.code, e.msg, rid
	b.Error.Problems, b.Error.Weakening = e.problems, e.weakening
	if e.retry > 0 {
		w.Header().Set("Retry-After", strconv.Itoa(e.retry))
	}
	if e.allow != "" {
		w.Header().Set("Allow", e.allow)
	}
	if e.etag != "" {
		w.Header().Set("ETag", e.etag)
	}
	writeJSON(w, e.status, b)
}

func writeResult(w http.ResponseWriter, rid string, r *result) {
	for k, v := range r.headers {
		w.Header().Set(k, v)
	}
	writeJSON(w, r.status, r.body)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(true)
	if err := enc.Encode(v); err != nil {
		buf.Reset()
		buf.WriteString(`{"error":{"code":"internal","message":"an internal error occurred","request_id":""}}` + "\n")
		status = http.StatusInternalServerError
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Content-Length", strconv.Itoa(buf.Len()))
	w.WriteHeader(status)
	_, _ = w.Write(buf.Bytes())
}
