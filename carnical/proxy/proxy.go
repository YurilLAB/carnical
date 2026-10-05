// Package proxy is a reverse proxy that inspects every request with Coraza running the OWASP Core Rule Set, and
// forwards what passes to one upstream.
//
// The WAF is only as good as the agreement between what it inspects and what the application receives, so the
// proxy works to keep them the same: it forwards the request target exactly as it was sent (and refuses a target
// it could not), it removes every header a client could use to claim an identity or a route, it does not forward
// trailers, and it does not allow protocol upgrades, which would turn the connection into a tunnel nobody inspects.
package proxy

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/http/httputil"
	"net/netip"
	"net/url"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/experimental"
	txhttp "github.com/corazawaf/coraza/v3/http"
	"github.com/corazawaf/coraza/v3/types"

	"github.com/YurilLAB/coraza/carnical/crs"
	"github.com/YurilLAB/coraza/carnical/inspect"
)

// Config describes one protected site.
type Config struct {
	// Upstream is where clean requests go: http or https, a host, no path, user name, query or fragment.
	Upstream *url.URL
	// Origin says which addresses the upstream may be at. By default only public addresses are allowed, so a site
	// cannot be pointed at this machine, the cloud metadata service or the private network; list a range in
	// Origin.Allow for an origin that is really there.
	Origin OriginPolicy
	// UpstreamHost is the Host header sent to the upstream. Empty keeps the visitor's Host, which is what a site
	// that serves several names expects; set it when the upstream is a shared machine, so a visitor cannot reach
	// another site there by choosing a different Host.
	UpstreamHost string
	// CRS holds the rule set settings (mode, paranoia level, thresholds, body limit).
	CRS crs.Settings
	// TrustedProxies may say who the visitor is through X-Forwarded-For.
	TrustedProxies []netip.Prefix
	// AllowUpgrade lets WebSocket and similar upgrades through. Nothing inspects them after the handshake.
	AllowUpgrade bool
	// MaxUpstreamInFlight is how many requests may be at the upstream at once (default 256). A request takes a
	// place only after its body has been read, so a slow upload does not use one up.
	MaxUpstreamInFlight int
	// EvalBudget is how long each phase of rule evaluation may take for one request (default 2 seconds). A request
	// that goes over it is refused with 503. Reading a slow client's body is not counted.
	EvalBudget time.Duration
	// MaxEvaluations is how many requests may be in rule evaluation at once (default: the number of CPUs). The rules
	// cost several milliseconds per KiB of body, so without this a few large requests use every core. Others wait up
	// to EvalBudget for a place and are then refused with 503. A negative value means no limit.
	MaxEvaluations int
	// AllowedHosts, if set, are the only names this site answers to (any other Host gets 421). Compared in lower case,
	// without a port or a trailing dot. Empty means any name.
	AllowedHosts []string
	// Paths says how plain a request path must be (the default is strict: no encoded slashes, dot segments,
	// semicolons or unnecessary escapes).
	Paths PathPolicy
	// DenyHeaders are headers whose presence refuses the request, for a site that does not use the feature they
	// belong to (Next-Action on a site with no server actions). Compared with - and _ alike.
	DenyHeaders []string
	// WordPress switches on the protections for a WordPress site.
	WordPress WordPressPolicy
	// Uploads says what is refused in a file upload.
	Uploads UploadPolicy
	// Responses says what the proxy changes in the application's responses.
	Responses ResponsePolicy
	// MaxConnsPerIP is how many connections one address may hold open (default 128; negative means no limit).
	// Connections from TrustedProxies are not counted.
	MaxConnsPerIP int
	// Observers are told, for every request that was let through, what the application answered. See inspect.Observer.
	Observers []inspect.Observer
	// AllowRequestEncoding lets a request body with a gzip or deflate Content-Encoding through to the inspectors, which can
	// decompress it within limits (package formats). Without it such a request is refused, because nothing could read it. Any
	// other encoding is always refused.
	AllowRequestEncoding bool
	// Inspectors look at every request, in this order, after the proxy's own checks and before the rule set: the virtual-patch
	// signatures, the body-format checks, the API guard. See package inspect.
	Inspectors []inspect.Inspector
	// MaxFormBody is the largest request body that is not a file upload (default 128 KiB). Evaluating a body costs
	// time in proportion to its size, and the engine does not apply its own limit for bodies without files, so the
	// proxy does. A multipart/form-data body may be as large as CRS.RequestBodyLimit.
	MaxFormBody int64
	// ResponseHeaderTimeout is how long the upstream has to start answering (default 30 seconds).
	ResponseHeaderTimeout time.Duration
	// OnMatch is called for every rule that matches. It must not block.
	OnMatch func(Match)
	// LogDetails adds the client address, the URI and the matched data to a Match. They hold what the visitor
	// sent, which can include personal data and credentials, so they are left out unless asked for.
	LogDetails bool
}

// Match is one rule that matched a request.
type Match struct {
	RuleID        int
	Severity      string
	Message       string // the rule's own text, which never holds request data
	TransactionID string
	Disruptive    bool
	// Set only with Config.LogDetails.
	ClientIP, URI, Data string
}

// Edge is the proxy. It is an http.Handler.
type Edge struct {
	cfg     Config
	waf     coraza.WAF
	handler http.Handler
	slots   chan struct{}
	hosts   map[string]bool
	deny    map[string]bool
	limiter rateLimiter
	conns   *connLimiter
}

type contextKey struct{}

// New builds the proxy and compiles the rule set.
func New(cfg Config) (*Edge, error) {
	u := cfg.Upstream
	switch {
	case u == nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "":
		return nil, errors.New("the upstream must be an http or https address with a host")
	case u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") || u.Opaque != "":
		return nil, errors.New("the upstream must not carry a user name, a path, a query or a fragment")
	}
	for _, p := range cfg.Origin.Allow {
		if !p.IsValid() || p.Bits() == 0 {
			return nil, fmt.Errorf("origin range %s: a range of /0 would switch the origin check off", p)
		}
	}
	if ip, err := netip.ParseAddr(u.Hostname()); err == nil {
		if err := cfg.Origin.Check(ip); err != nil {
			return nil, fmt.Errorf("the upstream: %w", err)
		}
	}
	for _, p := range cfg.TrustedProxies {
		if err := checkTrusted(p); err != nil {
			return nil, fmt.Errorf("trusted proxy %s: %w", p, err)
		}
	}
	directives, err := cfg.CRS.Directives()
	if err != nil {
		return nil, err
	}
	e := &Edge{cfg: cfg, hosts: map[string]bool{}, deny: map[string]bool{}}
	for _, h := range cfg.AllowedHosts {
		if n := normHost(h); n != "" {
			e.hosts[n] = true
		}
	}
	if len(cfg.AllowedHosts) > 0 && len(e.hosts) == 0 {
		return nil, errors.New("AllowedHosts has no usable name")
	}
	for _, h := range cfg.DenyHeaders {
		e.deny[strings.ReplaceAll(strings.ToLower(strings.TrimSpace(h)), "_", "-")] = true
	}
	waf, err := coraza.NewWAF(coraza.NewWAFConfig().WithRootFS(crs.FS()).WithDirectives(directives).WithErrorCallback(e.onMatch))
	if err != nil {
		return nil, fmt.Errorf("loading the rule set: %w", err)
	}
	e.waf = waf
	slots := cfg.MaxUpstreamInFlight
	if slots <= 0 {
		slots = 256
	}
	e.slots = make(chan struct{}, slots)
	budget := cfg.EvalBudget
	if budget == 0 {
		budget = 2 * time.Second
	}
	var evalSlots chan struct{}
	switch n := cfg.MaxEvaluations; {
	case n == 0:
		evalSlots = make(chan struct{}, runtime.GOMAXPROCS(0))
	case n > 0:
		evalSlots = make(chan struct{}, n)
	}
	if e.cfg.MaxFormBody == 0 {
		e.cfg.MaxFormBody = 128 << 10
	}
	e.handler = e.guard(txhttp.WrapHandler(withEvalBudget(waf, budget, evalSlots), e.forward()))
	return e, nil
}

// ServeHTTP implements http.Handler.
func (e *Edge) ServeHTTP(w http.ResponseWriter, r *http.Request) { e.handler.ServeHTTP(w, r) }

// Close releases the compiled rules.
func (e *Edge) Close() error {
	if c, ok := e.waf.(experimental.WAFCloser); ok {
		return c.Close()
	}
	return nil
}

// Server returns an http.Server with limits on how long a client may take over its headers and body.
func (e *Edge) Server(addr string) *http.Server {
	srv := &http.Server{Addr: addr, Handler: e, ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 30 * time.Second,
		WriteTimeout: 120 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 32 << 10,
		DisableGeneralOptionsHandler: true, // so that "OPTIONS *" reaches the guard instead of being answered by net/http
		// HTTP/2 over TLS. Few concurrent streams, small frames, and a write timeout so that a client that stops
		// reading cannot hold a connection. (Cleartext HTTP/2 is left off: it is how request smuggling past a front
		// end that does not speak it is done.)
		HTTP2: &http.HTTP2Config{MaxConcurrentStreams: 100, MaxReadFrameSize: 16 << 10, WriteByteTimeout: 30 * time.Second}}
	if limit := e.cfg.MaxConnsPerIP; limit >= 0 {
		if limit == 0 {
			limit = 128
		}
		e.conns = newConnLimiter(limit, e.cfg.TrustedProxies, func(ip netip.Addr) {
			if e.cfg.OnMatch != nil {
				e.cfg.OnMatch(Match{RuleID: idTooManyConns, Severity: "WARNING", Message: "an address holds too many connections open", Disruptive: true})
			}
		})
		srv.ConnState = e.conns.state
	}
	return srv
}

func (e *Edge) onMatch(m types.MatchedRule) {
	if e.cfg.OnMatch == nil {
		return
	}
	match := Match{RuleID: m.Rule().ID(), Severity: m.Rule().Severity().String(), Message: m.Message(),
		TransactionID: m.TransactionID(), Disruptive: m.Disruptive()}
	if e.cfg.LogDetails {
		match.ClientIP, match.URI, match.Data = m.ClientIPAddress(), m.URI(), m.Data()
	}
	e.cfg.OnMatch(match)
}

// guard refuses what cannot be inspected faithfully, and tells the WAF and the application who the visitor is.
func (e *Edge) guard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodConnect {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if !e.cfg.AllowUpgrade && wantsUpgrade(r.Header) {
			http.Error(w, "protocol upgrades are not supported", http.StatusNotImplemented)
			return
		}
		if err := checkTarget(r); err != nil {
			http.Error(w, "invalid request target", http.StatusBadRequest)
			return
		}
		addr, port, err := clientAddr(r, e.cfg.TrustedProxies)
		if err != nil {
			http.Error(w, "invalid client address", http.StatusBadRequest)
			return
		}
		// Coraza splits RemoteAddr at its last colon, so an IPv6 address is given without brackets.
		r.RemoteAddr = fmt.Sprintf("%s:%d", addr, port)
		if !e.checkRequest(w, r, addr) {
			return
		}
		rawPath, rawQuery, _ := strings.Cut(r.RequestURI, "?")

		limit := e.bodyLimit(r)
		if r.ContentLength > limit {
			http.Error(w, "request body too large", http.StatusRequestEntityTooLarge)
			return
		}
		capped := &capReader{left: limit}
		if r.Body != nil && r.Body != http.NoBody {
			capped.rc, r.Body = r.Body, capped
		}
		var seen *inspect.Request // what the inspectors saw, for the observers
		mt, params, mtErr := mime.ParseMediaType(r.Header.Get("Content-Type"))
		hasBody := r.Body != nil && r.Body != http.NoBody
		isUpload := mtErr == nil && mt == "multipart/form-data"
		if hasBody && (isUpload || len(e.cfg.Inspectors) > 0) {
			// Read the whole body (it is already capped) so that it can be looked at, then hand the same bytes on, or the
			// replacement an inspector made of them.
			body, err := io.ReadAll(r.Body)
			if err != nil {
				status, msg := http.StatusBadRequest, "the request could not be read"
				if capped.tooLarge {
					status, msg = http.StatusRequestEntityTooLarge, "request body too large"
				}
				http.Error(w, msg, status)
				return
			}
			if isUpload {
				if id, why := scanUpload(body, params["boundary"], e.cfg.Uploads); id != 0 {
					e.refuse(w, r, http.StatusForbidden, id, why)
					return
				}
			}
			ireq, replaced, ok := e.runInspectors(w, r, rawPath, rawQuery, body, addr)
			if !ok {
				return
			}
			seen = ireq
			if replaced != nil {
				body = replaced
				// The body the application gets is not the one that was sent, so its framing is rewritten to match.
				r.ContentLength, r.TransferEncoding = int64(len(body)), nil
				r.Header.Set("Content-Length", strconv.Itoa(len(body)))
			}
			r.Body = io.NopCloser(bytes.NewReader(body))
		} else if len(e.cfg.Inspectors) > 0 {
			ireq, _, ok := e.runInspectors(w, r, rawPath, rawQuery, nil, addr)
			if !ok {
				return
			}
			seen = ireq
		}
		tw := &trackWriter{ResponseWriter: w}
		ctx := context.WithValue(r.Context(), contextKey{}, addr)
		if seen != nil {
			ctx = context.WithValue(ctx, observedKey{}, seen)
		}
		next.ServeHTTP(tw, r.WithContext(ctx))
		if !tw.wrote {
			// The engine returns without answering when it could not process the request (the body ended early, a
			// chunk was malformed, the body went over its limit). net/http would send an empty 200, which tells the
			// visitor the request was handled when nothing was forwarded.
			status, msg := http.StatusBadRequest, "the request could not be processed"
			if capped.tooLarge {
				status, msg = http.StatusRequestEntityTooLarge, "request body too large"
			}
			http.Error(w, msg, status)
		}
	})
}

// bodyLimit is how large this request's body may be: a file upload as much as the rule set's body limit allows, anything
// else the (much smaller) form limit.
func (e *Edge) bodyLimit(r *http.Request) int64 {
	if mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type")); err == nil && mt == "multipart/form-data" {
		return e.cfg.CRS.RequestBodyLimit
	}
	return min(e.cfg.MaxFormBody, e.cfg.CRS.RequestBodyLimit)
}

// capReader stops a body at a limit, so a chunked body (which has no length to check up front) is held to it as well.
type capReader struct {
	rc       io.ReadCloser
	left     int64
	tooLarge bool
}

var errTooLarge = errors.New("request body too large")

func (c *capReader) Read(p []byte) (int, error) {
	if c.tooLarge {
		return 0, errTooLarge
	}
	if int64(len(p)) > c.left+1 {
		p = p[:c.left+1]
	}
	n, err := c.rc.Read(p)
	if int64(n) > c.left {
		c.tooLarge = true
		n = int(c.left)
		c.left = 0
		return n, errTooLarge
	}
	c.left -= int64(n)
	return n, err
}

func (c *capReader) Close() error {
	if c.rc == nil {
		return nil
	}
	return c.rc.Close()
}

// trackWriter notes whether anything was written to the response.
type trackWriter struct {
	http.ResponseWriter
	wrote bool
}

func (t *trackWriter) WriteHeader(code int) {
	t.wrote = true
	t.ResponseWriter.WriteHeader(code)
}

func (t *trackWriter) Write(b []byte) (int, error) {
	t.wrote = true
	return t.ResponseWriter.Write(b)
}

func (t *trackWriter) Flush() {
	t.wrote = true
	if f, ok := t.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (t *trackWriter) Unwrap() http.ResponseWriter { return t.ResponseWriter }

// checkTarget requires the target to be a path and query that Go would write back exactly as received. The WAF
// inspects the parsed form of the target and the application gets the raw one; this makes them the same.
func checkTarget(r *http.Request) error {
	raw := r.RequestURI
	if !strings.HasPrefix(raw, "/") || strings.HasPrefix(raw, "//") {
		return errors.New("not an origin-form target")
	}
	path, _, _ := strings.Cut(raw, "?")
	if r.URL.EscapedPath() != path {
		return errors.New("the path is not in the form that is forwarded unchanged")
	}
	return nil
}

// forward sends a request that has passed inspection to the upstream.
func (e *Edge) forward() http.Handler {
	target := e.cfg.Upstream
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil // never an environment proxy
	// Every connection is checked at the moment it is made, against the address it will really use.
	transport.DialContext = e.cfg.Origin.Dialer().DialContext
	transport.ResponseHeaderTimeout = e.cfg.ResponseHeaderTimeout
	if transport.ResponseHeaderTimeout <= 0 {
		transport.ResponseHeaderTimeout = 30 * time.Second
	}
	transport.MaxIdleConnsPerHost = 64
	rp := &httputil.ReverseProxy{
		Transport: transport,
		Rewrite: func(pr *httputil.ProxyRequest) {
			in, out := pr.In, pr.Out
			out.URL.Scheme, out.URL.Host = target.Scheme, target.Host
			// The target exactly as it was sent: Opaque keeps the path from being re-encoded, and the query
			// is taken from the original too, so nothing is dropped or reordered on the way.
			rawPath, rawQuery, hasQuery := strings.Cut(in.RequestURI, "?")
			out.URL.Path, out.URL.RawPath, out.URL.Opaque = "", "", rawPath
			out.URL.RawQuery, out.URL.ForceQuery = rawQuery, hasQuery && rawQuery == ""
			out.Host = in.Host
			if e.cfg.UpstreamHost != "" {
				out.Host = e.cfg.UpstreamHost
			}
			stripClaims(out.Header)
			// The proxy has the whole body before it forwards anything, so the application has nothing to wait for.
			out.Header.Del("Expect")
			out.Trailer = nil
			// A request with a body does not share its connection to the application with the next request. If the
			// application stops reading a body early (it ignores it, or answers before it is all there), what is
			// left on a reused connection is read as the start of the next request: the CL.0 / 0.CL desync attacks.
			if in.ContentLength != 0 {
				out.Close = true
			}
			addr, _ := in.Context().Value(contextKey{}).(netip.Addr)
			proto := "http"
			if in.TLS != nil {
				proto = "https"
			}
			out.Header.Set("X-Forwarded-For", addr.String())
			out.Header.Set("X-Real-IP", addr.String())
			out.Header.Set("X-Forwarded-Proto", proto)
			out.Header.Set("X-Forwarded-Host", in.Host)
		},
		ModifyResponse: func(resp *http.Response) error {
			if resp.StatusCode == http.StatusSwitchingProtocols && !e.cfg.AllowUpgrade {
				return errors.New("upstream protocol upgrade is not supported")
			}
			path, _, _ := strings.Cut(resp.Request.URL.Opaque, "?")
			e.cfg.Responses.harden(resp, path)
			if len(e.cfg.Observers) > 0 {
				if ir, ok := resp.Request.Context().Value(observedKey{}).(*inspect.Request); ok {
					for _, o := range e.cfg.Observers {
						o.Observe(ir, resp.StatusCode)
					}
				}
			}
			return nil
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			http.Error(w, "upstream unavailable", http.StatusBadGateway)
		},
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case e.slots <- struct{}{}:
			defer func() { <-e.slots }()
		default:
			w.Header().Set("Retry-After", "1")
			http.Error(w, "busy", http.StatusServiceUnavailable)
			return
		}
		rp.ServeHTTP(noInterim{w}, r)
	})
}

// noInterim drops interim (1xx) responses from the application. The engine takes the first status it is given for the
// final one: after a 103 Early Hints it never sees the real response's headers, does not buffer its body, and the
// response rules are never run on it. Nothing is lost by dropping them: they only let a browser start early.
type noInterim struct{ http.ResponseWriter }

func (n noInterim) WriteHeader(code int) {
	if code >= 100 && code < 200 && code != http.StatusSwitchingProtocols {
		return
	}
	n.ResponseWriter.WriteHeader(code)
}

func (n noInterim) Unwrap() http.ResponseWriter { return n.ResponseWriter }
