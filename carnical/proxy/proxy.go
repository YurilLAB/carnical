// SPDX-License-Identifier: Apache-2.0

// Package proxy is a reverse proxy that inspects every request with Coraza running the OWASP Core Rule Set, and
// forwards what passes to one upstream.
//
// The WAF is only as good as the agreement between what it inspects and what the application receives, so the
// proxy works to keep them the same: it forwards the request target exactly as it was sent (and refuses a target
// it could not), it removes every header a client could use to claim an identity or a route, it does not forward
// trailers, and it does not allow protocol upgrades, which would turn the connection into a tunnel nobody inspects.
package proxy

import (
	"bufio"
	"bytes"
	"cmp"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log"
	"mime"
	"net"
	"net/http"
	"net/http/httputil"
	"net/netip"
	"net/url"
	"os"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/experimental"
	txhttp "github.com/corazawaf/coraza/v3/http"
	"github.com/corazawaf/coraza/v3/types"

	"github.com/YurilLAB/coraza/carnical/crowdsec"
	"github.com/YurilLAB/coraza/carnical/crs"
	"github.com/YurilLAB/coraza/carnical/inspect"
	"github.com/YurilLAB/coraza/carnical/shield"
)

// Config describes one protected site.
type Config struct {
	// Upstream is where clean requests go: http or https, a host, no path, user name, query or fragment.
	Upstream *url.URL
	// Origin says which addresses the upstream may be at. By default only public addresses are allowed, so a site
	// cannot be pointed at this machine, the cloud metadata service or the private network; list a range in
	// Origin.Allow for an origin that is really there.
	Origin OriginPolicy
	// OriginTLS verifies the upstream and optionally authenticates this edge with a client certificate.
	OriginTLS OriginTLS
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
	// that goes over it is refused with 503. Reading a slow client's body is not counted. A negative value is refused.
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
	// APIRate limits requests across configured API path prefixes, by the verified client address. Zero disables it.
	APIRate APIRatePolicy
	// Limits are per-client rate rules (see RateRule and ParseRateRules), each with its own budget, counted after the
	// WordPress login limit and APIRate. A request goes on only if every enforcing rule it matches has room, and is then
	// counted by all of them; a monitor rule only reports. At most 32 rules. A signed policy does not change them.
	Limits []RateRule
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
	// NoJoinedParams leaves out the second reading of a parameter given more than once: by default the rules are also
	// given its values joined with commas, as ASP.NET hands them to an application, so that an injection split over
	// them is seen whole (see joined.go). The values come from the URL, a form or multipart body and the cookies.
	NoJoinedParams bool
	// MaxFormBody is the largest request body that is not a file upload (default 128 KiB). Evaluating a body costs
	// time in proportion to its size, and the engine does not apply its own limit for bodies without files, so the
	// proxy does. A multipart/form-data body may be as large as CRS.RequestBodyLimit.
	MaxFormBody int64
	// ResponseHeaderTimeout is how long the upstream has to start answering (default 30 seconds).
	ResponseHeaderTimeout time.Duration
	// ReadTimeout is how long a client has to send a whole request, headers and body (default 30 seconds; the headers
	// alone have at most 10). A body still arriving when it runs out is answered with 408. Raise it for large uploads
	// over slow connections; left at zero, WriteTimeout grows with it. At most 23 hours, so that a WriteTimeout longer
	// than it can still be given; a negative value is refused. Used by Server.
	ReadTimeout time.Duration
	// WriteTimeout is how long a request may take from the end of its headers to the last byte of its response, so it
	// includes the time the body takes to arrive (default ReadTimeout plus 90 seconds, 120 seconds with the default
	// ReadTimeout). A longer response is cut: raise it for large downloads to slow clients, Server-Sent Events and long
	// polling (with ResponseHeaderTimeout). It must be longer than ReadTimeout, or an upload that ReadTimeout allows could
	// reach the application and get no answer. At most 24 hours; a negative value is refused. Used by Server.
	WriteTimeout time.Duration
	// OnMatch is called for every rule that matches. It must not block.
	OnMatch func(Match)
	// Shield, if set, protects the site against floods (package shield), before body inspection and rule evaluation.
	// Its listener and ConnState judge connections. Wrap the listening socket with Shield.Listener.
	Shield *shield.Shield
	// CrowdSec checks LAPI bans against the verified visitor before reading a body.
	// Its owner must Sync before serving, run its refresh loop and close it on shutdown.
	CrowdSec *crowdsec.Client
	// LogDetails adds the client address, URI, matched data and expanded message to a Match. They hold what the visitor
	// sent, which can include personal data and credentials, so they are left out unless asked for.
	LogDetails bool
	// ErrorLog receives the lines the reverse proxy writes itself, such as an application that stops part way through a
	// response body. Nil leaves them to the standard logger.
	ErrorLog *log.Logger
}

// Match is one rule that matched a request.
type Match struct {
	RuleID        int
	Severity      string
	Message       string // the rule's own text, which never holds request data
	TransactionID string
	Disruptive    bool
	// Set only with Config.LogDetails.
	ClientIP, URI, Data, ExpandedMessage string
}

// Edge is the proxy. It is an http.Handler.
type Edge struct {
	crowdSecLogSecond atomic.Int64
	evalLogSecond     [2]atomic.Int64 // the last second a budget refusal of each kind was reported (see reportEval)
	cfg               Config
	originTLS         *tls.Config
	waf               coraza.WAF
	handler           http.Handler
	places            *upstreamPlaces
	hosts             map[string]bool
	deny              map[string]bool
	rules             []*compiledRule // the per-client rate limits, in the order their tables are locked
	now               func() int64    // test clock for the rate rules; nil uses monotonic
	evictLogSecond    atomic.Int64    // the last second a full rate-limit table was reported (see reportEvicted)
	evictUnlogged     atomic.Int64
	evictedLive       atomic.Int64 // clients dropped from a full rate-limit table while still counting
	rateRefused       atomic.Int64 // requests a rate rule refused
	conns             *connLimiter
	connLogSecond     atomic.Int64 // the last second a connection refused by MaxConnsPerIP was reported (see reportTooManyConns)
	connUnlogged      atomic.Int64
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
	originTLS, err := cfg.OriginTLS.ClientConfig(u)
	if err != nil {
		return nil, err
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
	cfg.TrustedProxies = append([]netip.Prefix(nil), cfg.TrustedProxies...)
	apiRate, err := cfg.APIRate.normalized()
	if err != nil {
		return nil, fmt.Errorf("API rate policy: %w", err)
	}
	cfg.APIRate = apiRate
	// Config is an API: the rules are checked again, as a caller may build them without ParseRateRules, and copied, so a
	// caller cannot change them after construction.
	limits, at, err := normalizeRateRules(cfg.Limits)
	if err != nil {
		return nil, fmt.Errorf("rate limit %d (%q): %w", at+1, excerpt(cfg.Limits[at].String()), err)
	}
	cfg.Limits = limits
	if cfg.EvalBudget < 0 {
		// The budget wrapper is also what applies MaxEvaluations, so this would quietly drop both limits.
		return nil, errors.New("the evaluation budget must not be negative")
	}
	if cfg.MaxFormBody < 0 {
		// It would refuse every body as too large, and size the read of a chunked one by a negative count.
		return nil, errors.New("the form body limit must not be negative")
	}
	if cfg.ReadTimeout < 0 || cfg.ReadTimeout > maxReadTimeout || cfg.WriteTimeout < 0 || cfg.WriteTimeout > maxWriteTimeout {
		// net/http takes a negative timeout for none at all, which would let a client hold a connection for ever.
		return nil, fmt.Errorf("the read timeout must be between zero (the default) and %v, and the write timeout between zero and %v",
			maxReadTimeout, maxWriteTimeout)
	}
	if read := cmp.Or(cfg.ReadTimeout, defaultReadTimeout); cfg.WriteTimeout != 0 && cfg.WriteTimeout <= read {
		// net/http starts the write deadline at the end of the headers, so a body that arrives within the read timeout
		// but after the write deadline would be forwarded and acted on, and its client never told the outcome.
		return nil, fmt.Errorf("the write timeout (%v) must be longer than the read timeout (%v), as it includes the time "+
			"the body takes to arrive", cfg.WriteTimeout, read)
	}
	e := &Edge{originTLS: originTLS, hosts: map[string]bool{}, deny: map[string]bool{}}
	for _, h := range cfg.AllowedHosts {
		if n := normHost(h); n != "" {
			e.hosts[n] = true
		}
	}
	if len(cfg.AllowedHosts) > 0 && len(e.hosts) == 0 {
		return nil, errors.New("AllowedHosts has no usable name")
	}
	// The names this site answers to are also what the rule set takes for this site, when it lets a link to the site
	// itself through. A request for any other name never reaches the rules (see checkRequest).
	if len(cfg.CRS.SiteHosts) == 0 {
		for h := range e.hosts {
			if crs.IsSiteHost(h) {
				cfg.CRS.SiteHosts = append(cfg.CRS.SiteHosts, h)
			}
		}
		slices.Sort(cfg.CRS.SiteHosts)
	}
	directives, err := cfg.CRS.Directives()
	if err != nil {
		return nil, err
	}
	e.cfg = cfg
	e.rules = compileLimits(cfg)
	e.evictLogSecond.Store(neverLogged)
	e.connLogSecond.Store(neverLogged)
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
	e.places = newUpstreamPlaces(slots)
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
	e.handler = e.guard(txhttp.WrapHandler(withEvalBudget(waf, budget, evalSlots, cfg.CRS.ResponseLimit(), e.reportEval), e.forward()))
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

const (
	// maxReadTimeout and maxWriteTimeout are the longest ReadTimeout and WriteTimeout a configuration may ask for. The
	// read timeout's is shorter, so that the default write timeout, answerTime past it, is within the write's.
	maxReadTimeout, maxWriteTimeout = 23 * time.Hour, 24 * time.Hour
	// defaultReadTimeout is Config.ReadTimeout when it is zero.
	defaultReadTimeout = 30 * time.Second
	// answerTime is what a WriteTimeout left at zero allows past ReadTimeout for the application to answer.
	answerTime = 90 * time.Second
)

// Server returns an http.Server with limits on how long a client may take over its headers and body (Config.ReadTimeout)
// and on how long a response may take (Config.WriteTimeout).
func (e *Edge) Server(addr string) *http.Server {
	// The write deadline starts at the end of the headers, while the body may still be arriving, so it outlasts the
	// read one (New refuses a WriteTimeout that does not).
	readTimeout := cmp.Or(e.cfg.ReadTimeout, defaultReadTimeout)
	writeTimeout := cmp.Or(e.cfg.WriteTimeout, readTimeout+answerTime)
	srv := &http.Server{Addr: addr, Handler: e, ReadHeaderTimeout: min(10*time.Second, readTimeout), ReadTimeout: readTimeout,
		WriteTimeout: writeTimeout, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 32 << 10,
		DisableGeneralOptionsHandler: true, // so that "OPTIONS *" reaches the guard instead of being answered by net/http
		// HTTP/2 over TLS. Few concurrent streams, small frames, and a write timeout so that a client that stops
		// reading cannot hold a connection. (Cleartext HTTP/2 is left off: it is how request smuggling past a front
		// end that does not speak it is done.)
		HTTP2: &http.HTTP2Config{MaxConcurrentStreams: 100, MaxReadFrameSize: 16 << 10, WriteByteTimeout: 30 * time.Second},
		// Each request can find the connection it came on, to drop it when its client stops reading (see stall.go).
		ConnContext: func(ctx context.Context, c net.Conn) context.Context { return context.WithValue(ctx, connKey{}, c) }}
	if limit := e.cfg.MaxConnsPerIP; limit >= 0 {
		if limit == 0 {
			limit = 128
		}
		e.conns = newConnLimiter(limit, e.cfg.TrustedProxies, e.reportTooManyConns)
		srv.ConnState = e.conns.state
	}
	if sh := e.cfg.Shield; sh != nil {
		prev := srv.ConnState
		srv.ConnState = func(c net.Conn, st http.ConnState) {
			if prev != nil {
				prev(c, st)
			}
			sh.ConnState(c, st)
		}
		// A shield refusal closes the refused client's connection, but not a trusted proxy's.
		connContext := srv.ConnContext
		srv.ConnContext = func(ctx context.Context, c net.Conn) context.Context { return sh.ConnContext(connContext(ctx, c), c) }
	}
	return srv
}

// reportTooManyConns reports a connection refused because its address holds too many open. One client can open them as
// fast as it likes, and the server runs this in its accept loop, so at most one is logged a second, and the next line logged
// says how many were not.
func (e *Edge) reportTooManyConns(ip netip.Addr) {
	if e.cfg.OnMatch == nil {
		return
	}
	second := e.clock() / int64(time.Second)
	if previous := e.connLogSecond.Load(); second == previous || !e.connLogSecond.CompareAndSwap(previous, second) {
		e.connUnlogged.Add(1)
		return
	}
	m := Match{RuleID: idTooManyConns, Severity: "WARNING", Message: "an address holds too many connections open", Disruptive: true}
	if n := e.connUnlogged.Swap(0); n > 0 {
		m.Message += " (" + strconv.FormatInt(n, 10) + " more refusals not logged)"
	}
	if e.cfg.LogDetails {
		m.ClientIP = ip.String()
	}
	e.cfg.OnMatch(m)
}

// reportEval reports a phase of rule evaluation that found no slot or ran out of its budget. Under a flood of expensive
// requests every one of them can, so each kind is reported at most once a second.
func (e *Edge) reportEval(timedOut bool) {
	if e.cfg.OnMatch == nil {
		return
	}
	kind, m := 0, Match{RuleID: idEvalBusy, Severity: "WARNING", Disruptive: true,
		Message: "no rule evaluation slot came free within the budget (at most one report a second)"}
	if timedOut {
		kind, m = 1, Match{RuleID: idEvalBudget, Severity: "WARNING", Disruptive: e.cfg.CRS.Mode == crs.ModeBlock,
			Message: "rule evaluation ran out of its budget (at most one report a second)"}
	}
	second := time.Now().Unix()
	if previous := e.evalLogSecond[kind].Load(); second == previous || !e.evalLogSecond[kind].CompareAndSwap(previous, second) {
		return
	}
	e.cfg.OnMatch(m)
}

func (e *Edge) onMatch(m types.MatchedRule) {
	if e.cfg.OnMatch == nil {
		return
	}
	// Coraza's Message is macro-expanded and may contain credentials or arbitrary request values.
	// Its public metadata exposes no unexpanded message; keep the default summary fixed.
	match := Match{RuleID: m.Rule().ID(), Severity: m.Rule().Severity().String(), Message: "Coraza rule matched",
		TransactionID: m.TransactionID(), Disruptive: m.Disruptive()}
	if label := crs.LocalRuleMessage(match.RuleID); label != "" {
		match.Message = label
	}
	if e.cfg.LogDetails {
		match.ClientIP, match.URI, match.Data = m.ClientIPAddress(), m.URI(), m.Data()
		match.ExpandedMessage = m.Message()
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
		watch := &writeWatch{ResponseWriter: w, onHijack: e.hijacked}
		if r.ProtoMajor == 1 { // an HTTP/2 connection carries other requests too
			watch.conn, _ = r.Context().Value(connKey{}).(net.Conn)
		}
		w = watch
		r = r.WithContext(context.WithValue(r.Context(), writeWatchKey{}, watch))
		if cs := e.cfg.CrowdSec; cs != nil {
			action := cs.Check(addr)
			if action != crowdsec.Allow {
				status, id, msg := http.StatusForbidden, idCrowdSecBan, "CrowdSec IP ban"
				if action == crowdsec.Unavailable {
					status, id, msg = http.StatusServiceUnavailable, idCrowdSecUnavailable, "CrowdSec decision cache unavailable"
					w.Header().Set("Retry-After", "10")
				}
				w.Header().Set("Cache-Control", "no-store")
				// Keep refusal logs bounded during a ban flood; every request is
				// counted in CrowdSec.Stats, including those with no sampled log.
				second := time.Now().Unix()
				previous := e.crowdSecLogSecond.Load()
				if second != previous && e.crowdSecLogSecond.CompareAndSwap(previous, second) {
					e.refuse(w, r, status, id, msg)
				} else {
					http.Error(w, http.StatusText(status), status)
				}
				return
			}
		}
		if sh := e.cfg.Shield; sh != nil {
			// Flood admission costs a few map lookups: a request it refuses is never read further.
			d := sh.Admit(r, addr)
			if d.Action != shield.Allow {
				sh.Write(w, r, d)
				return
			}
			sw := &shieldWriter{ResponseWriter: w}
			w = sw
			fromOrigin := new(bool)
			r = r.WithContext(context.WithValue(r.Context(), originKey{}, fromOrigin))
			defer func() { sh.Done(d, sw.code(), *fromOrigin) }()
		}
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
		hasBody := r.Body != nil && r.Body != http.NoBody
		isForm := hasBody && readAsForm(r.Header)
		var formBody []byte    // a form body, for the joined reading of repeated parameters
		var fields []joinParam // and the fields of a multipart one
		if hasBody {
			// Read the whole body (it is already capped) so that it can be looked at, then hand the same bytes on, or the
			// replacement an inspector made of them. Reading it here also holds it to its limit, and keeps it from taking an
			// upstream place before it is all in, when the engine does not read it (with the rules off, for one).
			body, err := io.ReadAll(r.Body)
			if err != nil {
				status, msg := http.StatusBadRequest, "the request could not be read"
				var networkError net.Error
				switch {
				case capped.tooLarge:
					status, msg = http.StatusRequestEntityTooLarge, "request body too large"
				case errors.Is(err, os.ErrDeadlineExceeded) || errors.As(err, &networkError) && networkError.Timeout():
					// The client was too slow for ReadTimeout: not a malformed request, and the shield does not count a 408
					// as a security rejection.
					status, msg = http.StatusRequestTimeout, "the request took too long to arrive"
				}
				http.Error(w, msg, status)
				return
			}
			ireq, replaced, ok := e.runInspectors(w, r, rawPath, rawQuery, body, addr)
			if !ok {
				return
			}
			seen = ireq
			if replaced != nil {
				body = replaced
			}
			// Validate the bytes and media type that will reach Coraza and the application, including after decompression.
			if int64(len(body)) > e.bodyLimit(r) {
				http.Error(w, "request body too large", http.StatusRequestEntityTooLarge)
				return
			}
			if readAsMultipart(r.Header) {
				boundary, ok := uploadBoundary(r.Header.Get("Content-Type"))
				if !ok {
					e.refuse(w, r, http.StatusBadRequest, idAmbiguousType, "a multipart Content-Type that parsers read differently")
					return
				}
				if id, why := scanUpload(body, boundary, e.cfg.Uploads); id != 0 {
					e.refuse(w, r, http.StatusForbidden, id, why)
					return
				}
				if !e.cfg.NoJoinedParams {
					fields = multipartFields(body, boundary)
				}
			}
			if isForm {
				formBody = body
			}
			if replaced != nil {
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
		// checkRequest let a compressed body through only for an inspector to decompress. If none did (monitor mode, a
		// rule turned off, no inspector), the rules would read compressed bytes that the application then unpacks.
		if hasBody && contentEncoded(r.Header) {
			e.refuse(w, r, http.StatusUnsupportedMediaType, idRequestEncoding, "a compressed request body was not decompressed for inspection")
			return
		}
		tw := &trackWriter{ResponseWriter: w}
		ctx := context.WithValue(r.Context(), contextKey{}, addr)
		if seen != nil {
			ctx = context.WithValue(ctx, observedKey{}, seen)
		}
		if !e.cfg.NoJoinedParams {
			if joined := joinRepeated(rawQuery, formBody, fields, r.Header["Cookie"]); len(joined) > 0 {
				ctx = context.WithValue(ctx, joinedKey{}, joined)
			}
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

// Hijack is for an allowed upgrade; once the connection is the tunnel's, nothing may be written to it as a response.
func (t *trackWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	c, rw, err := http.NewResponseController(t.ResponseWriter).Hijack()
	if err == nil {
		t.wrote = true
	}
	return c, rw, err
}

func (t *trackWriter) Unwrap() http.ResponseWriter { return t.ResponseWriter }

// hijacked keeps a connection taken over for an allowed upgrade counted against its address until the tunnel closes it.
func (e *Edge) hijacked(c net.Conn) net.Conn {
	if e.conns == nil {
		return c
	}
	return &hijackedConn{Conn: c, closed: func() { e.conns.state(c, http.StateClosed) }}
}

// checkTarget requires the target to be a path and query that Go would write back exactly as received. The WAF
// inspects the parsed form of the target and the application gets the raw one; this makes them the same. A raw '#' is
// refused anywhere: a request target has no fragment, and the engine cuts the URI at '#' before it reads the query,
// while an application that does not (Go's url.ParseQuery, for one) reads the parameters after it uninspected.
func checkTarget(r *http.Request) error {
	raw := r.RequestURI
	if !strings.HasPrefix(raw, "/") || strings.HasPrefix(raw, "//") {
		return errors.New("not an origin-form target")
	}
	if strings.IndexByte(raw, '#') >= 0 {
		return errors.New("a raw '#' in the target")
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
	transport.TLSClientConfig = e.originTLS
	transport.Proxy = nil // never an environment proxy
	// Every connection is checked at the moment it is made, against the address it will really use.
	dialer := e.cfg.Origin.Dialer()
	transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		conn, err, retries := dialBindRetry(ctx, network, address, dialer.DialContext)
		if retries > 0 && e.cfg.OnMatch != nil {
			e.cfg.OnMatch(Match{RuleID: idUpstreamBindRetry, Severity: "WARNING",
				Message: fmt.Sprintf("upstream socket bind retried %d time(s)", retries), Disruptive: false})
		}
		return conn, err
	}
	transport.ResponseHeaderTimeout = e.cfg.ResponseHeaderTimeout
	if transport.ResponseHeaderTimeout <= 0 {
		transport.ResponseHeaderTimeout = 30 * time.Second
	}
	transport.MaxIdleConnsPerHost = 64
	rp := &httputil.ReverseProxy{
		Transport: transport,
		ErrorLog:  e.cfg.ErrorLog,
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
			if e.cfg.CRS.InspectResponses {
				// The response rules read the body the application sends. Asked by the client, the application compresses it and
				// the rules read gzip bytes; without the client's Accept-Encoding the transport asks for gzip itself and hands on
				// the body decompressed, so the visitor gets it uncompressed. Asked for ranges, it sends a slice of the body, which
				// no rule sees whole, or several as multipart/byteranges, a type the rules do not read at all; without Range it
				// sends the whole body, which a client that asked for a range may take (RFC 9110, 14.2).
				out.Header.Del("Accept-Encoding")
				out.Header.Del("Range")
				out.Header.Del("If-Range")
			}
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
			markOrigin(resp.Request.Context())
			if resp.StatusCode == http.StatusSwitchingProtocols && !e.cfg.AllowUpgrade {
				return errors.New("upstream protocol upgrade is not supported")
			}
			if e.cfg.CRS.InspectResponses && encodedResponse(resp.Header) {
				// Compressed without being asked (the transport decompresses the gzip it asks for): the rules could not read it.
				return errors.New("the application compressed a response that is to be inspected")
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
			// A request cancelled because its client went away, or because its response was ended to free a place (see
			// stall.go), was not failed by the application: the shield must not take it for an application error.
			if !errors.Is(err, context.Canceled) || r.Context().Err() == nil {
				markOrigin(r.Context())
			}
			if e.cfg.OnMatch != nil {
				// Operational failure, not an attack finding. Error strings can
				// contain addresses or request data; default logs get only a class
				// and (when present) the numeric OS error code.
				m := Match{RuleID: idUpstreamFailed, Severity: "ERROR", Message: "upstream request failed", Disruptive: true}
				var errno syscall.Errno
				var networkError net.Error
				switch {
				case errors.As(err, &errno):
					m.Message = fmt.Sprintf("upstream network failure (errno %d)", errno)
				case errors.As(err, &networkError) && networkError.Timeout():
					m.Message = "upstream request timed out"
				case errors.Is(err, context.Canceled):
					m.Message = "upstream request canceled"
				case errors.Is(err, io.EOF), errors.Is(err, io.ErrUnexpectedEOF):
					m.Message = "upstream connection ended before a response"
				}
				if e.cfg.LogDetails {
					m.ClientIP, m.URI, m.ExpandedMessage = r.RemoteAddr, r.RequestURI, err.Error()
				}
				e.cfg.OnMatch(m)
			}
			http.Error(w, "upstream unavailable", http.StatusBadGateway)
		},
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		watch, _ := r.Context().Value(writeWatchKey{}).(*writeWatch)
		ok, reclaimed := e.places.acquire(watch)
		if reclaimed && e.cfg.OnMatch != nil {
			e.cfg.OnMatch(Match{RuleID: idUpstreamReclaimed, Severity: "WARNING", Disruptive: true,
				Message: "a response the client stopped reading was ended to free an upstream place"})
		}
		if !ok {
			markOrigin(r.Context()) // the application has as many requests as it may take: that is its health too
			w.Header().Set("Retry-After", "1")
			http.Error(w, "busy", http.StatusServiceUnavailable)
			return
		}
		defer e.places.release(watch)
		if watch != nil {
			// Ending this response to free its place (see stall.go) also cancels its request to the application, at once, so that
			// the application never has more requests than places while the ended response's handler is returning.
			ctx, cancel := context.WithCancel(r.Context())
			defer cancel()
			watch.setCancel(cancel)
			r = r.WithContext(ctx)
		}
		rp.ServeHTTP(noInterim{w}, r)
	})
}

// encodedResponse reports a response body in a content coding other than identity.
func encodedResponse(h http.Header) bool {
	for _, v := range h.Values("Content-Encoding") {
		for _, coding := range strings.Split(v, ",") {
			if c := strings.TrimSpace(coding); c != "" && !strings.EqualFold(c, "identity") {
				return true
			}
		}
	}
	return false
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

// originKey marks, for the shield, that a response came from (or was about) the application rather than from a check.
type originKey struct{}

func markOrigin(ctx context.Context) {
	if p, ok := ctx.Value(originKey{}).(*bool); ok {
		*p = true
	}
}

// shieldWriter records the status sent, for Shield.Done.
type shieldWriter struct {
	http.ResponseWriter
	status int
}

func (s *shieldWriter) WriteHeader(code int) {
	if s.status == 0 && code >= 200 {
		s.status = code
	}
	s.ResponseWriter.WriteHeader(code)
}

func (s *shieldWriter) Write(b []byte) (int, error) {
	if s.status == 0 {
		s.status = http.StatusOK
	}
	return s.ResponseWriter.Write(b)
}

func (s *shieldWriter) Flush() {
	if f, ok := s.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (s *shieldWriter) code() int {
	if s.status == 0 {
		return http.StatusOK
	}
	return s.status
}

func (s *shieldWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	return http.NewResponseController(s.ResponseWriter).Hijack()
}

func (s *shieldWriter) Unwrap() http.ResponseWriter { return s.ResponseWriter }
