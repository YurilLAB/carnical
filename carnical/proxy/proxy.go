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
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/experimental"
	txhttp "github.com/corazawaf/coraza/v3/http"
	"github.com/corazawaf/coraza/v3/types"

	"github.com/YurilLAB/coraza/carnical/alert"
	"github.com/YurilLAB/coraza/carnical/bots"
	"github.com/YurilLAB/coraza/carnical/challenge"
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
	// EvalBudgetDetect is what detection mode does with a request whose evaluation ran out of EvalBudget: forward it with
	// the rest of its rules unread (OverBudgetForward, the default), which its alert reports as not_inspected, or refuse it
	// with 503 as block mode does (OverBudgetRefuse). Block mode always refuses it.
	EvalBudgetDetect OverBudget
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
	// proxy does. A multipart/form-data body may be as large as CRS.RequestBodyLimit, but everything in it other than
	// the content of its files is held to MaxFormBody, as ModSecurity's SecRequestBodyNoFilesLimit holds it (refused
	// with 413, rule 5000012). A part the rules take for a file and PHP for a field, or the other way round, is refused
	// with 400 (rule 5000005).
	MaxFormBody int64
	// ResponseHeaderTimeout is how long the upstream has to start answering (default 30 seconds). Raise it, and
	// WriteTimeout past it, for long polling, where the application holds a request until it has something to say.
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
	// OnAlert is given the verdict of every request in which something was found, once the request is done: one
	// alert.Alert for each signature, saying whether the request was blocked, would have been (detection or monitor
	// mode), was only reported, or could not be inspected in full (ADR-0084). A request with no finding gives none. It
	// is called on the request's goroutine and must not block (see alert.Async); nil gives no alerts.
	OnAlert func(alert.Alert)
	// Alerts says what an alert shows of the visitor and the path.
	Alerts AlertOptions
	// Shield, if set, protects the site against floods (package shield), before body inspection and rule evaluation.
	// Its listener and ConnState judge connections. Wrap the listening socket with Shield.Listener.
	Shield *shield.Shield
	// Bots, if set, refuses the kinds of client it lists (package bots), after the flood protection and before the body
	// is read. Every request's alerts name the kind of client that sent it either way, and the alert totals count
	// refused bots and people apart.
	Bots *bots.Policy
	// Hellos, if set, keeps what each TLS connection's handshake showed, so that a program that sends a browser's user
	// agent without that browser's TLS is read as disguised (see bots.Classify). Set Hellos.Observe as the server's
	// tls.Config.GetConfigForClient; Server forgets each connection when it closes.
	Hellos *bots.Hellos
	// Challenge, if set, is a check that a visitor is a person (package challenge), which Carnical does not ship. It is
	// offered the requests the shield would challenge, or refuse as strangers over an attack's budget, in place of the
	// shield's own challenge; and every request that passed the shield, the bot policy and the request policy, before its
	// body is read. A request it answers goes no further. A visitor it accepts is admitted past the shield as a right
	// answer to the shield's challenge would be; one it refuses has an alert (rule 5007001). If it is also a
	// challenge.Responder, it sees the header of each response the application gives before it is forwarded.
	Challenge challenge.Gate
	// MaxChallenges bounds concurrent person-check callbacks, including response hooks (default: the number of CPUs).
	// Calls beyond the limit are refused with 503 without waiting. It must be between 0 (the default) and 65536.
	MaxChallenges int
	// ChallengeBudget is the deadline passed to each person-check callback (default 2 seconds, at most 24 hours).
	// Checks must honor cancellation and bound their own CPU work; an in-process callback cannot be forcibly stopped.
	ChallengeBudget time.Duration
	// CrowdSec checks LAPI bans against the verified visitor before reading a body.
	// Its owner must Sync before serving, run its refresh loop and close it on shutdown.
	CrowdSec *crowdsec.Client
	// NoRuleMatches leaves out of OnMatch the lines that report what a request matched or why it was refused: the rule
	// set's, the inspectors' verdicts, the proxy's own refusals and the rate rules'. The lines about the edge itself (an
	// upstream failure, an inspector that failed, the evaluation budget, a full table) are still given. By default every
	// match is reported.
	NoRuleMatches bool
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
	// Category is the rule's kind from the alert catalog ("sqli", "protocol", "rate"; several are joined with commas),
	// empty for a rule it gives none. Risk is info, low, medium or high: for a rule set rule that only adds to the anomaly
	// score, from its severity; for an inspector's verdict, from its severity and whether it refused; otherwise the
	// catalog's.
	Category, Risk string
	// Set only with Config.LogDetails.
	ClientIP, URI, Data, ExpandedMessage string
	// verdict marks the line of a check that decides on the request on its own, whether it refused it or, in detection or
	// monitor mode, would have: a rule set verdict (see refusesOnItsOwn) or an inspector's. Such a line is never held back
	// by maxRequestLines, so a request cannot hide its verdict behind the lines of the rules it matched.
	verdict bool
	// What the request's alerts are built from (see Edge.note): the status a refusal answered with; would, for a finding
	// that did not refuse, that its check refuses where it enforces; engine for a rule set match, with the categories of
	// the rule's attack tags and, on the anomaly verdict, the score it gave.
	status        int
	would, engine bool
	cats          alert.Categories
	score         int
}

// Edge is the proxy. It is an http.Handler.
type Edge struct {
	crowdSecLogSecond atomic.Int64
	evalLogSecond     [2]atomic.Int64 // the last second a budget refusal of each kind was reported (see reportEval)
	evalUnlogged      [2]atomic.Int64 // and how many of each kind were not since
	cfg               Config
	originTLS         *tls.Config
	waf               coraza.WAF
	handler           http.Handler
	places            *upstreamPlaces
	gateSlots         chan struct{}
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
	earlyLog          [idClientAddr - idConnect + 1]sampled // see refuseEarly
	slowBodies        atomic.Int64                          // see SlowBodies
}

type contextKey struct{}

// copyBuffers is the reverse proxy's httputil.BufferPool: without one it allocates a buffer for every response it copies.
type copyBuffers struct{ pool sync.Pool }

func (p *copyBuffers) Get() []byte {
	if b, ok := p.pool.Get().(*[]byte); ok {
		return *b
	}
	return make([]byte, 32<<10)
}

func (p *copyBuffers) Put(b []byte) { p.pool.Put(&b) }

// OverBudget is what detection mode does with a request whose evaluation ran out of its budget (Config.EvalBudgetDetect).
type OverBudget string

// The choices of Config.EvalBudgetDetect.
const (
	OverBudgetForward OverBudget = "forward"
	OverBudgetRefuse  OverBudget = "refuse"
)

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
	if len(cfg.Responses.SessionCookies) > MaxSessionCookies {
		return nil, fmt.Errorf("at most %d session cookie names", MaxSessionCookies)
	}
	for _, name := range cfg.Responses.SessionCookies {
		if !SessionCookieName(name) {
			return nil, fmt.Errorf("session cookie %q: not a cookie name", excerpt(name))
		}
	}
	cfg.Responses.SessionCookies = slices.Clone(cfg.Responses.SessionCookies)
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
	switch cfg.EvalBudgetDetect {
	case "", OverBudgetForward, OverBudgetRefuse:
	default:
		return nil, fmt.Errorf("the evaluation budget in detection mode must be %s or %s, not %q", OverBudgetForward, OverBudgetRefuse,
			excerpt(string(cfg.EvalBudgetDetect)))
	}
	switch cfg.Alerts.Source {
	case alert.SourceFull, alert.SourcePrefix, alert.SourceOff:
	default:
		return nil, errors.New("the alert source must be full, prefix or off")
	}
	switch cfg.Alerts.Path {
	case alert.PathTemplate, alert.PathFull, alert.PathOff:
	default:
		return nil, errors.New("the alert path must be template, full or off")
	}
	if cfg.MaxFormBody < 0 {
		// It would refuse every body as too large, and size the read of a chunked one by a negative count.
		return nil, errors.New("the form body limit must not be negative")
	}
	if cfg.MaxChallenges < 0 || cfg.MaxChallenges > 65536 || cfg.ChallengeBudget < 0 || cfg.ChallengeBudget > maxWriteTimeout {
		return nil, errors.New("person check: MaxChallenges must be between 0 and 65536 and ChallengeBudget between 0 and 24 hours")
	}
	if cfg.ChallengeBudget == 0 {
		cfg.ChallengeBudget = 2 * time.Second
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
	settings := cfg.CRS
	settings.WordPress = cfg.WordPress.Enabled // with the override checkRequest lets through (wordPressOverride)
	directives, err := settings.Directives()
	if err != nil {
		return nil, err
	}
	e.cfg = cfg
	if cfg.Challenge != nil {
		e.gateSlots = make(chan struct{}, cmp.Or(cfg.MaxChallenges, runtime.GOMAXPROCS(0)))
	}
	e.rules = compileLimits(cfg)
	e.evictLogSecond.Store(neverLogged)
	e.connLogSecond.Store(neverLogged)
	for i := range e.earlyLog {
		e.earlyLog[i].second.Store(neverLogged)
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
	refuseCut := cfg.CRS.Mode == crs.ModeDetect && cfg.EvalBudgetDetect == OverBudgetRefuse
	e.handler = e.guard(txhttp.WrapHandler(withEvalBudget(waf, budget, evalSlots, cfg.CRS.ResponseLimit(), refuseCut, e.reportEval), e.forward()))
	return e, nil
}

// RateTotals are the rate rules' running totals since the edge was made.
type RateTotals struct {
	// Refused is how many requests a rate rule refused (monitor rules refuse none).
	Refused int64
	// EvictedLive is how many clients a full rate-limit table dropped while they were still counting, each of which starts
	// again with a full allowance.
	EvictedLive int64
}

// RateTotals returns the rate rules' totals, for a periodic report: the log has at most one line a second for each rule.
func (e *Edge) RateTotals() RateTotals {
	return RateTotals{Refused: e.rateRefused.Load(), EvictedLive: e.evictedLive.Load()}
}

// SlowBodies is how many requests were answered 408 because their body did not arrive within ReadTimeout (rule 5000076). They
// are counted, not logged: a slow client is not refused for what it sent.
func (e *Edge) SlowBodies() int64 { return e.slowBodies.Load() }

// ServeHTTP implements http.Handler.
func (e *Edge) ServeHTTP(w http.ResponseWriter, r *http.Request) { e.handler.ServeHTTP(w, r) }

// Close logs the rate-rule and early refusals not logged yet and releases the compiled rules.
func (e *Edge) Close() error {
	for _, rule := range e.rules {
		e.flushLimit(rule)
	}
	for i := range e.earlyLog {
		e.flushEarly(i)
	}
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
	if hellos := e.cfg.Hellos; hellos != nil {
		prev := srv.ConnState
		srv.ConnState = func(c net.Conn, st http.ConnState) {
			if prev != nil {
				prev(c, st)
			}
			if st == http.StateClosed || st == http.StateHijacked {
				hellos.Forget(c)
			}
		}
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
	e.deliver(m)
}

// reportEval reports a phase of rule evaluation that found no slot or ran out of its budget, with the id of the request it
// was for. Under a flood of expensive requests every one of them can, so each kind is reported at most once a second, and
// the next line says how many were not. Each such request also has an alert of its own (see record.finish).
func (e *Edge) reportEval(timedOut bool, tx string) {
	if e.cfg.OnMatch == nil {
		return
	}
	kind, m := 0, Match{RuleID: idEvalBusy, Severity: "WARNING", Disruptive: true, TransactionID: tx,
		Message: "no rule evaluation slot came free within the budget"}
	if timedOut {
		kind, m = 1, Match{RuleID: idEvalBudget, Severity: "WARNING", TransactionID: tx, Message: "rule evaluation ran out of its budget",
			Disruptive: e.cfg.CRS.Mode == crs.ModeBlock || e.cfg.EvalBudgetDetect == OverBudgetRefuse}
	}
	second := time.Now().Unix()
	if previous := e.evalLogSecond[kind].Load(); second == previous || !e.evalLogSecond[kind].CompareAndSwap(previous, second) {
		e.evalUnlogged[kind].Add(1)
		return
	}
	if n := e.evalUnlogged[kind].Swap(0); n > 0 {
		m.Message += " (" + strconv.FormatInt(n, 10) + " more not logged)"
	}
	e.deliver(m)
}

func (e *Edge) onMatch(m types.MatchedRule) {
	if e.cfg.OnMatch == nil && e.cfg.OnAlert == nil {
		return
	}
	// Coraza's Message is macro-expanded and may contain credentials or arbitrary request values.
	// Its public metadata exposes no unexpanded message; keep the default summary fixed.
	// The engine marks every match of a rule with a disruptive action (block, which the CRS turns into pass) while it
	// enforces; only the rule that refused the request is disruptive here.
	match := Match{RuleID: m.Rule().ID(), Severity: m.Rule().Severity().String(), Message: "Coraza rule matched",
		TransactionID: m.TransactionID(), verdict: refusesOnItsOwn(m.Rule()), engine: true}
	for _, tag := range m.Rule().Tags() {
		match.cats = match.cats.With(alert.TagCategory(tag)) // static tags: what the rule looks for
	}
	match.Disruptive = m.Disruptive() && match.verdict
	if label := crs.LocalRuleMessage(match.RuleID); label != "" {
		match.Message = label
	}
	if e.cfg.LogDetails {
		match.ClientIP, match.URI, match.Data = m.ClientIPAddress(), m.URI(), m.Data()
		match.ExpandedMessage = m.Message()
	}
	if !match.verdict && (match.RuleID >= 900000 && match.RuleID <= 999999 || match.RuleID >= 5006000 && match.RuleID <= 5006999) {
		match.Risk = alert.CRSRisk(match.Severity).String() // a rule that scores: the verdict is 949110's or 949111's
	}
	var rec *record
	if c, ok := m.(interface{ Context() context.Context }); ok {
		rec = recordOf(c.Context()) // the transaction's context is the request's (see budgetWAF)
	}
	if rec != nil && rec.alerts && (match.RuleID == 949110 || match.RuleID == 959100) {
		match.score = anomalyScore(match.RuleID, m.Message())
	}
	e.finding(match, rec, nil)
}

// refusesOnItsOwn reports a rule that refuses a request when it matches, rather than adding to the anomaly score: the
// CRS's inbound and outbound verdicts (949110 and 959100, and 949111 and 959101, which refuse a phase early when
// tx.early_blocking is set), its configuration checks 901001 and 901500 (every CRS rule written with deny), Coraza's base
// rules (each of which that logs is a deny) and a rule tagged crs.DenyTag, which the site policy adds to the deny rules
// it writes.
func refusesOnItsOwn(rule types.RuleMetadata) bool {
	switch id := rule.ID(); {
	case id == 949110 || id == 949111 || id == 959100 || id == 959101 || id == 901001 || id == 901500:
		return true
	case id >= 200000 && id <= 200999:
		return true
	}
	return slices.Contains(rule.Tags(), crs.DenyTag)
}

// refuseCrowdSec answers a visitor CrowdSec has a decision against, or every visitor while its decisions are not known.
// The connection is closed after the refusal, as after the shield's: a banned client that keeps its connection open could
// go on sending requests on it, each one refused and each one costing a request's work. A trusted proxy's connection
// carries other visitors' requests too, so it is kept, unless the request has a body that was not read (see
// closeUnlessRelayed). The shield does not count this refusal toward the visitor's standing yet: that is to be added here,
// where the visitor's address and the kind of refusal are known.
func (e *Edge) refuseCrowdSec(w http.ResponseWriter, r *http.Request, action crowdsec.Action, relayed bool) {
	status, id, msg := http.StatusForbidden, idCrowdSecBan, "CrowdSec IP ban"
	if action == crowdsec.Unavailable {
		status, id, msg = http.StatusServiceUnavailable, idCrowdSecUnavailable, "CrowdSec decision cache unavailable"
		w.Header().Set("Retry-After", "10")
	}
	w.Header().Set("Cache-Control", "no-store")
	closeUnlessRelayed(w.Header(), r, relayed)
	// Keep refusal logs bounded during a ban flood; every request is
	// counted in CrowdSec.Stats, including those with no sampled log.
	second := time.Now().Unix()
	previous := e.crowdSecLogSecond.Load()
	if second != previous && e.crowdSecLogSecond.CompareAndSwap(previous, second) {
		e.refuse(w, r, status, id, msg)
	} else {
		e.note(Match{RuleID: id, Severity: "CRITICAL", Disruptive: true, status: status}, recordOf(r.Context())) // the alert is not sampled
		http.Error(w, http.StatusText(status), status)
	}
	if rec := recordOf(r.Context()); e.cfg.Shield != nil && id == idCrowdSecBan && rec != nil && rec.client.IsValid() {
		e.cfg.Shield.Rejected(rec.client) // a banned address counts toward its own limit, as a refusal before admission does
	}
}

// guard refuses what cannot be inspected faithfully, and tells the WAF and the application who the visitor is.
func (e *Edge) guard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec := newRecord()
		rec.alerts = e.cfg.OnAlert != nil || e.cfg.Shield != nil // the shield is told of would-be refusals and offences
		var watch *writeWatch
		defer func() {
			e.reportHeld(rec)
			rec.finish(e, r, watch.sent())
		}()
		rec.relayed = e.relayed(r.RemoteAddr)
		addr, port, addrErr := clientAddr(r, e.cfg.TrustedProxies)
		if addrErr == nil {
			rec.client, rec.via = addr, addr != connAddr(r.RemoteAddr)
		} else {
			rec.conn = connAddr(r.RemoteAddr) // the visitor's is not known: the line names the connection's
		}
		if r.Method == http.MethodConnect {
			e.refuseEarly(w, r, rec, http.StatusMethodNotAllowed, idConnect, "a CONNECT request")
			return
		}
		if !e.cfg.AllowUpgrade && wantsUpgrade(r.Header) {
			e.refuseEarly(w, r, rec, http.StatusNotImplemented, idUpgrade, "a protocol upgrade")
			return
		}
		if err := checkTarget(r); err != nil {
			e.refuseEarly(w, r, rec, http.StatusBadRequest, idTarget, "a request target that cannot be forwarded unchanged: "+err.Error())
			return
		}
		if addrErr != nil {
			e.refuseEarly(w, r, rec, http.StatusBadRequest, idClientAddr, "the client address or forwarding chain: "+addrErr.Error())
			return
		}
		peer := r.RemoteAddr // the connection's own address, before it is replaced by the visitor's
		// Coraza splits RemoteAddr at its last colon, so an IPv6 address is given without brackets.
		r.RemoteAddr = fmt.Sprintf("%s:%d", addr, port)
		watch = &writeWatch{ResponseWriter: w, onHijack: e.hijacked}
		if r.ProtoMajor == 1 { // an HTTP/2 connection carries other requests too
			watch.conn, _ = r.Context().Value(connKey{}).(net.Conn)
		}
		w = watch
		r = r.WithContext(context.WithValue(context.WithValue(r.Context(), recordKey{}, rec), writeWatchKey{}, watch))
		if cs := e.cfg.CrowdSec; cs != nil {
			if action := cs.Check(addr); action != crowdsec.Allow {
				e.refuseCrowdSec(w, r, action, e.relayed(peer))
				return
			}
		}
		if sh := e.cfg.Shield; sh != nil {
			// Flood admission costs a few map lookups: a request it refuses is never read further.
			d := sh.Admit(r, addr)
			if d.Action != shield.Allow {
				if e.cfg.Challenge != nil && d.Wants() {
					// The bot policy has not run yet: what the request says it is. A kind it refuses is not offered.
					var action bots.Action
					rec.kind, action = e.cfg.Bots.Claim(r, addr, e.helloOf(r))
					rec.watched = action == bots.Watch
					if action != bots.Refuse && e.serveGate(w, r, rec, challenge.Admission, d) {
						return
					}
				}
				// A refusal has its alert, deduplicated per source: no line per request, which a flood would multiply. The
				// challenge, shown or solved, is not a finding about the visitor.
				if d.Action == shield.Refuse || d.Action == shield.Respond && d.Status >= http.StatusBadRequest {
					e.note(Match{RuleID: d.RuleID(), Severity: "WARNING", Disruptive: true, status: d.Status}, rec)
				}
				sh.Write(w, r, d)
				return
			}
			sw := &shieldWriter{ResponseWriter: w}
			w = sw
			o := new(origin)
			r = r.WithContext(context.WithValue(r.Context(), originKey{}, o))
			defer func() {
				if o.hungUp {
					sh.Done(d, shield.StatusClientClosed, true)
					return
				}
				sh.Done(d, sw.code(), o.answered)
			}()
		}
		if !e.checkRequest(w, r, addr) {
			return
		}
		rawPath, rawQuery, _ := strings.Cut(r.RequestURI, "?")

		limit := e.bodyLimit(r)
		if r.ContentLength > limit {
			e.refuse(w, r, http.StatusRequestEntityTooLarge, idBodyTooLarge, "the request body is over its size limit")
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
				var networkError net.Error
				switch {
				case capped.tooLarge:
					e.refuse(w, r, http.StatusRequestEntityTooLarge, idBodyTooLarge, "the request body is over its size limit")
				case errors.Is(err, os.ErrDeadlineExceeded) || errors.As(err, &networkError) && networkError.Timeout():
					// The client was too slow for ReadTimeout: not a malformed request, and the shield does not count a 408
					// as a security rejection. It is counted, not logged.
					e.slowBodies.Add(1)
					http.Error(w, "the request took too long to arrive", http.StatusRequestTimeout)
				default:
					e.refuse(w, r, http.StatusBadRequest, idBodyUnreadable, "the request body could not be read")
				}
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
				e.refuse(w, r, http.StatusRequestEntityTooLarge, idBodyTooLarge, "the request body is over its size limit once decompressed")
				return
			}
			if readAsMultipart(r.Header) {
				boundary, ok := uploadBoundary(r.Header.Get("Content-Type"))
				if !ok {
					e.refuse(w, r, http.StatusBadRequest, idAmbiguousType, "a multipart Content-Type that parsers read differently")
					return
				}
				if !e.cfg.Uploads.AllowUploadProgress && uploadProgressField(body, []byte("--"+boundary)) {
					e.refuse(w, r, http.StatusForbidden, idPHP2ShellUpload, "PHP2Shell: a multipart body with PHP's session upload progress field")
					return
				}
				if id, why := scanUpload(body, boundary, e.cfg.Uploads); id != 0 {
					e.refuse(w, r, http.StatusForbidden, id, why)
					return
				}
				switch multipartParts(body, boundary, e.cfg.MaxFormBody) {
				case idAmbiguousType:
					e.refuse(w, r, http.StatusBadRequest, idAmbiguousType, "a multipart part that the rules read as a file and PHP as a field")
					return
				case idMultipartFields:
					e.refuse(w, r, http.StatusRequestEntityTooLarge, idMultipartFields, "the fields of a multipart body that are not files are over the form body limit")
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
			if capped.tooLarge {
				e.refuse(w, r, http.StatusRequestEntityTooLarge, idBodyTooLarge, "the request body is over its size limit")
			} else {
				e.refuse(w, r, http.StatusBadRequest, idEngineUnanswered, "the rule engine could not process the request")
			}
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

// errSocketNotSwitched is returned for a WebSocket handshake the application answered with anything but a switch or an error.
var errSocketNotSwitched = errors.New("the application answered a WebSocket handshake without switching protocols")

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
		if retries > 0 {
			e.report(Match{RuleID: idUpstreamBindRetry, Severity: "WARNING",
				Message: fmt.Sprintf("upstream socket bind retried %d time(s)", retries), Disruptive: false}, recordOf(ctx), nil)
		}
		return conn, err
	}
	transport.ResponseHeaderTimeout = e.cfg.ResponseHeaderTimeout
	if transport.ResponseHeaderTimeout <= 0 {
		transport.ResponseHeaderTimeout = 30 * time.Second
	}
	transport.MaxIdleConnsPerHost = 64
	rp := &httputil.ReverseProxy{
		Transport:  transport,
		ErrorLog:   e.cfg.ErrorLog,
		BufferPool: &copyBuffers{},
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
			if rec := recordOf(in.Context()); rec != nil && rec.override != "" {
				out.Header.Set("X-HTTP-Method-Override", rec.override) // checked by checkRequest (wordPressOverride)
			}
			if e.cfg.CRS.InspectResponses {
				// The response rules read the body the application sends. Asked by the client, the application compresses it and
				// the rules read gzip bytes; without the client's Accept-Encoding the transport asks for gzip itself and hands on
				// the body decompressed, so the visitor gets it uncompressed. Asked for ranges, it sends a slice of the body, which
				// no rule sees whole, or several as multipart/byteranges, a type the rules do not read at all; without Range it
				// sends the whole body, which a client that asked for a range may take (RFC 9110, 14.2). Apache reads the legacy
				// Request-Range when there is no Range.
				out.Header.Del("Accept-Encoding")
				out.Header.Del("Range")
				out.Header.Del("Request-Range")
				out.Header.Del("If-Range")
			}
			// The proxy has the whole body before it forwards anything, so the application has nothing to wait for.
			out.Header.Del("Expect")
			if _, ok := e.cfg.Challenge.(challenge.Responder); ok {
				pr.Out = out.WithContext(context.WithValue(out.Context(), inboundKey{}, in)) // for Respond, after the answer
				out = pr.Out
			}
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
			if resp.StatusCode < http.StatusBadRequest && resp.StatusCode != http.StatusSwitchingProtocols &&
				strings.EqualFold(resp.Request.Header.Get("Upgrade"), "websocket") {
				// A page sent for a handshake would reach a script that only had to copy a browser's handshake headers to
				// pass the bot checks a page request faces. Not marked as the application's answer: the refusal is the edge's.
				return errSocketNotSwitched
			}
			if !e.cfg.Responses.AllowBadSessionIDs && badSessionCookie(resp.Header, e.cfg.Responses.SessionCookies) {
				// What PHP2Shell's leak looks like, whatever request caused it. Answered 403 and not marked as the
				// application's answer, so that the shield counts it as a refusal of the visitor's.
				return errPHP2Shell
			}
			markOrigin(resp.Request.Context())
			if resp.StatusCode == http.StatusSwitchingProtocols && !e.cfg.AllowUpgrade {
				return errors.New("upstream protocol upgrade is not supported")
			}
			if e.cfg.CRS.InspectResponses && encodedResponse(resp.Header) {
				// Compressed without being asked (the transport decompresses the gzip it asks for): the rules could not read it.
				return errors.New("the application compressed a response that is to be inspected")
			}
			path, _, _ := strings.Cut(resp.Request.URL.Opaque, "?")
			if rs, ok := e.cfg.Challenge.(challenge.Responder); ok { // before the hardening, which sees what it added
				if in, _ := resp.Request.Context().Value(inboundKey{}).(*http.Request); in != nil {
					if err := e.callGate(in, func(gr *http.Request) { rs.Respond(gr, resp.StatusCode, resp.Header) }); err != nil {
						return err
					}
				}
			}
			e.cfg.Responses.harden(resp, path)
			// A switched connection has no trailers, and its body must stay writable for the tunnel.
			rs, hasTrailerGate := e.cfg.Challenge.(challenge.TrailerResponder)
			var in *http.Request
			if hasTrailerGate {
				in, _ = resp.Request.Context().Value(inboundKey{}).(*http.Request)
				hasTrailerGate = in != nil
			}
			checkSessionTrailers := !e.cfg.Responses.AllowBadSessionIDs &&
				(resp.ProtoMajor >= 2 || len(resp.TransferEncoding) != 0 || len(resp.Trailer) != 0)
			if resp.StatusCode != http.StatusSwitchingProtocols && (hasTrailerGate || checkSessionTrailers) {
				// The names announced now; what was sent once the body is closed, which is when the transport
				// fills them in and before the reverse proxy copies them on.
				check := func() error {
					if checkSessionTrailers && badSessionCookie(resp.Trailer, e.cfg.Responses.SessionCookies) {
						return errPHP2Shell
					}
					if hasTrailerGate {
						return e.callGate(in, func(gr *http.Request) { rs.RespondTrailer(gr, resp.Trailer) })
					}
					return nil
				}
				if err := check(); err != nil {
					return err
				}
				resp.Body = &trailerCheck{ReadCloser: resp.Body, check: func() {
					if err := check(); err != nil {
						if o, ok := resp.Request.Context().Value(originKey{}).(*origin); ok {
							o.answered = false
						}
						if errors.Is(err, errPHP2Shell) {
							watch, _ := resp.Request.Context().Value(writeWatchKey{}).(*writeWatch)
							e.finding(Match{RuleID: idPHP2ShellSession, Severity: "CRITICAL", Disruptive: true, status: watch.sent(),
								Message: "PHP2Shell: the application sent a session cookie that is not a session id in a trailer"}, nil, resp.Request)
						}
						panic(http.ErrAbortHandler) // headers have gone; do not forward unchecked trailers
					}
				}}
			}
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
			if errors.Is(err, errGateBudget) {
				if o, ok := r.Context().Value(originKey{}).(*origin); ok {
					o.answered = false // the check failed, not the application
				}
				gateUnavailable(w)
				return
			}
			if errors.Is(err, errSocketNotSwitched) {
				e.refuse(w, r, http.StatusBadGateway, idSocketNotSwitched, "a WebSocket handshake the application did not switch")
				return
			}
			if errors.Is(err, errPHP2Shell) {
				if o, ok := r.Context().Value(originKey{}).(*origin); ok {
					o.answered = false
				}
				e.refuse(w, r, http.StatusForbidden, idPHP2ShellSession, "PHP2Shell: the application set a session cookie that is not a session id")
				return
			}
			// A request cancelled because its client went away, or because its response was ended to free a place (see
			// stall.go), was not failed by the application, unless the client had waited long: the shield decides which.
			if errors.Is(err, context.Canceled) && r.Context().Err() != nil {
				if o, ok := r.Context().Value(originKey{}).(*origin); ok {
					o.hungUp = true
				}
			} else {
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
					m.ExpandedMessage = err.Error()
				}
				e.report(m, nil, r)
			}
			http.Error(w, "upstream unavailable", http.StatusBadGateway)
		},
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		watch, _ := r.Context().Value(writeWatchKey{}).(*writeWatch)
		ok, reclaimed := e.places.acquire(watch)
		if reclaimed {
			e.report(Match{RuleID: idUpstreamReclaimed, Severity: "WARNING", Disruptive: true,
				Message: "a response the client stopped reading was ended to free an upstream place"}, nil, nil) // another request's
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

// trailerCheck checks a response's trailers once its body is closed: the transport fills them in then, and the reverse
// proxy copies them on after. It does not buffer the body or delay streaming.
type trailerCheck struct {
	io.ReadCloser
	check func()
	done  bool
}

func (t *trailerCheck) Close() error {
	err := t.ReadCloser.Close()
	if !t.done {
		t.done = true
		t.check()
	}
	return err
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

// originKey marks, for the shield, that a response came from (or was about) the application rather than from a check,
// or that the client hung up while the application had the request.
type originKey struct{}

type origin struct{ answered, hungUp bool }

func markOrigin(ctx context.Context) {
	if o, ok := ctx.Value(originKey{}).(*origin); ok {
		o.answered = true
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
