// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"path"
	"regexp"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/YurilLAB/coraza/carnical/bots"
	"github.com/YurilLAB/coraza/carnical/shield"
)

// The checks in this file and the next ones do not depend on the rule set. They hold with the rule set off or in
// detection mode, because they protect against things a rule set cannot: a request the proxy and the application read
// differently, a framework's internal headers, and a site that has already been taken over.

// Identifiers for what the proxy itself refuses, in the range kept for it (the rule set uses 9xxxxx, local rules 1 to
// 99999). They appear as Match.RuleID, so one log and one feed carry both.
const (
	idHostNotAllowed      = 5000001
	idPathNotCanon        = 5000002
	idInternalHeader      = 5000003
	idRequestEncoding     = 5000004
	idAmbiguousType       = 5000005
	idUploadName          = 5000010
	idUploadScript        = 5000011
	idMultipartFields     = 5000012
	idWordPressPHP        = 5000020
	idXMLRPC              = 5000021
	idRateLimited         = 5000022
	idTooManyConns        = 5000030
	idAPIRateLimited      = 5000042
	idRateStateFull       = 5000041
	idMethodNotCanon      = 5000043
	idMethodOverride      = 5000044
	idEvalBudget          = 5000045
	idEvalBusy            = 5000046
	idLimitRule           = 5000047
	idLimitMonitor        = 5000048
	idUpstreamFailed      = 5000050
	idUpstreamBindRetry   = 5000051
	idUpstreamReclaimed   = 5000052
	idCrowdSecBan         = 5000060
	idCrowdSecUnavailable = 5000061
	// The refusals before the flood protection admits a request (see refuseEarly), and the body's.
	idConnect          = 5000070
	idUpgrade          = 5000071
	idTarget           = 5000072
	idClientAddr       = 5000073
	idBodyTooLarge     = 5000074
	idBodyUnreadable   = 5000075
	idBodySlow         = 5000076 // counted (Edge.SlowBodies), not logged: a slow client, not a refusal
	idEngineUnanswered = 5000077
	idLinesHeld        = 5000078 // how many of a request's lines went over the cap (see maxRequestLines)
)

// PathPolicy says how plain the request path must be. The zero value is the strict default.
//
// The WAF, the proxy and the application each read a path in their own way: one decodes %2f, another does not;
// one stops at a semicolon, another keeps it; one removes dot segments, another passes them. Every difference is a
// way to ask for /wp-admin/ in a form a deny rule does not recognise. A request whose path needs interpreting is
// refused, instead of being passed on in the hope that everyone reads it the same way.
type PathPolicy struct {
	// AllowEncodedSlash allows %2f and %5c, for an application that puts them in identifiers.
	AllowEncodedSlash bool
	// AllowPathParams allows a semicolon in the path (Java's ;jsessionid=, matrix parameters).
	AllowPathParams bool
}

func isHex(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F'
}

func unhex(c byte) byte {
	switch {
	case c >= 'a':
		return c - 'a' + 10
	case c >= 'A':
		return c - 'A' + 10
	}
	return c - '0'
}

// check reports why a raw path (no query) is refused, or nil.
func (p PathPolicy) check(path string) error {
	for i := 0; i < len(path); i++ {
		c := path[i]
		switch {
		case c < 0x21 || c >= 0x7f:
			return errors.New("a control, space or non-ASCII byte in the path")
		case c == '\\':
			return errors.New("a backslash in the path")
		case c == ';' && !p.AllowPathParams:
			return errors.New("a path parameter (;) in the path")
		case c == '%':
			if i+2 >= len(path) {
				return errors.New("a truncated percent escape")
			}
			if !isHex(path[i+1]) || !isHex(path[i+2]) {
				return errors.New("a malformed percent escape")
			}
			b := unhex(path[i+1])<<4 | unhex(path[i+2])
			switch {
			case b == '/' || b == '\\':
				if !p.AllowEncodedSlash {
					return errors.New("an encoded slash in the path")
				}
			case b == '?' || b == '#' || b == '%' || b == 0:
				return errors.New("an encoded delimiter, percent sign or NUL in the path")
			case b < 0x20 || b == 0x7f:
				return errors.New("an encoded control character in the path")
			case isUnreserved(b) && b != '~':
				// "%77p-admin" is "wp-admin" to the application and something else to a rule that matches the text.
				// A client has no reason to write it: only an attempt to avoid a rule does.
				return errors.New("an unnecessary percent escape of a plain character")
			}
			i += 2
		}
	}
	// A dot segment is judged on the path the application resolves: decoded, a backslash taken as a slash, and each segment
	// without its ;parameters, as a Java server reads it. "/public/..;/admin" and "/public%2F..%2Fadmin" are "/admin" to such
	// an application, while a rule that matches the start of the path (an allowed path, an exclusion) sees "/public/".
	decoded, err := url.PathUnescape(path)
	if err != nil {
		return errors.New("a malformed percent escape")
	}
	for _, seg := range strings.Split(strings.ReplaceAll(decoded, "\\", "/"), "/") {
		if seg, _, _ = strings.Cut(seg, ";"); seg == "." || seg == ".." {
			return errors.New("a dot segment in the path")
		}
	}
	return nil
}

func isUnreserved(b byte) bool {
	return b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' || b >= '0' && b <= '9' || b == '-' || b == '.' || b == '_' || b == '~'
}

// normHost reduces a Host header to the name it carries: lower case, no port, no trailing dot.
func normHost(h string) string {
	h = strings.ToLower(strings.TrimSpace(h))
	if strings.HasPrefix(h, "[") {
		if end := strings.Index(h, "]"); end > 0 {
			return h[:end+1]
		}
		return h
	}
	if host, _, err := net.SplitHostPort(h); err == nil {
		h = host
	}
	return strings.TrimSuffix(h, ".")
}

// headersThatSteerTheApplication are control headers some frameworks trust. A client may send them to skip a
// middleware or choose a route or method. Method overrides are refused at admission; the rest are removed on forwarding,
// whatever the rule set says.
func isInternalHeader(key string) bool {
	switch key {
	case "x-matched-path", "x-now-route-matches", "x-http-method-override", "x-method-override", "x-http-method":
		return true
	}
	return strings.HasPrefix(key, "x-middleware-") || strings.HasPrefix(key, "x-invoke-") || strings.HasPrefix(key, "x-nextjs-")
}

func isMethodOverrideHeader(key string) bool {
	return key == "x-http-method-override" || key == "x-method-override" || key == "x-http-method"
}

// contentEncoded reports a Content-Encoding other than identity.
func contentEncoded(h http.Header) bool {
	for _, v := range h.Values("Content-Encoding") {
		if enc := strings.ToLower(strings.TrimSpace(v)); enc != "" && enc != "identity" {
			return true
		}
	}
	return false
}

// refuse answers a request the proxy itself will not forward, and records why in the same form as a rule match.
func (e *Edge) refuse(w http.ResponseWriter, r *http.Request, status int, id int, msg string) {
	e.finding(Match{RuleID: id, Severity: "CRITICAL", Message: msg, Disruptive: true, status: status}, nil, r)
	http.Error(w, http.StatusText(status), status)
}

// refuseEarly answers a request refused before the flood protection has seen it: a CONNECT, an upgrade, a target that cannot
// be forwarded or a client address that cannot be read (rules 5000070 to 5000073). Nothing has limited such a request yet,
// so a client can send them as fast as it likes: each kind is logged at most once a second. The ones not logged are counted,
// and the count is logged in a line of its own a second later at most, before the kind's next line, or when the edge is
// closed (see flushEarly), as the rate rules' are. The shield counts each toward the visitor's address (Shield.Rejected),
// so that one sending only these is held to its own limit. When the visitor's address cannot be read (5000073, or a
// forwarding chain that is also bad) only the connection's is known, and that may be a trusted proxy's, which carries
// every visitor behind it: such a refusal is not counted against any address.
func (e *Edge) refuseEarly(w http.ResponseWriter, r *http.Request, rec *record, status, id int, msg string) {
	m := Match{RuleID: id, Severity: "CRITICAL", Message: msg, Disruptive: true, status: status}
	e.note(m, rec) // every refusal has its alert; only the lines are sampled
	if sh := e.cfg.Shield; sh != nil && rec != nil && rec.client.IsValid() {
		sh.Rejected(rec.client)
	}
	if i := id - idConnect; e.cfg.OnMatch != nil && i >= 0 && i < len(e.earlyLog) {
		s, second := &e.earlyLog[i], e.clock()/int64(time.Second)
		if previous := s.second.Load(); second == previous || !s.second.CompareAndSwap(previous, second) {
			s.unlogged.Add(1)
			if s.flushDue.CompareAndSwap(false, true) {
				time.AfterFunc(time.Second, func() { s.flushDue.Store(false); e.flushEarly(i) })
			}
		} else {
			e.flushEarly(i)
			e.finding(m, rec, r)
		}
	}
	http.Error(w, http.StatusText(status), status)
}

// earlyKinds names the kinds of refusal refuseEarly logs, by their place in Edge.earlyLog, for the line that counts the
// ones not logged.
var earlyKinds = [idClientAddr - idConnect + 1]string{"a CONNECT request", "a protocol upgrade", "a request target that cannot be forwarded unchanged",
	"the client address or forwarding chain"}

// flushEarly logs how many refusals of one kind refuseEarly did not log, if any. They may be any clients', so the line names
// none and no request, as flushLimit's.
func (e *Edge) flushEarly(i int) {
	if n := e.earlyLog[i].unlogged.Swap(0); n > 0 {
		e.finding(Match{RuleID: idConnect + i, Severity: "CRITICAL", Disruptive: true,
			Message: earlyKinds[i] + " (" + strconv.FormatInt(n, 10) + " more refusals not logged)"}, nil, nil)
	}
}

// sampled is the state of a line logged at most once a second: the second it was last logged, how many were not, and
// whether a line counting them is scheduled.
type sampled struct {
	second, unlogged atomic.Int64
	flushDue         atomic.Bool
}

// checkRequest applies the request-side policy that does not need the body. It reports whether the request may go on.
func (e *Edge) checkRequest(w http.ResponseWriter, r *http.Request, client netip.Addr) bool {
	// HTTP methods are case-sensitive, but some origins normalize them. Refuse that ambiguity before any inspector runs.
	if r.Method != strings.ToUpper(r.Method) {
		e.refuse(w, r, http.StatusBadRequest, idMethodNotCanon, "a noncanonical HTTP method token")
		return false
	}
	if len(e.hosts) > 0 && !e.hosts[normHost(r.Host)] {
		e.refuse(w, r, http.StatusMisdirectedRequest, idHostNotAllowed, "the Host header is not one of this site's names")
		return false
	}
	rawPath, _, _ := strings.Cut(r.RequestURI, "?")
	if err := e.cfg.Paths.check(rawPath); err != nil {
		e.refuse(w, r, http.StatusBadRequest, idPathNotCanon, "the request path is not in plain form: "+err.Error())
		return false
	}
	if len(r.Header.Values("Content-Type")) > 1 {
		e.refuse(w, r, http.StatusBadRequest, idAmbiguousType, "more than one Content-Type header")
		return false
	}
	// A compressed request body is not something the rules can read, and an application that unpacks it would
	// receive what nothing inspected. Browsers do not compress what they send. ServeHTTP refuses an allowed one that
	// no inspector decompressed.
	for _, v := range r.Header.Values("Content-Encoding") {
		enc := strings.ToLower(strings.TrimSpace(v))
		if e.cfg.AllowRequestEncoding && (enc == "gzip" || enc == "deflate") && len(r.Header.Values("Content-Encoding")) == 1 {
			continue // an inspector decompresses it, within limits
		}
		if enc != "" && enc != "identity" {
			e.refuse(w, r, http.StatusUnsupportedMediaType, idRequestEncoding, "a request body with a content encoding cannot be inspected")
			return false
		}
	}
	for name := range r.Header {
		key := strings.ReplaceAll(strings.ToLower(name), "_", "-")
		if isMethodOverrideHeader(key) {
			e.refuse(w, r, http.StatusBadRequest, idMethodOverride, "a header that overrides the HTTP method")
			return false
		}
		if e.deny[key] {
			e.refuse(w, r, http.StatusBadRequest, idInternalHeader, "a header this site does not accept: "+key)
			return false
		}
	}
	if e.cfg.Bots != nil && !e.checkBots(w, r, client) {
		return false
	}
	var route string
	if e.cfg.WordPress.Enabled || len(e.rules) > 0 {
		route = routePath(r.URL.Path)
	}
	if e.cfg.WordPress.Enabled && !e.checkWordPress(w, r, route) {
		return false
	}
	return e.checkLimits(w, r, client, route)
}

// checkBots refuses a kind of client the bot policy refuses (rules 5005003 to 5005012), or reports a kind it watches as
// one it would have refused. The kind is kept for the request's alerts.
func (e *Edge) checkBots(w http.ResponseWriter, r *http.Request, client netip.Addr) bool {
	kind, action := e.cfg.Bots.Judge(r.Context(), r, client, e.helloOf(r))
	if rec := recordOf(r.Context()); rec != nil {
		rec.kind = kind
	}
	msg := "a kind of client this site refuses: " + kind.String()
	switch action {
	case bots.Watch:
		e.finding(Match{RuleID: bots.RuleID(kind), Severity: "WARNING", Message: msg, would: true}, nil, r)
	case bots.Refuse:
		e.refuse(w, r, http.StatusForbidden, bots.RuleID(kind), msg)
		return false
	}
	return true
}

// helloOf is what the TLS handshake of r's connection showed, when Config.Hellos keeps it.
func (e *Edge) helloOf(r *http.Request) bots.Hello {
	if e.cfg.Hellos == nil || r.TLS == nil {
		return bots.Hello{}
	}
	c, _ := r.Context().Value(connKey{}).(net.Conn)
	return e.cfg.Hellos.Of(c)
}

// APIRatePolicy gives each client its own sliding-minute budget, shared across all matching prefixes and HTTP methods.
// Paths are plain paths compared without ASCII case distinctions: /api matches /api and /api/... but not /apiary, and
// also /index.php/api/... or any other PHP script in the first segment followed by /api/..., which PHP front controllers
// route as /api/....
// Empty uses /api and /graphql. Case, slash and matrix normalization are conservative quota matching, not route rewriting.
// PerMinute is 1..100000 when enabled; zero disables the policy. State is local to one Edge and is lost on restart.
type APIRatePolicy struct {
	PerMinute int
	Paths     []string
}

func (p APIRatePolicy) normalized() (APIRatePolicy, error) {
	if p.PerMinute < 0 || p.PerMinute > 100000 {
		return p, errors.New("PerMinute must be zero (disabled) or between 1 and 100000")
	}
	if len(p.Paths) == 0 {
		p.Paths = []string{"/api", "/graphql"}
	} else {
		p.Paths = append([]string(nil), p.Paths...)
	}
	if len(p.Paths) > maxRatePaths {
		return p, fmt.Errorf("at most %d path prefixes are allowed", maxRatePaths)
	}
	paths, err := normalizePrefixes(p.Paths)
	if err != nil {
		return p, err
	}
	p.Paths = paths
	return p, nil
}

// matches reports whether a route path (see routePath) is under one of the prefixes.
func (p APIRatePolicy) matches(route string) bool { return matchesPrefix(p.Paths, route) }

// routePath is a decoded path as an application is likely to route it: empty segments, a trailing slash and path
// parameters removed, backslashes as slashes, in lower case. It accounts conservatively for sites that permit encoded
// slashes or matrix parameters.
func routePath(decoded string) string {
	parts := strings.Split(strings.ReplaceAll(decoded, "\\", "/"), "/")
	for i := range parts {
		parts[i], _, _ = strings.Cut(parts[i], ";")
	}
	return strings.ToLower(path.Clean(strings.Join(parts, "/")))
}

// compiledRule is one per-client rate limit: which requests it counts, its own table of clients, and how a refusal is
// logged. A client is an IPv4 address or an IPv6 /64, as the shield counts it, so a client cannot get a fresh budget by
// changing the low bits of its IPv6 address.
type compiledRule struct {
	match   func(r *http.Request, route string) bool
	count   int           // requests a client may make in a window
	window  time.Duration // the window's length
	monitor bool          // only report what the rule would refuse
	id      int
	message string // fixed text, from the configuration: never request data
	table   *windowLimiter
	// A flood of refusals must not become a flood of log lines: a rule logs at most one refusal a second. How many were not
	// is said in a line of its own, with no client in it (see flushLimit).
	logSecond atomic.Int64
	unlogged  atomic.Int64
	flushDue  atomic.Bool // a flush of unlogged is scheduled
}

// neverLogged is a log second long before any clock reading.
const neverLogged = -1 << 62

// compileLimits builds the rate rules a configuration asks for, each with its own table: the WordPress login limit, the
// API limit, then cfg.Limits in their order. There are at most 34 (see maxRateRules), which checkLimits relies on.
func compileLimits(cfg Config) []*compiledRule {
	var rules []*compiledRule
	if cfg.WordPress.Enabled {
		perMinute := cfg.WordPress.LoginPerMinute
		if perMinute <= 0 {
			perMinute = 10
		}
		rules = append(rules, &compiledRule{count: perMinute, window: time.Minute, id: idRateLimited,
			message: "too many login attempts from one address",
			match: func(r *http.Request, route string) bool {
				return r.Method == http.MethodPost && runsScript(route, "/wp-login.php")
			}})
	}
	if cfg.APIRate.PerMinute > 0 {
		api := cfg.APIRate
		rules = append(rules, &compiledRule{count: api.PerMinute, window: time.Minute, id: idAPIRateLimited,
			message: "too many API requests from one address",
			match:   func(_ *http.Request, route string) bool { return api.matches(route) }})
	}
	for i := range cfg.Limits {
		limit := &cfg.Limits[i]
		rule := &compiledRule{count: limit.Count, window: limit.Window, monitor: limit.Monitor, id: idLimitRule,
			message: "rate limit exceeded: " + limit.String(), match: limit.matches}
		if limit.Monitor {
			enforcing := *limit
			enforcing.Monitor = false
			rule.id, rule.message = idLimitMonitor, "rate limit would be exceeded: "+enforcing.String()
		}
		rules = append(rules, rule)
	}
	for _, rule := range rules {
		rule.table = newWindowLimiter(rule.count, rule.window, min(rateKeysPerRule, rateKeysInAll/len(rules)))
		rule.logSecond.Store(neverLogged)
	}
	return rules
}

// clock is the time the rate rules go by, in nanoseconds: the monotonic clock, so that setting the wall clock cannot
// lift or extend a limit.
func (e *Edge) clock() int64 {
	if e.now != nil {
		return e.now()
	}
	return monotonic()
}

// checkLimits counts a request against every rate rule it matches, all or nothing: it goes on only if each enforcing
// rule has room, and a refused request is counted by none of them, so a refusal by one rule never uses up another's
// budget. The tables are locked in rule order, so two requests cannot each hold one the other waits for. A monitor rule
// then counts the request as it would if it enforced, and reports what it would refuse.
func (e *Edge) checkLimits(w http.ResponseWriter, r *http.Request, client netip.Addr, route string) bool {
	var enforced, watched uint64 // there are far fewer rules than 64
	for i, rule := range e.rules {
		switch {
		case !rule.match(r, route):
		case rule.monitor:
			watched |= 1 << i
		default:
			enforced |= 1 << i
		}
	}
	if enforced|watched == 0 {
		return true
	}
	key, now := shield.SourceKey(client), e.clock()
	if enforced != 0 && !e.enforceLimits(w, r, key, now, enforced) {
		return false
	}
	for i, rule := range e.rules {
		if watched&(1<<i) == 0 {
			continue
		}
		rule.table.mu.Lock()
		ok, _ := rule.table.check(key, now)
		evicted := ok && rule.table.admit(key, now)
		rule.table.mu.Unlock()
		if evicted {
			e.reportEvicted(now, 1)
		}
		if !ok {
			e.logLimit(r, rule, now)
		}
	}
	return true
}

// enforceLimits decides a request for the enforcing rules in matched, and answers it when one of them refuses it.
func (e *Edge) enforceLimits(w http.ResponseWriter, r *http.Request, key netip.Addr, now int64, matched uint64) bool {
	for i, rule := range e.rules {
		if matched&(1<<i) != 0 {
			rule.table.mu.Lock()
		}
	}
	var refused *compiledRule
	var wait int64
	for i, rule := range e.rules {
		if matched&(1<<i) != 0 {
			if ok, d := rule.table.check(key, now); !ok {
				if refused == nil {
					refused = rule
				}
				wait = max(wait, d)
			}
		}
	}
	var evicted int64
	for i, rule := range e.rules {
		if matched&(1<<i) != 0 {
			if refused == nil && rule.table.admit(key, now) {
				evicted++
			}
			rule.table.mu.Unlock()
		}
	}
	if evicted > 0 {
		e.reportEvicted(now, evicted)
	}
	if refused == nil {
		return true
	}
	e.rateRefused.Add(1)
	// The client may come back once the request is in no rule's way: in whole seconds, rounded up.
	w.Header().Set("Retry-After", strconv.FormatInt(max((wait+int64(time.Second)-1)/int64(time.Second), 1), 10))
	w.Header().Set("Cache-Control", "no-store")
	e.logLimit(r, refused, now)
	http.Error(w, http.StatusText(http.StatusTooManyRequests), http.StatusTooManyRequests)
	return false
}

// logLimit records a refusal by a rate rule, or what a monitor rule would refuse. A flood of refusals must not become a
// flood of log lines: a rule logs at most one a second. The ones it does not log are counted, and the count is logged in a
// line of its own a second later at most, before the rule's next line, or when the edge is closed (see flushLimit).
func (e *Edge) logLimit(r *http.Request, rule *compiledRule, now int64) {
	m := Match{RuleID: rule.id, Severity: "CRITICAL", Message: rule.message, Disruptive: !rule.monitor, would: rule.monitor}
	if rule.monitor {
		m.Severity = "WARNING"
	} else {
		m.status = http.StatusTooManyRequests
	}
	e.note(m, recordOf(r.Context())) // every refusal has its alert; only the lines are sampled
	if e.cfg.OnMatch == nil {
		return
	}
	second := now / int64(time.Second)
	if previous := rule.logSecond.Load(); second == previous || !rule.logSecond.CompareAndSwap(previous, second) {
		rule.unlogged.Add(1)
		if rule.flushDue.CompareAndSwap(false, true) {
			time.AfterFunc(time.Second, func() { rule.flushDue.Store(false); e.flushLimit(rule) })
		}
		return
	}
	e.flushLimit(rule)
	e.finding(m, nil, r)
}

// flushLimit logs how many of a rule's refusals were not logged, if any. The refusals may be any clients', so the line names
// none, even with LogDetails: added to the next refusal's line, the count would read as that client's.
func (e *Edge) flushLimit(rule *compiledRule) {
	n := rule.unlogged.Swap(0)
	if n == 0 || e.cfg.OnMatch == nil {
		return
	}
	m := Match{RuleID: rule.id, Severity: "CRITICAL", Disruptive: !rule.monitor,
		Message: rule.message + " (" + strconv.FormatInt(n, 10) + " more refusals not logged)"}
	if rule.monitor {
		m.Severity, m.Message = "WARNING", rule.message+" ("+strconv.FormatInt(n, 10)+" more not logged)"
	}
	e.deliver(m)
}

// reportEvicted logs that a full rate-limit table dropped clients that were still counting to make room for new ones, at
// most once every ten seconds, with how many such evictions were not logged.
func (e *Edge) reportEvicted(now, n int64) {
	e.evictedLive.Add(n)
	if e.cfg.OnMatch == nil {
		return
	}
	second := now / int64(time.Second)
	previous := e.evictLogSecond.Load()
	if second-previous < 10 && second >= previous || !e.evictLogSecond.CompareAndSwap(previous, second) {
		e.evictUnlogged.Add(n)
		return
	}
	message := "rate-limit table full; least recently admitted client evicted"
	if missed := e.evictUnlogged.Swap(0) + n - 1; missed > 0 {
		message += " (" + strconv.FormatInt(missed, 10) + " more evictions not logged)"
	}
	e.deliver(Match{RuleID: idRateStateFull, Severity: "WARNING", Message: message})
}

// WordPressPolicy is the protection for a WordPress site. WordPress and its plugins are most of what is hacked:
// in 2025 more than half of the new vulnerabilities were broken access control, and the exploited ones were used
// within hours of disclosure, so the useful protection is to take away what an attacker needs next.
type WordPressPolicy struct {
	Enabled bool
	// AllowXMLRPC leaves xmlrpc.php reachable (Jetpack and the mobile app use it). By default it is refused, in any
	// directory (a site may be installed under /blog/): it allows many password guesses in one request.
	AllowXMLRPC bool
	// LoginPerMinute is how many POSTs to wp-login.php, in any directory, one address may make a minute (default 10).
	LoginPerMinute int
}

var (
	// Executable files under the directories WordPress writes to, for a site installed at the root or in a directory
	// (/blog/wp-content/uploads/). Nothing legitimate is run from there. A script extension is one before path info, a
	// second extension (x.php.jpg, which Apache runs with AddHandler) or the end, as local rule 5006011 reads it.
	wpWritable = regexp.MustCompile(`(?i)/wp-content/(uploads|cache|upgrade|backup[^/]*|backups[^/]*|ai1wm-backups|updraft|wc-logs|wflogs|et-cache|litespeed)(/|$)`)
	wpScript   = regexp.MustCompile(`(?i)\.(php[0-9]?|phtml?|pht|phps|phar|shtml?)([/.:\s]|$)`)
)

// checkWordPress refuses the scripts a WordPress site never runs. The route is the request's routePath: empty segments, a
// trailing slash, path parameters and path info do not change which script PHP runs. Both the scripts in its writable
// directories and xmlrpc.php are refused in any directory, for a site installed under one. Login attempts are limited by a rate rule (see compileLimits).
func (e *Edge) checkWordPress(w http.ResponseWriter, r *http.Request, p string) bool {
	if wpWritable.MatchString(p) && wpScript.MatchString(p) {
		e.refuse(w, r, http.StatusForbidden, idWordPressPHP, "a script is requested from a directory WordPress only writes data to")
		return false
	}
	if runsScript(p, "/xmlrpc.php") && !e.cfg.WordPress.AllowXMLRPC {
		e.refuse(w, r, http.StatusForbidden, idXMLRPC, "xmlrpc.php is switched off")
		return false
	}
	return true
}

// runsScript reports a route path that runs script (a "/" and a file name) from any directory, directly or with path info
// after it: /wp-login.php, /blog/wp-login.php and /blog/wp-login.php/x all run /wp-login.php, so a site installed under a
// subdirectory is covered as well as one at the root.
func runsScript(p, script string) bool {
	for {
		i := strings.Index(p, script)
		if i < 0 {
			return false
		}
		// script starts with a slash, so it starts a segment; it must also end one.
		if p = p[i+len(script):]; p == "" || p[0] == '/' {
			return true
		}
	}
}
