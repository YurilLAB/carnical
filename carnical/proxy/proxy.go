// Package proxy is a reverse proxy that inspects every request with Coraza running the OWASP Core Rule Set, and
// forwards what passes to one upstream.
//
// The WAF is only as good as the agreement between what it inspects and what the application receives, so the
// proxy works to keep them the same: it forwards the request target exactly as it was sent (and refuses a target
// it could not), it removes every header a client could use to claim an identity or a route, it does not forward
// trailers, and it does not allow protocol upgrades, which would turn the connection into a tunnel nobody inspects.
package proxy

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httputil"
	"net/netip"
	"net/url"
	"strings"
	"time"

	"github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/experimental"
	txhttp "github.com/corazawaf/coraza/v3/http"
	"github.com/corazawaf/coraza/v3/types"

	"github.com/YurilLAB/coraza/carnical/crs"
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
	e := &Edge{cfg: cfg}
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
	e.handler = e.guard(txhttp.WrapHandler(waf, e.forward()))
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
	return &http.Server{Addr: addr, Handler: e, ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 30 * time.Second,
		WriteTimeout: 120 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 32 << 10,
		DisableGeneralOptionsHandler: true} // so that "OPTIONS *" reaches the guard instead of being answered by net/http
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
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), contextKey{}, addr)))
	})
}

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
			out.Trailer = nil
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
		rp.ServeHTTP(w, r)
	})
}
