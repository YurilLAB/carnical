// SPDX-License-Identifier: Apache-2.0

// Package crowdsec consumes CrowdSec LAPI IP and range ban decisions. It does not
// modify kernel firewall rules or forward requests to CrowdSec AppSec.
package crowdsec

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Config configures one independently registered LAPI bouncer. Never share a key
// between running clients: the stream cursor belongs to the bouncer, not its socket.
type Config struct {
	URL              string // HTTP on literal loopback, HTTPS, or an absolute Unix socket path
	APIKey           string
	Roots            *x509.CertPool // nil loads the system roots before confinement
	Interval         time.Duration  // default 10s, between 1s and 1h
	Timeout          time.Duration  // default 5s, between 100ms and 30s
	MaxStale         time.Duration  // default 2m; at least Interval + Timeout, at most 24h
	FailOpen         bool           // stale cache allows unlisted visitors; unexpired bans still apply
	MaxDecisions     int            // default 200,000; between 1 and 1,000,000
	MaxResponseBytes int64          // default 64 MiB; between 1 KiB and 256 MiB
	Origins          string         // optional comma-separated LAPI origins, empty means all
}

// Action is the result of a local lookup, with no network access.
type Action uint8

const (
	Allow Action = iota
	Ban
	Unavailable
)

type decision struct {
	ID        int64  `json:"id"`
	Duration  string `json:"duration"`
	Until     string `json:"until"`
	Scope     string `json:"scope"`
	Type      string `json:"type"`
	Value     string `json:"value"`
	Simulated bool   `json:"simulated"`
}
type entry struct {
	prefix  netip.Prefix
	expires time.Time
}
type snapshot struct {
	prefixes     map[netip.Prefix]time.Time
	bits4, bits6 []int
	updated      time.Time
	count        int
	skipped      int
}

// Stats provides bounded, privacy-safe counters. Entries may include bans that
// expired since the last refresh; Check always enforces their individual expiry.
type Stats struct {
	Entries                               int
	Skipped                               int
	LastSuccess                           time.Time
	Stale                                 bool
	Syncs, Failures, Blocked, Unavailable uint64
}

// Client publishes immutable snapshots while serializing stream updates. The
// owner calls Sync before serving and Run until shutdown, then Close.
type Client struct {
	cfg                                   Config
	http                                  *http.Client
	endpoint                              string
	port                                  uint16
	mu                                    sync.Mutex
	state                                 map[int64]entry
	resync                                bool
	view                                  atomic.Pointer[snapshot]
	syncs, failures, blocked, unavailable atomic.Uint64
	now                                   func() time.Time
}

// New validates transport and resource limits. It does not contact LAPI.
func New(cfg Config) (*Client, error) {
	if cfg.Interval == 0 {
		cfg.Interval = 10 * time.Second
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = 5 * time.Second
	}
	if cfg.MaxStale == 0 {
		cfg.MaxStale = 2 * time.Minute
	}
	if cfg.MaxDecisions == 0 {
		cfg.MaxDecisions = 200000
	}
	if cfg.MaxResponseBytes == 0 {
		cfg.MaxResponseBytes = 64 << 20
	}
	if cfg.Interval < time.Second || cfg.Interval > time.Hour || cfg.Timeout < 100*time.Millisecond || cfg.Timeout > 30*time.Second ||
		cfg.MaxStale < cfg.Interval+cfg.Timeout || cfg.MaxStale > 24*time.Hour || cfg.MaxDecisions < 1 || cfg.MaxDecisions > 1000000 ||
		cfg.MaxResponseBytes < 1024 || cfg.MaxResponseBytes > 256<<20 {
		return nil, errors.New("crowdsec: invalid polling or capacity limits")
	}
	if len(cfg.APIKey) == 0 || len(cfg.APIKey) > 4096 {
		return nil, errors.New("crowdsec: missing or oversized bouncer key")
	}
	for _, b := range []byte(cfg.APIKey) {
		if b <= 32 || b > 126 {
			return nil, errors.New("crowdsec: invalid bouncer key")
		}
	}
	for _, b := range []byte(cfg.Origins) {
		if !(b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' || b >= '0' && b <= '9' || strings.ContainsRune("_,-", rune(b))) {
			return nil, errors.New("crowdsec: invalid origins filter")
		}
	}
	if len(cfg.Origins) > 1024 {
		return nil, errors.New("crowdsec: oversized origins filter")
	}
	dialer := &net.Dialer{Timeout: cfg.Timeout, KeepAlive: 30 * time.Second}
	transport := &http.Transport{DialContext: dialer.DialContext, MaxIdleConns: 2, MaxIdleConnsPerHost: 2,
		IdleConnTimeout: 90 * time.Second, ResponseHeaderTimeout: cfg.Timeout, MaxResponseHeaderBytes: 16 << 10,
		DisableCompression: true} // no proxy environment variables or implicit decompression
	c := &Client{cfg: cfg, resync: true, now: time.Now}
	if strings.HasPrefix(cfg.URL, "/") && filepath.IsAbs(cfg.URL) {
		if cfg.Roots != nil {
			return nil, errors.New("crowdsec: TLS roots cannot be used with a Unix socket")
		}
		transport.DialContext = func(ctx context.Context, _, _ string) (net.Conn, error) {
			return dialer.DialContext(ctx, "unix", cfg.URL)
		}
		c.endpoint = "http://localhost/v1/decisions/stream"
	} else {
		u, err := url.Parse(cfg.URL)
		if err != nil || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" ||
			(u.Path != "" && u.Path != "/") || u.RawPath != "" || (u.Scheme != "http" && u.Scheme != "https") {
			return nil, errors.New("crowdsec: API URL must be an HTTP(S) origin or absolute Unix socket path")
		}
		if u.Scheme == "http" {
			a, err := netip.ParseAddr(u.Hostname())
			if err != nil || a.Zone() != "" || !a.Unmap().IsLoopback() {
				return nil, errors.New("crowdsec: plain HTTP requires a literal loopback address")
			}
			if cfg.Roots != nil {
				return nil, errors.New("crowdsec: TLS roots require HTTPS")
			}
		}
		port := u.Port()
		if port == "" {
			if u.Scheme == "https" {
				port = "443"
			} else {
				port = "80"
			}
		}
		n, err := strconv.ParseUint(port, 10, 16)
		if err != nil || n == 0 {
			return nil, errors.New("crowdsec: invalid API port")
		}
		c.port = uint16(n)
		if u.Scheme == "https" {
			roots := cfg.Roots
			if roots == nil {
				roots, err = x509.SystemCertPool()
				if err != nil {
					return nil, errors.New("crowdsec: cannot load system TLS roots")
				}
			}
			transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots.Clone()}
		}
		u.Path = "/v1/decisions/stream"
		c.endpoint = u.String()
	}
	c.http = &http.Client{Transport: transport, Timeout: cfg.Timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("crowdsec: redirects refused") }}
	return c, nil
}

// ConnectPort is zero for a Unix socket; otherwise this TCP port must be allowed
// explicitly by the deployment's confinement and network policy.
func (c *Client) ConnectPort() uint16 { return c.port }
func (c *Client) Close()              { c.http.CloseIdleConnections() }

// Sync applies an entire update atomically. A failed pull always forces a full
// resync: LAPI may already have advanced its cursor even if decoding failed here.
// Errors never include the credential, URL, upstream response or decision value.
func (c *Client) Sync(ctx context.Context) (err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	defer func() {
		if err != nil {
			c.resync = true
			c.failures.Add(1)
		}
	}()
	started := c.now()
	u, _ := url.Parse(c.endpoint)
	q := u.Query()
	q.Set("startup", strconv.FormatBool(c.resync))
	q.Set("scopes", "ip,range")
	if c.cfg.Origins != "" {
		q.Set("origins", c.cfg.Origins)
	}
	u.RawQuery = q.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return errors.New("crowdsec: cannot construct request")
	}
	req.Header.Set("X-Api-Key", c.cfg.APIKey)
	req.Header.Set("User-Agent", "crowdsec-carnical-bouncer/v0.1.0")
	req.Header.Set("Accept", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return errors.New("crowdsec: API connection failed")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("crowdsec: API returned HTTP %d", resp.StatusCode)
	}
	if resp.ContentLength > c.cfg.MaxResponseBytes {
		return errors.New("crowdsec: response capacity exceeded")
	}
	lr := &io.LimitedReader{R: resp.Body, N: c.cfg.MaxResponseBytes + 1}
	added, deleted, err := readStream(lr, c.cfg.MaxDecisions)
	if err != nil {
		return err
	}
	if lr.N == 0 {
		return errors.New("crowdsec: response capacity exceeded")
	}
	next := make(map[int64]entry)
	if !c.resync {
		for id, e := range c.state {
			if started.Before(e.expires) {
				next[id] = e
			}
		}
	}
	for _, d := range deleted {
		if d.ID <= 0 {
			return errors.New("crowdsec: invalid deleted decision ID")
		}
		delete(next, d.ID)
	}
	skipped := 0
	seen := make(map[int64]bool, len(added))
	for _, d := range added {
		if d.ID <= 0 || seen[d.ID] {
			return errors.New("crowdsec: invalid or duplicate decision ID")
		}
		seen[d.ID] = true
		if d.Type == "" || d.Scope == "" || d.Value == "" || d.Duration == "" {
			return errors.New("crowdsec: missing required decision fields")
		}
		if d.Simulated || !strings.EqualFold(d.Type, "ban") || (!strings.EqualFold(d.Scope, "ip") && !strings.EqualFold(d.Scope, "range")) {
			delete(next, d.ID)
			skipped++
			continue
		}
		e, err := parseBan(d, started)
		if err != nil {
			return err
		}
		if !started.Before(e.expires) {
			delete(next, d.ID)
			continue
		}
		// An existing ID must never silently change its target during a delta.
		if old, ok := next[d.ID]; ok && old.prefix != e.prefix {
			return errors.New("crowdsec: decision ID changed target")
		}
		next[d.ID] = e
		if len(next) > c.cfg.MaxDecisions {
			return errors.New("crowdsec: decision capacity exceeded")
		}
	}
	view := &snapshot{prefixes: make(map[netip.Prefix]time.Time, len(next)), updated: started, count: len(next), skipped: skipped}
	var lengths4 [33]bool
	var lengths6 [129]bool
	for _, e := range next {
		if e.expires.After(view.prefixes[e.prefix]) {
			view.prefixes[e.prefix] = e.expires
		}
		if e.prefix.Addr().Is4() {
			lengths4[e.prefix.Bits()] = true
		} else {
			lengths6[e.prefix.Bits()] = true
		}
	}
	for b := 32; b >= 0; b-- {
		if lengths4[b] {
			view.bits4 = append(view.bits4, b)
		}
	}
	for b := 128; b >= 0; b-- {
		if lengths6[b] {
			view.bits6 = append(view.bits6, b)
		}
	}
	c.state, c.resync = next, false
	c.view.Store(view)
	c.syncs.Add(1)
	return nil
}

func parseBan(d decision, now time.Time) (entry, error) {
	var p netip.Prefix
	if strings.EqualFold(d.Scope, "ip") {
		a, err := netip.ParseAddr(d.Value)
		if err != nil || a.Zone() != "" {
			return entry{}, errors.New("crowdsec: invalid ban address")
		}
		a = a.Unmap()
		p = netip.PrefixFrom(a, a.BitLen())
	} else {
		var err error
		p, err = netip.ParsePrefix(d.Value)
		if err != nil {
			return entry{}, errors.New("crowdsec: invalid ban range")
		}
		if p.Addr().Is4In6() {
			if p.Bits() < 96 {
				return entry{}, errors.New("crowdsec: ambiguous mapped ban range")
			}
			p = netip.PrefixFrom(p.Addr().Unmap(), p.Bits()-96)
		}
		p = p.Masked()
	}
	ttl, err := time.ParseDuration(d.Duration)
	if err != nil {
		return entry{}, errors.New("crowdsec: invalid decision duration")
	}
	expires := now.Add(ttl)
	if d.Until != "" {
		until, err := time.Parse(time.RFC3339Nano, d.Until)
		if err != nil {
			return entry{}, errors.New("crowdsec: invalid decision expiry")
		}
		if until.Before(expires) {
			expires = until
		}
	}
	return entry{p, expires}, nil
}

// readStream decodes entries individually, capping both their count and encoded
// bytes. Both arrays must be present; malformed/truncated/duplicate envelopes
// cannot clear a previously working snapshot. Unknown fields permit API evolution.
func readStream(r io.Reader, limit int) ([]decision, []decision, error) {
	dec := json.NewDecoder(r)
	t, err := dec.Token()
	bad := errors.New("crowdsec: invalid decision stream")
	if err != nil || t != json.Delim('{') {
		return nil, nil, bad
	}
	var added, deleted []decision
	seen := map[string]bool{}
	total := 0
	for dec.More() {
		t, err := dec.Token()
		if err != nil {
			return nil, nil, bad
		}
		key, ok := t.(string)
		if !ok || seen[key] {
			return nil, nil, bad
		}
		seen[key] = true
		if key != "new" && key != "deleted" {
			var discard json.RawMessage
			if err := dec.Decode(&discard); err != nil {
				return nil, nil, bad
			}
			continue
		}
		t, err = dec.Token()
		if err != nil {
			return nil, nil, bad
		}
		if t == nil {
			continue
		} // older LAPI versions use null for empty arrays
		if t != json.Delim('[') {
			return nil, nil, bad
		}
		for dec.More() {
			total++
			if total > limit {
				return nil, nil, errors.New("crowdsec: stream decision capacity exceeded")
			}
			d, err := readDecision(dec)
			if err != nil {
				return nil, nil, bad
			}
			if key == "new" {
				added = append(added, d)
			} else {
				deleted = append(deleted, d)
			}
		}
		if t, err = dec.Token(); err != nil || t != json.Delim(']') {
			return nil, nil, bad
		}
	}
	if t, err = dec.Token(); err != nil || t != json.Delim('}') || !seen["new"] || !seen["deleted"] {
		return nil, nil, bad
	}
	var extra json.RawMessage
	if dec.Decode(&extra) != io.EOF {
		return nil, nil, bad
	}
	return added, deleted, nil
}

// readDecision rejects duplicate fields that could otherwise overwrite a ban or its ID.
// EqualFold preserves encoding/json's case-insensitive field matching, including Unicode aliases.
// Unknown LAPI metadata remains compatible and cannot overwrite these enforcement fields.
func readDecision(dec *json.Decoder) (decision, error) {
	var d decision
	bad := errors.New("crowdsec: invalid decision stream")
	if token, err := dec.Token(); err != nil || token != json.Delim('{') {
		return d, bad
	}
	fields := [...]string{"id", "duration", "until", "scope", "type", "value", "simulated"}
	var seen uint8
	for dec.More() {
		token, err := dec.Token()
		name, ok := token.(string)
		if err != nil || !ok {
			return decision{}, bad
		}
		field := len(fields)
		for i, canonical := range fields {
			if strings.EqualFold(name, canonical) {
				mask := uint8(1) << i
				if seen&mask != 0 {
					return decision{}, bad
				}
				seen |= mask
				field = i
				break
			}
		}
		switch field {
		case 0:
			err = dec.Decode(&d.ID)
		case 1:
			err = dec.Decode(&d.Duration)
		case 2:
			err = dec.Decode(&d.Until)
		case 3:
			err = dec.Decode(&d.Scope)
		case 4:
			err = dec.Decode(&d.Type)
		case 5:
			err = dec.Decode(&d.Value)
		case 6:
			err = dec.Decode(&d.Simulated)
		default:
			var discard json.RawMessage
			err = dec.Decode(&discard)
		}
		if err != nil {
			return decision{}, bad
		}
	}
	if token, err := dec.Token(); err != nil || token != json.Delim('}') {
		return decision{}, bad
	}
	return d, nil
}

// Check evaluates the verified client IP, including IPv4-mapped IPv6. It makes
// at most 33 IPv4 or 129 IPv6 prefix probes regardless of blocklist size.
func (c *Client) Check(addr netip.Addr) Action {
	if !addr.IsValid() || addr.Zone() != "" {
		c.unavailable.Add(1)
		return Unavailable
	}
	addr = addr.Unmap()
	now, view := c.now(), c.view.Load()
	if view != nil {
		bits := view.bits6
		if addr.Is4() {
			bits = view.bits4
		}
		for _, b := range bits {
			if until, ok := view.prefixes[netip.PrefixFrom(addr, b).Masked()]; ok && now.Before(until) {
				c.blocked.Add(1)
				return Ban
			}
		}
	}
	if !c.cfg.FailOpen && (view == nil || now.Sub(view.updated) >= c.cfg.MaxStale) {
		c.unavailable.Add(1)
		return Unavailable
	}
	return Allow
}

func (c *Client) Stats() Stats {
	s := Stats{Stale: true, Syncs: c.syncs.Load(), Failures: c.failures.Load(), Blocked: c.blocked.Load(), Unavailable: c.unavailable.Load()}
	if v := c.view.Load(); v != nil {
		s.Entries, s.Skipped, s.LastSuccess = v.count, v.skipped, v.updated
		s.Stale = c.now().Sub(v.updated) >= c.cfg.MaxStale
	}
	return s
}

// Run refreshes at Interval, and invokes report after each bounded attempt. Sync
// must succeed at startup; Run does not perform that initial pull. Cancel ctx and
// wait for Run to return before Close, including when server startup fails.
func (c *Client) Run(ctx context.Context, report func(Stats, error)) {
	ticker := time.NewTicker(c.cfg.Interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			err := c.Sync(ctx)
			if ctx.Err() != nil {
				return
			}
			if report != nil {
				report(c.Stats(), err)
			}
		}
	}
}
