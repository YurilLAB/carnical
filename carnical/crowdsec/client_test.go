// SPDX-License-Identifier: Apache-2.0

package crowdsec

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

const key = "dedicated-test-bouncer-key"

func ban(id int64, scope, value, ttl string) decision {
	return decision{ID: id, Scope: scope, Type: "ban", Value: value, Duration: ttl}
}
func stream(added, deleted []decision) string {
	b, _ := json.Marshal(map[string]any{"new": added, "deleted": deleted})
	return string(b)
}

type apiFixture struct {
	mu       sync.Mutex
	body     string
	status   int
	startups []string
	badAuth  bool
}

func (f *apiFixture) serve(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if r.Header.Get("X-Api-Key") != key || r.URL.Path != "/v1/decisions/stream" || r.URL.Query().Get("scopes") != "ip,range" ||
		!strings.HasPrefix(r.Header.Get("User-Agent"), "crowdsec-carnical-bouncer/") {
		f.badAuth = true
		http.Error(w, "unauthorized", 401)
		return
	}
	f.startups = append(f.startups, r.URL.Query().Get("startup"))
	if f.status != 0 {
		w.WriteHeader(f.status)
	}
	fmt.Fprint(w, f.body)
}
func (f *apiFixture) update(body string, status int) {
	f.mu.Lock()
	f.body, f.status = body, status
	f.mu.Unlock()
}
func newTestClient(t *testing.T, f *apiFixture, change func(*Config)) *Client {
	t.Helper()
	api := httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(api.Close)
	cfg := Config{URL: api.URL, APIKey: key, Interval: time.Second, Timeout: 100 * time.Millisecond, MaxStale: 2 * time.Second}
	if change != nil {
		change(&cfg)
	}
	c, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.Close)
	return c
}

// LAPI stream cursors and atomic cache transactions are not SecLang behavior.
func TestStreamTransactions(t *testing.T) {
	a, b := netip.MustParseAddr("192.0.2.9"), netip.MustParseAddr("2001:db8::9")
	first := stream([]decision{ban(1, "Ip", a.String(), "1m"), ban(2, "Range", "2001:db8::/64", "1m")}, nil)
	tests := []struct {
		name, body   string
		status       int
		limit        int
		wantErr      bool
		wantA, wantB Action
	}{
		{"delta adds", stream([]decision{ban(3, "ip", "198.51.100.9", "1m")}, nil), 0, 0, false, Ban, Ban},
		{"delete one ID", stream(nil, []decision{{ID: 1}}), 0, 0, false, Allow, Ban},
		{"overlapping ban survives delete", stream([]decision{ban(3, "range", "192.0.2.0/24", "1m")}, []decision{{ID: 1}}), 0, 0, false, Ban, Ban},
		{"empty delta retains bans", `{"new":null,"deleted":null}`, 0, 0, false, Ban, Ban},
		{"duplicate ban type", "{\"new\":[{\"id\":1,\"scope\":\"Ip\",\"value\":\"192.0.2.9\",\"duration\":\"1m\",\"type\":\"ban\",\"type\":\"captcha\"}],\"deleted\":[]}", 0, 0, true, Ban, Ban},
		{"case alias ban type", "{\"new\":[{\"id\":1,\"scope\":\"Ip\",\"value\":\"192.0.2.9\",\"duration\":\"1m\",\"type\":\"ban\",\"Type\":\"captcha\"}],\"deleted\":[]}", 0, 0, true, Ban, Ban},
		{"escaped duplicate ban type", "{\"new\":[{\"id\":1,\"scope\":\"Ip\",\"value\":\"192.0.2.9\",\"duration\":\"1m\",\"type\":\"ban\",\"t\\u0079pe\":\"captcha\"}],\"deleted\":[]}", 0, 0, true, Ban, Ban},
		{"duplicate expiry duration", "{\"new\":[{\"id\":1,\"scope\":\"Ip\",\"value\":\"192.0.2.9\",\"type\":\"ban\",\"duration\":\"1m\",\"duration\":\"0s\"}],\"deleted\":[]}", 0, 0, true, Ban, Ban},
		{"Unicode alias simulation", "{\"new\":[{\"id\":1,\"scope\":\"Ip\",\"value\":\"192.0.2.9\",\"duration\":\"1m\",\"type\":\"ban\",\"simulated\":false,\"ſimulated\":true}],\"deleted\":[]}", 0, 0, true, Ban, Ban},
		{"duplicate deletion ID", "{\"new\":[],\"deleted\":[{\"id\":999,\"ID\":1}]}", 0, 0, true, Ban, Ban},
		{"single case aliases", "{\"new\":[{\"ID\":1,\"Scope\":\"Ip\",\"Value\":\"192.0.2.9\",\"Duration\":\"1m\",\"Type\":\"ban\"}],\"deleted\":[]}", 0, 0, false, Ban, Ban},
		{"single Unicode alias", "{\"new\":[{\"id\":1,\"ſcope\":\"Ip\",\"value\":\"192.0.2.9\",\"duration\":\"1m\",\"type\":\"ban\"}],\"deleted\":[]}", 0, 0, false, Ban, Ban},
		{"forward compatible metadata", "{\"new\":[{\"id\":1,\"scope\":\"Ip\",\"value\":\"192.0.2.9\",\"duration\":\"1m\",\"type\":\"ban\",\"future_metadata\":{\"id\":7,\"type\":\"captcha\"}}],\"deleted\":[]}", 0, 0, false, Ban, Ban},
		{"HTTP failure preserves bans", `SECRET_UPSTREAM_BODY`, 503, 0, true, Ban, Ban},
		{"authentication failure preserves bans", `SECRET_UPSTREAM_BODY`, 401, 0, true, Ban, Ban},
		{"missing required fields", `{"new":[{"id":3,"type":null,"scope":"Ip","value":"192.0.2.9","duration":"1m"}],"deleted":[]}`, 0, 0, true, Ban, Ban},
		{"missing new cannot clear cache", `{"deleted":[]}`, 0, 0, true, Ban, Ban},
		{"truncated JSON", `{"new":[`, 0, 0, true, Ban, Ban},
		{"duplicate envelope", `{"new":[],"new":[],"deleted":[]}`, 0, 0, true, Ban, Ban},
		{"trailing JSON", `{"new":[],"deleted":[]} {}`, 0, 0, true, Ban, Ban},
		{"bad ban target", stream([]decision{ban(3, "ip", "not-an-ip", "1m")}, []decision{{ID: 1}}), 0, 0, true, Ban, Ban},
		{"bad TTL", stream([]decision{ban(3, "ip", a.String(), "forever")}, nil), 0, 0, true, Ban, Ban},
		{"duplicate ID", stream([]decision{ban(3, "ip", a.String(), "1m"), ban(3, "ip", b.String(), "1m")}, nil), 0, 0, true, Ban, Ban},
		{"zero ID", stream([]decision{ban(0, "ip", a.String(), "1m")}, nil), 0, 0, true, Ban, Ban},
		{"ID changes target", stream([]decision{ban(1, "ip", b.String(), "1m")}, nil), 0, 0, true, Ban, Ban},
		{"invalid deleted ID", stream(nil, []decision{{ID: 0}}), 0, 0, true, Ban, Ban},
		{"state cap", stream([]decision{ban(3, "ip", "198.51.100.9", "1m")}, nil), 0, 2, true, Ban, Ban},
		{"response count cap", stream([]decision{ban(3, "ip", a.String(), "1m"), ban(4, "ip", b.String(), "1m"), ban(5, "ip", "198.51.100.9", "1m")}, nil), 0, 2, true, Ban, Ban},
		{"encoded body cap", `{"new":[],"deleted":[],"ignored":"` + strings.Repeat("x", 1100) + `"}`, 0, -1, true, Ban, Ban},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := &apiFixture{body: first}
			c := newTestClient(t, f, func(cfg *Config) {
				if tt.limit > 0 {
					cfg.MaxDecisions = tt.limit
				}
				if tt.limit < 0 {
					cfg.MaxResponseBytes = 1024
				}
			})
			if err := c.Sync(context.Background()); err != nil {
				t.Fatal(err)
			}
			f.update(tt.body, tt.status)
			err := c.Sync(context.Background())
			if (err != nil) != tt.wantErr {
				t.Fatalf("Sync: %v; actions=%v,%v", err, c.Check(a), c.Check(b))
			}
			if err != nil && (strings.Contains(err.Error(), key) || strings.Contains(err.Error(), "SECRET_UPSTREAM_BODY")) {
				t.Fatal("error leaked secret")
			}
			if c.Check(a) != tt.wantA || c.Check(b) != tt.wantB {
				t.Fatalf("actions: %v %v", c.Check(a), c.Check(b))
			}
			// After any failed update the next response is authoritative, not a
			// delta based on a possibly advanced server cursor.
			f.update(stream(nil, nil), 0)
			if err := c.Sync(context.Background()); err != nil {
				t.Fatal(err)
			}
			if tt.wantErr && (c.Check(a) != Allow || c.Check(b) != Allow) {
				t.Fatal("full resync retained deleted bans")
			}
			f.mu.Lock()
			defer f.mu.Unlock()
			want := "false"
			if tt.wantErr {
				want = "true"
			}
			if f.badAuth || len(f.startups) != 3 || f.startups[0] != "true" || f.startups[1] != "false" || f.startups[2] != want {
				t.Fatalf("protocol: %+v", f.startups)
			}
		})
	}
}

// Ban expiry and stale-service policy use a controlled clock, without timing sleeps.
func TestBanExpiryAndOutages(t *testing.T) {
	a := netip.MustParseAddr("192.0.2.9")
	for _, failOpen := range []bool{false, true} {
		t.Run(fmt.Sprint("fail-open=", failOpen), func(t *testing.T) {
			f := &apiFixture{body: stream([]decision{ban(1, "ip", a.String(), "10s"), ban(2, "ip", a.String(), "20s")}, nil)}
			c := newTestClient(t, f, func(cfg *Config) { cfg.FailOpen = failOpen })
			now := time.Now()
			c.now = func() time.Time { return now }
			want := Unavailable
			if failOpen {
				want = Allow
			}
			if c.Check(a) != want {
				t.Fatal("uninitialized cache action")
			}
			if err := c.Sync(context.Background()); err != nil {
				t.Fatal(err)
			}
			f.update(stream(nil, []decision{{ID: 1}}), 0)
			if err := c.Sync(context.Background()); err != nil {
				t.Fatal(err)
			}
			f.update("unavailable", 503)
			if err := c.Sync(context.Background()); err == nil {
				t.Fatal("outage not recorded")
			}
			now = now.Add(3 * time.Second)
			if c.Check(a) != Ban || c.Check(netip.MustParseAddr("198.51.100.9")) != want {
				t.Fatal("stale cache bypass or wrong fallback")
			}
			now = now.Add(18 * time.Second)
			if c.Check(a) != want {
				t.Fatal("expired ban still enforced")
			}
			f.update(stream(nil, nil), 0)
			if err := c.Sync(context.Background()); err != nil {
				t.Fatal(err)
			}
			if c.Check(a) != Allow || c.Stats().Stale {
				t.Fatal("recovery did not restore service")
			}
		})
	}
	tests := []struct {
		name string
		d    decision
		ip   string
		want Action
		bad  bool
	}{
		{"IPv4 range", ban(1, "Range", "192.0.2.10/24", "1m"), a.String(), Ban, false},
		{"IPv4 outside range", ban(1, "Range", "192.0.2.0/24", "1m"), "192.0.3.9", Allow, false},
		{"IPv6 range", ban(1, "Range", "2001:db8::/48", "1m"), "2001:db8:0:1::9", Ban, false},
		{"IPv6 outside range", ban(1, "Range", "2001:db8::/48", "1m"), "2001:db8:1::9", Allow, false},
		{"mapped visitor", ban(1, "Ip", a.String(), "1m"), "::ffff:192.0.2.9", Ban, false},
		{"mapped decision", ban(1, "Ip", "::ffff:192.0.2.9", "1m"), a.String(), Ban, false},
		{"mapped range", ban(1, "Range", "::ffff:192.0.2.0/120", "1m"), a.String(), Ban, false},
		{"ambiguous mapped range", ban(1, "Range", "::ffff:192.0.2.0/80", "1m"), a.String(), Unavailable, true},
		{"expired", ban(1, "Ip", a.String(), "-1s"), a.String(), Allow, false},
		{"simulation", func() decision { d := ban(1, "Ip", a.String(), "1m"); d.Simulated = true; return d }(), a.String(), Allow, false},
		{"captcha stays distinct", func() decision { d := ban(1, "Ip", a.String(), "1m"); d.Type = "captcha"; return d }(), a.String(), Allow, false},
		{"non-IP scope", func() decision { d := ban(1, "username", "alice", "1m"); return d }(), a.String(), Allow, false},
		{"absolute expiry", func() decision { d := ban(1, "Ip", a.String(), "1m"); d.Until = "2020-01-01T00:00:00Z"; return d }(), a.String(), Allow, false},
		{"malformed expiry", func() decision { d := ban(1, "Ip", a.String(), "1m"); d.Until = "forever"; return d }(), a.String(), Unavailable, true},
		{"zone forbidden", ban(1, "Ip", "fe80::1%eth0", "1m"), a.String(), Unavailable, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := &apiFixture{body: stream([]decision{tt.d}, nil)}
			c := newTestClient(t, f, nil)
			if err := c.Sync(context.Background()); (err != nil) != tt.bad {
				t.Fatalf("sync: %v", err)
			}
			if got := c.Check(netip.MustParseAddr(tt.ip)); got != tt.want {
				t.Fatalf("action %v want %v", got, tt.want)
			}
		})
	}
}

// Transport tests exercise secret-bearing requests, redirects, TLS verification
// and optional Unix sockets, which engine profiles cannot express.
func TestSecureTransport(t *testing.T) {
	f := &apiFixture{body: stream(nil, nil)}
	tlsAPI := httptest.NewTLSServer(http.HandlerFunc(f.serve))
	defer tlsAPI.Close()
	roots := x509.NewCertPool()
	roots.AddCert(tlsAPI.Certificate())
	var stolen atomic.Int64
	sink := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { stolen.Add(1) }))
	defer sink.Close()
	redirect := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, sink.URL, 302) }))
	defer redirect.Close()
	timeout := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { <-r.Context().Done() }))
	defer timeout.Close()
	tests := []struct {
		name            string
		cfg             Config
		newErr, syncErr bool
	}{
		{"verified HTTPS", Config{URL: tlsAPI.URL, APIKey: key, Roots: roots}, false, false},
		{"untrusted TLS", Config{URL: tlsAPI.URL, APIKey: key}, false, true},
		{"redirect", Config{URL: redirect.URL, APIKey: key}, false, true},
		{"bounded timeout", Config{URL: timeout.URL, APIKey: key, Timeout: 100 * time.Millisecond}, false, true},
		{"remote cleartext", Config{URL: "http://192.0.2.1:8080", APIKey: key}, true, false},
		{"DNS cleartext", Config{URL: "http://localhost:8080", APIKey: key}, true, false},
		{"embedded credentials", Config{URL: "https://user:secret@example.test", APIKey: key}, true, false},
		{"query", Config{URL: "https://example.test?key=secret", APIKey: key}, true, false},
		{"path", Config{URL: "https://example.test/v1", APIKey: key}, true, false},
		{"header injection", Config{URL: tlsAPI.URL, APIKey: key + "\r\nInjected: yes"}, true, false},
		{"missing key", Config{URL: tlsAPI.URL}, true, false},
		{"invalid capacity", Config{URL: tlsAPI.URL, APIKey: key, MaxDecisions: -1}, true, false},
		{"stale smaller than poll", Config{URL: tlsAPI.URL, APIKey: key, MaxStale: time.Second}, true, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, err := New(tt.cfg)
			if (err != nil) != tt.newErr {
				t.Fatalf("new: %v", err)
			}
			if err != nil {
				return
			}
			defer c.Close()
			if err = c.Sync(context.Background()); (err != nil) != tt.syncErr {
				t.Fatalf("sync: %v", err)
			}
		})
	}
	if stolen.Load() != 0 {
		t.Fatal("redirect forwarded the credential")
	}
	if runtime.GOOS != "windows" {
		t.Run("Unix socket", func(t *testing.T) {
			// Linux t.TempDir can exceed sockaddr_un's 108-byte path bound.
			base := ""
			if runtime.GOOS == "linux" {
				base = "/dev/shm"
			} // WSL's mounted Windows drives cannot bind Unix sockets.
			dir, err := os.MkdirTemp(base, "cs-")
			if err != nil {
				t.Fatal(err)
			}
			defer os.RemoveAll(dir)
			path := filepath.Join(dir, "api.sock")
			ln, err := net.Listen("unix", path)
			if err != nil {
				t.Fatal(err)
			}
			srv := &http.Server{Handler: http.HandlerFunc(f.serve), ReadHeaderTimeout: time.Second}
			defer srv.Close()
			go srv.Serve(ln)
			c, err := New(Config{URL: path, APIKey: key})
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			if err = c.Sync(context.Background()); err != nil {
				t.Fatal(err)
			}
		})
	}
}

// Reloading decisions during concurrent requests exercises immutable publication
// and shutdown cancellation, not rule semantics. The 100,000-entry list also
// proves nominal CrowdSec list sizes are not rejected by default capacities.
func TestConcurrentReloadAndShutdown(t *testing.T) {
	items := make([]decision, 100000)
	for i := range items {
		a := netip.AddrFrom4([4]byte{10, byte(i >> 16), byte(i >> 8), byte(i)})
		items[i] = ban(int64(i+1), "Ip", a.String(), "1h")
	}
	f := &apiFixture{body: stream(items, nil)}
	c := newTestClient(t, f, func(cfg *Config) { cfg.MaxStale = 10 * time.Minute; cfg.Timeout = 30 * time.Second })
	if err := c.Sync(context.Background()); err != nil {
		t.Fatal(err)
	}
	const probes = 100000
	var wg sync.WaitGroup
	for n := 0; n < 8; n++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < probes; i++ {
				if c.Check(netip.MustParseAddr("10.0.0.1")) != Ban || c.Check(netip.MustParseAddr("192.0.2.1")) != Allow {
					t.Error("torn or incorrect snapshot")
					return
				}
			}
		}()
	}
	// Another overlapping ban preserves 10.0.0.1 during deletion of ID 2.
	f.update(stream([]decision{ban(100001, "Range", "10.0.0.0/8", "1h")}, []decision{{ID: 2}}), 0)
	if err := c.Sync(context.Background()); err != nil {
		t.Fatal(err)
	}
	wg.Wait()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	f.update(stream(nil, nil), 0)
	go func() { c.Run(ctx, func(Stats, error) { cancel() }); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		cancel()
		t.Fatal("poll loop did not stop")
	}
	if c.Stats().Entries != 100000 || c.Stats().Blocked != 8*probes {
		t.Fatalf("lost decisions or counters: %+v", c.Stats())
	}
}
