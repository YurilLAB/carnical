// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"math/rand/v2"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"reflect"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"

	"github.com/YurilLAB/coraza/carnical/crowdsec"
	"github.com/YurilLAB/coraza/carnical/crs"
	"github.com/YurilLAB/coraza/carnical/shield"
)

// Everything here that says so runs with the rule set OFF. These protections must hold without it: they are the part
// that does not depend on a rule recognising an attack.
func ruleSetOff(c *Config) { c.CRS.Mode = crs.ModeOff }

type refusals struct {
	mu  sync.Mutex
	ids []int
}

func (r *refusals) record(m Match) { r.mu.Lock(); r.ids = append(r.ids, m.RuleID); r.mu.Unlock() }
func (r *refusals) last() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.ids) == 0 {
		return 0
	}
	return r.ids[len(r.ids)-1]
}

func TestPathPolicy(t *testing.T) {
	strict := PathPolicy{}
	tests := []struct {
		name, path string
		policy     PathPolicy
		ok         bool
	}{
		{"root", "/", strict, true},
		{"nested", "/a/b/c", strict, true},
		{"a file", "/index.php", strict, true},
		{"unreserved characters", "/a.b-c_d~e", strict, true},
		{"a segment of dots that is not a dot segment", "/a/.../b", strict, true},
		{"dots inside a name", "/a/b..c", strict, true},
		{"an escaped multibyte character", "/caf%C3%A9", strict, true},
		{"an escaped space", "/a%20b", strict, true},
		{"an escaped tilde", "/a%7Eb", strict, true},
		{"an encoded slash", "/a%2fb", strict, false},
		{"an encoded slash in capitals", "/a%2Fb", strict, false},
		{"an encoded backslash", "/a%5cb", strict, false},
		{"an encoded question mark", "/a%3fb", strict, false},
		{"an encoded hash", "/a%23b", strict, false},
		{"an encoded NUL", "/a%00b", strict, false},
		{"an encoded percent (double decoding)", "/a%25b", strict, false},
		{"an encoded newline", "/a%0ab", strict, false},
		{"an encoded DEL", "/a%7fb", strict, false},
		{"an escaped letter", "/%77p-admin/", strict, false},
		{"an escaped dot", "/a%2Eb", strict, false},
		{"encoded dot segments", "/%2e%2e/etc/passwd", strict, false},
		{"a dot segment", "/a/./b", strict, false},
		{"a parent segment", "/a/../b", strict, false},
		{"a trailing parent segment", "/a/..", strict, false},
		{"a path parameter", "/a;jsessionid=1", strict, false},
		{"a backslash", "/a" + string(rune(92)) + "b", strict, false},
		{"a truncated escape", "/a%", strict, false},
		{"a half escape", "/a%2", strict, false},
		{"a malformed escape", "/a%zz", strict, false},
		{"a space", "/a b", strict, false},
		{"a non-ASCII byte", "/é", strict, false},
		{"an encoded slash, allowed", "/a%2fb", PathPolicy{AllowEncodedSlash: true}, true},
		{"an encoded backslash, allowed", "/a%5Cb", PathPolicy{AllowEncodedSlash: true}, true},
		{"an encoded NUL stays refused when slashes are allowed", "/a%00b", PathPolicy{AllowEncodedSlash: true}, false},
		{"a path parameter, allowed", "/a;x=1", PathPolicy{AllowPathParams: true}, true},
		{"dot segments stay refused when parameters are allowed", "/a/../b", PathPolicy{AllowPathParams: true}, false},
		{"a parent segment with a path parameter", "/public/..;/admin", PathPolicy{AllowPathParams: true}, false},
		{"a parent segment with a parameter value", "/public/..;x=1/admin", PathPolicy{AllowPathParams: true}, false},
		{"a current segment with a path parameter", "/public/.;/admin", PathPolicy{AllowPathParams: true}, false},
		{"a parameter on a name with dots", "/a/b..c;x=1", PathPolicy{AllowPathParams: true}, true},
		{"a parent segment between encoded slashes", "/public%2F..%2Fadmin", PathPolicy{AllowEncodedSlash: true}, false},
		{"a parent segment before an encoded slash", "/public/..%2Fadmin", PathPolicy{AllowEncodedSlash: true}, false},
		{"a parent segment before an encoded backslash", "/public/..%5Cadmin", PathPolicy{AllowEncodedSlash: true}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.policy.check(tt.path); (err == nil) != tt.ok {
				t.Fatalf("check(%q) = %v, want ok=%v", tt.path, err, tt.ok)
			}
		})
	}
}

func TestRefusalsHoldWithTheRuleSetOffAndAreRecorded(t *testing.T) {
	tests := []struct {
		name    string
		request string
		change  func(*Config)
		want    int
		id      int
	}{
		{"an ordinary request", get("/page"), nil, 200, 0},
		{"an encoded slash", get("/a%2fb"), nil, 400, idPathNotCanon},
		{"a dot segment", get("/a/../admin"), nil, 400, idPathNotCanon},
		{"a raw hash in the query", get("/page?a=1#&q=x"), nil, 400, idTarget},
		{"an encoded hash in the query", get("/page?a=%23&q=x"), nil, 200, 0},
		{"a name the site does not answer to", get("/page"), func(c *Config) { c.AllowedHosts = []string{"www.other.test"} }, 421, idHostNotAllowed},
		{"a name it does answer to", get("/page"), func(c *Config) { c.AllowedHosts = []string{"SHOP.example.test."} }, 200, 0},
		{"a name with a port", "GET /page HTTP/1.1\r\nHost: shop.example.test:8443\r\nConnection: close\r\n\r\n", func(c *Config) { c.AllowedHosts = []string{"shop.example.test"} }, 200, 0},
		{"a gzip request body", get("/page", "Content-Encoding: gzip\r\n"), nil, 415, idRequestEncoding},
		{"an identity request encoding", get("/page", "Content-Encoding: identity\r\n"), nil, 200, 0},
		{"two Content-Type headers", get("/page", "Content-Type: text/plain\r\n", "Content-Type: application/json\r\n"), nil, 400, idAmbiguousType},
		{"an upload whose type only PHP and the rules read as multipart", strings.Replace(uploadRequest(multipartBody(filePart("shell.php", "x"))), "data; boundary", "data, boundary", 1), nil, 400, idAmbiguousType},
		// Go and the rule set take these parts for files, whose content is no argument; PHP takes them for fields.
		{"a part only filename* names as a file", uploadRequest(multipartBody("Content-Disposition: form-data; name=\"q\"; filename*=UTF-8''a.txt\r\n\r\n1 union select password from users")), nil, 400, idAmbiguousType},
		{"a part whose filename has a space before its '='", uploadRequest(multipartBody("Content-Disposition: form-data; name=\"q\"; filename =\"a.txt\"\r\n\r\n1 union select password from users")), nil, 400, idAmbiguousType},
		// PHP takes this part for a file; Go and the rule set, which cannot parse its Content-Disposition, filename* and
		// all, for a field.
		{"a file whose Content-Disposition only PHP can parse", uploadRequest(multipartBody("Content-Disposition: form-data; name=\"q\";; filename=\"a.txt\"; filename*=UTF-8''a.txt\r\n\r\n1 union select password from users")), nil, 400, idAmbiguousType},
		{"a file named by filename and filename*", uploadRequest(multipartBody("Content-Disposition: form-data; name=\"q\"; filename=\"a.txt\"; filename*=UTF-8''a.txt\r\n\r\ntext")), nil, 200, 0},
		{"an empty file input", uploadRequest(multipartBody(filePart("", ""))), nil, 200, 0},
		{"a chunked JSON body over the form limit", "POST /api HTTP/1.1\r\n" + preamble + "Content-Type: application/json\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n1388\r\n" +
			strings.Repeat("1", 5000) + "\r\n0\r\n\r\n", func(c *Config) { c.MaxFormBody = 4 << 10 }, 413, idBodyTooLarge},
		{"a forwarding chain that is not addresses", get("/page", "X-Forwarded-For: 198.51.100.10, junk\r\n"), func(c *Config) { c.TrustedProxies = loopback.Allow }, 400, idClientAddr},
		{"a forwarding chain that is", get("/page", "X-Forwarded-For: 198.51.100.10\r\n"), func(c *Config) { c.TrustedProxies = loopback.Allow }, 200, 0},
		{"a header the site does not accept", get("/page", "Next-Action: abc\r\n"), func(c *Config) { c.DenyHeaders = []string{"next-action"} }, 400, idInternalHeader},
		{"the same header with underscores", get("/page", "Next_Action: abc\r\n"), func(c *Config) { c.DenyHeaders = []string{"Next-Action"} }, 400, idInternalHeader},
		{"that header on a site that did not ask", get("/page", "Next-Action: abc\r\n"), nil, 200, 0},
		// A slow client, not a refusal: it is counted, and nothing is recorded.
		{"a body that does not arrive within the read timeout", strings.Replace(post("a=1"), "Content-Length: 3", "Content-Length: 30", 1),
			func(c *Config) { c.ReadTimeout = 300 * time.Millisecond }, 408, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var seen refusals
			s := start(t, func(c *Config) {
				ruleSetOff(c)
				c.OnMatch = seen.record
				if tt.change != nil {
					tt.change(c)
				}
			})
			status, _ := s.raw(t, tt.request)
			if status != tt.want {
				t.Fatalf("status %d, want %d", status, tt.want)
			}
			if got := len(s.up.requests()) > 0; got != (tt.want == 200) {
				t.Fatalf("reached the application: %v", got)
			}
			if seen.last() != tt.id {
				t.Fatalf("recorded id %d, want %d", seen.last(), tt.id)
			}
			if slow := s.edge.SlowBodies(); slow != map[bool]int64{true: 1}[tt.want == http.StatusRequestTimeout] {
				t.Fatalf("%d slow bodies counted", slow)
			}
		})
	}
	// The existing refusal table owns policy wiring. CrowdSec requires an
	// external decision stream and verified client identity, not a SecLang profile.
	t.Run("CrowdSec verified visitors", func(t *testing.T) {
		cases := []struct {
			name, scope, value, forwarded string
			trusted, sync                 bool
			status, id                    int
		}{
			{"direct ban", "Range", "127.0.0.0/8", "", false, true, 403, idCrowdSecBan},
			{"clean direct visitor", "Ip", "192.0.2.9", "", false, true, 200, 0},
			{"untrusted claimed banned address", "Ip", "192.0.2.9", "192.0.2.9", false, true, 200, 0},
			{"untrusted claimed clean address", "Range", "127.0.0.0/8", "198.51.100.9", false, true, 403, idCrowdSecBan},
			{"trusted IPv4 visitor", "Ip", "192.0.2.9", "192.0.2.9", true, true, 403, idCrowdSecBan},
			{"trusted IPv6 visitor", "Range", "2001:db8::/64", "2001:db8::9", true, true, 403, idCrowdSecBan},
			{"trusted clean visitor", "Ip", "192.0.2.9", "198.51.100.9", true, true, 200, 0},
			{"ban covers peer but not visitor", "Range", "127.0.0.0/8", "198.51.100.9", true, true, 200, 0},
			{"spoofed left entry", "Ip", "192.0.2.9", "198.51.100.9, 192.0.2.9", true, true, 403, idCrowdSecBan},
			{"missing snapshot", "Ip", "192.0.2.9", "", false, false, 503, idCrowdSecUnavailable},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					fmt.Fprintf(w, `{"new":[{"id":1,"scope":%q,"value":%q,"type":"ban","duration":"1h"}],"deleted":[]}`, tc.scope, tc.value)
				}))
				defer api.Close()
				cs, err := crowdsec.New(crowdsec.Config{URL: api.URL, APIKey: "proxy-test-bouncer-key"})
				if err != nil {
					t.Fatal(err)
				}
				defer cs.Close()
				if tc.sync {
					if err := cs.Sync(context.Background()); err != nil {
						t.Fatal(err)
					}
				}
				var seen refusals
				s := start(t, func(c *Config) {
					ruleSetOff(c)
					c.CrowdSec = cs
					c.OnMatch = seen.record
					if tc.trusted {
						c.TrustedProxies = loopback.Allow
					}
				})
				headers := []string{}
				if tc.forwarded != "" {
					headers = append(headers, "X-Forwarded-For: "+tc.forwarded+"\r\n")
				}
				status, _ := s.raw(t, get("/page", headers...))
				if status != tc.status || seen.last() != tc.id || (len(s.up.requests()) > 0) != (tc.status == 200) {
					t.Fatalf("status %d id %d reached origin %v", status, seen.last(), len(s.up.requests()) > 0)
				}
			})
		}
	})
	// A CrowdSec refusal is for one visitor; whether the connection survives it is HTTP, not a SecLang profile.
	t.Run("CrowdSec refusals close only the refused client's own connection", func(t *testing.T) {
		get := func(visitor string) string {
			return "GET /page HTTP/1.1\r\n" + preamble + "X-Forwarded-For: " + visitor + "\r\n\r\n"
		}
		for _, tc := range []struct {
			name, banned string
			trusted      bool
			requests     []string
			want         []int
		}{
			{"a banned direct client loses its connection", "127.0.0.0/8", false, []string{get("192.0.2.9"), get("192.0.2.9")}, []int{403}},
			{"a trusted proxy relaying a banned visitor keeps its connection", "192.0.2.9/32", true,
				[]string{get("192.0.2.9"), get("198.51.100.9")}, []int{403, 200}},
		} {
			t.Run(tc.name, func(t *testing.T) {
				api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					fmt.Fprintf(w, `{"new":[{"id":1,"scope":"Range","value":%q,"type":"ban","duration":"1h"}],"deleted":[]}`, tc.banned)
				}))
				defer api.Close()
				cs, err := crowdsec.New(crowdsec.Config{URL: api.URL, APIKey: "proxy-test-bouncer-key"})
				if err != nil {
					t.Fatal(err)
				}
				defer cs.Close()
				if err := cs.Sync(context.Background()); err != nil {
					t.Fatal(err)
				}
				s := start(t, func(c *Config) {
					ruleSetOff(c)
					c.CrowdSec = cs
					if tc.trusted {
						c.TrustedProxies = loopback.Allow
					}
				})
				if statuses := onOneConnection(t, s, tc.requests); !equalInts(statuses, tc.want) {
					t.Fatalf("statuses on one connection %v, want %v", statuses, tc.want)
				}
			})
		}
	})
	// A shield refusal is for one visitor; whether the connection survives it is HTTP, not a SecLang profile.
	t.Run("shield refusals close only the refused client's own connection", func(t *testing.T) {
		get := func(visitor string) string {
			return "GET /page HTTP/1.1\r\n" + preamble + "X-Forwarded-For: " + visitor + "\r\n\r\n"
		}
		// A body that is still arriving: the refusal must not wait for it.
		post := "POST /page HTTP/1.1\r\n" + preamble + "X-Forwarded-For: 192.0.2.9\r\nContent-Type: text/plain\r\nContent-Length: 1000\r\n\r\n0123456789"
		// A wrong answer to the challenge counts as a refusal, and ends like one.
		wrong := "GET " + shield.VerifyPath + "?t=x&n=1 HTTP/1.1\r\n" + preamble + "X-Forwarded-For: 192.0.2.9\r\n\r\n"
		for _, tc := range []struct {
			name     string
			trusted  bool
			requests []string
			want     []int
		}{
			{"a trusted proxy relaying a refused visitor keeps its connection", true, []string{get("192.0.2.9"), get("192.0.2.9"), get("198.51.100.9")}, []int{200, 429, 200}},
			{"a refused direct client loses its own", false, []string{get("192.0.2.9"), get("192.0.2.9"), get("198.51.100.9")}, []int{200, 429}},
			{"a refused relayed request whose body is still coming is answered at once", true, []string{get("192.0.2.9"), post}, []int{200, 429}},
			{"a direct client's wrong answer to the challenge loses its connection", false, []string{wrong, get("198.51.100.9")}, []int{403}},
			{"a trusted proxy relaying a wrong answer keeps its connection", true, []string{wrong, get("198.51.100.9")}, []int{403, 200}},
		} {
			t.Run(tc.name, func(t *testing.T) {
				var trusted []netip.Prefix
				if tc.trusted {
					trusted = loopback.Allow
				}
				sh, err := shield.New(shield.Config{RequestRate: 0.1, RequestBurst: 1, Trusted: trusted})
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(sh.Close)
				s := start(t, func(c *Config) { ruleSetOff(c); c.Shield = sh; c.TrustedProxies = trusted })
				if statuses := onOneConnection(t, s, tc.requests); !equalInts(statuses, tc.want) {
					t.Fatalf("statuses on one connection %v, want %v", statuses, tc.want)
				}
			})
		}
	})
	// The 502 is recorded either way; only one the application caused may tell the shield's detector it is failing.
	t.Run("shield counts only the application's own failures as its errors", func(t *testing.T) {
		for _, tc := range []struct {
			name, path string
			wait       time.Duration // how long the client waited before it went away
			errRatio   float64
		}{
			{"the client went away", "/hang", 0, -1}, // nothing the application answered or failed
			// An application that queues what it cannot serve shows it only so: its clients give up first.
			{"the client went away after waiting far longer than the application usually takes", "/hang", 5 * time.Second, 1},
			{"the application dropped the connection", "/drop", 0, 1},
		} {
			t.Run(tc.name, func(t *testing.T) {
				arrived := make(chan struct{})
				up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					close(arrived)
					if r.URL.Path == "/drop" {
						panic(http.ErrAbortHandler)
					}
					<-r.Context().Done()
				}))
				t.Cleanup(up.Close)
				var clock atomic.Int64
				clock.Store(time.Unix(1_700_000_000, 0).UnixNano())
				sh, err := shield.New(shield.Config{Now: func() time.Time { return time.Unix(0, clock.Load()) }})
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(sh.Close)
				var seen refusals
				cfg := Config{Upstream: mustURL(up.URL), Origin: loopback, CRS: crs.DefaultSettings(), Shield: sh, OnMatch: seen.record}
				ruleSetOff(&cfg)
				e, err := New(cfg)
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { e.Close() })
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				go func() {
					<-arrived
					if tc.path == "/hang" {
						clock.Add(int64(tc.wait))
						cancel()
					}
				}()
				rec := httptest.NewRecorder()
				e.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, tc.path, nil).WithContext(ctx))
				if rec.Code != http.StatusBadGateway || seen.last() != idUpstreamFailed {
					t.Fatalf("status %d, recorded id %d", rec.Code, seen.last())
				}
				clock.Add(int64(2 * time.Second))
				sh.Tick()
				if got := sh.Snapshot().ErrRatio; got != tc.errRatio {
					t.Fatalf("the detector's error ratio is %v, want %v", got, tc.errRatio)
				}
			})
		}
	})
}

func TestFrameworkControlHeadersNeverReachTheApplication(t *testing.T) {
	names := []struct {
		name     string
		override bool
	}{
		{"X-Middleware-Subrequest", false}, {"X_Middleware_Subrequest", false}, {"X-Middleware-Prefetch", false},
		{"X-Invoke-Path", false}, {"X-Invoke-Status", false}, {"X-Matched-Path", false}, {"X-Now-Route-Matches", false},
		{"X-HTTP-Method-Override", true}, {"X_HTTP_Method_Override", true}, {"X-Method-Override", true},
		{"X-HTTP-Method", true}, {"X_HTTP_Method", true}, {"X-Nextjs-Data", false},
	}
	for _, tc := range names {
		t.Run(tc.name, func(t *testing.T) {
			var seen matches
			s := start(t, func(c *Config) { ruleSetOff(c); c.OnMatch = seen.record })
			status, _ := s.raw(t, get("/page", tc.name+": middleware:middleware:middleware\r\n", "X-Application-Token: keep\r\n"))
			got := s.up.requests()
			if tc.override {
				if status != 400 || len(got) != 0 || len(seen.all()) != 1 || seen.all()[0].RuleID != idMethodOverride {
					t.Fatalf("override refusal: status %d, origin %d, findings %+v", status, len(got), seen.all())
				}
				return
			}
			if status != 200 || len(got) != 1 {
				t.Fatalf("status %d, %d requests", status, len(got))
			}
			dashed := strings.ReplaceAll(strings.ToLower(tc.name), "_", "-")
			for header := range got[0].Header {
				if strings.ReplaceAll(strings.ToLower(header), "_", "-") == dashed {
					t.Fatalf("%s reached the application", header)
				}
			}
			if got[0].Header.Get("X-Application-Token") == "" {
				t.Fatal("an ordinary header was dropped with them")
			}
		})
	}
}

func TestAHeaderNamedInConnectionCannotRemoveTheProxysOwn(t *testing.T) {
	s := start(t, ruleSetOff)
	status, _ := s.raw(t, get("/page", "Connection: close, X-Forwarded-For, X-Real-IP, X-Forwarded-Proto\r\n"))
	got := s.up.requests()
	if status != 200 || len(got) != 1 {
		t.Fatalf("status %d, %d requests", status, len(got))
	}
	for _, h := range []string{"X-Forwarded-For", "X-Real-Ip", "X-Forwarded-Proto"} {
		if got[0].Header.Get(h) == "" {
			t.Errorf("%s was removed because the client listed it in Connection", h)
		}
	}
}

// The classic smuggling shapes. The proxy re-serialises every request it forwards and the engine inspects each one it
// parses, so whatever is hidden in a body either stays inert body text or is parsed as a request of its own and
// inspected like any other. What must never happen is an attack reaching the application as a request without having
// been looked at. Here the hidden request is an attack the rule set blocks, in blocking mode.
func TestSmuggledAttacksAreStillInspected(t *testing.T) {
	hidden := "GET /x?q=%3Cscript%3Ealert(1)%3C/script%3E HTTP/1.1\r\nHost: shop.example.test\r\nUser-Agent: Mozilla/5.0 Chrome/120\r\nAccept: text/html\r\n\r\n"
	post := func(headers string, body string) string {
		return "POST /submit HTTP/1.1\r\n" + preamble + "Content-Type: text/plain\r\n" + headers + "\r\n" + body
	}
	chunkedHidden := "0\r\n\r\n" + hidden
	tests := map[string]string{
		"CL.TE":                     post("Content-Length: 4\r\nTransfer-Encoding: chunked\r\n", "5c\r\n"+hidden+"\r\n0\r\n\r\n"),
		"TE.CL":                     post("Content-Length: 4\r\nTransfer-Encoding: chunked\r\n", chunkedHidden),
		"TE.TE obfuscated":          post("Content-Length: 4\r\nTransfer-Encoding: xchunked\r\n", chunkedHidden),
		"TE with a space before :":  post("Content-Length: 4\r\nTransfer-Encoding : chunked\r\n", chunkedHidden),
		"TE tab after :":            post("Content-Length: 4\r\nTransfer-Encoding:\tchunked\r\n", chunkedHidden),
		"two Content-Length":        post("Content-Length: 4\r\nContent-Length: 60\r\n", "a=1&"+hidden),
		"Content-Length with plus":  post("Content-Length: +4\r\n", "a=1&"+hidden),
		"CL.0":                      post("Content-Length: "+strconv.Itoa(len(hidden))+"\r\n", hidden),
		"bare LF in a chunk header": post("Transfer-Encoding: chunked\r\n", "0\n\r\n"+hidden),
	}
	for name, request := range tests {
		t.Run(name, func(t *testing.T) {
			s := start(t, nil) // the rule set on, blocking
			s.raw(t, request)
			for _, got := range s.up.requests() {
				uri := strings.ToLower(got.RequestURI)
				if strings.Contains(uri, "script") || strings.Contains(uri, "%3c") {
					t.Fatalf("an attack hidden in a body reached the application as a request: %q", got.RequestURI)
				}
			}
		})
	}
}

func TestARequestWithABodyDoesNotShareItsApplicationConnection(t *testing.T) {
	var opened, closed atomic.Int32
	app := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ok")) }))
	app.Config.ConnState = func(_ net.Conn, s http.ConnState) {
		switch s {
		case http.StateNew:
			opened.Add(1)
		case http.StateClosed:
			closed.Add(1)
		}
	}
	app.Start()
	defer app.Close()
	s := start(t, func(c *Config) {
		ruleSetOff(c)
		c.Upstream = mustURL(app.URL)
	})
	for i := 0; i < 3; i++ {
		s.raw(t, get("/page"))
	}
	if opened.Load() != 1 || closed.Load() != 0 {
		t.Fatalf("three requests without a body: %d connections opened, %d closed; want 1 and 0 (the control: the connection is reused)", opened.Load(), closed.Load())
	}
	for i := 0; i < 3; i++ {
		s.raw(t, post("a=1"))
	}
	deadline := time.Now().Add(3 * time.Second)
	for closed.Load() < 3 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if closed.Load() != 3 {
		t.Fatalf("three requests with a body closed %d application connections, want 3 (each one's own, so nothing is left on a reused connection)", closed.Load())
	}
}

func TestResponsePolicy(t *testing.T) {
	tests := []struct {
		name   string
		path   string
		policy ResponsePolicy
		check  func(t *testing.T, h http.Header)
	}{
		{"nosniff is added", "/page", ResponsePolicy{}, func(t *testing.T, h http.Header) {
			if h.Get("X-Content-Type-Options") != "nosniff" {
				t.Fatalf("X-Content-Type-Options = %q", h.Get("X-Content-Type-Options"))
			}
		}},
		{"banners are removed", "/banner", ResponsePolicy{}, func(t *testing.T, h http.Header) {
			if h.Get("X-Powered-By") != "" || h.Get("Server") != "" {
				t.Fatalf("banners remain: %q %q", h.Get("X-Powered-By"), h.Get("Server"))
			}
		}},
		{"banners are kept when asked", "/banner", ResponsePolicy{KeepBanners: true}, func(t *testing.T, h http.Header) {
			if h.Get("X-Powered-By") == "" {
				t.Fatal("the banner was removed although asked to keep it")
			}
		}},
		{"a cookie makes a response private", "/set-cookie", ResponsePolicy{}, func(t *testing.T, h http.Header) {
			if h.Get("Cache-Control") != "private, no-store" {
				t.Fatalf("Cache-Control = %q", h.Get("Cache-Control"))
			}
		}},
		{"a cookie leaves caching alone when asked", "/set-cookie", ResponsePolicy{KeepCaching: true}, func(t *testing.T, h http.Header) {
			if h.Get("Cache-Control") != "" {
				t.Fatalf("Cache-Control = %q", h.Get("Cache-Control"))
			}
		}},
		{"HTML at a stylesheet's address is not cached", "/account/profile.css", ResponsePolicy{}, func(t *testing.T, h http.Header) {
			if h.Get("Cache-Control") != "private, no-store" {
				t.Fatalf("Cache-Control = %q", h.Get("Cache-Control"))
			}
		}},
		{"an ordinary page is left to the application", "/page", ResponsePolicy{}, func(t *testing.T, h http.Header) {
			if h.Get("Cache-Control") != "" {
				t.Fatalf("Cache-Control = %q on an ordinary page", h.Get("Cache-Control"))
			}
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := start(t, func(c *Config) { ruleSetOff(c); c.Responses = tt.policy })
			_, reply := s.raw(t, get(tt.path))
			resp, err := http.ReadResponse(bufio.NewReader(strings.NewReader(reply)), nil)
			if err != nil {
				t.Fatal(err)
			}
			tt.check(t, resp.Header)
		})
	}
}

func multipartBody(parts ...string) string {
	var b strings.Builder
	for _, p := range parts {
		b.WriteString("--XX\r\n" + p + "\r\n")
	}
	b.WriteString("--XX--\r\n")
	return b.String()
}

func filePart(name, content string) string {
	return "Content-Disposition: form-data; name=\"f\"; filename=\"" + name + "\"\r\nContent-Type: application/octet-stream\r\n\r\n" + content
}

func uploadRequest(body string) string {
	return "POST /upload HTTP/1.1\r\n" + preamble + "Content-Type: multipart/form-data; boundary=XX\r\nContent-Length: " + strconv.Itoa(len(body)) +
		"\r\nConnection: close\r\n\r\n" + body
}

func TestUploadPolicy(t *testing.T) {
	jpeg := "\xff\xd8\xff\xe0\x00\x10JFIF\x00 an ordinary picture \xff\xd9"
	shell := "GIF89a<?php system($_GET['c']); ?>"
	tests := []struct {
		name    string
		body    string
		policy  UploadPolicy
		refused int // the id, or 0
	}{
		{"a picture", multipartBody(filePart("photo.jpg", jpeg)), UploadPolicy{}, 0},
		{"a document with a long name", multipartBody(filePart("Quarterly report - final (2).pdf", "%PDF-1.7 text")), UploadPolicy{}, 0},
		{"a text field mentioning php", multipartBody("Content-Disposition: form-data; name=\"comment\"\r\n\r\nuse <?php echo 1; ?> in your template"), UploadPolicy{}, 0},
		{"an XML file", multipartBody(filePart("data.xml", "<?xml version=\"1.0\"?><a/>")), UploadPolicy{}, 0},
		{"a script name", multipartBody(filePart("shell.php", "x")), UploadPolicy{}, idUploadName},
		{"a script name in capitals", multipartBody(filePart("SHELL.PHP", "x")), UploadPolicy{}, idUploadName},
		{"a double extension", multipartBody(filePart("shell.php.jpg", jpeg)), UploadPolicy{}, idUploadName},
		{"a trailing dot", multipartBody(filePart("shell.php.", "x")), UploadPolicy{}, idUploadName},
		{"a trailing space", multipartBody(filePart("shell.php ", "x")), UploadPolicy{}, idUploadName},
		{"a semicolon trick", multipartBody(filePart("shell.asp;.jpg", "x")), UploadPolicy{}, idUploadName},
		{"phtml", multipartBody(filePart("a.phtml", "x")), UploadPolicy{}, idUploadName},
		{"php5", multipartBody(filePart("a.php5", "x")), UploadPolicy{}, idUploadName},
		{"jsp", multipartBody(filePart("a.jsp", "x")), UploadPolicy{}, idUploadName},
		{"a NUL in the name, percent-encoded", multipartBody(filePart("shell.php%00.jpg", jpeg)), UploadPolicy{}, idUploadName},
		{"an NTFS stream", multipartBody(filePart("shell.php::$DATA", "x")), UploadPolicy{}, idUploadName},
		{"htaccess", multipartBody(filePart(".htaccess", "AddType application/x-httpd-php .jpg")), UploadPolicy{}, idUploadName},
		{"web.config", multipartBody(filePart("web.config", "<configuration/>")), UploadPolicy{}, idUploadName},
		{"a path in the name", multipartBody(filePart("..\\..\\shell.php", "x")), UploadPolicy{}, idUploadName},
		{"an RFC 5987 name", multipartBody("Content-Disposition: form-data; name=\"f\"; filename*=UTF-8''%73hell.php\r\n\r\nx"), UploadPolicy{}, idUploadName},
		{"an unquoted name", multipartBody("Content-Disposition: form-data; name=f; filename=shell.php\r\n\r\nx"), UploadPolicy{}, idUploadName},
		{"a picture with a script in it", multipartBody(filePart("photo.jpg", shell)), UploadPolicy{}, idUploadScript},
		{"a script far into a large file", multipartBody(filePart("photo.jpg", jpeg+strings.Repeat("A", 50000)+"<?= `id` ?>")), UploadPolicy{}, idUploadScript},
		{"an asp tag", multipartBody(filePart("photo.jpg", "x<%@ Page Language=\"C#\" %>")), UploadPolicy{}, idUploadScript},
		{"a script after a boundary in the middle of a line", multipartBody(filePart("photo.jpg", "GIF89a--XX\r\n\r\n<?php system($_GET['c']); ?>")), UploadPolicy{}, idUploadScript},
		{"script names allowed", multipartBody(filePart("shell.php", "x")), UploadPolicy{AllowExecutableNames: true}, 0},
		{"script content allowed", multipartBody(filePart("photo.jpg", shell)), UploadPolicy{AllowScriptContent: true}, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var seen refusals
			s := start(t, func(c *Config) {
				ruleSetOff(c)
				c.OnMatch = seen.record
				c.Uploads = tt.policy
				c.CRS.RequestBodyLimit = 1 << 20
			})
			status, _ := s.raw(t, uploadRequest(tt.body))
			if tt.refused == 0 {
				if status != 200 || len(s.up.requests()) != 1 {
					t.Fatalf("a harmless upload: status %d, %d requests", status, len(s.up.requests()))
				}
				return
			}
			if status != 403 || len(s.up.requests()) != 0 || seen.last() != tt.refused {
				t.Fatalf("status %d, %d requests, id %d; want 403, none, %d", status, len(s.up.requests()), seen.last(), tt.refused)
			}
		})
	}
}

func TestWordPressPolicy(t *testing.T) {
	on := func(c *Config) { ruleSetOff(c); c.WordPress = WordPressPolicy{Enabled: true, LoginPerMinute: 3} }
	tests := []struct {
		name, path string
		change     func(*Config)
		want       int
	}{
		{"a picture in uploads", "/wp-content/uploads/2026/10/photo.jpg", on, 200},
		{"a script in uploads", "/wp-content/uploads/2026/10/shell.php", on, 403},
		{"a script in uploads, in capitals", "/wp-content/UPLOADS/shell.PHP", on, 403},
		{"a script with a path after it", "/wp-content/uploads/shell.php/x.jpg", on, 403},
		{"phtml in a cache directory", "/wp-content/cache/a.phtml", on, 403},
		{"a script in a backup directory", "/wp-content/backup-db/x.php", on, 403},
		{"a plugin's own script", "/wp-content/plugins/contact-form/handler.php", on, 200},
		{"admin-ajax", "/wp-admin/admin-ajax.php", on, 200},
		{"an empty segment before uploads", "/wp-content//uploads/shell.php", on, 403},
		{"xmlrpc is off by default", "/xmlrpc.php", on, 403},
		{"xmlrpc with a trailing slash", "/xmlrpc.php/", on, 403},
		{"xmlrpc with path info", "/xmlrpc.php/x", on, 403},
		{"xmlrpc after an empty segment", "//xmlrpc.php", on, 400},
		{"xmlrpc with a path parameter", "/xmlrpc.php;v=1", func(c *Config) { on(c); c.Paths.AllowPathParams = true }, 403},
		{"xmlrpc allowed", "/xmlrpc.php", func(c *Config) { on(c); c.WordPress.AllowXMLRPC = true }, 200},
		{"xmlrpc of a site installed in a subdirectory", "/blog/xmlrpc.php", on, 403},
		{"a script whose name only ends like xmlrpc", "/blog/not-xmlrpc.php", on, 200},
		{"a script in uploads on a site not marked as WordPress", "/wp-content/uploads/shell.php", ruleSetOff, 200},
		{"a script in a backup plugin's folder of a site in a subdirectory", "/blog/wp-content/updraft/s.php", on, 403},
		{"a picture in uploads of a site in a subdirectory", "/blog/wp-content/uploads/a.jpg", on, 200},
		{"a script behind a second extension, which Apache may still run", "/blog/wp-content/uploads/x.php.jpg", on, 403},
		{"a directory only named like wp-content", "/blog/my-wp-content/uploads/s.php", on, 200},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := start(t, tt.change)
			if status, _ := s.raw(t, get(tt.path)); status != tt.want {
				t.Fatalf("status %d, want %d", status, tt.want)
			}
		})
	}

	t.Run("login attempts are limited per address", func(t *testing.T) {
		s := start(t, on)
		login := "POST /wp-login.php HTTP/1.1\r\n" + preamble + "Content-Type: application/x-www-form-urlencoded\r\nContent-Length: 11\r\nConnection: close\r\n\r\nlog=a&pwd=b"
		var statuses []int
		for i := 0; i < 5; i++ {
			status, _ := s.raw(t, login)
			statuses = append(statuses, status)
		}
		if want := []int{200, 200, 200, 429, 429}; !equalInts(statuses, want) {
			t.Fatalf("statuses %v, want %v", statuses, want)
		}
		if status, _ := s.raw(t, get("/wp-login.php")); status != 200 {
			t.Fatalf("reading the login page was limited: %d", status)
		}
	})
	t.Run("login spellings and addresses in one IPv6 /64 share the limit", func(t *testing.T) {
		s := start(t, func(c *Config) { on(c); c.TrustedProxies = []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")} })
		var statuses []int
		// The last is the login of a site installed in a subdirectory.
		for i, target := range []string{"/wp-login.php", "/wp-login.php/", "/wp-login.php/x", "/blog/wp-login.php"} {
			login := "POST " + target + " HTTP/1.1\r\n" + preamble + fmt.Sprintf("X-Forwarded-For: 2001:db8:1:2::%x\r\n", i+1) +
				"Content-Type: application/x-www-form-urlencoded\r\nContent-Length: 11\r\nConnection: close\r\n\r\nlog=a&pwd=b"
			status, _ := s.raw(t, login)
			statuses = append(statuses, status)
		}
		if want := []int{200, 200, 200, 429}; !equalInts(statuses, want) {
			t.Fatalf("statuses %v, want %v", statuses, want)
		}
	})
}

func TestAPIRatePolicy(t *testing.T) {
	on := func(c *Config) { ruleSetOff(c); c.APIRate = APIRatePolicy{PerMinute: 2} }
	// limit sets rate rules, as -limit writes them, after the other changes.
	limit := func(text string, changes ...func(*Config)) func(*Config) {
		rules, err := ParseRateRules(text)
		if err != nil {
			panic(err)
		}
		return func(c *Config) {
			ruleSetOff(c)
			for _, change := range changes {
				change(c)
			}
			c.Limits = rules
		}
	}
	tests := []struct {
		name, target string // a target may start with a method other than GET, as in "POST /api"
		change       func(*Config)
		want         []int
	}{
		{"API namespace", "/api/orders", on, []int{200, 200, 429}},
		{"case variant shares quota", "/API/ORDERS", on, []int{200, 200, 429}},
		{"namespace root", "/api", on, []int{200, 200, 429}},
		{"GraphQL namespace", "/graphql", on, []int{200, 200, 429}},
		{"query strings share quota", "/api?q=1", on, []int{200, 200, 429}},
		{"unrelated route", "/page", on, []int{200, 200, 200}},
		{"prefix requires segment boundary", "/apiary", on, []int{200, 200, 200}},
		{"explicit custom prefix", "/internal/orders", func(c *Config) { on(c); c.APIRate.Paths = []string{"/internal"} }, []int{200, 200, 429}},
		{"all routes", "/page", func(c *Config) { on(c); c.APIRate.Paths = []string{"/"} }, []int{200, 200, 429}},
		{"encoded slash allowed by site", "/api%2forders", func(c *Config) { on(c); c.Paths.AllowEncodedSlash = true }, []int{200, 200, 429}},
		{"encoded backslash allowed by site", "/api%5corders", func(c *Config) { on(c); c.Paths.AllowEncodedSlash = true }, []int{200, 200, 429}},
		{"matrix parameters allowed by site", "/api;v=1/orders", func(c *Config) { on(c); c.Paths.AllowPathParams = true }, []int{200, 200, 429}},
		{"nested matrix parameters", "/api;v=1/orders;v=2", func(c *Config) { on(c); c.Paths.AllowPathParams = true; c.APIRate.Paths = []string{"/api/orders"} }, []int{200, 200, 429}},
		{"repeated slash normalization", "/api//orders", func(c *Config) { on(c); c.APIRate.Paths = []string{"/api/orders"} }, []int{200, 200, 429}},
		{"disabled", "/api", ruleSetOff, []int{200, 200, 200}},
		{"a POST rule", "POST /api", limit("POST /api 2/m"), []int{200, 200, 429}},
		{"a POST rule leaves GET unlimited", "/api", limit("POST /api 2/m"), []int{200, 200, 200}},
		{"a GET rule also counts HEAD", "HEAD /api", limit("GET /api 2/m"), []int{200, 200, 429}},
		{"a HEAD rule leaves GET unlimited", "/api", limit("HEAD /api 2/m"), []int{200, 200, 200}},
		{"a rule for every method", "DELETE /x", limit("* / 2/m"), []int{200, 200, 429}},
		{"a rule's path counts what is under it", "/api/x", limit("/api 2/m"), []int{200, 200, 429}},
		{"a rule's path needs a segment boundary", "/apiary", limit("/api 2/m"), []int{200, 200, 200}},
		{"a rule's path ignores case", "/API/X", limit("/api 2/m"), []int{200, 200, 429}},
		{"a rule's path after matrix parameters", "/api;v=1/x", limit("/api/x 2/m", func(c *Config) { c.Paths.AllowPathParams = true }), []int{200, 200, 429}},
		{"a rule with several paths", "/b/c", limit("/a,/b 2/m"), []int{200, 200, 429}},
		{"a monitor rule never refuses", "/api", limit("/api 2/m monitor"), []int{200, 200, 200}},
		{"a rule counts its path behind index.php", "POST /index.php/login", limit("POST /login 2/m"), []int{200, 200, 429}},
		{"the API limit counts its path behind index.php", "/Index.php//api/orders", on, []int{200, 200, 429}},
		{"a rule counts its path behind another PHP script", "POST /App_Dev.PHP/login", limit("POST /login 2/m"), []int{200, 200, 429}},
		{"a front controller alone is not the path", "POST /index.php", limit("POST /login 2/m"), []int{200, 200, 200}},
		{"a script named like the path is not the path", "POST /login.php", limit("POST /login 2/m"), []int{200, 200, 200}},
		{"a rule counts its path with a format suffix", "POST /login.json", limit("POST /login 2/m"), []int{200, 200, 429}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s := start(t, tc.change)
			method, target, found := strings.Cut(tc.target, " ")
			request := get(tc.target)
			if found {
				request = strings.Replace(get(target, "Content-Length: 0\r\n"), "GET ", method+" ", 1)
			}
			accepted := 0
			for _, want := range tc.want {
				status, reply := s.raw(t, request)
				if status != want {
					t.Fatalf("status %d, want %d", status, want)
				}
				if want == 200 {
					accepted++
				} else if retry := retryAfter(reply); retry < 55 || retry > 66 || !strings.Contains(reply, "Cache-Control: no-store\r\n") {
					// Requests a few seconds apart, two a minute: the window clears 55 to 66 seconds after the first.
					t.Fatalf("rate refusal with Retry-After %d or without no-store", retry)
				}
			}
			if len(s.up.requests()) != accepted {
				t.Fatal("rate refusal reached the origin")
			}
		})
	}
	t.Run("prefixes share one budget and cannot be changed by the caller", func(t *testing.T) {
		prefixes := []string{"/api", "/graphql"}
		s := start(t, func(c *Config) { on(c); c.APIRate.Paths = prefixes })
		prefixes[0] = "/changed"
		for i, target := range []string{"/api/orders", "/graphql", "/api/users"} {
			want := 200
			if i == 2 {
				want = 429
			}
			if status, _ := s.raw(t, get(target)); status != want {
				t.Fatalf("status %d, want %d", status, want)
			}
		}
	})
	t.Run("untrusted forwarding headers cannot rotate identity", func(t *testing.T) {
		s := start(t, on)
		for i := 1; i <= 3; i++ {
			want := 200
			if i == 3 {
				want = 429
			}
			status, _ := s.raw(t, get("/api", fmt.Sprintf("X-Forwarded-For: 198.51.100.%d\r\nX_Forwarded_For: 203.0.113.%d\r\n", i, i)))
			if status != want {
				t.Fatalf("status %d, want %d", status, want)
			}
		}
	})
	t.Run("trusted chain selects the first untrusted hop", func(t *testing.T) {
		s := start(t, func(c *Config) { on(c); c.TrustedProxies = []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")} })
		for i := 1; i <= 3; i++ {
			want := 200
			if i == 3 {
				want = 429
			}
			status, _ := s.raw(t, get("/api", fmt.Sprintf("X-Forwarded-For: 203.0.113.%d, 198.51.100.1\r\n", i)))
			if status != want {
				t.Fatalf("status %d, want %d", status, want)
			}
		}
		if status, _ := s.raw(t, get("/api", "X-Forwarded-For: 198.51.100.2\r\n")); status != 200 {
			t.Fatalf("a separate verified client got %d", status)
		}
	})
	t.Run("addresses in one IPv6 /64 share a budget", func(t *testing.T) {
		s := start(t, func(c *Config) { on(c); c.TrustedProxies = []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")} })
		for i := 1; i <= 3; i++ {
			want := 200
			if i == 3 {
				want = 429
			}
			if status, _ := s.raw(t, get("/api", fmt.Sprintf("X-Forwarded-For: 2001:db8:1:2::%x\r\n", i))); status != want {
				t.Fatalf("status %d, want %d", status, want)
			}
		}
		if status, _ := s.raw(t, get("/api", "X-Forwarded-For: 2001:db8:1:3::1\r\n")); status != 200 {
			t.Fatalf("a client in another /64 got %d", status)
		}
	})
	t.Run("state saturation does not refuse new clients", func(t *testing.T) {
		s := start(t, func(c *Config) { on(c); c.TrustedProxies = []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")} })
		now := int64(time.Hour) // the start of a slot
		s.edge.now = func() int64 { return now }
		table := s.edge.rules[0].table
		table.mu.Lock()
		for i := 0; i < rateKeysPerRule; i++ {
			table.admit(netip.AddrFrom4([4]byte{10, byte(i >> 16), byte(i >> 8), byte(i)}), now)
		}
		table.mu.Unlock()
		for i, want := range []int{200, 200, 429} {
			status, reply := s.raw(t, get("/api", "X-Forwarded-For: 198.51.100.1\r\n"))
			if status != want || want == 429 && !strings.Contains(reply, "Retry-After: 66\r\n") {
				t.Fatalf("request %d from a client over its limit: %d, want %d\n%s", i+1, status, want, reply)
			}
		}
		if status, _ := s.raw(t, get("/api", "X-Forwarded-For: 198.51.100.2\r\n")); status != 200 {
			t.Fatalf("a new client was refused: %d", status)
		}
		if len(table.index) > rateKeysPerRule || len(s.up.requests()) != 3 {
			t.Fatalf("%d clients in the table, %d requests at the origin", len(table.index), len(s.up.requests()))
		}
	})
	t.Run("a refusal says exactly when to come back", func(t *testing.T) {
		s := start(t, on)
		start := int64(time.Hour) // the start of a slot
		now := start
		s.edge.now = func() int64 { return now }
		for _, step := range []struct {
			at     time.Duration
			status int
			retry  string
		}{
			{0, 200, ""}, {0, 200, ""}, {54 * time.Second, 429, "12"}, {65 * time.Second, 429, "1"}, {66 * time.Second, 200, ""},
			// A wait of 55.7 seconds is 56, never 55, which would send the client back while it is still refused.
			{66500 * time.Millisecond, 200, ""}, {76300 * time.Millisecond, 429, "56"}, {131300 * time.Millisecond, 429, "1"}, {132300 * time.Millisecond, 200, ""},
		} {
			now = start + int64(step.at)
			status, reply := s.raw(t, get("/api"))
			if status != step.status || step.retry != "" && (!strings.Contains(reply, "Retry-After: "+step.retry+"\r\n") || !strings.Contains(reply, "Cache-Control: no-store\r\n")) {
				t.Fatalf("at %v: %d, want %d with Retry-After %q\n%s", step.at, status, step.status, step.retry, reply)
			}
		}
		if len(s.up.requests()) != 5 {
			t.Fatalf("%d requests at the origin, want 5", len(s.up.requests()))
		}
	})
	t.Run("a refusal by one rule uses up no other rule's budget", func(t *testing.T) {
		seen := &refusals{}
		s := start(t, func(c *Config) {
			ruleSetOff(c)
			c.OnMatch = seen.record
			c.WordPress = WordPressPolicy{Enabled: true, LoginPerMinute: 1}
			c.APIRate = APIRatePolicy{PerMinute: 3, Paths: []string{"/"}}
		})
		start := int64(time.Hour) // the start of a slot
		now := start
		s.edge.now = func() int64 { return now }
		login := "POST /wp-login.php HTTP/1.1\r\n" + preamble + "Content-Type: application/x-www-form-urlencoded\r\nContent-Length: 11\r\nConnection: close\r\n\r\nlog=a&pwd=b"
		page := get("/page")
		var statuses []int
		for _, step := range []struct {
			at      time.Duration // each refusal is a second or more after the last, so each is logged
			request string
		}{
			// The second login is refused by the login rule and not counted by the API rule, which has room for two more.
			{1 * time.Second, login}, {2 * time.Second, login}, {3 * time.Second, page}, {4 * time.Second, page}, {5 * time.Second, page}, {6 * time.Second, login},
			// Two minutes on, the API rule is full and refuses a login the login rule has room for. Had the login rule
			// counted it, it would still be in the login window at 186s and refuse the login the API rule lets through.
			{120 * time.Second, page}, {121 * time.Second, page}, {122 * time.Second, page}, {150 * time.Second, login}, {186 * time.Second, login},
		} {
			now = start + int64(step.at)
			status, _ := s.raw(t, step.request)
			statuses = append(statuses, status)
		}
		if want := []int{200, 429, 200, 200, 429, 429, 200, 200, 200, 429, 200}; !equalInts(statuses, want) || len(s.up.requests()) != 7 {
			t.Fatalf("statuses %v, want %v; %d at the origin", statuses, want, len(s.up.requests()))
		}
		if want := []int{idRateLimited, idAPIRateLimited, idRateLimited, idAPIRateLimited}; !equalInts(seen.ids, want) {
			t.Fatalf("logged %v, want %v", seen.ids, want)
		}
	})
	t.Run("refusals are logged at most once a second per rule", func(t *testing.T) {
		seen := &matches{}
		s := start(t, func(c *Config) { on(c); c.OnMatch = seen.record })
		now := int64(time.Hour)
		s.edge.now = func() int64 { return now }
		for i, want := range []int{200, 200, 429, 429, 429, 429, 429} {
			if status, _ := s.raw(t, get("/api")); status != want {
				t.Fatalf("request %d: %d, want %d", i+1, status, want)
			}
		}
		now += int64(time.Second)
		if status, _ := s.raw(t, get("/api")); status != 429 {
			t.Fatalf("a refusal a second later: %d", status)
		}
		var logged []string
		for _, m := range seen.all() {
			logged = append(logged, fmt.Sprint(m.RuleID, " ", m.Message))
		}
		want := []string{"5000042 too many API requests from one address", "5000042 too many API requests from one address (4 more refusals not logged)",
			"5000042 too many API requests from one address"}
		if strings.Join(logged, "\n") != strings.Join(want, "\n") {
			t.Fatalf("logged %q, want %q", logged, want)
		}
	})
	t.Run("refusals not logged are counted in a line that names no client, and are not lost at close", func(t *testing.T) {
		for _, tc := range []struct {
			name, rule string
			refused    int
			id         int
			more       string
			total      int64 // what RateTotals counts as refused
		}{
			{"an enforcing rule", "/ 1/m", 429, idLimitRule, "more refusals not logged", 9},
			{"a monitor rule", "/ 1/m monitor", 200, idLimitMonitor, "more not logged", 0},
		} {
			t.Run(tc.name, func(t *testing.T) {
				seen := &matches{}
				rules, err := ParseRateRules(tc.rule)
				if err != nil {
					t.Fatal(err)
				}
				s := start(t, func(c *Config) {
					ruleSetOff(c)
					c.Limits, c.OnMatch, c.LogDetails = rules, seen.record, true
					c.TrustedProxies = []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}
				})
				now := int64(time.Hour)
				s.edge.now = func() int64 { return now }
				from := func(client string, n int) {
					for i := range n {
						want := tc.refused
						if i == 0 {
							want = 200
						}
						if status, _ := s.raw(t, get("/page", "X-Forwarded-For: "+client+"\r\n")); status != want {
							t.Fatalf("request %d from %s: %d, want %d", i+1, client, status, want)
						}
					}
				}
				from("192.0.2.66", 6) // one let through, one logged, four not
				// The count does not wait for the rule's next line: it is logged within a second or so.
				for deadline := time.Now().Add(5 * time.Second); len(seen.all()) < 2; time.Sleep(10 * time.Millisecond) {
					if time.Now().After(deadline) {
						t.Fatalf("the count was not logged on its own: %+v", seen.all())
					}
				}
				now += int64(time.Second)
				from("192.0.2.77", 5) // one let through, one logged after the four are, three not
				if err := s.edge.Close(); err != nil {
					t.Fatal(err)
				}
				if got := s.edge.RateTotals(); got != (RateTotals{Refused: tc.total}) {
					t.Fatalf("totals %+v, want %d refused", got, tc.total)
				}
				var logged []string
				for _, m := range seen.all() {
					if m.RuleID != tc.id {
						t.Fatalf("logged rule %d", m.RuleID)
					}
					client, _, _ := strings.Cut(m.ClientIP, ":")
					_, count, _ := strings.Cut(m.Message, " (")
					logged = append(logged, client+" "+count)
				}
				// The counts name no client, though details are on, and they add up to every refusal but those logged.
				want := []string{"192.0.2.66 ", " 4 " + tc.more + ")", "192.0.2.77 ", " 3 " + tc.more + ")"}
				if strings.Join(logged, "|") != strings.Join(want, "|") {
					t.Fatalf("logged %q, want %q", logged, want)
				}
			})
		}
	})
	t.Run("rate rules log their own text, and a monitor rule reports only what it would refuse", func(t *testing.T) {
		seen := &matches{}
		rules, err := ParseRateRules("POST /login 1/m; / 2/m monitor")
		if err != nil {
			t.Fatal(err)
		}
		s := start(t, func(c *Config) { ruleSetOff(c); c.OnMatch = seen.record; c.Limits = rules })
		rules[0].Count, rules[0].Paths[0] = 100, "/elsewhere" // too late to change anything
		now := int64(time.Hour)
		s.edge.now = func() int64 { return now }
		login := "POST /login HTTP/1.1\r\n" + preamble + "Content-Length: 0\r\nConnection: close\r\n\r\n"
		var statuses []int
		// The refused login is not counted by the monitor rule either, which has room for the first /page. Nor does it
		// count what it would refuse: two hours on, the /page it would refuse at 30s is not in its window once the two
		// before it leave at 66s, so the /page at 68s is one it would let through, and only the one at 30s is reported.
		page := get("/page")
		for _, step := range []struct {
			after   time.Duration
			request string
		}{{0, login}, {0, login}, {0, page}, {0, page}, {0, page}, {time.Second, page},
			{2 * time.Hour, page}, {0, page}, {30 * time.Second, page}, {36 * time.Second, page}, {2 * time.Second, page}} {
			now += int64(step.after)
			status, _ := s.raw(t, step.request)
			statuses = append(statuses, status)
		}
		if want := []int{200, 429, 200, 200, 200, 200, 200, 200, 200, 200, 200}; !equalInts(statuses, want) || len(s.up.requests()) != 10 {
			t.Fatalf("statuses %v, want %v; %d at the origin", statuses, want, len(s.up.requests()))
		}
		var logged []string
		for _, m := range seen.all() {
			logged = append(logged, fmt.Sprint(m.RuleID, " ", m.Disruptive, " ", m.Message))
		}
		want := []string{"5000047 true rate limit exceeded: POST /login 1/1m", "5000048 false rate limit would be exceeded: / 2/1m",
			"5000048 false rate limit would be exceeded: / 2/1m (1 more not logged)", "5000048 false rate limit would be exceeded: / 2/1m",
			"5000048 false rate limit would be exceeded: / 2/1m"}
		if strings.Join(logged, "\n") != strings.Join(want, "\n") {
			t.Fatalf("logged %q, want %q", logged, want)
		}
	})
	t.Run("trusted ranges cannot be changed by the caller after construction", func(t *testing.T) {
		trusted := []netip.Prefix{netip.MustParsePrefix("192.0.2.1/32")}
		s := start(t, func(c *Config) { on(c); c.TrustedProxies = trusted })
		trusted[0] = netip.MustParsePrefix("127.0.0.0/8")
		for i := 1; i <= 3; i++ {
			want := 200
			if i == 3 {
				want = 429
			}
			if status, _ := s.raw(t, get("/api", fmt.Sprintf("X-Forwarded-For: 198.51.100.%d\r\n", i))); status != want {
				t.Fatalf("status %d, want %d", status, want)
			}
		}
	})
	t.Run("invalid configuration refuses construction", func(t *testing.T) {
		for _, p := range []APIRatePolicy{{PerMinute: -1}, {PerMinute: 100001}, {PerMinute: 1, Paths: []string{"api"}}, {PerMinute: 1, Paths: []string{"/api/"}}, {PerMinute: 1, Paths: []string{"/api?x=1"}}, {PerMinute: 1, Paths: []string{"/api%2forders"}}, {PerMinute: 1, Paths: []string{"/api/../"}}, {PerMinute: 1, Paths: []string{"/api;v=1"}}, {PerMinute: 1, Paths: make([]string, 101)}} {
			if _, err := p.normalized(); err == nil {
				t.Fatalf("accepted %+v", p)
			}
		}
		// Rate rules built without ParseRateRules are checked as strictly.
		ok := RateRule{Paths: []string{"/x"}, Count: 1, Window: time.Minute}
		for _, tc := range []struct {
			name  string
			rules func() []RateRule
		}{
			{"no path", func() []RateRule { r := ok; r.Paths = nil; return []RateRule{r} }},
			{"a path without a slash", func() []RateRule { r := ok; r.Paths = []string{"x"}; return []RateRule{r} }},
			{"a path with a comma", func() []RateRule { r := ok; r.Paths = []string{"/a,b"}; return []RateRule{r} }},
			{"a misspelt method", func() []RateRule { r := ok; r.Methods = []string{"PSOT"}; return []RateRule{r} }},
			{"a count of 0", func() []RateRule { r := ok; r.Count = 0; return []RateRule{r} }},
			{"a window of two hours", func() []RateRule { r := ok; r.Window = 2 * time.Hour; return []RateRule{r} }},
			{"a window that is not whole seconds", func() []RateRule { r := ok; r.Window = 1500 * time.Millisecond; return []RateRule{r} }},
			{"a repeated rule", func() []RateRule { return []RateRule{ok, ok} }},
			{"33 rules", func() []RateRule {
				rules := make([]RateRule, 33)
				for i := range rules {
					rules[i] = ok
					rules[i].Paths = []string{fmt.Sprintf("/r%d", i)}
				}
				return rules
			}},
		} {
			t.Run(tc.name, func(t *testing.T) {
				if _, err := New(Config{Upstream: mustURL("http://origin.example"), CRS: crs.Settings{Mode: crs.ModeOff}, Limits: tc.rules()}); err == nil || !strings.HasPrefix(err.Error(), "rate limit ") {
					t.Fatalf("New: %v", err)
				}
			})
		}
	})
}

// allowAt is one request by key at now, checked and, when admitted, counted.
func allowAt(l *windowLimiter, key netip.Addr, now int64) (ok bool, wait int64, evicted bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if ok, wait = l.check(key, now); ok {
		evicted = l.admit(key, now)
	}
	return ok, wait, evicted
}

// retryAfter is a reply's Retry-After in seconds, or -1 without one.
func retryAfter(reply string) int {
	_, value, found := strings.Cut(reply, "\r\nRetry-After: ")
	value, _, _ = strings.Cut(value, "\r\n")
	if seconds, err := strconv.Atoi(value); found && err == nil {
		return seconds
	}
	return -1
}

func TestSlidingRateBudget(t *testing.T) {
	a, b, c := netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.2"), netip.MustParseAddr("192.0.2.3")
	sec := int64(time.Second)
	t.Run("no window holds more than the limit, and a refusal is at most a slot late", func(t *testing.T) {
		for _, tc := range []struct {
			name   string
			limit  int
			window time.Duration
			seed   uint64
		}{
			{"5 a minute", 5, time.Minute, 1},
			{"1 a second", 1, time.Second, 2},
			{"100 an hour", 100, time.Hour, 3},
			{"7 in 10 seconds", 7, 10 * time.Second, 4},
		} {
			t.Run(tc.name, func(t *testing.T) {
				rng := rand.New(rand.NewPCG(tc.seed, 0))
				l := newWindowLimiter(tc.limit, tc.window, 16)
				window, slot := int64(tc.window), int64(tc.window)/windowSlots
				admitted, refused := map[netip.Addr][]int64{}, map[netip.Addr][]int64{}
				now := int64(0)
				for i := 0; i < 20000; i++ {
					// Three clients, each sending about twice its limit.
					now += rng.Int64N(window/int64(3*tc.limit) + 1)
					key := []netip.Addr{a, b, c}[rng.IntN(3)]
					if ok, _, _ := allowAt(l, key, now); ok {
						admitted[key] = append(admitted[key], now)
					} else {
						refused[key] = append(refused[key], now)
					}
				}
				within := func(times []int64, from, to int64) (n int) {
					for _, at := range times {
						if at >= from && at <= to {
							n++
						}
					}
					return n
				}
				for key, times := range admitted {
					for _, at := range times {
						if n := within(times, at, at+window); n > tc.limit {
							t.Fatalf("%s: %d admitted in the window from %d", key, n, at)
						}
					}
					for _, at := range refused[key] {
						if n := within(times, at-window-slot, at); n < tc.limit {
							t.Fatalf("%s: refused at %d with only %d admitted in the window and a slot before", key, at, n)
						}
					}
				}
				if len(refused) == 0 {
					t.Fatal("the trace never reached the limit")
				}
			})
		}
	})
	t.Run("Retry-After is exact", func(t *testing.T) {
		for _, tc := range []struct {
			name     string
			limit    int
			window   time.Duration
			admitted []int64 // nanoseconds
			at       int64
			wait     int64
		}{
			{"a burst at the start of a slot", 3, time.Minute, []int64{0, 0, 0}, 10 * sec, 56 * sec},
			{"spread over the window", 3, time.Minute, []int64{0, 20 * sec, 40 * sec}, 50 * sec, 16 * sec},
			{"the oldest slot is enough", 2, time.Minute, []int64{5 * sec, 59 * sec}, 61 * sec, 5 * sec},
			{"a short window", 1, 10 * time.Second, []int64{sec / 2}, 3200 * int64(time.Millisecond), 7800 * int64(time.Millisecond)},
			// A request that read the clock just before another one took the lock and was admitted into the next slot.
			{"a reading from before the newest slot", 3, time.Minute, []int64{30 * sec, 30 * sec, 30 * sec}, 30*sec - 1, 66*sec + 1},
		} {
			t.Run(tc.name, func(t *testing.T) {
				l := newWindowLimiter(tc.limit, tc.window, 4)
				for _, at := range tc.admitted {
					if ok, _, _ := allowAt(l, a, at); !ok {
						t.Fatalf("refused at %d", at)
					}
				}
				ok, wait, _ := allowAt(l, a, tc.at)
				if ok || wait != tc.wait {
					t.Fatalf("admitted %v, wait %v; want a refusal with %v", ok, time.Duration(wait), time.Duration(tc.wait))
				}
				for _, probe := range []struct {
					at int64
					ok bool
				}{{tc.at + wait - 1, false}, {tc.at + wait, true}} {
					l.mu.Lock()
					ok, _ := l.check(a, probe.at)
					l.mu.Unlock()
					if ok != probe.ok {
						t.Fatalf("at %v: admitted %v, want %v", time.Duration(probe.at), ok, probe.ok)
					}
				}
			})
		}
	})
	t.Run("a refused request is not counted and does not keep its client in the table", func(t *testing.T) {
		l := newWindowLimiter(2, time.Minute, 4)
		allowAt(l, a, 0)
		allowAt(l, a, 0)
		for i := 0; i < 100; i++ {
			if ok, _, _ := allowAt(l, a, 30*sec); ok {
				t.Fatal("admitted over the limit")
			}
		}
		if ok, _, _ := allowAt(l, a, 66*sec); !ok {
			t.Fatal("refusals extended the window")
		}
		l = newWindowLimiter(1, time.Minute, 2)
		allowAt(l, a, 0)
		allowAt(l, b, sec)
		if ok, _, _ := allowAt(l, a, 2*sec); ok {
			t.Fatal("admitted over the limit")
		}
		if ok, _, evicted := allowAt(l, c, 3*sec); !ok || !evicted {
			t.Fatalf("a new client in a full table: admitted %v, evicted a live client %v", ok, evicted)
		}
		if _, kept := l.index[a]; kept {
			t.Fatal("a refusal kept its client in the table")
		}
		if ok, _, _ := allowAt(l, b, 4*sec); ok {
			t.Fatal("the client admitted later lost its count")
		}
	})
	t.Run("an idle client makes room first", func(t *testing.T) {
		l := newWindowLimiter(1, time.Minute, 2)
		allowAt(l, a, 0)
		allowAt(l, b, 50*sec)
		if ok, _, evicted := allowAt(l, c, 70*sec); !ok || evicted {
			t.Fatalf("admitted %v, evicted a live client %v", ok, evicted)
		}
		if _, kept := l.index[a]; kept || len(l.index) != 2 {
			t.Fatalf("the idle client was kept: %d clients", len(l.index))
		}
		if ok, _, _ := allowAt(l, b, 70*sec); ok {
			t.Fatal("the live client lost its count")
		}
	})
	t.Run("a client dropped from a full table costs its neighbours nothing", func(t *testing.T) {
		for _, tc := range []struct {
			name     string
			attacker func(i int) netip.Addr
		}{
			{"IPv6 /64s of many /48s", func(i int) netip.Addr {
				return netip.AddrFrom16([16]byte{0x20, 0x01, 0x0d, 0xb8, byte(i >> 8), byte(i), 0, 0, 0, 0, 0, 0, 0, 0, 0, 1})
			}},
			{"IPv4 addresses of many /24s", func(i int) netip.Addr { return netip.AddrFrom4([4]byte{10, byte(i >> 8), byte(i), 1}) }},
		} {
			t.Run(tc.name, func(t *testing.T) {
				// The users of one /24 each make one request of their two, then a flood drops every one of them.
				const limit, capacity = 2, 8
				l := newWindowLimiter(limit, time.Minute, capacity)
				user := func(i int) netip.Addr { return netip.AddrFrom4([4]byte{198, 51, 100, byte(i)}) }
				for i := 0; i < capacity; i++ {
					allowAt(l, user(i), 0)
				}
				for i := 0; i < capacity; i++ {
					if ok, _, _ := allowAt(l, tc.attacker(i), sec); !ok {
						t.Fatalf("attacker %d refused", i)
					}
				}
				for _, client := range []netip.Addr{user(0), user(200)} {
					if ok, wait, _ := allowAt(l, client, 2*sec); !ok {
						t.Fatalf("%s refused for its neighbours' requests, wait %v", client, time.Duration(wait))
					}
				}
			})
		}
	})
	t.Run("a full table admits a new client and says so once every ten seconds", func(t *testing.T) {
		seen := &matches{}
		s := start(t, func(c *Config) { ruleSetOff(c); c.APIRate = APIRatePolicy{PerMinute: 2}; c.OnMatch = seen.record })
		now := int64(time.Hour)
		s.edge.now = func() int64 { return now }
		request := httptest.NewRequest(http.MethodGet, "/api", nil)
		key := func(i int) netip.Addr { return netip.AddrFrom4([4]byte{10, byte(i >> 16), byte(i >> 8), byte(i)}) }
		for i := 0; i < rateKeysPerRule; i++ {
			if !s.edge.checkRequest(httptest.NewRecorder(), request, key(i)) {
				t.Fatal("refused while the table filled")
			}
		}
		table := s.edge.rules[0].table
		for i := 0; i < 26; i++ {
			newcomer := netip.AddrFrom4([4]byte{198, 51, 100, byte(i)})
			if w := httptest.NewRecorder(); !s.edge.checkRequest(w, request, newcomer) {
				t.Fatalf("new client %d refused: %d", i, w.Code)
			}
			if _, kept := table.index[key(i)]; kept || len(table.index) != rateKeysPerRule {
				t.Fatalf("new client %d: the first client admitted is kept %v, %d clients", i, kept, len(table.index))
			}
			now += int64(time.Second)
		}
		var logged []string
		for _, m := range seen.all() {
			logged = append(logged, fmt.Sprint(m.RuleID, " ", m.Severity, " ", m.Message))
		}
		line := "5000041 WARNING rate-limit table full; least recently admitted client evicted"
		want := []string{line, line + " (9 more evictions not logged)", line + " (9 more evictions not logged)"}
		if strings.Join(logged, "\n") != strings.Join(want, "\n") || s.edge.evictedLive.Load() != 26 {
			t.Fatalf("logged %q, want %q; %d evictions counted", logged, want, s.edge.evictedLive.Load())
		}
	})
	t.Run("clients within their limits never lock out a new client", func(t *testing.T) {
		for _, tc := range []struct {
			name         string
			perMinute, n int
		}{{"two clients at 100000 a minute", 100000, 2}, {"334 clients at 600 a minute", 600, 334}} {
			t.Run(tc.name, func(t *testing.T) {
				s := start(t, func(c *Config) {
					ruleSetOff(c)
					c.WordPress = WordPressPolicy{Enabled: true}
					c.APIRate = APIRatePolicy{PerMinute: tc.perMinute}
				})
				api := httptest.NewRequest(http.MethodGet, "/api/orders", nil)
				for i := 0; i < tc.n; i++ {
					client := netip.AddrFrom4([4]byte{10, 0, byte(i >> 8), byte(i)})
					for j := 0; j < tc.perMinute; j++ {
						if w := httptest.NewRecorder(); !s.edge.checkRequest(w, api, client) {
							t.Fatalf("client %d refused within its limit: %d", i, w.Code)
						}
					}
				}
				fresh := netip.MustParseAddr("203.0.113.9")
				login := httptest.NewRequest(http.MethodPost, "/wp-login.php", strings.NewReader("log=a&pwd=b"))
				for _, r := range []*http.Request{login, api} {
					if w := httptest.NewRecorder(); !s.edge.checkRequest(w, r, fresh) {
						t.Fatalf("a new client's %s %s: %d", r.Method, r.URL.Path, w.Code)
					}
				}
				if w := httptest.NewRecorder(); s.edge.checkRequest(w, api, netip.AddrFrom4([4]byte{10, 0, 0, 0})) || w.Code != 429 {
					t.Fatalf("a client over its limit: %d", w.Code)
				}
			})
		}
	})
	t.Run("concurrent admission does not overshoot", func(t *testing.T) {
		s := start(t, func(c *Config) { ruleSetOff(c); c.APIRate = APIRatePolicy{PerMinute: 7} })
		request := httptest.NewRequest(http.MethodGet, "/api", nil)
		var accepted atomic.Int64
		var group sync.WaitGroup
		for i := 0; i < 100; i++ {
			group.Add(1)
			go func() {
				defer group.Done()
				if s.edge.checkRequest(httptest.NewRecorder(), request, a) {
					accepted.Add(1)
				}
			}()
		}
		group.Wait()
		if accepted.Load() != 7 {
			t.Fatalf("accepted %d", accepted.Load())
		}
	})
}

func FuzzSlidingRateBudget(f *testing.F) {
	f.Add([]byte{0, 0, 0, 0, 0xff, 0xff, 0xff, 0xff, 0}, uint8(3))
	f.Add([]byte(strings.Repeat("0123456", 20)), uint8(7))
	f.Add([]byte(strings.Repeat("\x10\x21\x32\x43\x54\x65\x06", 30)), uint8(0))
	f.Fuzz(func(t *testing.T, commands []byte, quota uint8) {
		if len(commands) > 4096 {
			return
		}
		// A table of four, for seven clients, makes room often.
		const capacity = 4
		n := int(quota%8) + 1
		slot := int64(time.Minute) / windowSlots
		l := newWindowLimiter(n, time.Minute, capacity)
		// The model keeps each client's admission times, and the clients in the order they were last admitted. A client
		// dropped from the table starts again with nothing.
		admitted := map[netip.Addr][]int64{}
		var order []netip.Addr
		inWindow := func(times []int64, from int64) (count int) {
			for _, at := range times {
				if at/slot >= from {
					count++
				}
			}
			return count
		}
		var now int64
		for _, cmd := range commands {
			now += int64(cmd>>4) * int64(time.Second)
			key := netip.AddrFrom4([4]byte{192, 0, 2, cmd % 7})
			current := now / slot
			times, known := admitted[key]
			wantOK, wantWait, wantEvicted := inWindow(times, current-windowSlots) < n, int64(0), false
			if !wantOK {
				for k := int64(1); ; k++ {
					if inWindow(times, current+k-windowSlots) < n {
						wantWait = (current+k)*slot - now
						break
					}
				}
			} else {
				if !known && len(admitted) == capacity {
					wantEvicted = inWindow(admitted[order[0]], current-windowSlots) > 0
					delete(admitted, order[0])
					order = order[1:]
				}
				admitted[key] = append(admitted[key], now)
				order = append(slices.DeleteFunc(order, func(k netip.Addr) bool { return k == key }), key)
			}
			ok, wait, evicted := allowAt(l, key, now)
			if ok != wantOK || wait != wantWait || evicted != wantEvicted {
				t.Fatalf("%s at %v: admitted %v, wait %v, evicted %v; want %v, %v, %v", key, time.Duration(now), ok, time.Duration(wait), evicted, wantOK, time.Duration(wantWait), wantEvicted)
			}
			var listed []netip.Addr
			for i := l.head; i >= 0; i = l.slab[i].next {
				listed = append(listed, l.slab[i].key)
			}
			if len(l.index) != len(admitted) || len(l.slab) > capacity || !slices.Equal(listed, order) {
				t.Fatalf("table %d clients in order %v, model %d in order %v", len(l.index), listed, len(admitted), order)
			}
		}
	})
}

// joinRules is rules as ParseRateRules reads them back.
func joinRules(rules []RateRule) string {
	texts := make([]string, len(rules))
	for i, r := range rules {
		texts[i] = r.String()
	}
	return strings.Join(texts, "; ")
}

// manyRules is n rules, each with paths paths of its own.
func manyRules(n, paths int) string {
	rules := make([]string, n)
	for i := range rules {
		list := make([]string, paths)
		for j := range list {
			list[j] = fmt.Sprintf("/r%d/p%d", i, j)
		}
		rules[i] = strings.Join(list, ",") + " 1/m"
	}
	return strings.Join(rules, "; ")
}

func TestRateRules(t *testing.T) {
	const how = "write [METHODS] PATHS COUNT/WINDOW, such as POST /login 5/m"
	const units = "use s, m or h, such as 5/m, 100/10s or 1k/h"
	// 32 rules of 125 bytes each, 4031 bytes in all, that String writes out as 4158.
	long := make([]string, 32)
	for i := range long {
		long[i] = fmt.Sprintf("/%s%02d 1k/h", strings.Repeat("a", 117), i)
	}
	longRules := strings.Join(long, ";")
	tests := []struct {
		name, text string
		want       string // the rules normalized, or the whole error
		fails      bool
	}{
		{"a login limit", "POST /login 5/m", "POST /login 5/1m", false},
		{"every method", "/api 600/m", "/api 600/1m", false},
		{"methods in any case, and a monitor", "get,head /s 30/10s monitor", "GET,HEAD /s 30/10s monitor", false},
		{"a star and thousands", "* / 3k/m", "/ 3000/1m", false},
		{"several rules and paths", "POST /login,/register 10/m; /api 600/m", "POST /login,/register 10/1m; /api 600/1m", false},
		{"empty rules are skipped", ";;/x 1/s", "/x 1/1s", false},
		{"tabs, case and repeats normalized", "\tpost,POST\t/Login,/login  1K/60m ; ", "POST /login 1000/1h", false},
		{"methods it does not know", "MKCOL,propfind,TRACE /dav 5/3600s", "MKCOL,PROPFIND,TRACE /dav 5/1h", false},
		{"the bounds", "/x 1000000/1s; /y 1/h; /z 1/1s", "/x 1000000/1s; /y 1/1h; /z 1/1s", false},
		{"a monitor copy of a rule", "POST /a 1/m; POST /a 1/m monitor", "POST /a 1/1m; POST /a 1/1m monitor", false},
		{"32 rules and 96 paths", manyRules(32, 3), "", false},
		{"no rate", "POST /login 5", `-limit rule 1 ("POST /login 5"): no rate; ` + how, true},
		{"no path", "; 5/m", `-limit rule 1 ("5/m"): no path; ` + how, true},
		{"an unknown unit", "/x 5/x", `-limit rule 1 ("/x 5/x"): "5/x": unknown window unit "x"; ` + units, true},
		{"a unit near m", "/x 5/mn", `-limit rule 1 ("/x 5/mn"): "5/mn": unknown window unit "mn"; ` + units + " (did you mean m?)", true},
		{"min", "/x 5/min", `-limit rule 1 ("/x 5/min"): "5/min": unknown window unit "min"; ` + units + " (did you mean m?)", true},
		{"a window of seconds without its unit", "/x 5/60", `-limit rule 1 ("/x 5/60"): "5/60": the window needs a unit, s, m or h; write 5/60s or 5/1m`, true},
		{"a window too long for seconds without its unit", "/x 5/7200", `-limit rule 1 ("/x 5/7200"): "5/7200": the window needs a unit, s, m or h; write 5/s, 5/m or 5/h`, true},
		{"a unit near two", "/x 5/ms", `-limit rule 1 ("/x 5/ms"): "5/ms": unknown window unit "ms"; ` + units, true},
		{"a window of two hours", "/x 5/2h", `-limit rule 1 ("/x 5/2h"): the window must be between 1s and 1h`, true},
		{"a window of nothing", "/x 5/0s", `-limit rule 1 ("/x 5/0s"): the window must be between 1s and 1h`, true},
		{"a count of 0", "/x 0/m", `-limit rule 1 ("/x 0/m"): the count must be a whole number from 1 to 1000000, optionally with k (to switch a rule off, remove it)`, true},
		{"a count too large", "/x 1000001/m", `-limit rule 1 ("/x 1000001/m"): the count must be a whole number from 1 to 1000000, optionally with k (to switch a rule off, remove it)`, true},
		{"thousands past 32 bits", "/x 4294968k/m", `-limit rule 1 ("/x 4294968k/m"): the count must be a whole number from 1 to 1000000, optionally with k (to switch a rule off, remove it)`, true},
		{"thousands too large", "/x 1001k/m", `-limit rule 1 ("/x 1001k/m"): the count must be a whole number from 1 to 1000000, optionally with k (to switch a rule off, remove it)`, true},
		{"a fraction", "/x 1.5k/m", `-limit rule 1 ("/x 1.5k/m"): the count must be a whole number from 1 to 1000000, optionally with k (to switch a rule off, remove it)`, true},
		{"a path without a slash", "/x 1/m; login 5/m", `-limit rule 2 ("login 5/m"): "login" is not a path; paths start with /, as in /login`, true},
		{"a path with a trailing slash", "POST /api/ 5/m", `-limit rule 1 ("POST /api/ 5/m"): path "/api/" must be a plain absolute path without a trailing slash, query, %-encoding or ; parameters`, true},
		{"an encoded path", "/a%2fb 5/m", `-limit rule 1 ("/a%2fb 5/m"): path "/a%2fb" must be a plain absolute path without a trailing slash, query, %-encoding or ; parameters`, true},
		{"paths given apart", "POST /a /b 5/m", `-limit rule 1 ("POST /a /b 5/m"): "/b": write several paths with commas, as in /login,/register`, true},
		{"a misspelt method", "PSOT /login 5/m", `-limit rule 1 ("PSOT /login 5/m"): "PSOT" is not an HTTP method (did you mean POST?)`, true},
		{"a method near two", "PET /x 1/m", `-limit rule 1 ("PET /x 1/m"): "PET" is not an HTTP method (did you mean GET or PUT?)`, true},
		{"a method with a digit", "G3T /x 1/m", `-limit rule 1 ("G3T /x 1/m"): "G3T" is not an HTTP method (did you mean GET?)`, true},
		{"a star among methods", "GET,* /x 1/m", `-limit rule 1 ("GET,* /x 1/m"): "*" is not an HTTP method`, true},
		{"nine methods", "GET,POST,PUT,PATCH,DELETE,HEAD,OPTIONS,MKCOL,COPY /x 1/m", `-limit rule 1 ("GET,POST,PUT,PATCH,DELETE,HEAD,OPTIONS,MKCOL,COPY /x 1/m"): at most 8 methods in a rule`, true},
		{"a misspelt monitor", "POST /login 5/m monitr", `-limit rule 1 ("POST /login 5/m monitr"): unknown word "monitr" (did you mean monitor?)`, true},
		{"monitor before the paths", "monitor /login 5/m", `-limit rule 1 ("monitor /login 5/m"): "monitor" goes after the rate, as in /login 5/m monitor`, true},
		{"monitor before the methods", "Monitor POST /login 5/m", `-limit rule 1 ("Monitor POST /login 5/m"): "monitor" goes after the rate, as in /login 5/m monitor`, true},
		{"monitor among the methods", "GET,monitor /x 1/m", `-limit rule 1 ("GET,monitor /x 1/m"): "monitor" goes after the rate, as in /login 5/m monitor`, true},
		{"two rates", "/x 5/m 10/s", `-limit rule 1 ("/x 5/m 10/s"): two rates; split them into two rules`, true},
		{"a repeated rule", "/x 5/m; /y 1/s; /X 5/1m", `-limit rule 3 ("/X 5/1m"): repeats rule 1`, true},
		{"33 rules", manyRules(33, 1), `-limit rule 33 ("/r32/p0 1/m"): at most 32 rules`, true},
		{"17 paths in a rule", manyRules(1, 17), `-limit rule 1 ("` + manyRules(1, 17)[:77] + `..."): at most 16 paths in a rule (100 in all)`, true},
		{"101 paths in all", manyRules(7, 15), `-limit rule 7 ("` + strings.Split(manyRules(7, 15), "; ")[6][:77] + `..."): at most 100 paths in all the rules (this rule brings them to 105)`, true},
		{"more than 4 KiB", "/x 1/m;" + strings.Repeat(" ", 4090), "-limit is longer than 4 KiB", true},
		{"more than 4 KiB written out", longRules, "-limit is longer than 4 KiB when written out in full, as in 1000/1h for 1k/h", true},
		{"nothing", " ; ;", "-limit: no rule; " + how, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rules, err := ParseRateRules(tt.text)
			if tt.fails {
				if err == nil || err.Error() != tt.want {
					t.Fatalf("error %v, want %s", err, tt.want)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if text := joinRules(rules); tt.want != "" && text != tt.want {
				t.Fatalf("read as %q, want %q", text, tt.want)
			}
			// What String writes reads back as the same rules.
			again, err := ParseRateRules(joinRules(rules))
			if err != nil || !reflect.DeepEqual(again, rules) {
				t.Fatalf("read back as %+v (%v), want %+v", again, err, rules)
			}
		})
	}
}

func FuzzRateRules(f *testing.F) {
	for _, seed := range []string{"POST /login 5/m", "get,head /s 30/10s monitor; * / 3k/m", ";;/x 1/s", "PSOT /a,/b 1k/h", "/x 5/mn monitr"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, text string) {
		rules, err := ParseRateRules(text)
		if err != nil {
			return
		}
		again, err := ParseRateRules(joinRules(rules))
		if err != nil || !reflect.DeepEqual(again, rules) {
			t.Fatalf("%q read back as %+v (%v), want %+v", text, again, err, rules)
		}
	})
}

func equalInts(a, b []int) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestOneAddressCannotHoldManyConnectionsOpen(t *testing.T) {
	s := start(t, func(c *Config) { ruleSetOff(c); c.MaxConnsPerIP = 3 })
	var held []net.Conn
	for i := 0; i < 3; i++ {
		c, err := net.DialTimeout("tcp", s.addr, 3*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		held = append(held, c)
	}
	defer func() {
		for _, c := range held {
			c.Close()
		}
	}()
	time.Sleep(100 * time.Millisecond) // let the server see all three

	extra, err := net.DialTimeout("tcp", s.addr, 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer extra.Close()
	extra.SetDeadline(time.Now().Add(3 * time.Second))
	extra.Write([]byte(get("/page")))
	if _, err := bufio.NewReader(extra).ReadString('\n'); err == nil {
		t.Fatal("a fourth connection from the same address was served")
	}

	held[0].Close() // a place comes free
	time.Sleep(100 * time.Millisecond)
	if status, _ := s.raw(t, get("/page")); status != 200 {
		t.Fatalf("after one was closed, a new connection got %d", status)
	}

	t.Run("addresses in one IPv6 /64 share the cap", func(t *testing.T) {
		l := newConnLimiter(2, nil, nil)
		var open []*limitConn
		for i, addr := range []string{"[2001:db8:1:2::1]:1000", "[2001:db8:1:2::2]:1000", "[2001:db8:1:2::3]:1000", "[2001:db8:1:3::1]:1000"} {
			c := &limitConn{remote: addr}
			l.state(c, http.StateNew)
			if want := i != 2; c.closed == want {
				t.Fatalf("%s: closed %v, want %v", addr, c.closed, !want)
			}
			open = append(open, c)
		}
		l.state(open[0], http.StateClosed)
		again := &limitConn{remote: "[2001:db8:1:2::9]:1000"}
		if l.state(again, http.StateNew); again.closed {
			t.Fatal("a place freed in the /64 was not reused")
		}
	})
	t.Run("refusals are logged at most once a second, with the address only when asked", func(t *testing.T) {
		for _, details := range []bool{false, true} {
			t.Run(fmt.Sprintf("LogDetails %v", details), func(t *testing.T) {
				var mu sync.Mutex
				var logged []Match
				e, err := New(Config{Upstream: mustURL("http://127.0.0.1:1"), CRS: crs.DefaultSettings(), Origin: loopback, MaxConnsPerIP: 1,
					LogDetails: details, OnMatch: func(m Match) { mu.Lock(); logged = append(logged, m); mu.Unlock() }})
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { e.Close() })
				now := int64(time.Hour)
				e.now = func() int64 { return now }
				state := e.Server("").ConnState
				state(&limitConn{remote: "192.0.2.1:1000"}, http.StateNew) // holds the address's one place
				refuse := func(n int) {
					for i := 0; i < n; i++ {
						c := &limitConn{remote: "192.0.2.1:" + strconv.Itoa(2000+i)}
						if state(c, http.StateNew); !c.closed {
							t.Fatal("a connection over the limit was kept")
						}
					}
				}
				refuse(1000)
				now += int64(time.Second)
				refuse(1)
				mu.Lock()
				defer mu.Unlock()
				wantIP := ""
				if details {
					wantIP = "192.0.2.1"
				}
				if len(logged) != 2 || logged[0].ClientIP != wantIP || logged[1].ClientIP != wantIP ||
					logged[1].Message != "an address holds too many connections open (999 more refusals not logged)" {
					t.Fatalf("logged %d lines, the first two %+v; want two, the second counting 999 not logged, with the address %q",
						len(logged), logged[:min(2, len(logged))], wantIP)
				}
			})
		}
	})
	t.Run("a connection taken over for an upgrade counts until it closes", func(t *testing.T) {
		l := newConnLimiter(1, nil, nil)
		tunnel := &limitConn{remote: "192.0.2.1:1000"}
		l.state(tunnel, http.StateNew)
		l.state(tunnel, http.StateHijacked)
		second := &limitConn{remote: "192.0.2.1:1001"}
		if l.state(second, http.StateNew); !second.closed {
			t.Fatal("a hijacked connection stopped counting against its address")
		}
		l.state(tunnel, http.StateClosed)
		third := &limitConn{remote: "192.0.2.1:1002"}
		if l.state(third, http.StateNew); third.closed {
			t.Fatal("a closed tunnel still counts")
		}
	})
}

// limitConn is a connection with only an address, for the connection limiter.
type limitConn struct {
	net.Conn
	remote string
	closed bool
}

func (c *limitConn) RemoteAddr() net.Addr { return limitAddr(c.remote) }
func (c *limitConn) Close() error         { c.closed = true; return nil }

type limitAddr string

func (a limitAddr) Network() string { return "tcp" }
func (a limitAddr) String() string  { return string(a) }

func TestHTTP2LimitsAreAdvertisedToClients(t *testing.T) {
	s := start(t, ruleSetOff)
	srv := httptest.NewUnstartedServer(nil)
	srv.Config = s.edge.Server("")
	srv.EnableHTTP2 = true
	srv.StartTLS()
	defer srv.Close()

	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	conn, err := tls.Dial("tcp", srv.Listener.Addr().String(), &tls.Config{RootCAs: pool, ServerName: "example.com", NextProtos: []string{"h2"}})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if conn.ConnectionState().NegotiatedProtocol != "h2" {
		t.Fatalf("negotiated %q, want h2", conn.ConnectionState().NegotiatedProtocol)
	}
	conn.Write([]byte(http2.ClientPreface))
	fr := http2.NewFramer(conn, conn)
	if err := fr.WriteSettings(); err != nil {
		t.Fatal(err)
	}
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	for {
		f, err := fr.ReadFrame()
		if err != nil {
			t.Fatalf("no SETTINGS frame from the server: %v", err)
		}
		if sf, ok := f.(*http2.SettingsFrame); ok && !sf.IsAck() {
			streams, ok := sf.Value(http2.SettingMaxConcurrentStreams)
			if !ok || streams != 100 {
				t.Fatalf("MAX_CONCURRENT_STREAMS = %d (set: %v), want 100", streams, ok)
			}
			if size, ok := sf.Value(http2.SettingMaxFrameSize); ok && size > 16<<10 {
				t.Fatalf("MAX_FRAME_SIZE = %d, want 16384 or less", size)
			}
			return
		}
	}
}

// stallEdge serves a large response at /big through an edge with the given number of upstream places, over TLS with HTTP/2.
// connCloses records when the server was done with each client connection, by the client's address.
type connCloses struct {
	mu sync.Mutex
	at map[string]time.Time
}

func (c *connCloses) when(addr string) (time.Time, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	at, ok := c.at[addr]
	return at, ok
}

func stallEdge(t *testing.T, places int, active *atomic.Int64) (*httptest.Server, *Edge, *refusals, *x509.CertPool, *connCloses) {
	t.Helper()
	chunk := []byte(strings.Repeat("x", 64<<10)) // /big never ends: more than every socket buffer on the way
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		if r.URL.Path == "/big" {
			active.Add(1) // requests at the application with a response it is still sending
			defer active.Add(-1)
			for r.Context().Err() == nil {
				if _, err := w.Write(chunk); err != nil {
					return
				}
			}
			return
		}
		_, _ = w.Write([]byte("ok")) // nothing to do if the edge has gone
	}))
	t.Cleanup(up.Close)
	rec := &refusals{}
	// Connections come in through the shield's listener, as they do in the program: the connection the edge is given is
	// the shield's, under the TLS one.
	sh, err := shield.New(shield.Config{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(sh.Close)
	cfg := Config{Upstream: mustURL(up.URL), Origin: loopback, CRS: crs.DefaultSettings(), MaxUpstreamInFlight: places, OnMatch: rec.record,
		Shield: sh, MaxConnsPerIP: -1}
	ruleSetOff(&cfg)
	e, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { e.Close() })
	srv := httptest.NewUnstartedServer(nil)
	srv.Listener = sh.Listener(srv.Listener)
	srv.Config = e.Server("")
	closes := &connCloses{at: map[string]time.Time{}}
	state := srv.Config.ConnState
	srv.Config.ConnState = func(c net.Conn, st http.ConnState) {
		if state != nil {
			state(c, st)
		}
		if st == http.StateClosed {
			closes.mu.Lock()
			closes.at[c.RemoteAddr().String()] = time.Now()
			closes.mu.Unlock()
		}
	}
	srv.EnableHTTP2 = true
	srv.StartTLS()
	t.Cleanup(srv.Close)
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	return srv, e, rec, pool, closes
}

// waitActive waits until the application is sending exactly want large responses.
func waitActive(t *testing.T, active *atomic.Int64, want int64, within time.Duration) {
	t.Helper()
	for deadline := time.Now().Add(within); active.Load() != want; time.Sleep(10 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatalf("%d requests are being answered by the application, want %d within %v", active.Load(), want, within)
		}
	}
}

// waitStuck waits until n responses are held at a write the client does not take.
func waitStuck(t *testing.T, e *Edge, n int) {
	t.Helper()
	for deadline := time.Now().Add(10 * time.Second); ; {
		stuck := 0
		e.places.mu.Lock()
		for w := range e.places.held {
			if w.since.Load() != 0 {
				stuck++
			}
		}
		e.places.mu.Unlock()
		if stuck >= n {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%d responses stuck, want %d", stuck, n)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func fetch(t *testing.T, srv *httptest.Server, pool *x509.CertPool) int {
	t.Helper()
	c := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, ServerName: "example.com"}}}
	defer c.CloseIdleConnections()
	resp, err := c.Get(srv.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	return resp.StatusCode
}

func (r *refusals) count(id int) (n int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, x := range r.ids {
		if x == id {
			n++
		}
	}
	return n
}

// A client that opens requests and then reads nothing must not hold the upstream's places, and so the whole site, until
// the write timeout. When no place is free, the response stuck the longest (at least stallGrace) is ended; while places
// are free, a slow reader is left alone.
func TestAClientThatStopsReadingCannotHoldTheUpstream(t *testing.T) {
	t.Run("HTTP/2 streams with a window of zero", func(t *testing.T) {
		t.Parallel()
		var active atomic.Int64
		srv, e, rec, pool, _ := stallEdge(t, 4, &active)
		conn, err := tls.Dial("tcp", srv.Listener.Addr().String(), &tls.Config{RootCAs: pool, ServerName: "example.com", NextProtos: []string{"h2"}})
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		if _, err := conn.Write([]byte(http2.ClientPreface)); err != nil {
			t.Fatal(err)
		}
		fr := http2.NewFramer(conn, conn)
		if err := fr.WriteSettings(http2.Setting{ID: http2.SettingInitialWindowSize, Val: 0}); err != nil {
			t.Fatal(err)
		}
		var mu sync.Mutex // guards the framer's writes (it is not safe for concurrent use) and the resets seen
		reset := map[uint32]bool{}
		go func() { // the connection itself is read; only the streams are never given room
			for {
				f, err := fr.ReadFrame()
				if err != nil {
					return
				}
				switch f := f.(type) {
				case *http2.SettingsFrame:
					if !f.IsAck() {
						mu.Lock()
						_ = fr.WriteSettingsAck() // the read loop has no one to tell; a failed write ends the test's reads
						mu.Unlock()
					}
				case *http2.RSTStreamFrame:
					mu.Lock()
					reset[f.StreamID] = true
					mu.Unlock()
				}
			}
		}()
		var hb strings.Builder
		open := func(id uint32) {
			hb.Reset()
			enc := hpack.NewEncoder(&hb)
			for _, f := range [][2]string{{":method", "GET"}, {":scheme", "https"}, {":authority", "example.com"}, {":path", "/big"}} {
				if err := enc.WriteField(hpack.HeaderField{Name: f[0], Value: f[1]}); err != nil {
					t.Fatal(err)
				}
			}
			mu.Lock()
			err := fr.WriteHeaders(http2.HeadersFrameParam{StreamID: id, BlockFragment: []byte(hb.String()), EndStream: true, EndHeaders: true})
			mu.Unlock()
			if err != nil {
				t.Fatal(err)
			}
		}
		for _, id := range []uint32{1, 3, 5} {
			open(id)
		}
		waitStuck(t, e, 3)
		time.Sleep(stallGrace + 500*time.Millisecond)
		if got := fetch(t, srv, pool); got != http.StatusOK || rec.count(idUpstreamReclaimed) != 0 {
			t.Fatalf("with a place to spare: status %d, %d responses ended", got, rec.count(idUpstreamReclaimed))
		}
		open(7) // now every place is held
		waitStuck(t, e, 4)
		waitActive(t, &active, 4, 5*time.Second)
		if got := fetch(t, srv, pool); got != http.StatusOK || rec.count(idUpstreamReclaimed) != 1 {
			t.Fatalf("with every place held by streams the client does not read: status %d, %d responses ended", got, rec.count(idUpstreamReclaimed))
		}
		waitActive(t, &active, 3, 2*time.Second) // the ended response's request to the application was cancelled with it
		for deadline := time.Now().Add(5 * time.Second); ; time.Sleep(10 * time.Millisecond) {
			mu.Lock()
			n, newest := len(reset), reset[7]
			mu.Unlock()
			if n == 1 && !newest {
				break
			}
			if n > 1 || newest || time.Now().After(deadline) {
				t.Fatalf("streams reset: %v, want one of the three stuck longest", reset)
			}
		}
		// Every request that finished has given back what it held: the three responses still stuck hold three places.
		for deadline := time.Now().Add(5 * time.Second); ; time.Sleep(10 * time.Millisecond) {
			e.places.mu.Lock()
			ending, held, free := e.places.ending, len(e.places.held), len(e.places.free)
			e.places.mu.Unlock()
			if ending == 0 && held == 3 && free == 3 {
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("%d still ending, %d held, %d places in use (want 0, 3, 3)", ending, held, free)
			}
		}
	})
	t.Run("HTTP/1.1 connections that stop reading", func(t *testing.T) {
		t.Parallel()
		var active atomic.Int64
		srv, e, rec, pool, closes := stallEdge(t, 2, &active)
		var clients []*tls.Conn
		for i := 0; i < 2; i++ {
			raw, err := net.Dial("tcp", srv.Listener.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			if err := raw.(*net.TCPConn).SetReadBuffer(4 << 10); err != nil {
				t.Fatal(err)
			}
			c := tls.Client(raw, &tls.Config{RootCAs: pool, ServerName: "example.com", NextProtos: []string{"http/1.1"}})
			defer c.Close()
			clients = append(clients, c)
			if _, err := c.Write([]byte("GET /big HTTP/1.1\r\nHost: example.com\r\n\r\n")); err != nil {
				t.Fatal(err)
			}
		}
		waitStuck(t, e, 2)
		// Control: a response that has only just stopped being read is not ended; the site is busy for the moment.
		if got := fetch(t, srv, pool); got != http.StatusServiceUnavailable || rec.count(idUpstreamReclaimed) != 0 {
			t.Fatalf("with both places held by writes stuck for under %v: status %d, %d responses ended", stallGrace, got, rec.count(idUpstreamReclaimed))
		}
		time.Sleep(stallGrace + 500*time.Millisecond)
		waitActive(t, &active, 2, 5*time.Second)
		if got := fetch(t, srv, pool); got != http.StatusOK || rec.count(idUpstreamReclaimed) != 1 {
			t.Fatalf("with both places held by connections that do not read: status %d, %d responses ended", got, rec.count(idUpstreamReclaimed))
		}
		// The ended response's request to the application stops at once.
		waitActive(t, &active, 1, time.Second)
		// So does its connection: the server is done with it without waiting for the client to take a TLS close_notify
		// (which a client that is not reading holds up for five seconds), and the client finds it reset, not closed in
		// good order with the unsent part of the response still on its way. The other connection is left alone.
		var ended *tls.Conn
		for deadline := time.Now().Add(2 * time.Second); ended == nil; time.Sleep(10 * time.Millisecond) {
			for _, c := range clients {
				if _, ok := closes.when(c.LocalAddr().String()); ok {
					if ended != nil {
						t.Fatal("the server closed both connections, and only one response was ended")
					}
					ended = c
				}
			}
			if ended == nil && time.Now().After(deadline) {
				t.Fatal("two seconds after its response was ended, the server still holds the connection of the client that does not read")
			}
		}
		if err := ended.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
			t.Fatal(err)
		}
		// (Windows words a reset as a connection "forcibly closed by the remote host".)
		if _, err := io.Copy(io.Discard, ended); err == nil {
			t.Fatal("the ended connection closed in good order: it was not reset")
		} else if ne, ok := err.(net.Error); ok && ne.Timeout() {
			t.Fatalf("the ended connection is still open at the client: %v", err)
		} else if msg := err.Error(); !strings.Contains(msg, "connection reset") && !strings.Contains(msg, "forcibly closed") {
			t.Fatalf("the ended connection was closed, not reset: %v", err)
		}
		// The ended response's handler has returned without giving back the place that went to the new request: one place
		// is still held, by the response that was not ended, which is left to go on.
		for deadline := time.Now().Add(15 * time.Second); ; time.Sleep(10 * time.Millisecond) {
			e.places.mu.Lock()
			ending, held, free := e.places.ending, len(e.places.held), len(e.places.free)
			e.places.mu.Unlock()
			if ending == 0 && held == 1 && free == 1 {
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("after the ended response's handler should have returned: %d still ending, %d held, %d places in use (want 0, 1, 1)", ending, held, free)
			}
		}
		e.places.mu.Lock()
		defer e.places.mu.Unlock()
		for w := range e.places.held {
			if w.ended || w.since.Load() == 0 {
				t.Fatal("the response that was not ended is no longer waiting on its client")
			}
		}
	})
}

// The accounting behind the hand-over, without a network: which response is ended, how many may be finishing at once, and that
// a place goes back exactly once.
func TestUpstreamPlacesAreHandedOverWithinTheirLimits(t *testing.T) {
	const n = 16 // at most two ended responses may be finishing at once
	p := newUpstreamPlaces(n)
	var held []*writeWatch
	for i := 0; i < n; i++ {
		w := &writeWatch{ResponseWriter: httptest.NewRecorder()}
		if ok, reclaimed := p.acquire(w); !ok || reclaimed {
			t.Fatalf("place %d of %d: ok %v, reclaimed %v", i+1, n, ok, reclaimed)
		}
		held = append(held, w)
	}
	stuckFor := func(w *writeWatch, d time.Duration) { w.since.Store(monotonic() - int64(d)) }
	acquire := func() (bool, bool, *writeWatch) {
		w := &writeWatch{ResponseWriter: httptest.NewRecorder()}
		ok, reclaimed := p.acquire(w)
		return ok, reclaimed, w
	}

	if ok, _, _ := acquire(); ok {
		t.Fatal("a place was found with nothing writing")
	}
	for _, w := range held {
		stuckFor(w, stallGrace-time.Second)
	}
	if ok, _, _ := acquire(); ok {
		t.Fatalf("a place was taken from a write stuck for under %v", stallGrace)
	}
	for i, w := range held {
		stuckFor(w, time.Duration(30-i)*time.Second) // the first has waited longest
	}
	stuckFor(held[n-1], time.Second) // not yet long enough
	if ok, _, _ := acquire(); !ok {
		t.Fatal("no place was handed over although writes had been stuck for 30 seconds")
	}
	if !held[0].ended || held[1].ended {
		t.Fatalf("ended: first %v, second %v: want the response stuck longest, and only it", held[0].ended, held[1].ended)
	}
	if ok, reclaimed, _ := acquire(); !ok || !reclaimed || !held[1].ended || held[2].ended {
		t.Fatalf("second hand-over: ok %v, reclaimed %v, ended %v %v", ok, reclaimed, held[1].ended, held[2].ended)
	}
	if ok, _, _ := acquire(); ok || held[2].ended {
		t.Fatal("a third response was ended while two were still finishing")
	}
	p.release(held[0]) // the first ended response's handler returns
	if p.ending != 1 || len(p.free) != n {
		t.Fatalf("after one returned: %d finishing, %d places in use (want 1, %d): its place must not be given back twice", p.ending, len(p.free), n)
	}
	if ok, reclaimed, _ := acquire(); !ok || !reclaimed || !held[2].ended {
		t.Fatalf("after one returned: ok %v, reclaimed %v, third ended %v", ok, reclaimed, held[2].ended)
	}
	for _, w := range held[3 : n-1] {
		w.since.Store(0) // not writing: never taken from
	}
	p.release(held[1])
	p.release(held[2])
	if ok, _, _ := acquire(); ok {
		t.Fatal("a place was taken from a response that was not stuck")
	}
	p.release(held[n-1])
	if ok, reclaimed, _ := acquire(); !ok || reclaimed {
		t.Fatalf("a released place: ok %v, reclaimed %v", ok, reclaimed)
	}
}

// Many requests take places, some get stuck and are ended by the others, and every one releases: at no moment do more requests run
// than there are places plus the ended ones still finishing, and every place is back at the end.
func TestUpstreamPlacesHoldTheirLimitsUnderLoad(t *testing.T) {
	const n = 16
	p := newUpstreamPlaces(n)
	var running, ended, peak atomic.Int64
	var wg sync.WaitGroup
	for g := 0; g < 48; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 400; i++ {
				w := &writeWatch{ResponseWriter: httptest.NewRecorder()}
				ok, reclaimed := p.acquire(w)
				if !ok {
					continue
				}
				if reclaimed {
					ended.Add(1)
				}
				now := running.Add(1)
				for {
					seen := peak.Load()
					if now <= seen || peak.CompareAndSwap(seen, now) {
						break
					}
				}
				if i%3 == 0 {
					w.since.Store(monotonic() - int64(time.Hour)) // stuck, for as long as it takes someone to end it
					for spins := 0; spins < 200; spins++ {
						p.mu.Lock()
						done := w.ended
						p.mu.Unlock()
						if done {
							break
						}
						runtime.Gosched()
					}
					w.since.Store(0)
				}
				running.Add(-1)
				p.release(w)
			}
		}()
	}
	wg.Wait()
	if got, limit := peak.Load(), int64(n+p.maxEnding); got > limit {
		t.Fatalf("%d requests ran at once, more than %d places and %d ended ones finishing", got, n, p.maxEnding)
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.free) != 0 || p.ending != 0 || len(p.held) != 0 {
		t.Fatalf("after every request returned: %d places in use, %d finishing, %d held (want 0, 0, 0)", len(p.free), p.ending, len(p.held))
	}
	if ended.Load() == 0 {
		t.Fatal("no response was ended: the test did not exercise the hand-over")
	}
}

// stuckClient is a response writer for a client that reads nothing and cannot be given a write deadline: its Write waits.
type stuckClient struct {
	header  http.Header
	in      chan struct{}
	release chan struct{}
	once    sync.Once
}

func (s *stuckClient) Header() http.Header { return s.header }
func (s *stuckClient) WriteHeader(int)     {}
func (s *stuckClient) Write(b []byte) (int, error) {
	s.once.Do(func() { close(s.in) })
	<-s.release
	return len(b), nil
}

// Ending a response that cannot be cut by a deadline still stops its request to the application, at once: the guarantee does not
// depend on what the web server does when a client's connection fails.
func TestEndingAResponseAlsoCancelsItsRequestToTheApplication(t *testing.T) {
	started, cancelled, giveUp := make(chan struct{}), make(chan struct{}), make(chan struct{})
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/slow" {
			_, _ = w.Write([]byte("ok"))
			return
		}
		_, _ = w.Write([]byte("the first of a response that never ends"))
		w.(http.Flusher).Flush()
		close(started)
		select {
		case <-r.Context().Done(): // the edge closing its connection to the application is what ends this
			close(cancelled)
		case <-giveUp: // the test is over, and did not see that happen
		}
	}))
	t.Cleanup(up.Close)
	t.Cleanup(func() { close(giveUp) })
	cfg := Config{Upstream: mustURL(up.URL), Origin: loopback, CRS: crs.DefaultSettings(), MaxUpstreamInFlight: 1}
	ruleSetOff(&cfg)
	e, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { e.Close() })
	stuck := &stuckClient{header: http.Header{}, in: make(chan struct{}), release: make(chan struct{})}
	t.Cleanup(func() { close(stuck.release) })
	go e.ServeHTTP(stuck, httptest.NewRequest(http.MethodGet, "/slow", nil))
	<-started
	<-stuck.in
	e.places.mu.Lock()
	for w := range e.places.held {
		w.since.Store(monotonic() - int64(time.Minute)) // stuck for long enough
	}
	e.places.mu.Unlock()
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if rec.Code != http.StatusOK || rec.Body.String() != "ok" {
		t.Fatalf("the request that needed the place: status %d, body %q", rec.Code, rec.Body.String())
	}
	select {
	case <-cancelled:
	case <-time.After(5 * time.Second):
		t.Fatal("the request to the application of the ended response was not cancelled")
	}
}

// deadlineBlocker is a response writer whose SetWriteDeadline does not come back until told to.
type deadlineBlocker struct {
	http.ResponseWriter
	in, out chan struct{}
}

func (d deadlineBlocker) SetWriteDeadline(time.Time) error { close(d.in); <-d.out; return nil }

// The call that ends a stuck response may be slow to come back. It must not hold up anything else: other requests take and give
// back places meanwhile, the request that was waiting for a place has it at once, and the ended response's handler does not
// return until the call is done with its writer.
func TestAStuckCallThatEndsAResponseDoesNotStallThePlaces(t *testing.T) {
	within := func(what string, f func()) {
		t.Helper()
		done := make(chan struct{})
		go func() { f(); close(done) }()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatal(what)
		}
	}
	p := newUpstreamPlaces(2)
	blocker := deadlineBlocker{httptest.NewRecorder(), make(chan struct{}), make(chan struct{})}
	victim := &writeWatch{ResponseWriter: blocker}
	other := &writeWatch{ResponseWriter: httptest.NewRecorder()}
	p.acquire(victim)
	p.acquire(other)
	victim.since.Store(monotonic() - int64(time.Minute))
	newcomer := &writeWatch{ResponseWriter: httptest.NewRecorder()}
	within("the request waiting for a place was held up by the call that ends the response", func() {
		if ok, reclaimed := p.acquire(newcomer); !ok || !reclaimed {
			t.Errorf("acquire: ok %v, reclaimed %v", ok, reclaimed)
		}
	})
	<-blocker.in // the call is under way, and does not return
	within("other requests were held up by the call that ends a response", func() {
		p.release(other)
		again := &writeWatch{ResponseWriter: httptest.NewRecorder()}
		if ok, _ := p.acquire(again); !ok {
			t.Error("a place that was given back was not found")
		}
		p.release(again)
	})
	returned := make(chan struct{})
	go func() { p.release(victim); close(returned) }()
	select {
	case <-returned:
		t.Fatal("the ended response's handler returned while its writer was still in use")
	case <-time.After(100 * time.Millisecond):
	}
	close(blocker.out)
	within("the ended response's handler did not return once the call was done", func() { <-returned })
	p.release(newcomer)
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.free) != 0 || p.ending != 0 || len(p.held) != 0 {
		t.Fatalf("at the end: %d places in use, %d finishing, %d held (want 0, 0, 0)", len(p.free), p.ending, len(p.held))
	}
}

// deadlineCounter counts the write deadlines it is given.
type deadlineCounter struct {
	http.ResponseWriter
	n *atomic.Int32
}

func (d deadlineCounter) SetWriteDeadline(time.Time) error { d.n.Add(1); return nil }

// A response writer may not be used once its handler is returning: ending a response that has finished does nothing.
func TestEndingAResponseWhoseHandlerIsReturningDoesNothing(t *testing.T) {
	var calls atomic.Int32
	w := &writeWatch{ResponseWriter: deadlineCounter{httptest.NewRecorder(), &calls}}
	w.cut()
	if calls.Load() != 1 {
		t.Fatalf("a running response was given %d write deadlines, want 1", calls.Load())
	}
	p := newUpstreamPlaces(1)
	p.acquire(w)
	p.release(w)
	w.cut()
	if calls.Load() != 1 {
		t.Fatalf("a response whose handler had returned was given %d write deadlines, want 1", calls.Load())
	}
}

// flushBlocker is a response writer whose Flush waits to be told to go on, like a socket whose client is not reading.
type flushBlocker struct {
	http.ResponseWriter
	in, out chan struct{}
}

func (b flushBlocker) Flush() { close(b.in); <-b.out }

func TestAWriteWatchSeesAFlushThatIsStuck(t *testing.T) {
	b := flushBlocker{httptest.NewRecorder(), make(chan struct{}), make(chan struct{})}
	w := &writeWatch{ResponseWriter: b}
	done := make(chan struct{})
	go func() { w.Flush(); close(done) }()
	<-b.in
	if w.since.Load() == 0 {
		t.Fatal("a flush in progress was not seen")
	}
	close(b.out)
	<-done
	if w.since.Load() != 0 {
		t.Fatal("a finished flush is still seen as stuck")
	}
}

// The rules that refuse an address on another host let one on this site through, and "this site" is what the operator
// named: the Host header is the client's to write, so a request must not be able to make a remote address local by
// naming that host. With AllowedHosts set such a request never reaches the rules; without it nothing is this site's.
func TestOnlyTheSitesOwnNamesMakeAnAddressLocal(t *testing.T) {
	named := func(c *Config) { c.AllowedHosts = []string{"Shop.Example.Test.", "www.brand.example.test"} }
	req := func(host, target string, headers ...string) string {
		return "GET " + target + " HTTP/1.1\r\nHost: " + host + "\r\nUser-Agent: Mozilla/5.0 Chrome/120\r\nAccept: text/html\r\n" +
			strings.Join(headers, "") + "Connection: close\r\n\r\n"
	}
	page := func(u string) string { return "/index.php?page=" + url.QueryEscape(u) }
	for _, tt := range []struct {
		name    string
		change  func(*Config)
		request string
		want    int
		id      int
	}{
		{"this site, named", named, req("shop.example.test", page("https://shop.example.test/about")), 200, 0},
		{"this site on a port, named", named, req("shop.example.test:8443", page("https://cdn.shop.example.test:8443/a")), 200, 0},
		{"the name without www, named", named, req("www.brand.example.test", page("https://brand.example.test/a")), 200, 0},
		{"this site beside a name the rules cannot take", func(c *Config) { c.AllowedHosts = []string{"bücher.example.test", "shop.example.test"} },
			req("shop.example.test", page("https://shop.example.test/about")), 200, 0},
		{"another host, named", named, req("shop.example.test", page("http://evil.example/x")), 403, 5006015},
		{"the request names the remote host, named", named, req("evil.example", page("http://evil.example/x")), 421, idHostNotAllowed},
		{"the request names the remote host", nil, req("evil.example", page("http://evil.example/x")), 403, 5006015},
		{"the same with a text file", nil, req("evil.example", "/x?u="+url.QueryEscape("http://evil.example/shell.txt")), 403, 5006017},
		{"the same with a script", nil, req("evil.example", "/x?view="+url.QueryEscape("http://evil.example/a.php")), 403, 5006021},
		{"this site, not named", nil, req("shop.example.test", page("https://shop.example.test/about")), 403, 5006015},
		{"a forwarded host folded over two lines", nil, req("shop.example.test", "/", "X-Forwarded-Host: evil.example\r\n x: y\r\n"), 403, 5006022},
		{"a forwarded host with a bare line feed", nil, req("shop.example.test", "/", "X-Forwarded-Host: evil.example\n x: y\r\n"), 403, 5006022},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var seen refusals
			s := start(t, func(c *Config) {
				c.OnMatch = seen.record
				if tt.change != nil {
					tt.change(c)
				}
			})
			status, _ := s.raw(t, tt.request)
			if status != tt.want {
				t.Fatalf("status %d, want %d", status, tt.want)
			}
			if got := len(s.up.requests()) > 0; got != (tt.want == 200) {
				t.Fatalf("reached the application: %v", got)
			}
			if tt.id != 0 && seen.count(tt.id) == 0 {
				t.Fatalf("rule %d was not recorded (recorded %v)", tt.id, seen.ids)
			}
		})
	}
	// A forwarded host that is a host name is not refused, and is never what the application is told.
	s := start(t, nil)
	if status, _ := s.raw(t, req("shop.example.test", "/", "X-Forwarded-Host: evil.example\r\n", "X-Host: evil.example\r\n")); status != 200 {
		t.Fatalf("an ordinary forwarded host: status %d", status)
	}
	got := s.up.requests()
	if len(got) != 1 || got[0].Header.Get("X-Forwarded-Host") != "shop.example.test" || got[0].Header.Get("X-Host") != "" {
		t.Fatalf("the application was told %q and %q", got[0].Header.Values("X-Forwarded-Host"), got[0].Header.Values("X-Host"))
	}
}

// An injection split over the values of one name is whole only to an application whose framework joins them. The rules
// are given the joined value as well, and the application still gets exactly what was sent.
func TestAnInjectionSplitOverARepeatedParameterIsRefused(t *testing.T) {
	post := func(target, ct, body string) string {
		return "POST " + target + " HTTP/1.1\r\nHost: shop.example.test\r\nUser-Agent: Mozilla/5.0 Chrome/120\r\nAccept: text/html\r\n" +
			"Content-Type: " + ct + "\r\nContent-Length: " + strconv.Itoa(len(body)) + "\r\nConnection: close\r\n\r\n" + body
	}
	const form = "application/x-www-form-urlencoded"
	field := func(name, value string) string {
		return "--b\r\nContent-Disposition: form-data; name=\"" + name + "\"\r\n\r\n" + value + "\r\n"
	}
	cookie := func(request, value string) string {
		return strings.Replace(request, "\r\nAccept: ", "\r\nCookie: "+value+"\r\nAccept: ", 1)
	}
	// As many parameters in the URL as the rule set reads from one place: one more and it refuses the request itself.
	names := make([]string, 1000)
	for i := range names {
		names[i] = "p" + strconv.Itoa(i) + "="
	}
	filler := strings.Join(names, "&")
	formFiller := strings.Join(names[:998], "&")
	apart := func(c *Config) { c.NoJoinedParams = true }
	// Two thousand parameters take the rules a while; a slow machine must not turn that into a 503.
	patient := func(c *Config) { c.EvalBudget = time.Minute }
	for _, tt := range []struct {
		name    string
		request string
		change  func(*Config)
		want    int
	}{
		{"split over the query", get("/api/update?q=UNION&q=SELECT+password+FROM+users"), nil, 403},
		{"split over a form", post("/api/update", form, "q=UNION&q=SELECT+password+FROM+users"), nil, 403},
		{"split over multipart fields", post("/api/update", "multipart/form-data; boundary=b", field("q", "UNION")+field("q", "SELECT password FROM users")+"--b--\r\n"), nil, 403},
		{"split between the query and a form", post("/api/update?q=UNION", form, "x=1&q=SELECT+password+FROM+users"), nil, 403},
		{"split over two spellings of the name", get("/api/update?Q=UNION&q=SELECT+password+FROM+users"), nil, 403},
		{"split with the name escaped", get("/api/update?%71=UNION&q=SELECT+password+FROM+users"), nil, 403},
		{"split into three", get("/api/update?q=1+UNION&q=SELECT+password&q=FROM+users"), nil, 403},
		{"each half alone", get("/api/update?q=UNION&p=SELECT+password+FROM+users"), nil, 200},
		{"split over the items of a list", get("/api/update?" + url.QueryEscape("q[]") + "=UNION&" + url.QueryEscape("q[]") + "=SELECT+password+FROM+users"), nil, 403},
		{"split over numbered items", get("/api/update?" + url.QueryEscape("q[0]") + "=UNION&" + url.QueryEscape("q[1]") + "=SELECT+password+FROM+users"), nil, 403},
		{"split between the query and a cookie", cookie(get("/api/update?q=UNION"), "sid=abc; q=SELECT password FROM users"), nil, 403},
		{"split at the end of as many parameters as the rules read", post("/api/update?"+filler, form, formFiller+"&q=UNION&q=SELECT+password+FROM+users"), patient, 403},
		{"as many parameters as the rules read", post("/api/update?"+filler, form, formFiller+"&q=UNION&r=SELECT+password+FROM+users"), patient, 200},
		{"one parameter more than the rules read", get("/api/update?" + filler + "&q=1"), nil, 400},
		{"one form field more than the rules read", post("/api/update", form, filler+"&q=1"), nil, 400},
		{"as many repeated names as the rules take", cookie(post("/api/update?"+filler, form, filler), "p0=x; q=1"), patient, 200},
		{"more repeated names than the rules take", cookie(post("/api/update?"+filler, form, formFiller+"&p998=&q=1"), "p999=x; q=2"), nil, 400},
		{"split over a form whose type only the rules read as one", post("/api/update", form+`; charset="utf-8`, "q=UNION&q=SELECT+password+FROM+users"), nil, 403},
		{"split over a form whose type goes on", post("/api/update", form+"x", "q=UNION&q=SELECT+password+FROM+users"), nil, 403},
		{"split over a form whose type is in capitals", post("/api/update", "Application/X-WWW-Form-Urlencoded; Charset=UTF-8", "q=UNION&q=SELECT+password+FROM+users"), nil, 403},
		{"split over multipart fields under a type that cannot be read", post("/api/update", `multipart/form-data; boundary="b`, field("q", "UNION")+field("q", "SELECT password FROM users")+"--b--\r\n"), nil, 400},
		{"a session cookie sent twice", cookie(get("/account"), "PHPSESSID=0123456789abcdef0123456789abcdef; lang=en; PHPSESSID=fedcba9876543210fedcba9876543210"), nil, 200},
		{"a session cookie sent twice beside parameters", cookie(get("/account?tab=orders&page=2"), "JSESSIONID=0123456789ABCDEF0123456789ABCDEF; JSESSIONID=FEDCBA9876543210FEDCBA9876543210"), nil, 200},
		{"a list of choices", get("/shop?" + url.QueryEscape("tag[]") + "=red&" + url.QueryEscape("tag[]") + "=blue&" + url.QueryEscape("id[0]") + "=4&" + url.QueryEscape("id[1]") + "=9"), nil, 200},
		{"a list of names", post("/guests", form, "name%5B%5D=Mary+O%27Brien&name%5B%5D=Se%C3%A1n+O%27Neill&name%5B%5D=Anne-Marie"), nil, 200},
		{"a token in a form and in a cookie", cookie(post("/settings", form, "csrf_token=Zm9vYmFy_0123-abc&name=Alice"), "csrf_token=Zm9vYmFy_0123-abc; lang=en"), nil, 200},
		{"a parameter and a cookie of one name", cookie(get("/shop?lang=en&currency=EUR"), "lang=en-GB; currency=EUR; sid=0123456789abcdef"), nil, 200},
		{"ordinary repeated choices", get("/shop?color=red&color=blue&size=m&size=l"), nil, 200},
		{"a checkbox and its hidden field", post("/settings", form, "enabled=true&enabled=false&name=Alice"), nil, 200},
		{"split over the query, joining switched off", get("/api/update?q=UNION&q=SELECT+password+FROM+users"), apart, 200},
		{"split over a form, joining switched off", post("/api/update", form, "q=UNION&q=SELECT+password+FROM+users"), apart, 200},
		{"split into a cookie, joining switched off", cookie(get("/api/update?q=UNION"), "q=SELECT password FROM users"), apart, 200},
		{"split over multipart fields, joining switched off", post("/api/update", "multipart/form-data; boundary=b", field("q", "UNION")+field("q", "SELECT password FROM users")+"--b--\r\n"), apart, 200},
	} {
		t.Run(tt.name, func(t *testing.T) {
			s := start(t, tt.change)
			status, _ := s.rawFor(t, time.Minute, tt.request)
			if status != tt.want {
				t.Fatalf("status %d, want %d", status, tt.want)
			}
			got := s.up.requests()
			if (len(got) > 0) != (tt.want == 200) {
				t.Fatalf("reached the application: %v", len(got) > 0)
			}
			if tt.want != 200 {
				return
			}
			// What the application gets is the request as it was sent, with nothing joined into it.
			line, _, _ := strings.Cut(tt.request, "\r\n")
			_, body, _ := strings.Cut(tt.request, "\r\n\r\n")
			if target := strings.Fields(line)[1]; got[0].RequestURI != target || string(got[0].Body) != body {
				t.Fatalf("the application got %q with body %q, sent %q with body %q", got[0].RequestURI, got[0].Body, target, body)
			}
		})
	}
}

func mustURL(s string) *url.URL {
	u, err := url.Parse(s)
	if err != nil {
		panic(err)
	}
	return u
}

// onOneConnection sends the requests one after the other on one connection and returns the status of each answer it read,
// up to the first that did not come because the connection was closed.
func onOneConnection(t *testing.T, s *setup, requests []string) []int {
	t.Helper()
	conn, err := net.DialTimeout("tcp", s.addr, 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	br := bufio.NewReader(conn)
	var statuses []int
	for _, request := range requests {
		if _, err := conn.Write([]byte(request)); err != nil {
			break
		}
		resp, err := http.ReadResponse(br, nil)
		if err != nil {
			break
		}
		_, err = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		if err != nil {
			break
		}
		statuses = append(statuses, resp.StatusCode)
	}
	return statuses
}
