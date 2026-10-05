// SPDX-License-Identifier: Apache-2.0

package apiguard

import (
	"fmt"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/YurilLAB/coraza/carnical/inspect"
)

// fakeClock is a clock a test moves by hand.
type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func newClock() *fakeClock { return &fakeClock{t: time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)} }

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

type reqOpt func(*inspect.Request)

// mk builds a request the way the proxy hands one to an inspector.
func mk(method, target string, opts ...reqOpt) *inspect.Request {
	path, query, _ := strings.Cut(target, "?")
	r := &inspect.Request{Method: method, Host: "api.example.test", Path: path, RawQuery: query, Header: http.Header{}, Client: netip.MustParseAddr("203.0.113.7")}
	for _, o := range opts {
		o(r)
	}
	return r
}

func withBody(ct, body string) reqOpt {
	return func(r *inspect.Request) {
		r.Body = []byte(body)
		if ct != "" {
			r.Header.Set("Content-Type", ct)
		}
	}
}

func withJSON(body string) reqOpt { return withBody("application/json", body) }

func withClient(ip string) reqOpt {
	return func(r *inspect.Request) { r.Client = netip.MustParseAddr(ip) }
}

func withHeader(k, v string) reqOpt {
	return func(r *inspect.Request) { r.Header.Add(k, v) }
}

// ids returns the verdict identifiers of a result, in order.
func ids(res inspect.Result) []int {
	var out []int
	for _, v := range res.Verdicts {
		out = append(out, v.ID)
	}
	return out
}

func blocked(res inspect.Result) bool {
	for _, v := range res.Verdicts {
		if v.Block {
			return true
		}
	}
	return false
}

func has(res inspect.Result, id int) bool {
	for _, v := range res.Verdicts {
		if v.ID == id {
			return true
		}
	}
	return false
}

// testGuard makes a guard with a fake clock; change may alter the configuration first.
func testGuard(t testing.TB, change func(*Config)) (*Guard, *fakeClock) {
	t.Helper()
	clk := newClock()
	cfg := DefaultConfig()
	cfg.Clock = clk.Now
	if change != nil {
		change(&cfg)
	}
	g, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return g, clk
}

// ip makes the nth distinct client address in 198.51.0.0/16, each in a /24 of its own so the evidence rule counts them apart.
func ip(n int) string { return fmt.Sprintf("198.51.%d.%d", n%250, 1+n/250) }

// traffic sends n answered requests, from n different clients if spread is true (else all from one), through the guard's
// observer, as the proxy does after the application answered.
func traffic(g *Guard, n int, make func(i int) *inspect.Request) {
	for i := 0; i < n; i++ {
		g.Observe(make(i), 200)
	}
}

func mustImport(t testing.TB, doc string) Model {
	t.Helper()
	m, rep, err := ImportOpenAPI([]byte(doc))
	if err != nil {
		t.Fatalf("import: %v (%+v)", err, rep)
	}
	return m
}

func nowNano() int64 { return time.Now().UnixNano() }
