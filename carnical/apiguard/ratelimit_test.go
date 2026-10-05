// SPDX-License-Identifier: Apache-2.0

package apiguard

import (
	"bytes"
	"fmt"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestTokenBuckets(t *testing.T) {
	clk := newClock()
	sustained := Limit{Burst: 10, Per: time.Minute}
	burst := Limit{Burst: 3, Per: time.Second}
	tests := []struct {
		name  string
		steps func(l *limiter, k rlKey) (allowed int, last time.Duration)
		want  int
		retry time.Duration // the wait reported with the last denial, 0 to skip
	}{
		{"the burst is allowed and then the bucket is empty", func(l *limiter, k rlKey) (int, time.Duration) {
			return spend(l, k, sustained, burst, clk.Now(), 10)
		}, 3, 333 * time.Millisecond},
		{"after a second the burst is back", func(l *limiter, k rlKey) (int, time.Duration) {
			spend(l, k, sustained, burst, clk.Now(), 3)
			return spend(l, k, sustained, burst, clk.Now().Add(time.Second), 10)
		}, 3, 0},
		{"a partial refill allows what has refilled", func(l *limiter, k rlKey) (int, time.Duration) {
			spend(l, k, sustained, burst, clk.Now(), 3)
			return spend(l, k, sustained, burst, clk.Now().Add(400*time.Millisecond), 10) // 1.2 tokens
		}, 1, 0},
		{"the sustained bucket binds over a long time", func(l *limiter, k rlKey) (int, time.Duration) {
			n := 0
			for i := 0; i < 20; i++ { // 3 a second for 20 seconds asks for 60; the minute allows 10, plus what refills (10/min)
				a, _ := spend(l, k, sustained, burst, clk.Now().Add(time.Duration(i)*time.Second), 3)
				n += a
			}
			return n, 0
		}, 10 + 3, 0}, // 10 to start, 20s of refill at 1/6 per second is 3
		{"a denial takes nothing", func(l *limiter, k rlKey) (int, time.Duration) {
			spend(l, k, sustained, burst, clk.Now(), 3)
			for i := 0; i < 50; i++ {
				l.allow(k, sustained, burst, clk.Now())
			}
			return spend(l, k, sustained, burst, clk.Now().Add(334*time.Millisecond), 10)
		}, 1, 0},
		{"the wait reported is the wait needed", func(l *limiter, k rlKey) (int, time.Duration) {
			spend(l, k, sustained, burst, clk.Now(), 3)
			ok, wait, _ := l.allow(k, sustained, burst, clk.Now())
			if ok || wait < 330*time.Millisecond || wait > 340*time.Millisecond {
				t.Errorf("ok=%v wait=%v, want about 333ms", ok, wait)
			}
			ok, _, _ = l.allow(k, sustained, burst, clk.Now().Add(wait))
			if !ok {
				t.Error("not allowed after the reported wait")
			}
			return 0, 0
		}, 0, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			l := newLimiter(1000, clk.Now())
			k, _ := addrKey(scopeClient, netip.MustParseAddr("203.0.113.1"))
			got, last := tt.steps(l, k)
			if got != tt.want {
				t.Fatalf("allowed %d, want %d", got, tt.want)
			}
			if tt.retry != 0 && (last < tt.retry-5*time.Millisecond || last > tt.retry+5*time.Millisecond) {
				t.Fatalf("wait %v, want %v", last, tt.retry)
			}
		})
	}
}

// spend asks n times at one moment and returns how many were allowed and the wait with the last denial.
func spend(l *limiter, k rlKey, s, b Limit, at time.Time, n int) (allowed int, wait time.Duration) {
	for i := 0; i < n; i++ {
		ok, w, _ := l.allow(k, s, b, at)
		if ok {
			allowed++
		} else {
			wait = w
		}
	}
	return allowed, wait
}

func TestClientKeys(t *testing.T) {
	l := newLimiter(1000, newClock().Now())
	l2 := newLimiter(1000, newClock().Now())
	a := netip.MustParseAddr("203.0.113.1")
	tests := []struct {
		name string
		x, y func() (rlKey, bool)
		same bool
	}{
		{"an address is its own key", func() (rlKey, bool) { return addrKey(scopeClient, a) }, func() (rlKey, bool) { return addrKey(scopeClient, a) }, true},
		{"two addresses differ", func() (rlKey, bool) { return addrKey(scopeClient, a) }, func() (rlKey, bool) { return addrKey(scopeClient, netip.MustParseAddr("203.0.113.2")) }, false},
		{"scopes differ", func() (rlKey, bool) { return addrKey(scopeClient, a) }, func() (rlKey, bool) { return addrKey(scopeAuth, a) }, false},
		{"an IPv4-mapped address is the IPv4 address", func() (rlKey, bool) { return addrKey(scopeClient, a) }, func() (rlKey, bool) { return addrKey(scopeClient, netip.MustParseAddr("::ffff:203.0.113.1")) }, true},
		{"addresses in one IPv6 /64 share a key", func() (rlKey, bool) { return addrKey(scopeClient, netip.MustParseAddr("2001:db8:1:2::1")) }, func() (rlKey, bool) { return addrKey(scopeClient, netip.MustParseAddr("2001:db8:1:2:ffff::9")) }, true},
		{"another /64 is another key", func() (rlKey, bool) { return addrKey(scopeClient, netip.MustParseAddr("2001:db8:1:2::1")) }, func() (rlKey, bool) { return addrKey(scopeClient, netip.MustParseAddr("2001:db8:1:3::1")) }, false},
		{"the same credential from the same address", func() (rlKey, bool) { return l.credKey(scopeClient, a, "Bearer abc") }, func() (rlKey, bool) { return l.credKey(scopeClient, a, "Bearer abc") }, true},
		{"another credential from the same address", func() (rlKey, bool) { return l.credKey(scopeClient, a, "Bearer abc") }, func() (rlKey, bool) { return l.credKey(scopeClient, a, "Bearer abd") }, false},
		{"the same credential from another address", func() (rlKey, bool) { return l.credKey(scopeClient, a, "Bearer abc") }, func() (rlKey, bool) { return l.credKey(scopeClient, netip.MustParseAddr("203.0.113.9"), "Bearer abc") }, false},
		{"a credential's key is not its address's key", func() (rlKey, bool) { return l.credKey(scopeClient, a, "Bearer abc") }, func() (rlKey, bool) { return addrKey(scopeClient, a) }, false},
		{"the credential hash is keyed per guard", func() (rlKey, bool) { return l.credKey(scopeClient, a, "Bearer abc") }, func() (rlKey, bool) { return l2.credKey(scopeClient, a, "Bearer abc") }, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			kx, okx := tt.x()
			ky, oky := tt.y()
			if !okx || !oky {
				t.Fatal("no key")
			}
			if (kx == ky) != tt.same {
				t.Fatalf("same = %v, want %v", kx == ky, tt.same)
			}
		})
	}
	if _, ok := addrKey(scopeClient, netip.Addr{}); ok {
		t.Error("an invalid address made a key")
	}
}

func TestACredentialIsNeverStoredOrLogged(t *testing.T) {
	g, _ := testGuard(t, func(c *Config) { c.Modes.Rate = ModeEnforce })
	secret := "Bearer SUPER-SECRET-TOKEN-0123456789"
	var logged []string
	for i := 0; i < 5; i++ {
		res := g.Inspect(mk("GET", "/api/items", withHeader("Authorization", secret)))
		for _, v := range res.Verdicts {
			logged = append(logged, v.Message)
		}
	}
	for i := range g.lim.shards {
		for k := range g.lim.shards[i].m {
			if bytes.Contains(k[:], []byte("SECRET")) {
				t.Fatal("the credential is in the table")
			}
		}
	}
	// Force a rate-limit message and check it too.
	for i := 0; i < 100; i++ {
		for _, v := range g.Inspect(mk("GET", "/api/items", withHeader("Authorization", secret))).Verdicts {
			logged = append(logged, v.Message)
		}
	}
	if len(logged) == 0 {
		t.Fatal("no verdict was produced, the check proves nothing")
	}
	if strings.Contains(strings.Join(logged, "\n"), "SECRET") {
		t.Fatal("the credential is in a verdict message")
	}
}

func TestTheTableIsBoundedAndEvictsOnlyWhatSaysNothing(t *testing.T) {
	sustained, burst := Limit{Burst: 5, Per: time.Minute}, Limit{Burst: 5, Per: time.Second}
	keyOf := func(i int) rlKey {
		k, _ := addrKey(scopeClient, netip.MustParseAddr(fmt.Sprintf("10.%d.%d.%d", i>>16&255, i>>8&255, i&255)))
		return k
	}
	t.Run("idle clients are forgotten to make room", func(t *testing.T) {
		clk := newClock()
		l := newLimiter(64, clk.Now()) // one place per shard
		for i := 0; i < 2000; i++ {
			l.allow(keyOf(i), sustained, burst, clk.Now().Add(time.Duration(i)*time.Minute)) // each is long idle before the next
		}
		if n := l.keys(); n > 64 {
			t.Fatalf("%d keys, limit 64", n)
		}
		if l.evicted.Load() == 0 || l.failOpen.Load() != 0 {
			t.Fatalf("evicted %d, failed open %d", l.evicted.Load(), l.failOpen.Load())
		}
	})
	t.Run("active clients are not forgotten, and the new one is let through uncounted", func(t *testing.T) {
		clk := newClock()
		l := newLimiter(64, clk.Now())
		for i := 0; i < 2000; i++ {
			l.allow(keyOf(i), sustained, burst, clk.Now()) // all at one moment: every one of them has spent a token
		}
		if n := l.keys(); n > 64 {
			t.Fatalf("%d keys, limit 64", n)
		}
		if l.failOpen.Load() == 0 {
			t.Fatal("a full table of active clients did not fail open")
		}
		ok, _, tracked := l.allow(keyOf(99999), sustained, burst, clk.Now())
		if !ok || tracked {
			t.Fatalf("a client that did not fit: allowed=%v tracked=%v", ok, tracked)
		}
	})
	t.Run("a client being limited keeps its state while others come and go", func(t *testing.T) {
		clk := newClock()
		l := newLimiter(6400, clk.Now())
		heavy := keyOf(1)
		spend(l, heavy, sustained, burst, clk.Now(), 20)
		for i := 100; i < 3000; i++ {
			l.allow(keyOf(i), sustained, burst, clk.Now())
		}
		if ok, _, _ := l.allow(heavy, sustained, burst, clk.Now()); ok {
			t.Fatal("a client that was being limited was handed a fresh bucket")
		}
	})
}

func TestRateLimitsThroughTheGuard(t *testing.T) {
	t.Run("the general limit is a warning by default", func(t *testing.T) {
		g, _ := testGuard(t, nil)
		var res = g.Inspect(mk("GET", "/api/items"))
		for i := 0; i < 60; i++ {
			res = g.Inspect(mk("GET", "/api/items"))
		}
		if !has(res, IDRateLimited) || blocked(res) {
			t.Fatalf("verdicts = %+v", res.Verdicts)
		}
	})
	t.Run("the general limit blocks when it is enforced, with Retry-After", func(t *testing.T) {
		g, _ := testGuard(t, func(c *Config) { c.Modes.Rate = ModeEnforce })
		var res = g.Inspect(mk("GET", "/api/items"))
		for i := 0; i < 60; i++ {
			res = g.Inspect(mk("GET", "/api/items"))
		}
		if !blocked(res) || res.Verdicts[0].Status != 429 || !strings.Contains(res.Verdicts[0].Message, "Retry-After: 1") {
			t.Fatalf("verdicts = %+v", res.Verdicts)
		}
	})
	t.Run("the limit is per client", func(t *testing.T) {
		g, _ := testGuard(t, func(c *Config) { c.Modes.Rate = ModeEnforce })
		for i := 0; i < 60; i++ {
			g.Inspect(mk("GET", "/api/items", withClient("203.0.113.1")))
		}
		if res := g.Inspect(mk("GET", "/api/items", withClient("203.0.113.2"))); len(res.Verdicts) != 0 {
			t.Fatalf("another client was limited: %+v", res.Verdicts)
		}
	})
	t.Run("the limit refills", func(t *testing.T) {
		g, clk := testGuard(t, func(c *Config) { c.Modes.Rate = ModeEnforce })
		for i := 0; i < 60; i++ {
			g.Inspect(mk("GET", "/api/items"))
		}
		clk.Advance(2 * time.Second)
		if res := g.Inspect(mk("GET", "/api/items")); len(res.Verdicts) != 0 {
			t.Fatalf("still limited after the bucket refilled: %+v", res.Verdicts)
		}
	})
	t.Run("an authentication endpoint is limited much sooner, and by default it blocks", func(t *testing.T) {
		g, _ := testGuard(t, nil)
		var res = g.Inspect(mk("POST", "/api/auth/login", withJSON(`{}`)))
		for i := 0; i < 10; i++ {
			res = g.Inspect(mk("POST", "/api/auth/login", withJSON(`{}`)))
		}
		if !has(res, IDAuthRateLimited) || !blocked(res) || res.Verdicts[0].Status != 429 {
			t.Fatalf("verdicts = %+v", res.Verdicts)
		}
	})
	t.Run("changing the credential does not escape the limit on a login endpoint", func(t *testing.T) {
		g, _ := testGuard(t, nil)
		var last = g.Inspect(mk("POST", "/api/login", withJSON(`{}`)))
		for i := 0; i < 12; i++ {
			last = g.Inspect(mk("POST", "/api/login", withJSON(`{}`), withHeader("Authorization", fmt.Sprintf("Bearer guess-%d", i))))
		}
		if !has(last, IDAuthRateLimited) {
			t.Fatalf("verdicts = %+v", last.Verdicts)
		}
	})
	t.Run("changing the credential does not escape the general limit either", func(t *testing.T) {
		g, _ := testGuard(t, func(c *Config) { c.Modes.Rate = ModeEnforce })
		var last = g.Inspect(mk("GET", "/api/items"))
		// 40 per second per client, four times that for the address as a whole: 200 requests with a new credential each time.
		for i := 0; i < 300; i++ {
			last = g.Inspect(mk("GET", "/api/items", withHeader("X-API-Key", fmt.Sprintf("key-%d", i))))
		}
		if !blocked(last) {
			t.Fatalf("a client rotating its key was never limited: %+v", last.Verdicts)
		}
	})
	t.Run("a request that is not an API request is not counted", func(t *testing.T) {
		g, _ := testGuard(t, func(c *Config) { c.Modes.Rate = ModeEnforce })
		for i := 0; i < 500; i++ {
			if res := g.Inspect(mk("GET", "/index.html")); len(res.Verdicts) != 0 {
				t.Fatalf("a page was limited: %+v", res.Verdicts)
			}
		}
		if g.Stats().RateKeys != 0 {
			t.Fatal("a page was counted")
		}
	})
	t.Run("a request with no client address is not counted", func(t *testing.T) {
		g, _ := testGuard(t, func(c *Config) { c.Modes.Rate = ModeEnforce })
		for i := 0; i < 500; i++ {
			r := mk("GET", "/api/items")
			r.Client = netip.Addr{}
			if res := g.Inspect(r); len(res.Verdicts) != 0 {
				t.Fatalf("limited: %+v", res.Verdicts)
			}
		}
		if g.Stats().RateNoClient != 500 {
			t.Fatalf("stats = %+v", g.Stats())
		}
	})
	t.Run("the table's fail-open is in the stats", func(t *testing.T) {
		g, _ := testGuard(t, func(c *Config) { c.Rate.MaxKeys = 64; c.Modes.Rate = ModeEnforce })
		for i := 0; i < 3000; i++ {
			g.Inspect(mk("GET", "/api/items", withClient(ip(i))))
		}
		if st := g.Stats(); st.RateFailOpen == 0 || st.RateKeys > 64 {
			t.Fatalf("stats = %+v", st)
		}
	})
}

func TestTheLimiterIsSafeForManyRequestsAtOnce(t *testing.T) {
	g, _ := testGuard(t, func(c *Config) { c.Modes.Rate = ModeEnforce })
	var wg sync.WaitGroup
	var limited atomic.Int64
	for w := 0; w < 16; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < 2000; i++ {
				res := g.Inspect(mk("GET", "/api/items", withClient(ip(i%40)), withHeader("Authorization", fmt.Sprintf("Bearer %d", i%7))))
				if blocked(res) {
					limited.Add(1)
				}
			}
		}(w)
	}
	wg.Wait()
	if limited.Load() == 0 {
		t.Fatal("32,000 requests from 40 clients in one instant were never limited")
	}
}
