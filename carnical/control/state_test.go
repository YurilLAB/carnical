// SPDX-License-Identifier: Apache-2.0

package control

import (
	"crypto/sha256"
	"math/rand"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

func nonce(i int) string {
	s := strconv.FormatInt(int64(i), 16)
	return "00000000000000000000000000000000"[:32-len(s)] + s
}

func TestReplayCacheUnit(t *testing.T) {
	const skew = 60 * time.Second
	t.Run("a nonce is fresh once", func(t *testing.T) {
		c := newReplayCache(100, 100, skew)
		if v := c.use("a", nonce(1), 1000, 1000); v != replayFresh {
			t.Fatalf("first: %v", v)
		}
		if v := c.use("a", nonce(1), 1000, 1000); v != replayRepeat {
			t.Fatalf("second: %v", v)
		}
		if !c.peek("a", nonce(1)) || c.peek("a", nonce(2)) || c.peek("b", nonce(1)) {
			t.Fatal("peek")
		}
	})
	t.Run("nonces belong to a credential", func(t *testing.T) {
		c := newReplayCache(100, 100, skew)
		c.use("a", nonce(1), 1000, 1000)
		if v := c.use("b", nonce(1), 1000, 1000); v != replayFresh {
			t.Fatalf("%v", v)
		}
	})
	t.Run("an entry is kept exactly as long as its request could still be accepted", func(t *testing.T) {
		// a request with timestamp ts is accepted while now is in [ts-60, ts+60], so its nonce lives until ts+61
		c := newReplayCache(100, 100, skew)
		c.use("a", nonce(1), 1000, 1000)
		for _, now := range []int64{1000, 1030, 1059, 1060} {
			c.mu.Lock()
			c.purge(now)
			c.mu.Unlock()
			if !c.peek("a", nonce(1)) {
				t.Fatalf("forgotten at %d, when a replay would still be accepted", now)
			}
		}
		c.mu.Lock()
		c.purge(1061)
		c.mu.Unlock()
		if c.peek("a", nonce(1)) || c.size() != 0 {
			t.Fatal("kept after it could no longer be accepted")
		}
	})
	t.Run("a request timestamped in the future is remembered longer", func(t *testing.T) {
		c := newReplayCache(100, 100, skew)
		c.use("a", nonce(1), 1060, 1000) // 60 seconds ahead: accepted until 1120
		c.mu.Lock()
		c.purge(1120)
		c.mu.Unlock()
		if !c.peek("a", nonce(1)) {
			t.Fatal("forgotten while still replayable")
		}
		c.mu.Lock()
		c.purge(1121)
		c.mu.Unlock()
		if c.peek("a", nonce(1)) {
			t.Fatal("kept too long")
		}
	})
	t.Run("when full it refuses new nonces and keeps the old ones", func(t *testing.T) {
		c := newReplayCache(3, 100, skew)
		for i := 1; i <= 3; i++ {
			if v := c.use("a", nonce(i), 1000, 1000); v != replayFresh {
				t.Fatalf("%d: %v", i, v)
			}
		}
		if v := c.use("a", nonce(4), 1000, 1000); v != replayFull {
			t.Fatalf("a fourth: %v", v)
		}
		if v := c.use("b", nonce(5), 1000, 1000); v != replayFull {
			t.Fatalf("another credential when the whole cache is full: %v", v)
		}
		for i := 1; i <= 3; i++ {
			if v := c.use("a", nonce(i), 1000, 1000); v != replayRepeat {
				t.Fatalf("nonce %d was forgotten to make room: %v", i, v)
			}
		}
		if c.full != 2 {
			t.Fatalf("full counted %d", c.full)
		}
		// it recovers once the old ones are too old to matter
		if v := c.use("a", nonce(4), 1100, 1100); v != replayFresh {
			t.Fatalf("after the window: %v", v)
		}
	})
	t.Run("one credential cannot use the whole cache", func(t *testing.T) {
		c := newReplayCache(10, 3, skew)
		for i := 1; i <= 3; i++ {
			c.use("a", nonce(i), 1000, 1000)
		}
		if v := c.use("a", nonce(4), 1000, 1000); v != replayFull {
			t.Fatalf("%v", v)
		}
		if v := c.use("b", nonce(1), 1000, 1000); v != replayFresh {
			t.Fatalf("another credential: %v", v)
		}
	})
	t.Run("against a simple model, with random times", func(t *testing.T) {
		// the model: a nonce is a repeat exactly while now <= ts+skew for the request that first used it
		rng := rand.New(rand.NewSource(7))
		c := newReplayCache(1_000_000, 1_000_000, skew)
		type rec struct{ ts int64 }
		model := map[string]rec{}
		now := int64(10_000)
		for op := 0; op < 30_000; op++ {
			now += int64(rng.Intn(3))
			cred := []string{"a", "b", "c"}[rng.Intn(3)]
			n := nonce(rng.Intn(400))
			ts := now + int64(rng.Intn(121)) - 60
			key := cred + n
			want := replayFresh
			if r, ok := model[key]; ok && now <= r.ts+60 {
				want = replayRepeat
			}
			got := c.use(cred, n, ts, now)
			if got != want {
				t.Fatalf("op %d: got %v, want %v (now %d, ts %d, first used with %+v)", op, got, want, now, ts, model[key])
			}
			if got == replayFresh {
				model[key] = rec{ts}
			}
		}
	})
	t.Run("many goroutines using one nonce: exactly one is fresh", func(t *testing.T) {
		c := newReplayCache(1000, 1000, skew)
		var wg sync.WaitGroup
		var mu sync.Mutex
		fresh := 0
		for i := 0; i < 64; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				if c.use("a", nonce(1), 1000, 1000) == replayFresh {
					mu.Lock()
					fresh++
					mu.Unlock()
				}
			}()
		}
		wg.Wait()
		if fresh != 1 {
			t.Fatalf("%d goroutines were told the nonce was fresh", fresh)
		}
	})
}

func TestFailureLimiterUnit(t *testing.T) {
	t0 := time.Unix(1_000_000, 0)
	mk := func() *failureLimiter { return newFailureLimiter(100, 3, time.Second, time.Minute, 10*time.Minute) }
	t.Run("nothing happens below the threshold", func(t *testing.T) {
		l := mk()
		for i := 0; i < 2; i++ {
			if d := l.fail("k", t0); d != 0 {
				t.Fatalf("failure %d earned %v", i+1, d)
			}
		}
		if l.wait("k", t0) != 0 {
			t.Fatal("waiting below the threshold")
		}
	})
	t.Run("the wait doubles with each failure and stops at the maximum", func(t *testing.T) {
		l := mk()
		l.fail("k", t0)
		l.fail("k", t0)
		want := []time.Duration{1, 2, 4, 8, 16, 32, 60, 60, 60}
		for i, w := range want {
			got := l.fail("k", t0)
			if got != w*time.Second {
				t.Fatalf("failure %d earned %v, want %v", i+3, got, w*time.Second)
			}
		}
		for i := 0; i < 200; i++ {
			if d := l.fail("k", t0); d != time.Minute {
				t.Fatalf("after many failures the wait is %v", d)
			}
		}
	})
	t.Run("the wait runs down with time", func(t *testing.T) {
		l := mk()
		for i := 0; i < 5; i++ {
			l.fail("k", t0) // the fifth earned 4 seconds
		}
		for _, tc := range []struct {
			after time.Duration
			want  time.Duration
		}{{0, 4 * time.Second}, {time.Second, 3 * time.Second}, {3999 * time.Millisecond, time.Millisecond}, {4 * time.Second, 0}, {time.Hour, 0}} {
			if got := l.wait("k", t0.Add(tc.after)); got != tc.want {
				t.Fatalf("after %v the wait is %v, want %v", tc.after, got, tc.want)
			}
		}
	})
	t.Run("keys are separate", func(t *testing.T) {
		l := mk()
		for i := 0; i < 5; i++ {
			l.fail("a", t0)
		}
		if l.wait("b", t0) != 0 {
			t.Fatal("b waits for a's failures")
		}
	})
	t.Run("a long quiet time starts a key again", func(t *testing.T) {
		l := mk()
		for i := 0; i < 10; i++ {
			l.fail("k", t0)
		}
		later := t0.Add(11 * time.Minute)
		if d := l.fail("k", later); d != 0 {
			t.Fatalf("a failure after a long quiet time earned %v", d)
		}
	})
	t.Run("a failure while still waiting makes it longer, not fresh", func(t *testing.T) {
		l := mk()
		for i := 0; i < 3; i++ {
			l.fail("k", t0) // waits 1s
		}
		if d := l.fail("k", t0.Add(500*time.Millisecond)); d != 2*time.Second {
			t.Fatalf("%v", d)
		}
	})
	t.Run("success clears the history", func(t *testing.T) {
		l := mk()
		for i := 0; i < 5; i++ {
			l.fail("k", t0)
		}
		l.succeed("k")
		if l.wait("k", t0) != 0 || l.size() != 0 {
			t.Fatal("not cleared")
		}
		if d := l.fail("k", t0); d != 0 {
			t.Fatalf("history survived: %v", d)
		}
	})
	t.Run("a block is announced once", func(t *testing.T) {
		l := mk()
		if l.firstBlocked("k") {
			t.Fatal("announced a key that is not blocked")
		}
		for i := 0; i < 3; i++ {
			l.fail("k", t0)
		}
		if !l.firstBlocked("k") || l.firstBlocked("k") || l.firstBlocked("k") {
			t.Fatal("not announced exactly once")
		}
		l.fail("k", t0.Add(2*time.Second)) // a longer wait is a new block
		if !l.firstBlocked("k") {
			t.Fatal("a new wait was not announced")
		}
	})
	t.Run("the table never grows past its bound", func(t *testing.T) {
		l := mk()
		for i := 0; i < 5000; i++ {
			l.fail("k"+strconv.Itoa(i), t0)
			if l.size() > 100 {
				t.Fatalf("%d keys", l.size())
			}
		}
		// even when every key is waiting
		l2 := newFailureLimiter(50, 1, time.Hour, time.Hour, time.Hour)
		for i := 0; i < 500; i++ {
			l2.fail("k"+strconv.Itoa(i), t0)
			if l2.size() > 50 {
				t.Fatalf("%d keys, all waiting", l2.size())
			}
		}
	})
	t.Run("expired keys are dropped before live ones", func(t *testing.T) {
		l := newFailureLimiter(10, 1, time.Second, time.Second, time.Minute)
		for i := 0; i < 5; i++ {
			l.fail("old"+strconv.Itoa(i), t0)
		}
		later := t0.Add(2 * time.Minute)
		for i := 0; i < 5; i++ {
			l.fail("live"+strconv.Itoa(i), later)
		}
		l.fail("new", later) // the table is full: the old, expired keys go first
		for i := 0; i < 5; i++ {
			if l.wait("live"+strconv.Itoa(i), later) == 0 {
				t.Fatalf("a live key was dropped while expired ones remained")
			}
		}
	})
	t.Run("a huge number of failures does not overflow", func(t *testing.T) {
		l := newFailureLimiter(10, 1, time.Second, 15*time.Minute, time.Hour)
		for i := 0; i < 300; i++ {
			if d := l.fail("k", t0); d <= 0 || d > 15*time.Minute {
				t.Fatalf("failure %d earned %v", i, d)
			}
		}
	})
}

func TestIdempotencyUnit(t *testing.T) {
	t0 := time.Unix(1_000_000, 0)
	h1, h2 := sha256.Sum256([]byte("one")), sha256.Sum256([]byte("two"))
	t.Run("expiry is checked even between periodic sweeps", func(t *testing.T) {
		s := newIdempotency(10, 10, 100*time.Millisecond)
		s.begin("c", "k", h1, t0)
		s.finish("k", 200, nil, t0)
		if v, _, _ := s.begin("c", "k", h2, t0.Add(100*time.Millisecond)); v != idemNew {
			t.Fatalf("expired key was retained until the next sweep: %v", v)
		}
		if len(s.m) != 1 || s.counts["c"] != 1 {
			t.Fatalf("expired replacement changed accounting: entries=%d counts=%v", len(s.m), s.counts)
		}
	})
	t.Run("a key is claimed once and replays its answer", func(t *testing.T) {
		s := newIdempotency(10, 10, time.Hour)
		if v, _, _ := s.begin("c", "k", h1, t0); v != idemNew {
			t.Fatalf("%v", v)
		}
		if v, _, _ := s.begin("c", "k", h1, t0); v != idemBusy {
			t.Fatalf("while in progress: %v", v)
		}
		s.finish("k", 200, []byte(`{"ok":true}`), t0)
		v, status, body := s.begin("c", "k", h1, t0)
		if v != idemReplay || status != 200 || string(body) != `{"ok":true}` {
			t.Fatalf("%v %d %s", v, status, body)
		}
	})
	t.Run("the same key with another request is a mismatch, before and after the answer", func(t *testing.T) {
		s := newIdempotency(10, 10, time.Hour)
		s.begin("c", "k", h1, t0)
		if v, _, _ := s.begin("c", "k", h2, t0); v != idemMismatch {
			t.Fatalf("in progress: %v", v)
		}
		s.finish("k", 200, nil, t0)
		if v, _, _ := s.begin("c", "k", h2, t0); v != idemMismatch {
			t.Fatalf("done: %v", v)
		}
	})
	t.Run("an abandoned key can be used again", func(t *testing.T) {
		s := newIdempotency(10, 10, time.Hour)
		s.begin("c", "k", h1, t0)
		s.abandon("k")
		if v, _, _ := s.begin("c", "k", h2, t0); v != idemNew {
			t.Fatalf("%v", v)
		}
		s.finish("k", 200, nil, t0)
		s.abandon("k") // a finished key cannot be abandoned
		if v, _, _ := s.begin("c", "k", h2, t0); v != idemReplay {
			t.Fatalf("%v", v)
		}
	})
	t.Run("keys expire", func(t *testing.T) {
		s := newIdempotency(10, 10, time.Hour)
		s.begin("c", "k", h1, t0)
		s.finish("k", 200, nil, t0)
		if v, _, _ := s.begin("c", "k", h1, t0.Add(59*time.Minute)); v != idemReplay {
			t.Fatalf("%v", v)
		}
		if v, _, _ := s.begin("c", "k", h2, t0.Add(61*time.Minute)); v != idemNew {
			t.Fatalf("after the window: %v", v)
		}
	})
	t.Run("the table and each credential are bounded, and nothing is forgotten to make room", func(t *testing.T) {
		s := newIdempotency(3, 2, time.Hour)
		s.begin("a", "k1", h1, t0)
		s.begin("a", "k2", h1, t0)
		if v, _, _ := s.begin("a", "k3", h1, t0); v != idemFull {
			t.Fatalf("per credential: %v", v)
		}
		s.begin("b", "k4", h1, t0)
		if v, _, _ := s.begin("c", "k5", h1, t0); v != idemFull {
			t.Fatalf("in all: %v", v)
		}
		for _, k := range []string{"k1", "k2", "k4"} {
			if v, _, _ := s.begin("x", k, h1, t0); v != idemBusy {
				t.Fatalf("%s was forgotten: %v", k, v)
			}
		}
		// Long-running claims still count against both bounds after the answer
		// retention period has passed. A failed operation releases its place.
		later := t0.Add(2 * time.Hour)
		if v, _, _ := s.begin("a", "k3", h1, later); v != idemFull {
			t.Fatalf("old unfinished claims escaped their caps: %v", v)
		}
		s.abandon("k1")
		if v, _, _ := s.begin("a", "k3", h1, later); v != idemNew {
			t.Fatalf("abandon did not free capacity: %v", v)
		}
	})
	t.Run("the answer is copied", func(t *testing.T) {
		s := newIdempotency(10, 10, time.Hour)
		s.begin("c", "k", h1, t0)
		b := []byte("abc")
		s.finish("k", 200, b, t0)
		b[0] = 'X'
		if _, _, got := s.begin("c", "k", h1, t0); string(got) != "abc" {
			t.Fatalf("%s", got)
		}
	})
}

func TestGateAndCounter(t *testing.T) {
	t0 := time.Unix(1000, 0)
	g := newGate(3)
	if !g.allow("a", t0, 10*time.Second) || g.allow("a", t0.Add(5*time.Second), 10*time.Second) || !g.allow("a", t0.Add(11*time.Second), 10*time.Second) {
		t.Fatal("gate timing")
	}
	g.allow("b", t0, 10*time.Second)
	g.allow("c", t0, 10*time.Second)
	if g.allow("d", t0, 10*time.Second) {
		t.Fatal("a full gate full of recent checks let another through")
	}
	if !g.allow("d", t0.Add(30*time.Second), 10*time.Second) {
		t.Fatal("old entries were not dropped to make room")
	}
	c := newCounter(2)
	if !c.acquire("a") || !c.acquire("a") || c.acquire("a") || !c.acquire("b") {
		t.Fatal("counter limits")
	}
	c.release("a")
	if !c.acquire("a") {
		t.Fatal("release did not free a place")
	}
	c.release("a")
	c.release("a")
	c.release("b")
	if len(c.m) != 0 {
		t.Fatalf("%d keys left", len(c.m))
	}
}

// ------------------------------------------------------------------------------------------------ through the server

func TestFailingSourcesWait(t *testing.T) {
	h := newHarness(t, func(c *Config) { c.Limits.FailureThreshold = 3 })
	status := "/v1/tenants/" + tenantA + "/status"
	bad := func(remote string) int { return h.do(reqOpts{target: status, keyAs: "ui-b", remote: remote}).Code }
	good := func(remote string) *httptest.ResponseRecorder {
		return h.do(reqOpts{target: status, remote: remote})
	}
	src := "198.51.100.10:4000"
	for i, want := range []int{401, 401, 429} {
		// the third failure starts the waiting, and says so in its own answer
		if c := bad(src); c != want {
			t.Fatalf("failure %d: %d, want %d", i+1, c, want)
		}
	}
	// the third failure earned a wait: even a perfectly good request from this address is refused, unread
	w := good(src)
	if w.Code != 429 || errorOf(t, w).Code != "too_many_failures" || w.Header().Get("Retry-After") != "1" {
		t.Fatalf("a good request from a failing source: %d %s retry %q", w.Code, w.Body.String(), w.Header().Get("Retry-After"))
	}
	// another address is not affected
	if w := good("198.51.100.11:4000"); w.Code != 200 {
		t.Fatalf("another source: %d", w.Code)
	}
	// the port does not matter, the address does
	if w := good("198.51.100.10:9999"); w.Code != 429 {
		t.Fatalf("the same address on another port: %d", w.Code)
	}
	// blocked requests are one audit line, not one each
	h.do(reqOpts{target: status, remote: src})
	h.do(reqOpts{target: status, remote: src})
	blocks := 0
	for _, e := range h.audit.all() {
		if e.Detail == "source_blocked" {
			blocks++
		}
	}
	if blocks != 1 {
		t.Fatalf("%d audit lines for a flood of blocked requests", blocks)
	}
	// the wait ends
	h.clock.advance(1100 * time.Millisecond)
	if w := good(src); w.Code != 200 {
		t.Fatalf("after the wait: %d", w.Code)
	}
	// a success clears the history: two more failures do not block
	bad(src)
	bad(src)
	if w := good(src); w.Code != 200 {
		t.Fatalf("history was not cleared by the success: %d", w.Code)
	}
}

func TestBackoffDoublesThroughTheServer(t *testing.T) {
	h := newHarness(t, func(c *Config) {
		c.Limits.FailureThreshold = 2
		c.Limits.BackoffBase = time.Second
		c.Limits.BackoffMax = 8 * time.Second
	})
	status := "/v1/tenants/" + tenantA + "/status"
	src := "198.51.100.10:4000"
	var waits []string
	for i := 0; i < 7; i++ {
		w := h.do(reqOpts{target: status, keyAs: "ui-b", remote: src})
		if w.Code == 429 {
			waits = append(waits, w.Header().Get("Retry-After"))
			// wait it out, and fail again as soon as the wait is over
			h.clock.advance(time.Duration(mustAtoi(w.Header().Get("Retry-After"))) * time.Second)
		}
	}
	if got := strings.Join(waits, ","); got != "1,2,4,8,8,8" {
		t.Fatalf("the waits were %s, want 1,2,4,8,8,8 (doubling, then the maximum)", got)
	}
}

func mustAtoi(s string) int {
	n, _ := strconv.Atoi(s)
	return n
}

func TestIPv6SourcesShareTheirSlash64(t *testing.T) {
	h := newHarness(t, func(c *Config) { c.Limits.FailureThreshold = 3 })
	status := "/v1/tenants/" + tenantA + "/status"
	for i := 1; i <= 3; i++ {
		h.do(reqOpts{target: status, keyAs: "ui-b", remote: "[2001:db8:1:2::" + strconv.Itoa(i) + "]:4000"})
	}
	// another address in the same /64 waits too; one in another /64 does not
	if w := h.do(reqOpts{target: status, remote: "[2001:db8:1:2:ffff::9]:4000"}); w.Code != 429 {
		t.Fatalf("the same /64: %d", w.Code)
	}
	if w := h.do(reqOpts{target: status, remote: "[2001:db8:1:3::1]:4000"}); w.Code != 200 {
		t.Fatalf("another /64: %d", w.Code)
	}
	// an IPv4 address written as IPv6 is the IPv4 address
	for i := 1; i <= 3; i++ {
		h.do(reqOpts{target: status, keyAs: "ui-b", remote: "198.51.100.77:4000"})
	}
	if w := h.do(reqOpts{target: status, remote: "[::ffff:198.51.100.77]:4000"}); w.Code != 429 {
		t.Fatalf("an IPv4-mapped address: %d", w.Code)
	}
}

// The credential's own failures slow down whoever is failing, but never a request that authenticates: otherwise anyone
// holding a stolen certificate could lock the real UI out of its own credential.
func TestCredentialBackoffNeverLocksOutTheRealCaller(t *testing.T) {
	h := newHarness(t, func(c *Config) { c.Limits.FailureThreshold = 3 })
	status := "/v1/tenants/" + tenantA + "/status"
	var attacker []int
	for i := 0; i < 8; i++ {
		// a different source each time, so only the credential's bucket can slow them down
		w := h.do(reqOpts{target: status, keyAs: "ui-b", remote: "203.0.113." + strconv.Itoa(10+i) + ":4000"})
		attacker = append(attacker, w.Code)
	}
	want := []int{401, 401, 429, 429, 429, 429, 429, 429}
	if len(attacker) != len(want) {
		t.Fatal("setup")
	}
	for i := range want {
		if attacker[i] != want[i] {
			t.Fatalf("the attacker's answers were %v, want %v", attacker, want)
		}
	}
	// the real caller, from its own address, still gets in
	if w := h.do(reqOpts{target: status}); w.Code != 200 {
		t.Fatalf("the real caller was locked out: %d %s", w.Code, w.Body.String())
	}
}

// An unknown credential id is treated exactly like a known one, so the sequence of answers cannot tell them apart.
func TestUnknownAndKnownCredentialsGetTheSameAnswers(t *testing.T) {
	sequence := func(claimed string) []int {
		h := newHarness(t, func(c *Config) { c.Limits.FailureThreshold = 3 })
		status := "/v1/tenants/" + tenantA + "/status"
		var out []int
		for i := 0; i < 8; i++ {
			w := h.do(reqOpts{as: claimed, keyAs: "ui-b", target: status, remote: "203.0.113." + strconv.Itoa(10+i) + ":4000"})
			out = append(out, w.Code)
		}
		return out
	}
	known, unknown := sequence("ui-a"), sequence("nobody-here")
	for i := range known {
		if known[i] != unknown[i] {
			t.Fatalf("known %v, unknown %v", known, unknown)
		}
	}
}

func TestTheFailureTableIsBoundedByTheServer(t *testing.T) {
	h := newHarness(t, func(c *Config) { c.Limits.FailureKeys = 200 })
	status := "/v1/tenants/" + tenantA + "/status"
	for i := 0; i < 2000; i++ {
		h.do(reqOpts{target: status, keyAs: "ui-b", remote: "10." + strconv.Itoa(i/250) + "." + strconv.Itoa(i%250) + ".1:4000", as: "ghost-" + strconv.Itoa(i)})
		if n := h.srv.Stats().FailingKeys; n > 200 {
			t.Fatalf("%d keys after %d failures", n, i+1)
		}
	}
}

func TestACacheFullRefusalIsNotAFailureOfTheCaller(t *testing.T) {
	h := newHarness(t, func(c *Config) { c.Limits.ReplayMaxPerCredential = 1; c.Limits.FailureThreshold = 2 })
	status := "/v1/tenants/" + tenantA + "/status"
	h.do(reqOpts{target: status})
	for i := 0; i < 5; i++ {
		if w := h.do(reqOpts{target: status}); w.Code != 503 {
			t.Fatalf("%d: %d", i, w.Code)
		}
	}
	if h.srv.Stats().FailingKeys != 0 || h.srv.Stats().AuthFailures != 0 {
		t.Fatalf("the server's own shortage counted against the caller: %+v", h.srv.Stats())
	}
}
