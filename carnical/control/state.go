// SPDX-License-Identifier: Apache-2.0

package control

import (
	"container/heap"
	"crypto/sha256"
	"runtime"
	"sync"
	"time"
)

func isWindows() bool { return runtime.GOOS == "windows" }

// ------------------------------------------------------------------------------------------------ replay cache

// replayCache remembers the nonces of requests that were accepted, so a captured request cannot be sent again while
// its timestamp is still in range. It is bounded in memory and does not forget: an entry leaves only once the request
// it came from would be refused for its age anyway. When it is full it says so and refuses new requests, because the
// alternative, to forget a nonce, is to allow a replay.
//
// Only requests that already carry a valid signature are put in (see Server.authenticate), so an attacker with no key
// cannot fill it.
type replayCache struct {
	mu         sync.Mutex
	seen       map[string]map[string]struct{} // credential id -> nonces
	exp        replayHeap
	total      int
	maxTotal   int
	maxPerCred int
	skew       int64 // seconds
	full       uint64
}

type replayEntry struct {
	expires     int64
	cred, nonce string
}

type replayHeap []replayEntry

func (h replayHeap) Len() int           { return len(h) }
func (h replayHeap) Less(i, j int) bool { return h[i].expires < h[j].expires }
func (h replayHeap) Swap(i, j int)      { h[i], h[j] = h[j], h[i] }
func (h *replayHeap) Push(x any)        { *h = append(*h, x.(replayEntry)) }
func (h *replayHeap) Pop() any {
	old := *h
	n := len(old)
	x := old[n-1]
	*h = old[:n-1]
	return x
}

func newReplayCache(maxTotal, maxPerCred int, skew time.Duration) *replayCache {
	return &replayCache{seen: map[string]map[string]struct{}{}, maxTotal: maxTotal, maxPerCred: maxPerCred, skew: int64(skew / time.Second)}
}

type replayVerdict int

const (
	replayFresh replayVerdict = iota
	replayRepeat
	replayFull
)

// purge drops entries whose requests are now too old to be accepted. It holds c.mu.
func (c *replayCache) purge(now int64) {
	for len(c.exp) > 0 && c.exp[0].expires <= now {
		e := heap.Pop(&c.exp).(replayEntry)
		if set := c.seen[e.cred]; set != nil {
			delete(set, e.nonce)
			if len(set) == 0 {
				delete(c.seen, e.cred)
			}
			c.total--
		}
	}
}

// use records a nonce, atomically with the check that it is new.
func (c *replayCache) use(cred, nonce string, ts, now int64) replayVerdict {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.purge(now)
	set := c.seen[cred]
	if _, dup := set[nonce]; dup {
		return replayRepeat
	}
	if c.total >= c.maxTotal || len(set) >= c.maxPerCred {
		c.full++
		return replayFull
	}
	if set == nil {
		set = map[string]struct{}{}
		c.seen[cred] = set
	}
	set[nonce] = struct{}{}
	c.total++
	heap.Push(&c.exp, replayEntry{expires: ts + c.skew + 1, cred: cred, nonce: nonce})
	return replayFresh
}

// peek reports whether a nonce is already remembered, without recording it. The authentication path calls it for
// every request so that a repeated nonce costs the same as a new one.
func (c *replayCache) peek(cred, nonce string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	_, dup := c.seen[cred][nonce]
	return dup
}

func (c *replayCache) size() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.total
}

// ------------------------------------------------------------------------------------------------ failure limiter

// failureLimiter slows down whoever keeps failing to authenticate. Each key (a source address, or a credential id as
// the request claimed it) has a count of recent failures; from the threshold on, each further failure doubles a wait
// that starts at base and stops at max. A key that fails less often than once in `decay` starts again.
//
// The table is bounded. When it is full of keys that are still waiting, an arbitrary key is dropped to make room: that
// forgets one attacker's history, which costs less than letting the table grow without limit.
type failureLimiter struct {
	mu        sync.Mutex
	m         map[string]*failState
	maxKeys   int
	threshold int
	base, max time.Duration
	decay     time.Duration
	swept     time.Time
}

type failState struct {
	fails int
	last  time.Time
	until time.Time
	noted bool
}

func newFailureLimiter(maxKeys, threshold int, base, max, decay time.Duration) *failureLimiter {
	return &failureLimiter{m: map[string]*failState{}, maxKeys: maxKeys, threshold: threshold, base: base, max: max, decay: decay}
}

// wait returns how long the key must still wait, or 0.
func (l *failureLimiter) wait(key string, now time.Time) time.Duration {
	l.mu.Lock()
	defer l.mu.Unlock()
	s := l.m[key]
	if s == nil || !s.until.After(now) {
		return 0
	}
	return s.until.Sub(now)
}

// fail records a failure and returns the wait it earned (0 below the threshold).
func (l *failureLimiter) fail(key string, now time.Time) time.Duration {
	l.mu.Lock()
	defer l.mu.Unlock()
	s := l.m[key]
	if s == nil {
		l.makeRoom(now)
		s = &failState{}
		l.m[key] = s
	}
	if now.Sub(s.last) > l.decay {
		s.fails = 0
	}
	s.fails++
	s.last = now
	if s.fails < l.threshold {
		return 0
	}
	shift := s.fails - l.threshold
	d := l.max
	if shift < 30 {
		if v := l.base << shift; v > 0 && v < l.max {
			d = v
		}
	}
	s.until, s.noted = now.Add(d), false
	return d
}

// succeed clears a key's history.
func (l *failureLimiter) succeed(key string) {
	l.mu.Lock()
	delete(l.m, key)
	l.mu.Unlock()
}

// firstBlocked reports true once for each wait a key is given, so that a flood of blocked requests is one audit line.
func (l *failureLimiter) firstBlocked(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	s := l.m[key]
	if s == nil || s.noted {
		return false
	}
	s.noted = true
	return true
}

func (l *failureLimiter) size() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.m)
}

// makeRoom keeps the table under maxKeys. It holds l.mu.
func (l *failureLimiter) makeRoom(now time.Time) {
	if len(l.m) < l.maxKeys {
		return
	}
	if now.Sub(l.swept) >= time.Second {
		l.swept = now
		for k, s := range l.m {
			if !s.until.After(now) && now.Sub(s.last) > l.decay {
				delete(l.m, k)
			}
		}
		if len(l.m) < l.maxKeys {
			return
		}
	}
	// still full: drop keys that are not waiting first, then any key (map order is random)
	for k, s := range l.m {
		if !s.until.After(now) {
			delete(l.m, k)
			return
		}
	}
	for k := range l.m {
		delete(l.m, k)
		return
	}
}

// ------------------------------------------------------------------------------------------------ idempotency

// idempotency makes a publish that is repeated (the first answer never arrived) do its work once. A key belongs to one
// credential and one tenant, and is tied to the request it first came with: the same key with a different request is an
// error, not a replay of the first answer.
type idempotency struct {
	mu     sync.Mutex
	m      map[string]*idemEntry
	max    int
	perCap int
	ttl    time.Duration
	swept  time.Time
	counts map[string]int // credential -> entries
}

type idemEntry struct {
	cred    string
	reqHash [sha256.Size]byte
	done    bool
	status  int
	body    []byte
	expires time.Time
}

type idemVerdict int

const (
	idemNew idemVerdict = iota
	idemReplay
	idemMismatch
	idemBusy
	idemFull
)

func newIdempotency(max, perCred int, ttl time.Duration) *idempotency {
	return &idempotency{m: map[string]*idemEntry{}, counts: map[string]int{}, max: max, perCap: perCred, ttl: ttl}
}

func (s *idempotency) sweep(now time.Time) {
	if now.Sub(s.swept) < time.Second {
		return
	}
	s.swept = now
	for k, e := range s.m {
		if !e.expires.After(now) {
			s.drop(k, e)
		}
	}
}

func (s *idempotency) drop(k string, e *idemEntry) {
	delete(s.m, k)
	if s.counts[e.cred]--; s.counts[e.cred] <= 0 {
		delete(s.counts, e.cred)
	}
}

// begin claims a key. For idemReplay the stored answer is returned.
func (s *idempotency) begin(cred, key string, reqHash [sha256.Size]byte, now time.Time) (idemVerdict, int, []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sweep(now)
	if e := s.m[key]; e != nil {
		switch {
		case e.reqHash != reqHash:
			return idemMismatch, 0, nil
		case !e.done:
			return idemBusy, 0, nil
		default:
			return idemReplay, e.status, e.body
		}
	}
	if len(s.m) >= s.max || s.counts[cred] >= s.perCap {
		return idemFull, 0, nil
	}
	s.m[key] = &idemEntry{cred: cred, reqHash: reqHash, expires: now.Add(s.ttl)}
	s.counts[cred]++
	return idemNew, 0, nil
}

// finish stores the answer of a request whose key was claimed.
func (s *idempotency) finish(key string, status int, body []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if e := s.m[key]; e != nil {
		e.done, e.status, e.body = true, status, append([]byte(nil), body...)
	}
}

// abandon releases a key whose request failed, so that it can be tried again.
func (s *idempotency) abandon(key string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if e := s.m[key]; e != nil && !e.done {
		s.drop(key, e)
	}
}

// ------------------------------------------------------------------------------------------------ small gates

// gate allows an action for a key at most once in a while. It is bounded the same way the limiter is.
type gate struct {
	mu   sync.Mutex
	last map[string]time.Time
	max  int
}

func newGate(max int) *gate { return &gate{last: map[string]time.Time{}, max: max} }

func (g *gate) allow(key string, now time.Time, every time.Duration) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	if t, ok := g.last[key]; ok && now.Sub(t) < every {
		return false
	}
	if len(g.last) >= g.max {
		for k, t := range g.last {
			if now.Sub(t) >= every {
				delete(g.last, k)
			}
		}
		if len(g.last) >= g.max {
			return false // full of recent checks: refuse rather than forget one
		}
	}
	g.last[key] = now
	return true
}

// counter limits how many things a key has in flight.
type counter struct {
	mu  sync.Mutex
	m   map[string]int
	max int
}

func newCounter(max int) *counter { return &counter{m: map[string]int{}, max: max} }

func (c *counter) acquire(key string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.m[key] >= c.max {
		return false
	}
	c.m[key]++
	return true
}

func (c *counter) release(key string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.m[key]--; c.m[key] <= 0 {
		delete(c.m, key)
	}
}
