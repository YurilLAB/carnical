// SPDX-License-Identifier: Apache-2.0

package apiguard

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"hash"
	"hash/maphash"
	"math"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"
)

// Limit is a token bucket: up to Burst requests at once, refilled evenly over Per. A client that spends the bucket must wait for
// it to refill, so over a long time it gets Burst per Per, and in a short time it gets at most Burst.
type Limit struct {
	Burst int           `json:"burst"`
	Per   time.Duration `json:"per"`
}

func (l Limit) rate() float64 { return float64(l.Burst) / float64(l.Per) } // tokens per nanosecond

// Scopes keep one client's different counts apart in one table.
const (
	scopeClient byte = 'c' // a client: address and credential together
	scopeAddr   byte = 'a' // an address, whatever credential it presents
	scopeAuth   byte = 'u' // an address on an authentication endpoint
)

const (
	rlShards   = 64
	rlEvictTry = 8
	// maxCredentialBytes is how much of a credential is hashed. A credential longer than this is cut, which only means two
	// credentials that share their first 4 KiB are counted as one client.
	maxCredentialBytes = 4096
)

type rlKey [16]byte

type bucket struct {
	tokens float64
	at     int64 // nanoseconds since the limiter began
}

type rlEntry struct {
	key        rlKey
	prev, next *rlEntry
	sustained  bucket
	burst      bucket
	fullAt     int64 // when both buckets will be full again, after which the entry says nothing and may be forgotten
}

type rlShard struct {
	mu   sync.Mutex
	m    map[rlKey]*rlEntry
	head *rlEntry // most recently used
	tail *rlEntry // least recently used
}

// limiter counts requests per client with a bounded amount of memory. The table holds at most maxKeys clients. When it is full, a
// client that has not been seen for as long as its buckets take to refill is forgotten (it would be handed a full bucket anyway,
// so nothing is lost), and if there is none the new client is let through uncounted and Stats.RateFailOpen goes up. That is the
// choice to make: a table that forgot a client who is being limited would let it start again, and one that refused the new client
// would let anyone who can invent many addresses lock everyone else out.
type limiter struct {
	shards   [rlShards]rlShard
	seed     maphash.Seed
	macKey   []byte
	macs     sync.Pool
	epoch    time.Time
	perShard int
	evicted  atomic.Uint64
	failOpen atomic.Uint64
	noClient atomic.Uint64
}

func newLimiter(maxKeys int, epoch time.Time) *limiter {
	l := &limiter{seed: maphash.MakeSeed(), macKey: make([]byte, 32), epoch: epoch, perShard: max(maxKeys/rlShards, 1)}
	if _, err := rand.Read(l.macKey); err != nil {
		// Without a random key the credential hash could be guessed offline. The key is also mixed with the table's own seed, which
		// the runtime picks at random, so this still is not predictable.
		var h maphash.Hash
		h.SetSeed(l.seed)
		h.WriteString("apiguard")
		sum := h.Sum64()
		for i := range l.macKey {
			l.macKey[i] = byte(sum >> (8 * (i % 8)))
		}
	}
	l.macs.New = func() any { return hmac.New(sha256.New, l.macKey) }
	for i := range l.shards {
		l.shards[i].m = make(map[rlKey]*rlEntry)
	}
	return l
}

// addrKey is the key for an address: an IPv4 address whole, an IPv6 address as its /64 (the smallest block a customer is given, so
// one machine cannot spend a fresh bucket on each address it holds).
func addrKey(scope byte, a netip.Addr) (k rlKey, ok bool) {
	a = a.Unmap()
	switch {
	case a.Is4():
		b := a.As4()
		k[0], k[1] = 4, scope
		copy(k[2:], b[:])
	case a.Is6():
		b := a.As16()
		k[0], k[1] = 6, scope
		copy(k[2:], b[:8])
	default:
		return k, false
	}
	return k, true
}

// credKey is the key for an address together with a credential. The credential is hashed with a key only this guard knows, so
// what is stored is neither the credential nor anything that could be tested against a guess without that key.
func (l *limiter) credKey(scope byte, a netip.Addr, cred string) (k rlKey, ok bool) {
	ak, ok := addrKey(scope, a)
	if !ok {
		return k, false
	}
	if len(cred) > maxCredentialBytes {
		cred = cred[:maxCredentialBytes]
	}
	h := l.macs.Get().(hash.Hash)
	h.Reset()
	h.Write(ak[:10])
	h.Write([]byte{scope})
	h.Write([]byte(cred))
	var sum [32]byte
	h.Sum(sum[:0])
	l.macs.Put(h)
	k[0] = 0xC0
	copy(k[1:], sum[:15])
	return k, true
}

func (l *limiter) shardOf(k *rlKey) *rlShard {
	return &l.shards[maphash.Bytes(l.seed, k[:])%rlShards]
}

func (s *rlShard) unlink(e *rlEntry) {
	if e.prev != nil {
		e.prev.next = e.next
	} else {
		s.head = e.next
	}
	if e.next != nil {
		e.next.prev = e.prev
	} else {
		s.tail = e.prev
	}
	e.prev, e.next = nil, nil
}

func (s *rlShard) pushFront(e *rlEntry) {
	e.prev, e.next = nil, s.head
	if s.head != nil {
		s.head.prev = e
	}
	s.head = e
	if s.tail == nil {
		s.tail = e
	}
}

// refill brings a bucket up to date.
func (b *bucket) refill(now int64, lim Limit) {
	if now > b.at {
		b.tokens = math.Min(float64(lim.Burst), b.tokens+float64(now-b.at)*lim.rate())
		b.at = now
	}
}

// wait is how long until the bucket holds a token.
func (b *bucket) wait(lim Limit) time.Duration {
	if b.tokens >= 1 {
		return 0
	}
	return time.Duration((1-b.tokens)/lim.rate()) + 1 // rounded up, so the bucket holds a token when the wait is over
}

// allow takes a token from both buckets of a client if both have one. If either is empty nothing is taken and the wait is
// returned, so a client that keeps pushing is held to the rate and not made to wait longer for pushing. tracked is false when the
// table was full and the client was let through uncounted.
func (l *limiter) allow(k rlKey, sustained, burst Limit, at time.Time) (ok bool, retry time.Duration, tracked bool) {
	now := int64(at.Sub(l.epoch))
	s := l.shardOf(&k)
	s.mu.Lock()
	defer s.mu.Unlock()
	e := s.m[k]
	if e == nil {
		if len(s.m) >= l.perShard {
			e = s.reclaim(now)
			if e == nil {
				l.failOpen.Add(1)
				return true, 0, false
			}
			l.evicted.Add(1)
		} else {
			e = &rlEntry{}
		}
		e.key = k
		e.sustained = bucket{tokens: float64(sustained.Burst), at: now}
		e.burst = bucket{tokens: float64(burst.Burst), at: now}
		s.m[k] = e
	} else {
		s.unlink(e)
	}
	s.pushFront(e)
	e.sustained.refill(now, sustained)
	e.burst.refill(now, burst)
	if w := max(e.sustained.wait(sustained), e.burst.wait(burst)); w > 0 {
		e.fullAt = now + int64(fullIn(&e.sustained, sustained, &e.burst, burst))
		return false, w, true
	}
	e.sustained.tokens--
	e.burst.tokens--
	e.fullAt = now + int64(fullIn(&e.sustained, sustained, &e.burst, burst))
	return true, 0, true
}

// fullIn is how long until both buckets are full again.
func fullIn(a *bucket, al Limit, b *bucket, bl Limit) time.Duration {
	wa := (float64(al.Burst) - a.tokens) / al.rate()
	wb := (float64(bl.Burst) - b.tokens) / bl.rate()
	return time.Duration(math.Max(wa, wb))
}

// reclaim makes room: it takes the entry, among the few least recently used, that has been idle long enough to say nothing.
func (s *rlShard) reclaim(now int64) *rlEntry {
	e := s.tail
	for i := 0; e != nil && i < rlEvictTry; i++ {
		if e.fullAt <= now {
			s.unlink(e)
			delete(s.m, e.key)
			*e = rlEntry{}
			return e
		}
		e = e.prev
	}
	return nil
}

// keys is how many clients are being followed.
func (l *limiter) keys() int {
	n := 0
	for i := range l.shards {
		s := &l.shards[i]
		s.mu.Lock()
		n += len(s.m)
		s.mu.Unlock()
	}
	return n
}
