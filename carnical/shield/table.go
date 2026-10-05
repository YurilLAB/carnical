// SPDX-License-Identifier: Apache-2.0

package shield

import (
	"hash/maphash"
	"net/netip"
	"sync"
)

// table is a bounded map split into shards, each with its own lock. When a shard is full, an entry that is no longer
// needed is forgotten to make room (one whose state is back to what a new entry would have, or failing that the oldest
// of a few looked at), so that an attacker with a million addresses cannot make it grow, and a new client is never
// refused for lack of room.
type table[K comparable, V any] struct {
	shards   []tableShard[K, V]
	per      int
	seed     maphash.Seed
	idle     func(v *V, now int64) bool // whether forgetting v loses nothing
	lastUsed func(v *V) int64
}

type tableShard[K comparable, V any] struct {
	mu sync.Mutex
	m  map[K]*V
}

func newTable[K comparable, V any](size int, idle func(*V, int64) bool, lastUsed func(*V) int64) *table[K, V] {
	const shards = 64
	t := &table[K, V]{shards: make([]tableShard[K, V], shards), per: max(size/shards, 16), seed: maphash.MakeSeed(), idle: idle, lastUsed: lastUsed}
	for i := range t.shards {
		t.shards[i].m = map[K]*V{}
	}
	return t
}

// do runs f on the entry for k, making it if it does not exist, under the shard's lock. f must be quick.
func (t *table[K, V]) do(k K, now int64, f func(v *V)) {
	s := &t.shards[maphash.Comparable(t.seed, k)%uint64(len(t.shards))]
	s.mu.Lock()
	defer s.mu.Unlock()
	v := s.m[k]
	if v == nil {
		if len(s.m) >= t.per {
			t.evict(s, now)
		}
		v = new(V)
		s.m[k] = v
	}
	f(v)
}

// peek runs f on the entry for k if there is one, and reports whether there was.
func (t *table[K, V]) peek(k K, f func(v *V)) bool {
	s := &t.shards[maphash.Comparable(t.seed, k)%uint64(len(t.shards))]
	s.mu.Lock()
	defer s.mu.Unlock()
	v := s.m[k]
	if v == nil {
		return false
	}
	f(v)
	return true
}

func (t *table[K, V]) evict(s *tableShard[K, V], now int64) {
	var oldest K
	oldestAt, n := int64(-1), 0
	for k, v := range s.m { // map order is random: a fair sample
		if t.idle(v, now) {
			delete(s.m, k)
			return
		}
		if at := t.lastUsed(v); oldestAt < 0 || at < oldestAt {
			oldest, oldestAt = k, at
		}
		if n++; n == 32 {
			break
		}
	}
	delete(s.m, oldest)
}

func (t *table[K, V]) len() int {
	n := 0
	for i := range t.shards {
		s := &t.shards[i]
		s.mu.Lock()
		n += len(s.m)
		s.mu.Unlock()
	}
	return n
}

// source is what the shield remembers about one client address (an IPv6 client is its /64).
type source struct {
	req, conn   bucket
	last        int64
	newAt       int64
	lastTpl     uint64
	distinct    uint8
	good        uint16
	goodFirst   int64
	knownUntil  int64
	knownAt     int64 // when the client became known
	strikes     uint16
	strikeEpoch uint32
	bannedUntil int64
}

func sourceIdle(s *source, now int64) bool {
	return s.knownUntil < now && s.bannedUntil < now && now-s.last > 60e9
}

func sourceLast(s *source) int64 { return s.last }

// subnet is what the shield remembers about one /24 (IPv4) or /48 (IPv6).
type subnet struct {
	req   bucket
	conns int32
	last  int64
}

func subnetIdle(s *subnet, now int64) bool { return s.conns <= 0 && now-s.last > 60e9 }

func subnetLast(s *subnet) int64 { return s.last }

// sourceKey is the unit the per-client limits apply to: an IPv4 address, or an IPv6 /64, the smallest block one
// customer of an internet provider is given (anything finer and one machine is a million clients).
func sourceKey(a netip.Addr) netip.Addr {
	a = a.Unmap()
	if a.Is6() {
		p, _ := a.Prefix(64)
		return p.Addr()
	}
	return a
}
