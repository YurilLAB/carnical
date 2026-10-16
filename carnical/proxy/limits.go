// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"net"
	"net/http"
	"net/netip"
	"sync"
	"time"

	"github.com/YurilLAB/coraza/carnical/shield"
)

// windowSlots is how many slots a rate rule's window is cut into. A key's count covers the slot now running and the
// windowSlots before it, which always contain the last window: no span of one window ever holds more requests than the
// rule allows, and a request is held back at most one slot (a tenth of the window) longer than an exact log would hold it.
const windowSlots = 10

// rateKeysInAll bounds the clients of all rate rules together, and rateKeysPerRule those of one rule. An entry is about
// 150 bytes, and a table grows only as clients arrive.
const (
	rateKeysInAll   = 200_000
	rateKeysPerRule = 50_000
)

// windowEntry is one client's count in one rule's window.
type windowEntry struct {
	key        netip.Addr
	counts     [windowSlots + 1]uint32 // admitted requests in each slot, at slot % (windowSlots+1)
	newest     int64                   // the slot the counts are current to
	sum        uint32                  // the counts added up
	prev, next int                     // the neighbours in admission order, -1 at either end
}

// windowLimiter is one rate rule's per-client sliding window: each client (an IPv4 address or an IPv6 /64) has its own
// counts, so no client's traffic uses up anything another client needs. When the table is full, the client admitted
// least recently makes room for a new one; the table never refuses a request for want of room, because that would let
// whoever fills it lock every new visitor out. Nor is a client held back for what its neighbours sent: a source able to
// fill the table already has more addresses than the table holds (one IPv6 /48 has 65,536 /64s), each a budget of its
// own, so a dropped client coming back with a fresh window gives it nothing it lacked. A network's total is the shield's
// to bound. The caller holds mu around check and admit.
type windowLimiter struct {
	mu    sync.Mutex
	limit int64 // requests a client may make in a window
	slot  int64 // the slot's length in nanoseconds
	max   int   // the most clients the table holds
	index map[netip.Addr]int
	slab  []windowEntry
	// head is the client admitted least recently and tail the one admitted last, -1 when there is none.
	head, tail int
}

func newWindowLimiter(limit int, window time.Duration, maxKeys int) *windowLimiter {
	// No client is admitted a quarter of a billion times in one window, and the counts, which never pass the limit, must
	// not wrap around.
	limit = min(max(limit, 1), 1<<28)
	return &windowLimiter{limit: int64(limit), slot: max(int64(window)/windowSlots, 1), max: max(maxKeys, 1),
		index: map[netip.Addr]int{}, head: -1, tail: -1}
}

// advance brings an entry's counts up to slot c, emptying the slots that have left the window.
func (l *windowLimiter) advance(e *windowEntry, c int64) {
	if c <= e.newest {
		return
	}
	if c-e.newest > windowSlots {
		e.counts, e.sum = [windowSlots + 1]uint32{}, 0
	} else {
		for s := e.newest + 1; s <= c; s++ {
			e.sum -= e.counts[s%(windowSlots+1)]
			e.counts[s%(windowSlots+1)] = 0
		}
	}
	e.newest = c
}

// check reports whether key may make one more request at now (nanoseconds on a clock that does not go back), and if not,
// how many nanoseconds until it may. It counts nothing: a request that is refused, here or by another rule, uses up no
// budget and does not make its client look recently admitted.
func (l *windowLimiter) check(key netip.Addr, now int64) (ok bool, wait int64) {
	i, found := l.index[key]
	if !found {
		return true, 0 // a client the table does not hold has nothing in its window
	}
	e := &l.slab[i]
	c := max(now, 0) / l.slot
	l.advance(e, c)
	if int64(e.sum) < l.limit {
		return true, 0
	}
	// A reading taken before another request took the lock can be a slot behind the entry, and the wait runs from the
	// entry's newest slot, the latest that holds anything.
	c = max(c, e.newest)
	// At slot c+k the window is slots c+k-10 to c+k, and nothing after c has been admitted: find the first k at which
	// slots c+k-10 to c hold fewer than the limit. Slot c-10+j is at (c+j+1) % 11 in the ring.
	left := int64(e.sum)
	for k := int64(1); k <= windowSlots; k++ {
		left -= int64(e.counts[(c+k)%(windowSlots+1)])
		if left < l.limit {
			return false, (c+k)*l.slot - now
		}
	}
	return false, (c+windowSlots+1)*l.slot - now
}

// admit counts one request by key at now. A client the table does not hold takes an empty place or, in a full table, the
// place of the client admitted least recently; admit reports whether that client still had requests in its window.
func (l *windowLimiter) admit(key netip.Addr, now int64) (evictedLive bool) {
	c := max(now, 0) / l.slot
	i, found := l.index[key]
	switch {
	case found:
		l.unlink(i)
	case len(l.slab) < l.max:
		l.slab = append(l.slab, windowEntry{key: key, newest: c})
		i = len(l.slab) - 1
		l.index[key] = i
	default:
		// The head is the client admitted least recently: if any client is idle, it is.
		i = l.head
		l.unlink(i)
		e := &l.slab[i]
		l.advance(e, c)
		evictedLive = e.sum > 0
		delete(l.index, e.key)
		*e = windowEntry{key: key, newest: c}
		l.index[key] = i
	}
	e := &l.slab[i]
	l.advance(e, c)
	// A request that read the clock before another one took the lock counts in the newest slot, never in one that has
	// already left the window.
	e.counts[e.newest%(windowSlots+1)]++
	e.sum++
	l.touch(i)
	return evictedLive
}

// touch makes entry i the one admitted last.
func (l *windowLimiter) touch(i int) {
	e := &l.slab[i]
	e.prev, e.next = l.tail, -1
	if l.tail >= 0 {
		l.slab[l.tail].next = i
	} else {
		l.head = i
	}
	l.tail = i
}

func (l *windowLimiter) unlink(i int) {
	e := &l.slab[i]
	if e.prev >= 0 {
		l.slab[e.prev].next = e.next
	} else {
		l.head = e.next
	}
	if e.next >= 0 {
		l.slab[e.next].prev = e.prev
	} else {
		l.tail = e.prev
	}
}

// connLimiter caps how many connections one address may hold open. A client that opens thousands of connections
// and sends nothing (or one byte a second) ties up the server's memory and file descriptors without sending a single
// request the rules could look at.
type connLimiter struct {
	mu      sync.Mutex
	max     int
	trusted []netip.Prefix
	perIP   map[netip.Addr]int
	counted map[net.Conn]netip.Addr
	onLimit func(netip.Addr)
}

func newConnLimiter(max int, trusted []netip.Prefix, onLimit func(netip.Addr)) *connLimiter {
	return &connLimiter{max: max, trusted: trusted, perIP: map[netip.Addr]int{}, counted: map[net.Conn]netip.Addr{}, onLimit: onLimit}
}

// state is for http.Server.ConnState.
func (l *connLimiter) state(c net.Conn, s http.ConnState) {
	switch s {
	case http.StateNew:
		ap, err := netip.ParseAddrPort(c.RemoteAddr().String())
		if err != nil {
			return
		}
		ip := ap.Addr().Unmap()
		if isTrusted(ip, l.trusted) {
			return // a load balancer carries many visitors on few connections
		}
		key := shield.SourceKey(ip) // an IPv6 client is its /64, as for the rate limits
		l.mu.Lock()
		if l.perIP[key] >= l.max {
			l.mu.Unlock()
			if l.onLimit != nil {
				l.onLimit(ip)
			}
			// #nosec G104 -- Admission was already refused and counted; Close is terminal cleanup with no request to recover.
			c.Close()
			return
		}
		l.perIP[key]++
		l.counted[c] = key
		l.mu.Unlock()
	case http.StateHijacked:
		// A connection taken over for an allowed upgrade is still the address's: it counts until the tunnel closes it, which
		// Edge.hijacked reports as StateClosed. Otherwise one address could hold any number of tunnels open.
	case http.StateClosed:
		l.mu.Lock()
		if ip, ok := l.counted[c]; ok {
			delete(l.counted, c)
			if l.perIP[ip]--; l.perIP[ip] <= 0 {
				delete(l.perIP, ip)
			}
		}
		l.mu.Unlock()
	}
}

// hijackedConn is a connection taken over for an upgrade, whose close is reported once.
type hijackedConn struct {
	net.Conn
	once   sync.Once
	closed func()
}

func (h *hijackedConn) Close() error {
	err := h.Conn.Close()
	h.once.Do(h.closed)
	return err
}
