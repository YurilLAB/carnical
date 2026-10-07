// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"net"
	"net/http"
	"net/netip"
	"sync"
	"time"
)

// rateLimiter counts admitted attempts in an exact sliding minute. A shared event ring bounds all timestamp storage,
// including clients with large individual limits. Expiration visits each admitted event once, avoiding full-map scans.
// Capacity exhaustion refuses admission; it never silently switches a protection off.
type rateLimiter struct {
	mu         sync.Mutex
	hits       map[string]int
	events     []rateEvent
	head, size int
	now        func() time.Time // test clock; nil uses time.Now under the lock
}

const rateLimiterKeys = 50_000
const rateLimiterEvents = 200_000

type rateEvent struct {
	key string
	at  time.Time
}

type rateDecision uint8

const (
	rateAllowed rateDecision = iota
	rateExceeded
	rateFull
)

func (l *rateLimiter) allow(key string, n int) rateDecision {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	if l.now != nil {
		now = l.now()
	}
	if l.hits == nil {
		l.hits = map[string]int{}
		l.events = make([]rateEvent, rateLimiterEvents)
	}
	for l.size > 0 {
		event := l.events[l.head]
		if now.Sub(event.at) < time.Minute {
			break
		}
		if l.hits[event.key]--; l.hits[event.key] == 0 {
			delete(l.hits, event.key)
		}
		l.events[l.head] = rateEvent{} // release the identity as well as the timestamp
		l.head = (l.head + 1) % len(l.events)
		l.size--
	}
	if n <= 0 || l.hits[key] >= n {
		return rateExceeded
	}
	if l.size >= len(l.events) || l.hits[key] == 0 && len(l.hits) >= rateLimiterKeys {
		return rateFull
	}
	l.events[(l.head+l.size)%len(l.events)] = rateEvent{key, now}
	l.size++
	l.hits[key]++
	return rateAllowed
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
		l.mu.Lock()
		if l.perIP[ip] >= l.max {
			l.mu.Unlock()
			if l.onLimit != nil {
				l.onLimit(ip)
			}
			// #nosec G104 -- Admission was already refused and counted; Close is terminal cleanup with no request to recover.
			c.Close()
			return
		}
		l.perIP[ip]++
		l.counted[c] = ip
		l.mu.Unlock()
	case http.StateClosed, http.StateHijacked:
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
