package proxy

import (
	"net"
	"net/http"
	"net/netip"
	"sync"
	"time"
)

// rateLimiter counts events per key in a sliding window. It is memory-bounded: once it holds a lot of keys it forgets
// the ones whose window has passed, and if that is not enough it refuses to remember more, which means an attacker
// using very many addresses is let through rather than the process growing without limit.
type rateLimiter struct {
	mu   sync.Mutex
	hits map[string][]time.Time
}

const rateLimiterKeys = 50_000

func (l *rateLimiter) allow(key string, n int, window time.Duration) bool {
	now := time.Now()
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.hits == nil {
		l.hits = map[string][]time.Time{}
	}
	if len(l.hits) >= rateLimiterKeys {
		for k, ts := range l.hits {
			if len(ts) == 0 || now.Sub(ts[len(ts)-1]) > window {
				delete(l.hits, k)
			}
		}
		if _, known := l.hits[key]; !known && len(l.hits) >= rateLimiterKeys {
			return true
		}
	}
	ts := l.hits[key][:0:0]
	for _, t := range l.hits[key] {
		if now.Sub(t) <= window {
			ts = append(ts, t)
		}
	}
	if len(ts) >= n {
		l.hits[key] = ts
		return false
	}
	l.hits[key] = append(ts, now)
	return true
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
