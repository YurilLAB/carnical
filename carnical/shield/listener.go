// SPDX-License-Identifier: Apache-2.0

package shield

import (
	"net"
	"net/http"
	"net/netip"
	"sync/atomic"
)

// Listener wraps the proxy's listening socket. Each connection is judged the moment it is accepted, before a goroutine,
// a TLS handshake or a buffer is spent on it; a refused one is closed with a reset (no TIME_WAIT left behind here).
// On Linux the listening socket is also set so that the kernel does not hand over a connection until the client has
// sent its first bytes or the defer timeout expires. Silent connections still need server read deadlines.
func (s *Shield) Listener(ln net.Listener) net.Listener {
	if s.cfg.DeferAccept > 0 {
		if err := setDeferAccept(ln, s.cfg.DeferAccept); err != nil {
			s.counters.socketOptionErrors.Add(1)
		}
	}
	return &listener{Listener: ln, s: s}
}

type listener struct {
	net.Listener
	s *Shield
}

func (l *listener) Accept() (net.Conn, error) {
	for {
		c, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		if sc := l.s.admitConn(c); sc != nil {
			return sc, nil
		}
	}
}

// conn is an admitted connection: it gives its place back when it closes.
type conn struct {
	net.Conn
	s       *Shield
	key     netip.Addr
	subnet  netip.Prefix
	trusted bool
	known   bool
	closed  atomic.Bool
	// idle list membership, guarded by s.idleMu
	prev, next *conn
	idleSince  int64
	inIdle     bool
}

func (c *conn) Close() error {
	if c.closed.CompareAndSwap(false, true) {
		c.s.release(c)
	}
	return c.Conn.Close()
}

func remoteAddr(c net.Conn) (netip.Addr, bool) {
	if ta, ok := c.RemoteAddr().(*net.TCPAddr); ok {
		ap := ta.AddrPort()
		return ap.Addr().Unmap(), ap.Addr().IsValid()
	}
	ap, err := netip.ParseAddrPort(c.RemoteAddr().String())
	if err != nil {
		return netip.Addr{}, false
	}
	return ap.Addr().Unmap(), true
}

// reset closes a connection with a RST rather than a FIN.
func (s *Shield) reset(c net.Conn) {
	if tc, ok := c.(*net.TCPConn); ok {
		if err := tc.SetLinger(0); err != nil {
			s.counters.socketOptionErrors.Add(1)
		}
	}
	// #nosec G104 -- Refused connection cleanup; admission is already denied and there is no caller recovery path. Close is attempted even if SetLinger fails.
	c.Close()
}

func (s *Shield) admitConn(c net.Conn) net.Conn {
	a, ok := remoteAddr(c)
	if !ok {
		s.reset(c)
		return nil
	}
	ns := s.now().UnixNano()
	sc := &conn{Conn: c, s: s, key: sourceKey(a), subnet: netOf(a), trusted: s.trusted(a)}
	attack := s.det.info.Load() != nil && !s.cfg.MonitorOnly
	refused := false
	scaleSrc, scaleNet := s.det.scales()
	if !sc.trusted {
		s.sources.do(sc.key, ns, func(src *source) {
			src.last = ns
			sc.known = s.isKnown(src, ns, s.det.info.Load())
			rate, burst := s.cfg.ConnRate*scaleSrc, s.cfg.ConnBurst*scaleSrc
			if attack && !sc.known {
				rate, burst = rate/4, max(burst/4, 1) // strangers open connections more slowly during an attack
			}
			refused = src.bannedUntil > ns || !src.conn.take(ns, rate, burst)
		})
	}
	if !refused {
		admitted, full := s.reserveConn(sc, scaleNet)
		if !admitted && full {
			s.evictIdle(ns, 16)
			admitted, _ = s.reserveConn(sc, scaleNet)
		}
		refused = !admitted
	}
	if refused {
		s.counters.connsRefused.Add(1)
		s.det.count(ns, func(w *window) { w.connsIn++; w.connsRefused++ })
		s.reset(c)
		return nil
	}
	s.det.count(ns, func(w *window) { w.connsIn++ })
	if s.cfg.UserTimeout > 0 {
		if err := setUserTimeout(c, s.cfg.UserTimeout); err != nil {
			s.counters.socketOptionErrors.Add(1)
		}
	}
	return sc
}

// reserveConn checks and reserves both capacities in one critical section. full means idle eviction may help.
func (s *Shield) reserveConn(c *conn, scaleNet float64) (admitted, full bool) {
	s.connMu.Lock()
	defer s.connMu.Unlock()
	limit := s.maxConns()
	if !c.known && !c.trusted {
		limit -= int64(float64(limit) * s.cfg.ReservedShare)
	}
	if s.conns.Load() >= limit {
		return false, true
	}
	if !c.trusted {
		n := s.connNets[c.subnet]
		if float64(n) >= float64(s.cfg.SubnetConns)*scaleNet {
			return false, false
		}
		s.connNets[c.subnet] = n + 1
	}
	s.conns.Add(1)
	return true, false
}

func (s *Shield) release(c *conn) {
	s.connMu.Lock()
	s.conns.Add(-1)
	if !c.trusted {
		if n := s.connNets[c.subnet]; n > 1 {
			s.connNets[c.subnet] = n - 1
		} else {
			delete(s.connNets, c.subnet)
		}
	}
	s.connMu.Unlock()
	s.idleMu.Lock()
	s.idle.remove(c)
	s.idleMu.Unlock()
}

// ConnState is for http.Server.ConnState: it keeps the list of idle keep-alive connections, oldest first, so that when
// connections run short the idle ones of clients the shield does not know are closed before anyone is refused.
func (s *Shield) ConnState(c net.Conn, st http.ConnState) {
	sc := unwrapConn(c)
	if sc == nil || sc.trusted {
		return
	}
	s.idleMu.Lock()
	defer s.idleMu.Unlock()
	switch st {
	case http.StateIdle:
		if !sc.closed.Load() {
			sc.idleSince = s.now().UnixNano()
			s.idle.push(sc)
		}
	default:
		s.idle.remove(sc)
	}
}

func (s *Shield) evictIdle(ns int64, n int) {
	var victims []*conn
	s.idleMu.Lock()
	for c, looked := s.idle.head, 0; c != nil && len(victims) < n && looked < 256; looked++ {
		next := c.next
		if !c.known && ns-c.idleSince >= 1e9 {
			s.idle.remove(c)
			victims = append(victims, c)
		}
		c = next
	}
	s.idleMu.Unlock()
	for _, c := range victims {
		s.counters.evicted.Add(1)
		// #nosec G104 -- The evicted connection has no request to recover; conn.Close releases its reservation once even if socket close reports an error.
		c.Close()
	}
}

// idleList is an intrusive doubly linked list of connections.
type idleList struct{ head, tail *conn }

func (l *idleList) push(c *conn) {
	if c.inIdle {
		l.remove(c)
	}
	c.inIdle, c.prev, c.next = true, l.tail, nil
	if l.tail != nil {
		l.tail.next = c
	} else {
		l.head = c
	}
	l.tail = c
}

func (l *idleList) remove(c *conn) {
	if !c.inIdle {
		return
	}
	if c.prev != nil {
		c.prev.next = c.next
	} else {
		l.head = c.next
	}
	if c.next != nil {
		c.next.prev = c.prev
	} else {
		l.tail = c.prev
	}
	c.prev, c.next, c.inIdle = nil, nil, false
}
