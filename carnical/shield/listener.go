// SPDX-License-Identifier: Apache-2.0

package shield

import (
	"context"
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
	s          *Shield
	key        netip.Addr
	subnet     netip.Prefix
	trusted    bool
	known      bool
	closed     atomic.Bool
	httpActive atomic.Bool
	// idle list membership, guarded by s.idleMu
	prev, next *conn
	idleSince  int64
	inIdle     bool
}

func (c *conn) Close() error {
	if c.closed.CompareAndSwap(false, true) {
		c.s.release(c)
		if !c.trusted {
			early := !c.httpActive.Load()
			if early {
				c.s.counters.earlyCloses.Add(1)
			}
			c.s.det.count(c.s.now().UnixNano(), func(w *window) {
				w.connClosed++
				if early {
					w.earlyCloses++
				}
			})
		}
	}
	return c.Conn.Close()
}

// SetLinger passes the setting to the connection underneath, so that whoever holds this one can have it reset when it
// is closed (the proxy does, to drop a client that stopped reading).
func (c *conn) SetLinger(sec int) error {
	if l, ok := c.Conn.(interface{ SetLinger(int) error }); ok {
		return l.SetLinger(sec)
	}
	return nil
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

// addrPort is the port of a listener's address, 0 when it has none.
func addrPort(a net.Addr) uint16 {
	switch a := a.(type) {
	case *net.TCPAddr:
		if a.Port > 0 && a.Port <= 0xffff {
			return uint16(a.Port)
		}
	case nil:
	default:
		if ap, err := netip.ParseAddrPort(a.String()); err == nil {
			return ap.Port()
		}
	}
	return 0
}

// localPort is the local port a request came to, 0 when the server did not say.
func localPort(r *http.Request) uint16 {
	a, _ := r.Context().Value(http.LocalAddrContextKey).(net.Addr)
	return addrPort(a)
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
	sc := &conn{Conn: c, s: s, key: SourceKey(a), subnet: netOf(a), trusted: s.trusted(a)}
	// In monitor mode an attack changes nothing here: who is known, and so may use the reserved share and keep an idle
	// connection, is decided as at any other time.
	info := s.det.info.Load()
	if s.cfg.MonitorOnly {
		info = nil
	}
	attack := info != nil
	refused := false
	scaleNet := 1.0
	if !sc.trusted {
		// An address that has earned a higher request limit may open connections as much faster, and its network hold
		// as many more.
		earn := s.det.earn.Load()
		s.sources.do(sc.key, ns, func(src *source) {
			src.last = ns
			sc.known = s.isKnown(src, ns, info)
			scaleSrc := s.raise(src.earned.roll(earn, s.cfg.RequestRate), s.cfg.RequestRate)
			rate, burst := s.cfg.ConnRate*scaleSrc, s.cfg.ConnBurst*scaleSrc
			if attack && !sc.known {
				rate, burst = rate/4, max(burst/4, 1) // strangers open connections more slowly during an attack
			}
			refused = src.bannedUntil > ns || !src.conn.take(ns, rate, burst)
		})
		s.subnets.peek(sc.subnet, func(n *subnet) {
			scaleNet = s.raise(n.earned.roll(earn, s.cfg.SubnetRate), s.cfg.SubnetRate)
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
	// The detector counts the addresses connections come from, as the limits count them: one address's flood of
	// connections is that address's, and not the spread of a botnet.
	h := hashAddr(sc.key)
	port := addrPort(c.LocalAddr())
	if refused {
		s.counters.connsRefused.Add(1)
		s.det.note(ns, func(w *window, inc *incidentAcc) {
			w.connsIn++
			w.connsRefused++
			w.connSrcs.add(h)
			w.via.addPort(port, 0, 1)
			if inc != nil {
				inc.via.addPort(port, 0, 1)
			}
		})
		s.reset(c)
		return nil
	}
	s.det.note(ns, func(w *window, inc *incidentAcc) {
		w.connsIn++
		w.connSrcs.add(h)
		w.via.addPort(port, 0, 1)
		if inc != nil {
			inc.via.addPort(port, 0, 1)
		}
	})
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

type connKey struct{}

// ConnContext is for http.Server.ConnContext: it keeps each request's connection, so that a refusal can tell a trusted
// proxy's connection, which carries other visitors' requests too, from the refused client's own.
func (s *Shield) ConnContext(ctx context.Context, c net.Conn) context.Context {
	return context.WithValue(ctx, connKey{}, c)
}

// relayed reports whether a request came on a trusted proxy's connection (see ConnContext).
func (s *Shield) relayed(r *http.Request) bool {
	c, _ := r.Context().Value(connKey{}).(net.Conn)
	if c == nil {
		return false
	}
	a, ok := remoteAddr(c)
	return ok && s.trusted(a)
}

// ConnState is for http.Server.ConnState: it keeps the list of idle keep-alive connections, oldest first, so that when
// connections run short the idle ones of clients the shield does not know are closed before anyone is refused.
func (s *Shield) ConnState(c net.Conn, st http.ConnState) {
	sc := unwrapConn(c)
	if sc == nil {
		return
	}
	if st == http.StateActive {
		sc.httpActive.Store(true)
	}
	if sc.trusted {
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
