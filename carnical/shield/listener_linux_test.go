// SPDX-License-Identifier: Apache-2.0

//go:build linux

package shield

import (
	"errors"
	"io"
	"math"
	"net"
	"net/http"
	"net/netip"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

func listen(t *testing.T, s *Shield) (net.Listener, chan net.Conn) {
	t.Helper()
	raw, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ln := raw
	if s != nil {
		ln = s.Listener(raw)
	}
	t.Cleanup(func() { ln.Close() })
	accepted := make(chan net.Conn, 4096)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			accepted <- c
		}
	}()
	return ln, accepted
}

func dialFrom(t *testing.T, local, addr string, expectRefused bool) net.Conn {
	t.Helper()
	d := net.Dialer{LocalAddr: &net.TCPAddr{IP: net.ParseIP(local)}, Timeout: 2 * time.Second}
	c, err := d.Dial("tcp", addr)
	if err != nil {
		if expectRefused && errors.Is(err, syscall.ECONNRESET) {
			return nil // a correct refusal may arrive before Dial returns
		}
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

func waitAccept(ch chan net.Conn, d time.Duration) net.Conn {
	select {
	case c := <-ch:
		return c
	case <-time.After(d):
		return nil
	}
}

func TestAConnectionThatSendsNothingNeverReachesTheProxy(t *testing.T) {
	now := time.Now()
	s := newTestShield(t, &now, func(c *Config) { c.DeferAccept = 3 * time.Second })
	ln, accepted := listen(t, s)
	if v, err := DeferAccept(ln); err != nil || v < 3 {
		t.Fatalf("TCP_DEFER_ACCEPT is %d (%v)", v, err)
	}
	c := dialFrom(t, "127.0.0.1", ln.Addr().String(), false)
	if waitAccept(accepted, 700*time.Millisecond) != nil {
		t.Fatal("a silent connection was handed to the proxy")
	}
	c.Write([]byte("G"))
	if waitAccept(accepted, 2*time.Second) == nil {
		t.Fatal("a connection that sent data was not handed over")
	}

	t.Run("optional socket tuning failures are visible", func(t *testing.T) {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		if err := ln.Close(); err != nil {
			t.Fatal(err)
		}
		before := s.Snapshot().SocketOptionErrors
		s.Listener(ln)
		if s.Snapshot().SocketOptionErrors != before+1 {
			t.Fatal("failed optional socket tuning was not counted")
		}
	})
	// Control: without the shield the same silent connection is accepted at once.
	plain, plainAccepted := listen(t, nil)
	dialFrom(t, "127.0.0.1", plain.Addr().String(), false)
	if waitAccept(plainAccepted, 700*time.Millisecond) == nil {
		t.Fatal("control: a plain listener did not accept a silent connection, so the test proves nothing")
	}
}

func TestConnectionLimitsPerNetworkAndForBannedAddresses(t *testing.T) {
	now := time.Now()
	s := newTestShield(t, &now, func(c *Config) { c.SubnetConns = 3; c.DeferAccept = -1; c.MaxSources = 1024 })
	ln, accepted := listen(t, s)
	addr := ln.Addr().String()
	var held []net.Conn
	for i := 0; i < 3; i++ {
		dialFrom(t, "127.0.5."+string(rune('1'+i)), addr, false)
		c := waitAccept(accepted, time.Second)
		if c == nil {
			t.Fatalf("connection %d of 3 from the network was refused", i+1)
		}
		held = append(held, c)
		t.Cleanup(func() { c.Close() })
	}
	fourth := dialFrom(t, "127.0.5.9", addr, true)
	if waitAccept(accepted, 500*time.Millisecond) != nil {
		t.Fatal("a fourth connection from the same /24 was accepted")
	}
	if fourth != nil {
		fourth.SetReadDeadline(time.Now().Add(time.Second))
		if _, err := fourth.Read(make([]byte, 1)); err == nil {
			t.Fatal("the refused connection was left open")
		}
	}
	// Churn through the actual request history until this network is forgotten. Its sockets still occupy capacity.
	p := netip.MustParsePrefix("127.0.5.0/24")
	s.Admit(req("GET", "/"), p.Addr())
	for i := 0; i < 16384; i++ {
		s.Admit(req("GET", "/"), netip.AddrFrom4([4]byte{198, byte(i >> 8), byte(i), 1}))
		if !s.subnets.peek(p, func(*subnet) {}) {
			break
		}
	}
	if s.subnets.peek(p, func(*subnet) {}) {
		t.Fatal("control: request history did not evict the network")
	}
	dialFrom(t, "127.0.5.10", addr, true)
	if c := waitAccept(accepted, 500*time.Millisecond); c != nil {
		c.Close()
		t.Fatal("request-history churn bypassed the open-connection limit")
	}
	held[0].Close()
	held[0].Close() // closing twice must only release one slot
	dialFrom(t, "127.0.5.11", addr, false)
	if c := waitAccept(accepted, time.Second); c == nil {
		t.Fatal("closing a socket did not release capacity")
	} else {
		t.Cleanup(func() { c.Close() })
	}
	dialFrom(t, "127.0.5.12", addr, true)
	if c := waitAccept(accepted, 500*time.Millisecond); c != nil {
		c.Close()
		t.Fatal("double close released a second slot")
	}
	dialFrom(t, "127.0.6.1", addr, false)
	if waitAccept(accepted, time.Second) == nil {
		t.Fatal("another network was refused")
	}

	s.sources.do(SourceKey(netip.MustParseAddr("127.0.7.7")), now.UnixNano(), func(src *source) { src.bannedUntil = now.Add(time.Hour).UnixNano() })
	dialFrom(t, "127.0.7.7", addr, true)
	if waitAccept(accepted, 500*time.Millisecond) != nil {
		t.Fatal("a banned address got a connection")
	}

	// Real simultaneous accepts on separate listeners exercise the shared capacity reservation, with and without trust.
	for _, tc := range []struct {
		name                       string
		trusted                    bool
		capacity, attempts         int
		fdLimit, average, admitted int64
	}{
		{"small direct", false, 16, 128, 0, 0, 13},
		{"small trusted", true, 16, 128, 0, 0, 16},
		{"low file limit at startup", false, 20000, 128, 64, 0, 41},
		{"low file limit after growth", true, 20000, 128, 64, 20000, 51},
		{"large direct", false, 2048, 4096, 0, 0, 1639},
		{"large trusted", true, 2048, 4096, 0, 0, 2048},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fixed := time.Now()
			sh := newTestShield(t, &fixed, func(c *Config) {
				c.MaxConns, c.SubnetConns, c.ConnBurst, c.DeferAccept = tc.capacity, tc.attempts, float64(tc.attempts), -1
				if tc.trusted {
					c.Trusted = []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}
				}
			})
			sh.fdLimit = tc.fdLimit // exercise a low server limit without exhausting the test client's own descriptors
			sh.connAvg.Store(math.Float64bits(float64(tc.average)))
			listeners := make([]net.Listener, 8)
			channels := make([]chan net.Conn, len(listeners))
			for i := range listeners {
				listeners[i], channels[i] = listen(t, sh)
			}
			attempts := tc.attempts
			start := make(chan struct{})
			clients := make(chan net.Conn, attempts)
			dialErrors := make(chan error, attempts)
			var wg sync.WaitGroup
			for i := 0; i < attempts; i++ {
				wg.Go(func() {
					<-start
					c, err := net.DialTimeout("tcp", listeners[i%len(listeners)].Addr().String(), 10*time.Second)
					if err != nil {
						dialErrors <- err
					} else {
						clients <- c
					}
				})
			}
			close(start)
			wg.Wait()
			close(clients)
			for c := range clients {
				t.Cleanup(func() { c.Close() })
			}
			close(dialErrors)
			for err := range dialErrors {
				// The listener may reset a refused socket before the client finishes Dial.
				if !errors.Is(err, syscall.ECONNRESET) {
					t.Errorf("dial: %v", err)
				}
			}
			deadline := time.Now().Add(10 * time.Second)
			for sh.conns.Load()+int64(sh.counters.connsRefused.Load()) < int64(attempts) && time.Now().Before(deadline) {
				time.Sleep(time.Millisecond)
			}
			want := tc.admitted
			snap := sh.Snapshot()
			if snap.Connections != want || snap.ConnsRefused != uint64(int64(attempts)-want) {
				t.Fatalf("admitted %d, refused %d; want %d, %d", snap.Connections, snap.ConnsRefused, want, int64(attempts)-want)
			}
			// Capacity is counted just before Accept returns. Wait for those sockets to reach their channels too.
			closed := int64(0)
			deadline = time.Now().Add(10 * time.Second)
			for closed < want && time.Now().Before(deadline) {
				for _, ch := range channels {
					select {
					case c := <-ch:
						if err := c.Close(); err != nil {
							t.Fatal(err)
						}
						closed++
					default:
					}
				}
				time.Sleep(time.Millisecond)
			}
			if sh.conns.Load() != 0 || len(sh.connNets) != 0 {
				t.Fatal("closing all sockets left capacity occupied")
			}
		})
	}
}

// When connections run short, idle keep-alive connections of clients the shield does not know are closed to make room;
// nobody is refused while one of those can go.
func TestIdleConnectionsOfStrangersMakeRoom(t *testing.T) {
	now := time.Now()
	var clock atomic.Int64
	clock.Store(now.UnixNano())
	s := newTestShield(t, &now, func(c *Config) {
		c.MaxConns = 20
		c.ReservedShare = 0.5
		c.DeferAccept = -1
		c.Now = func() time.Time { return time.Unix(0, clock.Load()) }
	})
	raw, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "ok") }), ConnState: s.ConnState}
	go srv.Serve(s.Listener(raw))
	t.Cleanup(func() { srv.Close() })
	addr := raw.Addr().String()
	var idle []net.Conn
	for i := 0; i < 10; i++ { // the strangers' share: 20 less the half kept back
		c := dialFrom(t, "127.0.8."+itoa(float64(i+1)), addr, false)
		c.Write([]byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n"))
		buf := make([]byte, 512)
		c.SetReadDeadline(time.Now().Add(2 * time.Second))
		if n, err := c.Read(buf); err != nil || n == 0 {
			t.Fatalf("request %d: %v", i, err)
		}
		idle = append(idle, c)
	}
	time.Sleep(200 * time.Millisecond) // the server marks them idle
	clock.Add(int64(2 * time.Second))
	newcomer := dialFrom(t, "127.0.9.1", addr, false)
	newcomer.Write([]byte("GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"))
	newcomer.SetReadDeadline(time.Now().Add(2 * time.Second))
	if b, _ := io.ReadAll(newcomer); len(b) == 0 {
		t.Fatal("the newcomer was refused although idle connections could have made room")
	}
	closed := 0
	for _, c := range idle {
		c.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
		if _, err := c.Read(make([]byte, 1)); err == io.EOF {
			closed++
		}
	}
	if closed == 0 || s.Snapshot().Evicted == 0 {
		t.Fatal("no idle connection was closed to make room")
	}
}
