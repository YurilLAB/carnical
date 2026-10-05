// SPDX-License-Identifier: Apache-2.0

//go:build linux

package shield

import (
	"io"
	"net"
	"net/http"
	"net/netip"
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
	accepted := make(chan net.Conn, 64)
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

func dialFrom(t *testing.T, local, addr string) net.Conn {
	t.Helper()
	d := net.Dialer{LocalAddr: &net.TCPAddr{IP: net.ParseIP(local)}, Timeout: 2 * time.Second}
	c, err := d.Dial("tcp", addr)
	if err != nil {
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
	c := dialFrom(t, "127.0.0.1", ln.Addr().String())
	if waitAccept(accepted, 700*time.Millisecond) != nil {
		t.Fatal("a silent connection was handed to the proxy")
	}
	c.Write([]byte("G"))
	if waitAccept(accepted, 2*time.Second) == nil {
		t.Fatal("a connection that sent data was not handed over")
	}

	// Control: without the shield the same silent connection is accepted at once.
	plain, plainAccepted := listen(t, nil)
	dialFrom(t, "127.0.0.1", plain.Addr().String())
	if waitAccept(plainAccepted, 700*time.Millisecond) == nil {
		t.Fatal("control: a plain listener did not accept a silent connection, so the test proves nothing")
	}
}

func TestConnectionLimitsPerNetworkAndForBannedAddresses(t *testing.T) {
	now := time.Now()
	s := newTestShield(t, &now, func(c *Config) { c.SubnetConns = 3; c.DeferAccept = -1 })
	ln, accepted := listen(t, s)
	addr := ln.Addr().String()
	for i := 0; i < 3; i++ {
		dialFrom(t, "127.0.5."+string(rune('1'+i)), addr)
		if waitAccept(accepted, time.Second) == nil {
			t.Fatalf("connection %d of 3 from the network was refused", i+1)
		}
	}
	fourth := dialFrom(t, "127.0.5.9", addr)
	if waitAccept(accepted, 500*time.Millisecond) != nil {
		t.Fatal("a fourth connection from the same /24 was accepted")
	}
	fourth.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := fourth.Read(make([]byte, 1)); err == nil {
		t.Fatal("the refused connection was left open")
	}
	dialFrom(t, "127.0.6.1", addr)
	if waitAccept(accepted, time.Second) == nil {
		t.Fatal("another network was refused")
	}

	s.sources.do(sourceKey(netip.MustParseAddr("127.0.7.7")), now.UnixNano(), func(src *source) { src.bannedUntil = now.Add(time.Hour).UnixNano() })
	dialFrom(t, "127.0.7.7", addr)
	if waitAccept(accepted, 500*time.Millisecond) != nil {
		t.Fatal("a banned address got a connection")
	}
}

// When connections run short, idle keep-alive connections of clients the shield does not know are closed to make room;
// nobody is refused while one of those can go.
func TestIdleConnectionsOfStrangersMakeRoom(t *testing.T) {
	now := time.Now()
	clock := &now
	s := newTestShield(t, clock, func(c *Config) { c.MaxConns = 20; c.ReservedShare = 0.5; c.DeferAccept = -1 })
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
		c := dialFrom(t, "127.0.8."+itoa(float64(i+1)), addr)
		c.Write([]byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n"))
		buf := make([]byte, 512)
		c.SetReadDeadline(time.Now().Add(2 * time.Second))
		if n, err := c.Read(buf); err != nil || n == 0 {
			t.Fatalf("request %d: %v", i, err)
		}
		idle = append(idle, c)
	}
	time.Sleep(200 * time.Millisecond) // the server marks them idle
	*clock = clock.Add(2 * time.Second)
	newcomer := dialFrom(t, "127.0.9.1", addr)
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
