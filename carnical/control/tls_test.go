// SPDX-License-Identifier: Apache-2.0

package control

import (
	"crypto/tls"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// tlsServer accepts connections, finishes the handshake and answers "ok". It reports handshake failures on errs.
type tlsServer struct {
	addr string
	ln   net.Listener
	errs chan error
}

func startTLS(t *testing.T, cfg *tls.Config) *tlsServer {
	t.Helper()
	ln, err := tls.Listen("tcp", "127.0.0.1:0", cfg)
	if err != nil {
		t.Fatal(err)
	}
	s := &tlsServer{addr: ln.Addr().String(), ln: ln, errs: make(chan error, 64)}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				tc := c.(*tls.Conn)
				_ = tc.SetDeadline(time.Now().Add(5 * time.Second))
				if err := tc.Handshake(); err != nil {
					select {
					case s.errs <- err:
					default:
					}
					return
				}
				_, _ = tc.Write([]byte("ok"))
				// stay open until the client is done, so a test can hold a connection across a reload
				_, _ = io.Copy(io.Discard, tc)
			}()
		}
	}()
	return s
}

// dial connects and reads the server's "ok". In TLS 1.3 a client learns that its certificate was refused only when it
// next reads, so a refusal shows up as an error from here.
func (s *tlsServer) dial(cfg *tls.Config) (*tls.Conn, error) {
	d := &net.Dialer{Timeout: 5 * time.Second}
	conn, err := tls.DialWithDialer(d, "tcp", s.addr, cfg)
	if err != nil {
		return nil, err
	}
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 2)
	if _, err := io.ReadFull(conn, buf); err != nil {
		conn.Close()
		return nil, err
	}
	return conn, nil
}

func clientCfg(p *testPKI, c *issued) *tls.Config {
	cfg := &tls.Config{RootCAs: p.pool(), ServerName: "control.test", MinVersion: tls.VersionTLS12}
	if c != nil {
		cfg.Certificates = []tls.Certificate{c.tls}
	}
	return cfg
}

func newTLS(t *testing.T) (*testPKI, *issued, *TLSReloader, *tlsServer, string, *fakeClock) {
	t.Helper()
	p := newPKI(t)
	server := p.server()
	dir := t.TempDir()
	certFile, keyFile, caFile := p.files(dir, server)
	clock := &fakeClock{t: epoch}
	r, err := NewTLSReloader(TLSOptions{CertFile: certFile, KeyFile: keyFile, ClientCAFile: caFile, CheckEvery: time.Second, Now: clock.now})
	if err != nil {
		t.Fatal(err)
	}
	return p, server, r, startTLS(t, r.Config()), dir, clock
}

func TestTLSConfigProperties(t *testing.T) {
	_, _, r, _, _, _ := newTLS(t)
	cfg := r.Config()
	if cfg.MinVersion != tls.VersionTLS13 || cfg.MaxVersion != tls.VersionTLS13 {
		t.Fatalf("versions %x..%x", cfg.MinVersion, cfg.MaxVersion)
	}
	if cfg.ClientAuth != tls.RequireAndVerifyClientCert {
		t.Fatalf("client auth %v", cfg.ClientAuth)
	}
	if !cfg.SessionTicketsDisabled {
		t.Fatal("session tickets are on")
	}
	want := []tls.CurveID{tls.X25519MLKEM768, tls.X25519, tls.CurveP256}
	if len(cfg.CurvePreferences) != len(want) {
		t.Fatalf("curves %v", cfg.CurvePreferences)
	}
	for i := range want {
		if cfg.CurvePreferences[i] != want[i] {
			t.Fatalf("curves %v", cfg.CurvePreferences)
		}
	}
	if cfg.GetConfigForClient == nil || len(cfg.NextProtos) != 2 || cfg.NextProtos[0] != "h2" {
		t.Fatal("handshake hook or protocols")
	}
	// the snapshot used for each handshake has the same properties
	snap, err := cfg.GetConfigForClient(nil)
	if err != nil {
		t.Fatal(err)
	}
	if snap.MinVersion != tls.VersionTLS13 || snap.ClientAuth != tls.RequireAndVerifyClientCert || !snap.SessionTicketsDisabled || snap.ClientCAs == nil || len(snap.Certificates) != 1 {
		t.Fatalf("snapshot: %+v", snap)
	}
}

func TestTLSHandshakes(t *testing.T) {
	p, server, _, srv, _, _ := newTLS(t)
	good := p.client("ui-a")
	otherCA := newPKI(t)
	foreign := otherCA.client("ui-a")
	expired := p.issue(issueOpts{cn: "old", notBefore: time.Now().Add(-48 * time.Hour), notAfter: time.Now().Add(-time.Hour)})
	notYet := p.issue(issueOpts{cn: "new", notBefore: time.Now().Add(time.Hour), notAfter: time.Now().Add(48 * time.Hour)})

	rows := []struct {
		name   string
		client func() *tls.Config
		ok     bool
	}{
		{"a valid client certificate", func() *tls.Config { return clientCfg(p, good) }, true},
		{"no client certificate", func() *tls.Config { return clientCfg(p, nil) }, false},
		{"a certificate from another CA", func() *tls.Config { return clientCfg(p, foreign) }, false},
		{"an expired certificate", func() *tls.Config { return clientCfg(p, expired) }, false},
		{"a certificate that is not valid yet", func() *tls.Config { return clientCfg(p, notYet) }, false},
		{"a server certificate used as a client certificate (wrong key usage)", func() *tls.Config { return clientCfg(p, server) }, false},
		{"TLS 1.2 only", func() *tls.Config {
			c := clientCfg(p, good)
			c.MaxVersion = tls.VersionTLS12
			return c
		}, false},
		{"TLS 1.3 offered with 1.2", func() *tls.Config { c := clientCfg(p, good); c.MaxVersion = tls.VersionTLS13; return c }, true},
		{"a client that supports only a curve the server does not", func() *tls.Config {
			c := clientCfg(p, good)
			c.CurvePreferences = []tls.CurveID{tls.CurveP384}
			return c
		}, false},
		{"a client that supports only P-256", func() *tls.Config {
			c := clientCfg(p, good)
			c.CurvePreferences = []tls.CurveID{tls.CurveP256}
			return c
		}, true},
		{"a client that does not trust the server", func() *tls.Config {
			c := clientCfg(p, good)
			c.RootCAs = otherCA.pool()
			return c
		}, false},
		{"a client that expects another name", func() *tls.Config {
			c := clientCfg(p, good)
			c.ServerName = "other.test"
			return c
		}, false},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			conn, err := srv.dial(row.client())
			if row.ok {
				if err != nil {
					t.Fatalf("refused: %v", err)
				}
				if v := conn.ConnectionState().Version; v != tls.VersionTLS13 {
					t.Fatalf("negotiated %x", v)
				}
				conn.Close()
				return
			}
			if err == nil {
				conn.Close()
				t.Fatal("accepted")
			}
		})
	}
	t.Run("the negotiated group is the post-quantum hybrid when the client offers it", func(t *testing.T) {
		c := clientCfg(p, good)
		c.CurvePreferences = []tls.CurveID{tls.X25519MLKEM768, tls.X25519}
		conn, err := srv.dial(c)
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		if got := conn.ConnectionState().CurveID; got != tls.X25519MLKEM768 {
			t.Fatalf("group %v", got)
		}
	})
}

func TestNoSessionResumption(t *testing.T) {
	p, _, _, srv, _, _ := newTLS(t)
	c := clientCfg(p, p.client("ui-a"))
	c.ClientSessionCache = tls.NewLRUClientSessionCache(8)
	for i := 0; i < 3; i++ {
		conn, err := srv.dial(c)
		if err != nil {
			t.Fatal(err)
		}
		if conn.ConnectionState().DidResume {
			t.Fatalf("connection %d resumed a session: it did not present its certificate again", i+1)
		}
		conn.Close()
	}
}

func setTimes(t *testing.T, mod time.Time, paths ...string) {
	t.Helper()
	for _, p := range paths {
		if err := os.Chtimes(p, mod, mod); err != nil {
			t.Fatal(err)
		}
	}
}

func serverSPKI(c *tls.Conn) Fingerprint {
	return SPKIFingerprint(c.ConnectionState().PeerCertificates[0])
}

func TestServerCertificateReloads(t *testing.T) {
	p, first, r, srv, dir, clock := newTLS(t)
	client := clientCfg(p, p.client("ui-a"))
	certFile, keyFile := filepath.Join(dir, "server.pem"), filepath.Join(dir, "server.key")

	conn1, err := srv.dial(client)
	if err != nil {
		t.Fatal(err)
	}
	defer conn1.Close()
	if serverSPKI(conn1) != SPKIFingerprint(first.cert) {
		t.Fatal("the first certificate is not the one on disk")
	}

	// a new certificate on a new key
	second := p.server()
	writeFile(t, certFile, second.certPEM)
	writeFile(t, keyFile, second.keyPEM)
	setTimes(t, time.Now().Add(time.Minute), certFile, keyFile)
	clock.advance(2 * time.Second)
	conn2, err := srv.dial(client)
	if err != nil {
		t.Fatalf("after the swap: %v", err)
	}
	defer conn2.Close()
	if serverSPKI(conn2) != SPKIFingerprint(second.cert) {
		t.Fatal("the new certificate was not served after the files changed")
	}
	if r.Reloads() != 1 || r.LastError() != nil {
		t.Fatalf("reloads %d, error %v", r.Reloads(), r.LastError())
	}
	// the connection made before the swap is still the old one, and still works
	if serverSPKI(conn1) != SPKIFingerprint(first.cert) {
		t.Fatal("an open connection changed certificate")
	}
	if _, err := conn1.Write([]byte("still here")); err != nil {
		t.Fatalf("the old connection was broken by the swap: %v", err)
	}

	t.Run("a swap is not noticed before the check interval", func(t *testing.T) {
		third := p.server()
		writeFile(t, certFile, third.certPEM)
		writeFile(t, keyFile, third.keyPEM)
		setTimes(t, time.Now().Add(2*time.Minute), certFile, keyFile)
		conn, err := srv.dial(client)
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		if serverSPKI(conn) != SPKIFingerprint(second.cert) {
			t.Fatal("reloaded without waiting for the interval")
		}
		clock.advance(2 * time.Second)
		conn, err = srv.dial(client)
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		if serverSPKI(conn) != SPKIFingerprint(third.cert) {
			t.Fatal("not reloaded after the interval")
		}
	})

	t.Run("files that do not load leave the working certificate in force", func(t *testing.T) {
		before := r.Reloads()
		current, _ := srv.dial(client)
		want := serverSPKI(current)
		current.Close()
		for name, write := range map[string]func(){
			"garbage": func() { writeFile(t, certFile, []byte("not a certificate")) },
			"a certificate and the key of another": func() {
				a, b := p.server(), p.server()
				writeFile(t, certFile, a.certPEM)
				writeFile(t, keyFile, b.keyPEM)
			},
			"empty files": func() { writeFile(t, certFile, nil); writeFile(t, keyFile, nil) },
			"a missing key": func() {
				a := p.server()
				writeFile(t, certFile, a.certPEM)
				_ = os.Remove(keyFile)
			},
		} {
			write()
			setTimes(t, time.Now().Add(10*time.Minute+time.Duration(len(name))*time.Second), certFile)
			clock.advance(2 * time.Second)
			conn, err := srv.dial(client)
			if err != nil {
				t.Fatalf("%s: the server stopped answering: %v", name, err)
			}
			if serverSPKI(conn) != want {
				t.Fatalf("%s: a certificate that did not load was served", name)
			}
			conn.Close()
			if r.LastError() == nil {
				t.Fatalf("%s: no error reported", name)
			}
		}
		if r.Reloads() != before {
			t.Fatal("a failed load counted as a reload")
		}
		// and it recovers when good files arrive
		good := p.server()
		writeFile(t, certFile, good.certPEM)
		writeFile(t, keyFile, good.keyPEM)
		setTimes(t, time.Now().Add(time.Hour), certFile, keyFile)
		clock.advance(2 * time.Second)
		conn, err := srv.dial(client)
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		if serverSPKI(conn) != SPKIFingerprint(good.cert) || r.LastError() != nil || r.Reloads() != before+1 {
			t.Fatalf("recovery: reloads %d, error %v", r.Reloads(), r.LastError())
		}
	})
}

func TestClientCAReloads(t *testing.T) {
	p, _, r, srv, dir, clock := newTLS(t)
	caFile := filepath.Join(dir, "clients-ca.pem")
	oldClient := p.client("old-ui")
	newCA := newPKI(t)
	newClient := newCA.client("new-ui")
	cfg := func(c *issued) *tls.Config {
		out := clientCfg(p, c) // the server certificate is from p in every case
		return out
	}

	if _, err := srv.dial(cfg(oldClient)); err != nil {
		t.Fatalf("the old CA's client: %v", err)
	}
	if _, err := srv.dial(cfg(newClient)); err == nil {
		t.Fatal("a client of a CA that is not in the bundle was accepted")
	}

	// the bundle gains the new CA: the new client is accepted, the old one still is
	writeFile(t, caFile, append(append([]byte(nil), p.caPEM...), newCA.caPEM...))
	setTimes(t, time.Now().Add(time.Minute), caFile)
	clock.advance(2 * time.Second)
	if _, err := srv.dial(cfg(newClient)); err != nil {
		t.Fatalf("after adding the CA: %v", err)
	}
	if _, err := srv.dial(cfg(oldClient)); err != nil {
		t.Fatalf("the old client after adding a CA: %v", err)
	}
	// the old CA is retired: its clients stop working at the next connection, with no restart
	writeFile(t, caFile, newCA.caPEM)
	setTimes(t, time.Now().Add(2*time.Minute), caFile)
	clock.advance(2 * time.Second)
	if _, err := srv.dial(cfg(oldClient)); err == nil {
		t.Fatal("a client of a retired CA was accepted")
	}
	if _, err := srv.dial(cfg(newClient)); err != nil {
		t.Fatalf("the new client: %v", err)
	}
	// a bundle with no certificate in it is not loaded
	writeFile(t, caFile, []byte("nothing here"))
	setTimes(t, time.Now().Add(3*time.Minute), caFile)
	clock.advance(2 * time.Second)
	if _, err := srv.dial(cfg(newClient)); err != nil {
		t.Fatalf("the working bundle was dropped: %v", err)
	}
	if r.LastError() == nil {
		t.Fatal("no error for an empty bundle")
	}
}

func TestTLSOptionsAreChecked(t *testing.T) {
	p := newPKI(t)
	dir := t.TempDir()
	cert, key, ca := p.files(dir, p.server())
	rows := []struct {
		name string
		opts TLSOptions
		ok   bool
	}{
		{"all three files", TLSOptions{CertFile: cert, KeyFile: key, ClientCAFile: ca}, true},
		{"no certificate file", TLSOptions{KeyFile: key, ClientCAFile: ca}, false},
		{"no key file", TLSOptions{CertFile: cert, ClientCAFile: ca}, false},
		{"no client CA file", TLSOptions{CertFile: cert, KeyFile: key}, false},
		{"a certificate file that is missing", TLSOptions{CertFile: filepath.Join(dir, "no.pem"), KeyFile: key, ClientCAFile: ca}, false},
		{"the key of another certificate", TLSOptions{CertFile: cert, KeyFile: func() string { _, k, _ := p.files(t.TempDir(), p.server()); return k }(), ClientCAFile: ca}, false},
		{"a CA file with a certificate and a key mixed in", TLSOptions{CertFile: cert, KeyFile: key, ClientCAFile: key}, false},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			cfg, err := TLSConfig(row.opts)
			if (err == nil) != row.ok {
				t.Fatalf("err = %v, want ok = %v", err, row.ok)
			}
			if row.ok && cfg == nil {
				t.Fatal("no config")
			}
		})
	}
}

func TestTLSPeerStateIsWhatTheHandlerNeeds(t *testing.T) {
	// the handler's checks (verified chain, TLS 1.3, certificate in its validity) are made on a real connection's state
	p, _, r, _, _, _ := newTLS(t)
	var got tls.ConnectionState
	ln, err := tls.Listen("tcp", "127.0.0.1:0", r.Config())
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		tc := c.(*tls.Conn)
		_ = tc.Handshake()
		got = tc.ConnectionState()
		_, _ = tc.Write([]byte("ok"))
	}()
	client := p.client("ui-a")
	conn, err := tls.Dial("tcp", ln.Addr().String(), clientCfg(p, client))
	if err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 2)
	_, _ = io.ReadFull(conn, buf)
	conn.Close()
	<-done
	if !got.HandshakeComplete || got.Version != tls.VersionTLS13 || len(got.PeerCertificates) != 1 || len(got.VerifiedChains) == 0 {
		t.Fatalf("state: complete %v version %x peers %d chains %d", got.HandshakeComplete, got.Version, len(got.PeerCertificates), len(got.VerifiedChains))
	}
	if SPKIFingerprint(got.PeerCertificates[0]) != SPKIFingerprint(client.cert) {
		t.Fatal("the fingerprint of the presented key is not the client's")
	}
}
