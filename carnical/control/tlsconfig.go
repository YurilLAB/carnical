// SPDX-License-Identifier: Apache-2.0

package control

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

// TLSOptions say where the server's certificate and the client CA bundle are.
type TLSOptions struct {
	// CertFile and KeyFile are the server's certificate chain and private key (PEM).
	CertFile, KeyFile string
	// ClientCAFile holds the CA certificates (PEM) that client certificates must chain to.
	ClientCAFile string
	// CheckEvery is how often the files are looked at for a change, at most; default 2 seconds. The look is made when
	// a client connects, so an idle server does no work.
	CheckEvery time.Duration
	// Now is the clock; default time.Now.
	Now func() time.Time
}

// TLSReloader serves a *tls.Config whose certificate and client CA pool are replaced, as a whole, when the files change
// on disk. A new certificate is used by the next connection; connections already made keep the one they began with. If
// the new files do not load (a certificate that does not match its key, a CA file with no certificates) the old ones
// stay in force and LastError says why.
type TLSReloader struct {
	opts TLSOptions
	cfg  *tls.Config
	cur  atomic.Pointer[tls.Config]

	mu      sync.Mutex
	loaded  filesSig
	failed  filesSig
	checked time.Time
	lastErr atomic.Pointer[error]
	reloads atomic.Uint64
}

type filesSig struct {
	m  [3]time.Time
	n  [3]int64
	ok bool
}

// TLSConfig returns the server's *tls.Config: TLS 1.3 only, a client certificate required and verified against the CA
// bundle, session tickets off (so every connection shows its certificate again and a restart leaves no ticket valid),
// a post-quantum hybrid and the two usual curves in that order, and the certificate and CA bundle reloaded from disk
// when their files change.
func TLSConfig(opts TLSOptions) (*tls.Config, error) {
	r, err := NewTLSReloader(opts)
	if err != nil {
		return nil, err
	}
	return r.Config(), nil
}

// NewTLSReloader is TLSConfig with a handle on the reloader.
func NewTLSReloader(opts TLSOptions) (*TLSReloader, error) {
	if opts.CertFile == "" || opts.KeyFile == "" || opts.ClientCAFile == "" {
		return nil, errors.New("control: CertFile, KeyFile and ClientCAFile are required")
	}
	if opts.CheckEvery <= 0 {
		opts.CheckEvery = 2 * time.Second
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	r := &TLSReloader{opts: opts}
	sig, cfg, err := r.load()
	if err != nil {
		return nil, err
	}
	r.loaded, r.checked = sig, opts.Now()
	r.cur.Store(cfg)
	// The config handed out is itself a handshake-time switch: every handshake asks which immutable snapshot to use.
	r.cfg = &tls.Config{
		MinVersion:             tls.VersionTLS13,
		MaxVersion:             tls.VersionTLS13,
		ClientAuth:             tls.RequireAndVerifyClientCert,
		ClientCAs:              cfg.ClientCAs,
		Certificates:           cfg.Certificates,
		CurvePreferences:       curvePreferences(),
		SessionTicketsDisabled: true,
		NextProtos:             []string{"h2", "http/1.1"},
		GetConfigForClient: func(*tls.ClientHelloInfo) (*tls.Config, error) {
			r.maybeReload()
			return r.cur.Load(), nil
		},
	}
	return r, nil
}

// Config returns the config to give to the server.
func (r *TLSReloader) Config() *tls.Config { return r.cfg }

// LastError returns why the most recent reload failed, or nil.
func (r *TLSReloader) LastError() error {
	if p := r.lastErr.Load(); p != nil {
		return *p
	}
	return nil
}

// Reloads counts successful reloads after the first load.
func (r *TLSReloader) Reloads() uint64 { return r.reloads.Load() }

func curvePreferences() []tls.CurveID {
	return []tls.CurveID{tls.X25519MLKEM768, tls.X25519, tls.CurveP256}
}

func (r *TLSReloader) signature() filesSig {
	var s filesSig
	s.ok = true
	for i, p := range []string{r.opts.CertFile, r.opts.KeyFile, r.opts.ClientCAFile} {
		st, err := os.Stat(p)
		if err != nil {
			s.ok = false
			continue
		}
		s.m[i], s.n[i] = st.ModTime(), st.Size()
	}
	return s
}

// load reads the three files and builds the snapshot. It returns the signature of the files as they were before it
// read them, so a change during the read is seen next time.
func (r *TLSReloader) load() (filesSig, *tls.Config, error) {
	sig := r.signature()
	cert, err := tls.LoadX509KeyPair(r.opts.CertFile, r.opts.KeyFile)
	if err != nil {
		return sig, nil, fmt.Errorf("control: server certificate: %w", err)
	}
	pem, err := os.ReadFile(r.opts.ClientCAFile)
	if err != nil {
		return sig, nil, fmt.Errorf("control: client CA file: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return sig, nil, errors.New("control: the client CA file holds no certificate")
	}
	return sig, &tls.Config{
		MinVersion:             tls.VersionTLS13,
		MaxVersion:             tls.VersionTLS13,
		ClientAuth:             tls.RequireAndVerifyClientCert,
		ClientCAs:              pool,
		Certificates:           []tls.Certificate{cert},
		CurvePreferences:       curvePreferences(),
		SessionTicketsDisabled: true,
		NextProtos:             []string{"h2", "http/1.1"},
	}, nil
}

func (r *TLSReloader) maybeReload() {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := r.opts.Now()
	if now.Sub(r.checked) < r.opts.CheckEvery {
		return
	}
	r.checked = now
	sig := r.signature()
	if sig == r.loaded || (r.failed.ok && sig == r.failed) {
		return
	}
	got, cfg, err := r.load()
	if err != nil {
		r.failed = got
		r.lastErr.Store(&err)
		return
	}
	r.cur.Store(cfg)
	r.loaded, r.failed = got, filesSig{}
	r.lastErr.Store(nil)
	r.reloads.Add(1)
}
