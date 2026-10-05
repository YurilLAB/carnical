// SPDX-License-Identifier: Apache-2.0

package control

import (
	"crypto/tls"
	"os"
	"sync"
	"time"
)

// certFiles is a client certificate read from two files and read again when either changes, so a renewed certificate is
// used by the next connection without restarting the UI.
type certFiles struct {
	certPath, keyPath string

	mu      sync.Mutex
	cert    *tls.Certificate
	sig     filesSig
	failed  filesSig
	checked time.Time
}

func newCertFiles(certPath, keyPath string) (*certFiles, error) {
	c := &certFiles{certPath: certPath, keyPath: keyPath}
	sig := c.signature()
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, err
	}
	c.cert, c.sig, c.checked = &cert, sig, time.Now()
	return c, nil
}

func (c *certFiles) signature() filesSig {
	var s filesSig
	s.ok = true
	for i, p := range []string{c.certPath, c.keyPath} {
		st, err := os.Stat(p)
		if err != nil {
			s.ok = false
			continue
		}
		s.m[i], s.n[i] = st.ModTime(), st.Size()
	}
	return s
}

func (c *certFiles) get(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if now := time.Now(); now.Sub(c.checked) >= 2*time.Second {
		c.checked = now
		if sig := c.signature(); sig != c.sig && !(c.failed.ok && sig == c.failed) {
			if cert, err := tls.LoadX509KeyPair(c.certPath, c.keyPath); err == nil {
				c.cert, c.sig, c.failed = &cert, sig, filesSig{}
			} else {
				c.failed = sig // keep the certificate that works until the files change again
			}
		}
	}
	return c.cert, nil
}
