// SPDX-License-Identifier: Apache-2.0

package control

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// testPKI is a throwaway certificate authority and the certificates it issues, for tests.
type testPKI struct {
	t      testing.TB
	ca     *x509.Certificate
	caKey  *ecdsa.PrivateKey
	caPEM  []byte
	serial int64
}

func newPKI(t testing.TB) *testPKI {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "carnical test CA"},
		NotBefore: validFrom(), NotAfter: validUntil(),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return &testPKI{t: t, ca: ca, caKey: key, caPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), serial: 1}
}

// issued is one certificate with its key in every form a test wants.
type issued struct {
	cert    *x509.Certificate
	key     *ecdsa.PrivateKey
	tls     tls.Certificate
	certPEM []byte
	keyPEM  []byte
}

type issueOpts struct {
	cn        string
	server    bool
	dns       []string
	ips       []net.IP
	notBefore time.Time
	notAfter  time.Time
	key       *ecdsa.PrivateKey // reuse a key (a renewed certificate)
}

func (p *testPKI) issue(o issueOpts) *issued {
	p.t.Helper()
	key := o.key
	if key == nil {
		var err error
		if key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader); err != nil {
			p.t.Fatal(err)
		}
	}
	if o.notBefore.IsZero() {
		o.notBefore = validFrom()
	}
	if o.notAfter.IsZero() {
		o.notAfter = validUntil()
	}
	p.serial++
	usage := x509.ExtKeyUsageClientAuth
	if o.server {
		usage = x509.ExtKeyUsageServerAuth
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(p.serial), Subject: pkix.Name{CommonName: o.cn}, DNSNames: o.dns, IPAddresses: o.ips,
		NotBefore: o.notBefore, NotAfter: o.notAfter, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{usage},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, p.ca, &key.PublicKey, p.caKey)
	if err != nil {
		p.t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		p.t.Fatal(err)
	}
	kb, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		p.t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb})
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		p.t.Fatal(err)
	}
	return &issued{cert: cert, key: key, tls: pair, certPEM: certPEM, keyPEM: keyPEM}
}

func (p *testPKI) server() *issued {
	return p.issue(issueOpts{cn: "control.test", server: true, dns: []string{"control.test", "localhost"}, ips: []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")}})
}

func (p *testPKI) client(cn string) *issued { return p.issue(issueOpts{cn: cn}) }

func (p *testPKI) pool() *x509.CertPool {
	pool := x509.NewCertPool()
	pool.AddCert(p.ca)
	return pool
}

func writeFile(t testing.TB, path string, b []byte) {
	t.Helper()
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
}

// files writes the server certificate, its key and the CA bundle into dir.
func (p *testPKI) files(dir string, server *issued) (certFile, keyFile, caFile string) {
	certFile, keyFile, caFile = filepath.Join(dir, "server.pem"), filepath.Join(dir, "server.key"), filepath.Join(dir, "clients-ca.pem")
	writeFile(p.t, certFile, server.certPEM)
	writeFile(p.t, keyFile, server.keyPEM)
	writeFile(p.t, caFile, p.caPEM)
	return
}

// validFrom and validUntil bound the validity of test certificates so that they are valid both now (real TLS handshakes
// use the real clock) and at the fake clock's epoch (the direct handler tests use that).
func validFrom() time.Time {
	t := time.Now()
	if epoch.Before(t) {
		t = epoch
	}
	return t.Add(-48 * time.Hour)
}

func validUntil() time.Time {
	t := time.Now()
	if epoch.After(t) {
		t = epoch
	}
	return t.Add(48 * time.Hour)
}
