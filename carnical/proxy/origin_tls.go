// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"bytes"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net/url"
	"slices"
	"time"
)

// OriginTLS describes origin trust and the edge's optional client identity.
// Nil Roots uses system roots. Certificate authenticates the edge to an HTTPS
// origin; the origin must require and authorize that certificate independently.
// The private signer must remain immutable and safe for concurrent handshakes.
type OriginTLS struct {
	Roots       *x509.CertPool
	Certificate *tls.Certificate
}

// ClientConfig creates a verified TLS configuration for the configured upstream.
// The upstream URL supplies SNI and the certificate name; HTTP Host overrides
// never change that identity. There is no option to skip server verification.
func (o OriginTLS) ClientConfig(upstream *url.URL) (*tls.Config, error) {
	if upstream == nil || upstream.Scheme != "https" {
		if o.Roots != nil || o.Certificate != nil {
			return nil, errors.New("origin TLS settings require an HTTPS upstream")
		}
		return nil, nil
	}
	cfg := &tls.Config{MinVersion: tls.VersionTLS12, ServerName: upstream.Hostname()}
	if o.Roots != nil {
		cfg.RootCAs = o.Roots.Clone()
	} else {
		// Resolve system trust before the CLI applies filesystem confinement.
		roots, err := x509.SystemCertPool()
		if err != nil {
			return nil, errors.New("cannot load system origin trust roots")
		}
		cfg.RootCAs = roots
	}
	if o.Certificate == nil {
		return cfg, nil
	}
	cert := *o.Certificate
	if len(cert.Certificate) == 0 || cert.PrivateKey == nil {
		return nil, errors.New("origin client certificate and private key are required")
	}
	cert.Certificate = slices.Clone(cert.Certificate)
	for i, der := range cert.Certificate {
		cert.Certificate[i] = slices.Clone(der)
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return nil, errors.New("invalid origin client certificate")
	}
	now := time.Now()
	if now.Before(leaf.NotBefore) || !now.Before(leaf.NotAfter) {
		return nil, errors.New("origin client certificate is not currently valid")
	}
	if !slices.Contains(leaf.ExtKeyUsage, x509.ExtKeyUsageClientAuth) && !slices.Contains(leaf.ExtKeyUsage, x509.ExtKeyUsageAny) {
		return nil, errors.New("origin client certificate must allow client authentication")
	}
	signer, ok := cert.PrivateKey.(crypto.Signer)
	if !ok {
		return nil, errors.New("unsupported origin client private key")
	}
	actual, err := x509.MarshalPKIXPublicKey(signer.Public())
	if err != nil {
		return nil, errors.New("invalid origin client private key")
	}
	expected, err := x509.MarshalPKIXPublicKey(leaf.PublicKey)
	if err != nil || !bytes.Equal(actual, expected) {
		return nil, errors.New("origin client certificate does not match its private key")
	}
	cert.Leaf = leaf
	cert.SupportedSignatureAlgorithms = slices.Clone(cert.SupportedSignatureAlgorithms)
	cert.OCSPStaple = slices.Clone(cert.OCSPStaple)
	cert.SignedCertificateTimestamps = slices.Clone(cert.SignedCertificateTimestamps)
	for i, sct := range cert.SignedCertificateTimestamps {
		cert.SignedCertificateTimestamps[i] = slices.Clone(sct)
	}
	cfg.Certificates = []tls.Certificate{cert}
	return cfg, nil
}
