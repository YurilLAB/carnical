// SPDX-License-Identifier: Apache-2.0

package main

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"runtime"

	"github.com/YurilLAB/coraza/carnical/proxy"
)

// Origin identity files are operator-owned and loaded before confinement. Values
// and private key bytes are never returned in errors or logged.
func configureOriginTLS(target *url.URL, certFile, keyFile, caFile string) (proxy.OriginTLS, error) {
	var out proxy.OriginTLS
	if (certFile == "") != (keyFile == "") {
		return out, errors.New("give both -origin-client-cert and -origin-client-key, or neither")
	}
	if (certFile != "" || caFile != "") && target.Scheme != "https" {
		return out, errors.New("origin TLS settings require an HTTPS upstream")
	}
	if certFile != "" {
		certPEM, err := readOriginFile(certFile, 1<<20, false)
		if err != nil {
			return out, errors.New("cannot read origin client certificate (regular file, maximum 1 MiB)")
		}
		keyPEM, err := readOriginFile(keyFile, 64<<10, true)
		if err != nil {
			return out, errors.New("cannot read origin client key (private regular file, maximum 64 KiB)")
		}
		cert, err := tls.X509KeyPair(certPEM, keyPEM)
		if err != nil {
			return out, errors.New("invalid origin client certificate/key pair")
		}
		out.Certificate = &cert
	}
	if caFile != "" {
		pem, err := readOriginFile(caFile, 1<<20, false)
		if err != nil {
			return out, errors.New("cannot read origin CA file (regular file, maximum 1 MiB)")
		}
		out.Roots = x509.NewCertPool()
		if !out.Roots.AppendCertsFromPEM(pem) {
			return out, errors.New("origin CA file contains no certificates")
		}
	}
	if _, err := out.ClientConfig(target); err != nil {
		return out, err
	}
	return out, nil
}

func readOriginFile(path string, limit int64, private bool) ([]byte, error) {
	path, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	root, err := os.OpenRoot(filepath.Dir(path))
	if err != nil {
		return nil, err
	}
	defer root.Close()
	name := filepath.Base(path)
	info, err := root.Lstat(name)
	if err != nil || !info.Mode().IsRegular() || info.Size() > limit {
		return nil, errors.New("invalid origin file")
	}
	file, err := root.Open(name)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !opened.Mode().IsRegular() || !os.SameFile(info, opened) {
		return nil, errors.New("origin file changed while opening")
	}
	if private && runtime.GOOS != "windows" && opened.Mode().Perm()&0027 != 0 {
		return nil, errors.New("origin key must not be world accessible or group writable")
	}
	data, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil || int64(len(data)) > limit {
		return nil, errors.New("origin file is too large or unreadable")
	}
	return data, nil
}
