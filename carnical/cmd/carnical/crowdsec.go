// SPDX-License-Identifier: Apache-2.0

package main

import (
	"crypto/x509"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/YurilLAB/coraza/carnical/crowdsec"
)

type crowdSecFlags struct {
	api, keyFile, caFile, origins string
	interval, timeout, maxStale   time.Duration
	failOpen                      bool
	maxDecisions                  int
}

// Configuration secrets and trust roots are loaded once, before confinement;
// no key material or API response is returned in an error or logged.
func configureCrowdSec(f crowdSecFlags) (*crowdsec.Client, error) {
	if f.api == "" {
		if f.keyFile != "" || f.caFile != "" || f.origins != "" || f.failOpen {
			return nil, errors.New("CrowdSec options require -crowdsec-api")
		}
		return nil, nil
	}
	if f.keyFile == "" {
		return nil, errors.New("-crowdsec-api requires -crowdsec-key-file")
	}
	key, err := readCrowdSecFile(f.keyFile, 4096, true)
	if err != nil {
		return nil, errors.New("cannot read CrowdSec bouncer key file (regular file, maximum 4096 bytes, not accessible to everyone or writable by its group)")
	}
	cfg := crowdsec.Config{URL: f.api, APIKey: strings.TrimSpace(string(key)), Interval: f.interval, Timeout: f.timeout,
		MaxStale: f.maxStale, FailOpen: f.failOpen, MaxDecisions: f.maxDecisions, Origins: f.origins}
	if f.caFile != "" {
		pem, err := readCrowdSecFile(f.caFile, 1<<20, false)
		if err != nil {
			return nil, errors.New("cannot read CrowdSec CA file (regular file, maximum 1 MiB)")
		}
		cfg.Roots = x509.NewCertPool()
		if !cfg.Roots.AppendCertsFromPEM(pem) {
			return nil, errors.New("CrowdSec CA file contains no certificates")
		}
	}
	return crowdsec.New(cfg)
}

// readCrowdSecFile reads a file inside its named directory. A private one (the bouncer key: whoever reads it can take this
// bouncer's place in the decision stream) must not be accessible to everyone or writable by its group.
func readCrowdSecFile(path string, limit int64, private bool) ([]byte, error) {
	path, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	root, err := os.OpenRoot(filepath.Dir(path))
	if err != nil {
		return nil, err
	}
	defer root.Close()
	// Opened without blocking, so a FIFO cannot hold start-up, and only a regular file is read. Root also prevents a
	// symlink escaping the named configuration directory.
	f, err := root.OpenFile(filepath.Base(path), os.O_RDONLY|syscall.O_NONBLOCK|syscall.O_NOCTTY, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return nil, errors.New("invalid file")
	}
	if private && runtime.GOOS != "windows" && info.Mode().Perm()&0o027 != 0 {
		return nil, errors.New("a private file must not be accessible to everyone or writable by its group")
	}
	b, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil || int64(len(b)) > limit {
		return nil, errors.New("file too large or unreadable")
	}
	return b, nil
}
