// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"time"

	"github.com/YurilLAB/coraza/carnical/proxy"
)

// checkDeployment does not bind a listener, consume inherited descriptors or
// apply a sandbox. The optional probe uses the same dial-time origin policy and
// system TLS roots as serving; it sends no application request or credentials.
func checkDeployment(listen string, target *url.URL, policy proxy.OriginPolicy, systemd, probe bool) error {
	if !systemd {
		if _, port, err := net.SplitHostPort(listen); err != nil {
			return fmt.Errorf("-listen: %w", err)
		} else if _, err := net.LookupPort("tcp", port); err != nil {
			return errors.New("-listen must have a valid TCP port")
		}
	}
	port := target.Port()
	if port == "" {
		port = "80"
		if target.Scheme == "https" {
			port = "443"
		}
	}
	if n, err := strconv.ParseUint(port, 10, 16); err != nil || n == 0 {
		return errors.New("the upstream must have a numeric port between 1 and 65535")
	}
	if !probe {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := policy.CheckHost(ctx, target.Hostname()); err != nil {
		return fmt.Errorf("origin preflight: %w", err)
	}
	address := net.JoinHostPort(target.Hostname(), port)
	var conn net.Conn
	var err error
	if target.Scheme == "https" {
		dialer := tls.Dialer{NetDialer: policy.Dialer(), Config: &tls.Config{MinVersion: tls.VersionTLS12}}
		conn, err = dialer.DialContext(ctx, "tcp", address)
	} else {
		conn, err = policy.Dialer().DialContext(ctx, "tcp", address)
	}
	if err != nil {
		return fmt.Errorf("origin preflight: %w", err)
	}
	if err := conn.Close(); err != nil {
		return fmt.Errorf("closing origin preflight connection: %w", err)
	}
	return nil
}
