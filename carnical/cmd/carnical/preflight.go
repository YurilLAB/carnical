// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/YurilLAB/coraza/carnical/proxy"
)

type deploymentCheck struct {
	listen                    string
	target                    *url.URL
	policy                    proxy.OriginPolicy
	originTLS                 proxy.OriginTLS
	host                      string
	systemd, probe, probeHTTP bool
}

// checkDeployment never binds a listener, consumes inherited descriptors or
// applies a sandbox. HTTP probing is a separate explicit action because a TLS
// 1.3 peer's refusal of client authentication may appear on the next read.
func checkDeployment(options deploymentCheck) error {
	listen, target, policy := options.listen, options.target, options.policy
	originTLS, host := options.originTLS, options.host
	systemd, probe, probeHTTP := options.systemd, options.probe, options.probeHTTP
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
	tlsConfig, err := originTLS.ClientConfig(target)
	if err != nil {
		return err
	}
	if probeHTTP {
		transport := &http.Transport{DialContext: policy.Dialer().DialContext, TLSClientConfig: tlsConfig,
			TLSHandshakeTimeout: 10 * time.Second, ResponseHeaderTimeout: 10 * time.Second, MaxResponseHeaderBytes: 32 << 10}
		defer transport.CloseIdleConnections()
		// Use only the configured origin and HEAD /, with no cookies, visitor
		// credentials or supplied redirect target. RoundTrip never follows redirects.
		probeTarget := *target
		probeTarget.Path, probeTarget.RawPath, probeTarget.RawQuery, probeTarget.Fragment = "/", "", "", ""
		probeTarget.ForceQuery = false
		request, err := http.NewRequestWithContext(ctx, http.MethodHead, probeTarget.String(), nil)
		if err != nil {
			return errors.New("invalid HTTP origin probe")
		}
		if host != "" {
			request.Host = host
		}
		response, err := transport.RoundTrip(request)
		if err != nil {
			return fmt.Errorf("origin HTTP preflight: %w", err)
		}
		closeErr := response.Body.Close()
		if response.StatusCode < 200 || response.StatusCode >= 400 {
			return fmt.Errorf("origin HTTP preflight refused (status %d)", response.StatusCode)
		}
		if closeErr != nil {
			return fmt.Errorf("closing origin HTTP preflight: %w", closeErr)
		}
		return nil
	}
	address := net.JoinHostPort(target.Hostname(), port)
	var conn net.Conn
	if target.Scheme == "https" {
		dialer := tls.Dialer{NetDialer: policy.Dialer(), Config: tlsConfig}
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
