// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"
)

type lifecycleOptions struct {
	healthAddress string
	drain         time.Duration
	shutdown      time.Duration
}

// validate runs in both check and serving modes. Health is deliberately confined
// to a numeric loopback address; it is never mounted on the visitor listener.
func (o lifecycleOptions) validate() error {
	if o.shutdown < 100*time.Millisecond || o.shutdown > 10*time.Minute {
		return errors.New("-shutdown-timeout must be between 100ms and 10m")
	}
	if o.drain < 0 || o.drain > time.Minute || o.drain >= o.shutdown {
		return errors.New("-drain-delay must be between 0 and 1m and less than -shutdown-timeout")
	}
	if o.healthAddress != "" {
		if _, err := loopbackHealthAddress(o.healthAddress); err != nil {
			return err
		}
	}
	return nil
}

func loopbackHealthAddress(value string) (string, error) {
	address, err := netip.ParseAddrPort(value)
	if err != nil || !address.Addr().IsLoopback() || address.Addr().Zone() != "" || address.Port() == 0 {
		return "", errors.New("-health-listen must be a numeric loopback address with a nonzero port")
	}
	return netip.AddrPortFrom(address.Addr().Unmap(), address.Port()).String(), nil
}

type runtimeHealth struct {
	started  atomic.Bool
	draining atomic.Bool
	// available checks only local state, never origin or LAPI network I/O.
	available func() bool
}

func (h *runtimeHealth) server(address string) *http.Server {
	return &http.Server{
		Addr: address, ReadHeaderTimeout: 2 * time.Second, ReadTimeout: 2 * time.Second,
		WriteTimeout: 2 * time.Second, IdleTimeout: 5 * time.Second, MaxHeaderBytes: 4 << 10,
		DisableGeneralOptionsHandler: true,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Cache-Control", "no-store")
			w.Header().Set("X-Content-Type-Options", "nosniff")
			if r.Host != address {
				http.Error(w, "invalid health host", http.StatusForbidden)
				return
			}
			if r.ContentLength != 0 || len(r.TransferEncoding) != 0 {
				r.Close = true
				w.Header().Set("Connection", "close")
				http.Error(w, "health requests must not have a body", http.StatusBadRequest)
				return
			}
			if r.Method != http.MethodGet && r.Method != http.MethodHead {
				w.Header().Set("Allow", "GET, HEAD")
				http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
				return
			}
			switch r.RequestURI {
			case "/livez":
				w.WriteHeader(http.StatusOK)
			case "/readyz":
				if !h.started.Load() || h.draining.Load() || (h.available != nil && !h.available()) {
					http.Error(w, "not ready", http.StatusServiceUnavailable)
					return
				}
				w.WriteHeader(http.StatusOK)
			default:
				http.NotFound(w, r)
			}
		}),
	}
}

// probeHealth is also usable in images without a shell or curl. It cannot use an
// environment proxy, follow redirects, resolve a hostname or inspect a website.
func probeHealth(kind, address string) error {
	if kind != "live" && kind != "ready" {
		return errors.New("-probe must be live or ready")
	}
	if address == "" {
		return errors.New("-probe requires -health-listen")
	}
	address, err := loopbackHealthAddress(address)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodHead, "http://"+address+"/"+kind+"z", nil)
	if err != nil {
		return errors.New("cannot construct health probe")
	}
	transport := &http.Transport{Proxy: nil, MaxResponseHeaderBytes: 4 << 10, DisableKeepAlives: true}
	defer transport.CloseIdleConnections()
	response, err := transport.RoundTrip(request)
	if err != nil {
		return errors.New("health probe unavailable")
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("health probe returned HTTP %d", response.StatusCode)
	}
	return nil
}

type servingListener struct {
	net.Listener
	once   sync.Once
	health *runtimeHealth
}

func (l *servingListener) Accept() (net.Conn, error) {
	// ServeTLS has validated its TLS configuration and initialized HTTP/2 before
	// it enters Accept. No readiness is published merely because net.Listen ran.
	l.once.Do(func() { l.health.started.Store(true) })
	return l.Listener.Accept()
}

type serveResult struct {
	listener string
	err      error
}

// serveRuntime owns all serving goroutines and closes both listeners on any
// failure. The shutdown budget includes the readiness withdrawal delay.
func serveRuntime(ctx context.Context, server *http.Server, listener net.Listener, healthListener net.Listener,
	health *runtimeHealth, options lifecycleOptions, log *slog.Logger) (err error) {
	done := make(chan serveResult, 2)
	count, received := 1, 0
	var healthServer *http.Server
	if healthListener != nil {
		count++
		healthServer = health.server(healthListener.Addr().String())
		go func() { done <- serveResult{"health", healthServer.Serve(healthListener)} }()
	}
	// Close aborts ordinary active requests when Shutdown exhausts its budget.
	// Explicitly opted-in upgraded connections terminate when the CLI exits.
	defer func() {
		health.draining.Store(true)
		err = errors.Join(err, server.Close())
		if healthServer != nil {
			err = errors.Join(err, healthServer.Close())
		}
		for _, ln := range []net.Listener{listener, healthListener} {
			if ln != nil {
				if closeErr := ln.Close(); closeErr != nil && !errors.Is(closeErr, net.ErrClosed) {
					err = errors.Join(err, closeErr)
				}
			}
		}
		for received < count {
			<-done
			received++
		}
	}()
	go func() {
		ln := &servingListener{Listener: listener, health: health}
		if server.TLSConfig != nil {
			done <- serveResult{"visitor", server.ServeTLS(ln, "", "")}
		} else {
			done <- serveResult{"visitor", server.Serve(ln)}
		}
	}()
	unexpected := func(result serveResult) error {
		if result.err == nil {
			result.err = errors.New("listener stopped without an error")
		}
		return fmt.Errorf("%s listener stopped: %w", result.listener, result.err)
	}
	select {
	case result := <-done:
		received++
		return unexpected(result)
	case <-ctx.Done():
	}
	health.draining.Store(true)
	shutdown, cancel := context.WithTimeout(context.Background(), options.shutdown)
	defer cancel()
	log.Info("draining", "delay", options.drain.String(), "shutdown_timeout", options.shutdown.String())
	if options.drain > 0 {
		delay := time.NewTimer(options.drain)
		defer delay.Stop()
		select {
		case <-delay.C:
		case result := <-done:
			received++
			return unexpected(result)
		case <-shutdown.Done():
		}
	}
	// Requests reaching the edge during load-balancer propagation still use the
	// complete WAF. Shutdown then stops accepting and waits for active requests.
	if err := server.Shutdown(shutdown); err != nil {
		log.Warn("shutdown incomplete", "deadline_exceeded", errors.Is(err, context.DeadlineExceeded))
		return err
	}
	log.Info("shutdown complete")
	return nil
}
