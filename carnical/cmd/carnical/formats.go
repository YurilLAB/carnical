// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"slices"
	"time"

	"github.com/YurilLAB/coraza/carnical/formats"
)

const maxFormatsPolicyBytes = formats.MaxPolicyBytes

// startFormatStats emits changed, bounded snapshots and a final snapshot on graceful shutdown.
// It opens no listener and adds no client/URI labels. The caller must invoke the returned stop function.
func startFormatStats(log *slog.Logger, in *formats.Inspector, interval time.Duration) func() {
	if in == nil || interval == 0 {
		return func() {}
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		var last []formats.RuleStats
		report := func() {
			current := in.Stats()
			if len(current) != 0 && !slices.Equal(current, last) {
				log.Info("format protection totals", "rules", current)
				last = current
			}
		}
		for {
			select {
			case <-ticker.C:
				report()
			case <-ctx.Done():
				report()
				return
			}
		}
	}()
	return func() { cancel(); <-done }
}

// configureFormats loads everything before the process opens its listener or confines itself.
// A bad policy or a conflicting flag refuses startup rather than dropping a protection.
func configureFormats(mode, path string, encoding bool) (*formats.Inspector, error) {
	switch mode {
	case "off":
		if path != "" || encoding {
			return nil, errors.New("-formats-mode off cannot be combined with -formats-policy or -allow-request-encoding")
		}
		return nil, nil
	case "monitor", "block":
	default:
		return nil, errors.New("-formats-mode must be monitor, block, or off")
	}
	p := formats.Policy{}
	if path != "" {
		file, err := os.Open(path) // #nosec G304 -- Operator-selected policy is read before listening; regular-file, size and strict policy checks follow.
		if err != nil {
			return nil, fmt.Errorf("-formats-policy: %w", err)
		}
		defer file.Close()
		info, err := file.Stat()
		if err != nil {
			return nil, fmt.Errorf("-formats-policy: %w", err)
		}
		if !info.Mode().IsRegular() {
			return nil, errors.New("-formats-policy must be a regular file")
		}
		data, err := io.ReadAll(io.LimitReader(file, maxFormatsPolicyBytes+1))
		if err != nil {
			return nil, fmt.Errorf("-formats-policy: %w", err)
		}
		if len(data) > maxFormatsPolicyBytes {
			return nil, errors.New("-formats-policy exceeds 1 MiB")
		}
		p, err = formats.ParsePolicy(data)
		if err != nil {
			return nil, fmt.Errorf("-formats-policy: %w", err)
		}
	}
	p.Monitor = mode == "monitor"
	in := formats.New(p)
	if err := in.Err(); err != nil {
		return nil, fmt.Errorf("-formats-policy: %w", err)
	}
	return in, nil
}
