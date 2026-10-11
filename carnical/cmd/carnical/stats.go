// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"errors"
	"log/slog"
	"reflect"
	"time"
)

// minStatsInterval and maxStatsInterval bound every -*-stats-interval flag the same way -formats-stats-interval is bounded.
const (
	minStatsInterval = 100 * time.Millisecond
	maxStatsInterval = 24 * time.Hour
)

// checkStatsInterval is the one check for every statistics interval: 0 (off) or 100ms to 24h.
func checkStatsInterval(flagName string, d time.Duration) error {
	if d != 0 && (d < minStatsInterval || d > maxStatsInterval) {
		return errors.New(flagName + " must be 0 or between 100ms and 24h")
	}
	return nil
}

// startSnapshotLog logs a bounded summary every interval, but only when it differs from the last one that was logged, and once
// more when it is stopped (a graceful shutdown). It is what startFormatStats does for the format inspector, for components whose
// totals are not a list of rules. The snapshot holds counts and fixed names only: nothing the visitor sent, no client address, no
// URI. The summary taken when the logger starts is the baseline, so a site that has seen nothing logs nothing.
//
// The returned function stops it and waits for the last line to be written. It is safe to call more than once.
func startSnapshotLog[T any](log *slog.Logger, msg string, interval time.Duration, snapshot func() T, attrs func(T) []any) func() {
	if interval == 0 {
		return func() {}
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	last := snapshot()
	go func() {
		defer close(done)
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		report := func() {
			if current := snapshot(); !reflect.DeepEqual(current, last) {
				log.Info(msg, attrs(current)...)
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
