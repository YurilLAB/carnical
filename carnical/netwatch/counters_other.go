// SPDX-License-Identifier: Apache-2.0

//go:build !linux

package netwatch

import (
	"context"
	"errors"
)

// ReadCounters reads the named counters of the inet table; nftables is Linux's alone.
func ReadCounters(context.Context, string) (map[string]Count, error) {
	return nil, errors.New("netwatch: the packet guards are read on Linux")
}
