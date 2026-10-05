// SPDX-License-Identifier: Apache-2.0

//go:build !linux

package shield

// fdLimit is unknown outside Linux.
func fdLimit() int64 { return 0 }
