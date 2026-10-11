// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package control

import (
	"errors"
	"os"
	"syscall"
)

// syncDirectory flushes a directory to disk, so that a rename inside it survives a power cut. A file system that does
// not support flushing a directory (some network file systems answer EINVAL) is treated as having done it, which is the
// most that can be said of it; a real failure is an error. It is the same as config's, which is not exported.
func syncDirectory(dir string) error {
	// #nosec G304 -- The directory of the operator's own credentials file, the one this store was opened on.
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	syncErr := d.Sync()
	if errors.Is(syncErr, syscall.EINVAL) {
		syncErr = nil
	}
	return errors.Join(syncErr, d.Close())
}
