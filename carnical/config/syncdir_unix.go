// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package config

import (
	"errors"
	"os"
	"syscall"
)

// syncDirectory flushes a directory to disk, so that a rename inside it survives a power cut. A file system that does
// not support flushing a directory (some network file systems answer EINVAL) is treated as having done it, which is the
// most that can be said of it; a real failure is an error.
func syncDirectory(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	if err := d.Sync(); err != nil && !errors.Is(err, syscall.EINVAL) {
		return err
	}
	return nil
}
