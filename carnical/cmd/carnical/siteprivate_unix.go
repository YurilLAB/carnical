// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package main

import (
	"errors"
	"os"
)

func createSiteFile(root *os.Root, name string) (*os.File, error) {
	return root.OpenFile(name, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
}

func protectSiteFile(file *os.File) error {
	if err := file.Chmod(0600); err != nil {
		return err
	}
	return checkPrivateSiteFile(file)
}

func checkPrivateSiteFile(file *os.File) error {
	info, err := file.Stat()
	if err != nil {
		return err
	}
	if info.Mode().Perm()&0077 != 0 {
		return errors.New("site encryption key must have owner-only permissions (0600)")
	}
	return nil
}
