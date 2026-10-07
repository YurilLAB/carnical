// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package io

import (
	"io/fs"
	"os"
	"path/filepath"
)

// OSFS implements fs.FS using methods on os to read from the system.
// Note that this implementation is not a compliant fs.FS, as they should only
// accept posix-style, relative paths, but as this is an internal implementation
// detail, we get the abstraction we need while being able to handle paths as
// the os package otherwise would.
// More context in: https://github.com/golang/go/issues/44279
type OSFS struct{}

func (OSFS) Open(name string) (fs.File, error) {
	return os.Open(name) // #nosec G304 -- Configuration-time rule paths intentionally support native absolute names; use a restricted RootFS for sandboxing.
}

func (OSFS) ReadFile(name string) ([]byte, error) {
	return os.ReadFile(name) // #nosec G304 -- Configuration-time rule/data paths; OSFS intentionally retains native filesystem semantics.
}

func (OSFS) ReadDir(name string) ([]fs.DirEntry, error) {
	return os.ReadDir(name)
}

func (OSFS) Glob(pattern string) ([]string, error) {
	return filepath.Glob(pattern)
}
