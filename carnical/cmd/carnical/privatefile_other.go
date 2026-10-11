// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package main

import "os"

// privateFileAccess is for Windows, where a file's mode says nothing about who may read it. Elsewhere the mode does, and
// the readers have tested it.
func privateFileAccess(*os.File) error { return nil }
