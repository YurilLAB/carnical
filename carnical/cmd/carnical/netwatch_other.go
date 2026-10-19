// SPDX-License-Identifier: Apache-2.0

//go:build !unix

package main

import "io/fs"

// checkStateOwner checks nothing where carnical-netwatch does not run: it needs the Linux packet guards.
func checkStateOwner(fs.FileInfo, int) error { return nil }
