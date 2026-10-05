// SPDX-License-Identifier: Apache-2.0

//go:build windows

package config

// syncDirectory does nothing on Windows: a directory cannot be flushed there (FlushFileBuffers refuses a directory
// handle), and NTFS writes the rename through its own journal. This is written down so it is not read as a guarantee:
// the power-cut safety of FileSeqStore is argued for Linux, where the directory is flushed.
func syncDirectory(string) error { return nil }
