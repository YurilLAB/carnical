// SPDX-License-Identifier: Apache-2.0

//go:build unix

package main

import (
	"errors"
	"fmt"
	"io/fs"
	"syscall"
)

// checkStateOwner refuses a state file that someone other than carnical-netwatch could have written: one that belongs
// to another user, or that its group or everyone may write. The directory is root's, which the host audit checks; this
// holds even where that is not so.
func checkStateOwner(fi fs.FileInfo, uid int) error {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return errors.New("the state file's owner cannot be read")
	}
	if int(st.Uid) != uid {
		return fmt.Errorf("the state file belongs to uid %d, not %d", st.Uid, uid)
	}
	if fi.Mode().Perm()&0o022 != 0 {
		return errors.New("the state file can be written by others than its owner")
	}
	return nil
}
