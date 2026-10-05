// SPDX-License-Identifier: Apache-2.0

package shield

import "syscall"

// fdLimit is the process's soft limit on open files, which bounds how many connections it can hold whatever the shield
// allows. Zero means unknown.
func fdLimit() int64 {
	var r syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &r); err != nil || r.Cur == 0 || r.Cur > 1<<40 {
		return 0
	}
	return int64(r.Cur)
}
