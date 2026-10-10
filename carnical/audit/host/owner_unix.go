//go:build unix

package host

import (
	"fmt"
	"io/fs"
	"os"
	"syscall"
)

const openNonblock = syscall.O_NONBLOCK

func owner(fi fs.FileInfo) (uid, gid int) {
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		return int(st.Uid), int(st.Gid)
	}
	return 0, 0
}

// checkPrivateDir refuses a directory that someone other than this process's user could change: one owned by another user,
// writable by its group or by everyone, or a symbolic link (which leads wherever its owner chose).
func checkPrivateDir(dir string) error {
	fi, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	uid, _ := owner(fi)
	switch {
	case fi.Mode()&fs.ModeSymlink != 0:
		return fmt.Errorf("%s is a symbolic link", dir)
	case !fi.IsDir():
		return fmt.Errorf("%s is not a directory", dir)
	case uid != geteuid():
		return fmt.Errorf("%s is owned by uid %d, not by this user (uid %d)", dir, uid, geteuid())
	case fi.Mode().Perm()&0o022 != 0:
		return fmt.Errorf("%s has mode %04o: others could replace what is written there", dir, fi.Mode().Perm())
	}
	return nil
}
