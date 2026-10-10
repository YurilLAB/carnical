//go:build !unix

package host

import "io/fs"

const openNonblock = 0

func owner(fs.FileInfo) (uid, gid int) { return 0, 0 }

// checkPrivateDir has nothing to check where files have no Unix owner and mode.
func checkPrivateDir(string) error { return nil }
