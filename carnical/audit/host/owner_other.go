//go:build !unix

package host

import "io/fs"

func owner(fs.FileInfo) (uid, gid int) { return 0, 0 }
