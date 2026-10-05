// Package host holds the checks that look at the machine itself: the kernel settings, the mounts, the services' sandboxes, the
// network and audit rules, who is listening, what is running, and whether anything that should not change has changed.
//
// They answer the question that comes after "can an attacker get in?": if one already has, is the machine still set up so that
// they get no further, and would anything show it? Each check reads what is really in force (the running kernel, the loaded
// rules, the process table), not what a file says should be, so a setting that was never applied or was undone later is found.
//
// The checks read through a Source, so that they are tested against fixtures and, on Linux, against live positive controls
// (a process whose program file was deleted while it ran, a listener nobody declared). A check that cannot read what it
// needs reports that it could not run; it never passes because it saw nothing.
package host

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
)

// Info is what the checks need to know about a file.
type Info struct {
	Mode fs.FileMode
	UID  int
	GID  int
}

// Source is how the checks read the machine.
type Source interface {
	ReadFile(path string) ([]byte, error)
	Glob(pattern string) ([]string, error)
	Readlink(path string) (string, error)
	Stat(path string) (Info, error)
	// Run runs a program and returns what it printed. It is only used for tools that have no file to read: systemctl,
	// nft, auditctl, find.
	Run(ctx context.Context, name string, args ...string) ([]byte, error)
}

// ErrNotLinux is returned by the real source on other systems.
var ErrNotLinux = errors.New("this check needs a Linux machine")

// OS reads the real machine.
type OS struct{}

func (OS) ReadFile(path string) ([]byte, error)  { return os.ReadFile(path) }
func (OS) Glob(pattern string) ([]string, error) { return filepath.Glob(pattern) }
func (OS) Readlink(path string) (string, error)  { return os.Readlink(path) }

func (OS) Stat(path string) (Info, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return Info{}, err
	}
	uid, gid := owner(fi)
	return Info{Mode: fi.Mode(), UID: uid, GID: gid}, nil
}

func (OS) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	return exec.CommandContext(ctx, name, args...).Output()
}

// linux reports a reason to skip when the machine is not Linux.
func linux() string {
	if runtime.GOOS != "linux" {
		return ErrNotLinux.Error()
	}
	return ""
}
