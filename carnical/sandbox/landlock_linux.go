//go:build linux && (amd64 || arm64)

// SPDX-License-Identifier: Apache-2.0

package sandbox

import (
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

// The Landlock system calls, written out because the kernel interface is small and a dependency for it is not worth
// what it costs in review. See Documentation/userspace-api/landlock.rst in the kernel.
const (
	sysLandlockCreateRuleset = 444
	sysLandlockAddRule       = 445
	sysLandlockRestrictSelf  = 446

	landlockCreateRulesetVersion = 1 << 0

	landlockRulePathBeneath = 1
	landlockRuleNetPort     = 2
)

// File system access rights, by the ABI that introduced them.
const (
	fsExecute    = 1 << 0
	fsWriteFile  = 1 << 1
	fsReadFile   = 1 << 2
	fsReadDir    = 1 << 3
	fsRemoveDir  = 1 << 4
	fsRemoveFile = 1 << 5
	fsMakeChar   = 1 << 6
	fsMakeDir    = 1 << 7
	fsMakeReg    = 1 << 8
	fsMakeSock   = 1 << 9
	fsMakeFifo   = 1 << 10
	fsMakeBlock  = 1 << 11
	fsMakeSym    = 1 << 12
	fsRefer      = 1 << 13 // ABI 2
	fsTruncate   = 1 << 14 // ABI 3
	fsIoctlDev   = 1 << 15 // ABI 5

	netBindTCP    = 1 << 0 // ABI 4
	netConnectTCP = 1 << 1

	scopeAbstractUnix = 1 << 0 // ABI 6
	scopeSignal       = 1 << 1
)

// fileRights are the rights that can be granted on something that is not a directory.
const fileRights = fsExecute | fsWriteFile | fsReadFile | fsTruncate | fsIoctlDev

func landlockABI() int {
	abi, _, errno := syscall.Syscall(sysLandlockCreateRuleset, 0, 0, landlockCreateRulesetVersion)
	if errno != 0 {
		return 0 // ENOSYS: too old; EOPNOTSUPP: not enabled
	}
	return int(abi)
}

// allFS is every file system right the given ABI knows, which is what the ruleset must "handle" so that anything not
// explicitly allowed is denied.
func allFS(abi int) uint64 {
	rights := uint64(1<<13 - 1) // ABI 1: bits 0 to 12
	if abi >= 2 {
		rights |= fsRefer
	}
	if abi >= 3 {
		rights |= fsTruncate
	}
	if abi >= 5 {
		rights |= fsIoctlDev
	}
	return rights
}

type pathBeneath struct {
	allowed uint64
	fd      int32
}

type netPort struct {
	allowed uint64
	port    uint64
}

// ruleset builds a Landlock ruleset.
type ruleset struct {
	fd  int
	abi int
	fs  uint64
}

func newRuleset(abi int, handleFS, handleNet, scoped uint64) (*ruleset, error) {
	// struct landlock_ruleset_attr grew with each ABI; pass the size the kernel knows.
	attr := [3]uint64{handleFS, handleNet, scoped}
	size := uintptr(8)
	switch {
	case abi >= 6:
		size = 24
	case abi >= 4:
		size = 16
	}
	fd, _, errno := syscall.Syscall(sysLandlockCreateRuleset, uintptr(unsafe.Pointer(&attr[0])), size, 0)
	if errno != 0 {
		return nil, fmt.Errorf("landlock_create_ruleset: %w", errno)
	}
	return &ruleset{fd: int(fd), abi: abi, fs: handleFS}, nil
}

func (r *ruleset) close() { unix.Close(r.fd) }

// allowPath grants rights on a file or directory and everything beneath it.
func (r *ruleset) allowPath(path string, rights uint64) error {
	fd, err := unix.Open(path, unix.O_PATH|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return err
	}
	rights &= r.fs
	if st.Mode&unix.S_IFMT != unix.S_IFDIR {
		rights &= fileRights // directory-only rights on a file are an error
	}
	if rights == 0 {
		return nil
	}
	if fd < 0 || fd > 0x7FFFFFFF {
		return errors.New("Landlock path descriptor exceeds the kernel ABI range")
	}
	// The kernel's struct is packed (12 bytes); Go would pad ours to 16.
	var packed [12]byte
	binary.NativeEndian.PutUint64(packed[:8], rights)
	binary.NativeEndian.PutUint32(packed[8:], uint32(fd))
	if _, _, errno := syscall.Syscall6(sysLandlockAddRule, uintptr(r.fd), landlockRulePathBeneath, uintptr(unsafe.Pointer(&packed[0])), 0, 0, 0); errno != 0 {
		return fmt.Errorf("landlock_add_rule %s: %w", path, errno)
	}
	return nil
}

func (r *ruleset) allowPort(port uint16, rights uint64) error {
	rule := netPort{allowed: rights, port: uint64(port)}
	if _, _, errno := syscall.Syscall6(sysLandlockAddRule, uintptr(r.fd), landlockRuleNetPort, uintptr(unsafe.Pointer(&rule)), 0, 0, 0); errno != 0 {
		return fmt.Errorf("landlock_add_rule port %d: %w", port, errno)
	}
	return nil
}

// enforce restricts every thread of the process, now and for good.
func (r *ruleset) enforce() error {
	// Landlock restricts the calling thread only (before ABI 8), and the Go runtime runs goroutines on whichever
	// thread is free. AllThreadsSyscall makes every thread of the process make the call, which is the only way a
	// restriction can cover the whole process. It does not work in a cgo binary.
	_, _, errno := syscall.AllThreadsSyscall(sysLandlockRestrictSelf, uintptr(r.fd), 0, 0)
	if errno != 0 {
		if errno == syscall.ENOTSUP {
			return errNeedsStaticBuild
		}
		return fmt.Errorf("landlock_restrict_self: %w", errno)
	}
	return nil
}

var errNeedsStaticBuild = errors.New("sandbox: this binary was built with cgo, so a restriction cannot reach all of its threads; build with CGO_ENABLED=0")

// applyLandlock builds and enforces a ruleset for the policy. It reports which kinds of access are now restricted.
func applyLandlock(p Policy, rep *Report) error {
	abi := landlockABI()
	rep.LandlockABI = abi
	if abi == 0 {
		return errors.New("the kernel has no Landlock (it needs Linux 5.13 or later, with Landlock enabled)")
	}
	handleFS := allFS(abi)
	var handleNet, scoped uint64
	if abi >= 4 {
		if p.BindTCP != nil {
			handleNet |= netBindTCP
		}
		if p.ConnectTCP != nil {
			handleNet |= netConnectTCP
		}
	} else if p.BindTCP != nil || p.ConnectTCP != nil {
		if p.Require {
			return fmt.Errorf("port restrictions need Landlock ABI 4 (Linux 6.7); this kernel has ABI %d", abi)
		}
		rep.Notes = append(rep.Notes, fmt.Sprintf("port restrictions skipped: Landlock ABI %d is older than 4", abi))
	}
	if abi >= 6 {
		scoped = scopeAbstractUnix | scopeSignal
	} else {
		rep.Notes = append(rep.Notes, fmt.Sprintf("abstract socket and signal scoping skipped: Landlock ABI %d is older than 6", abi))
	}
	rs, err := newRuleset(abi, handleFS, handleNet, scoped)
	if err != nil {
		return err
	}
	defer rs.close()

	read := uint64(fsReadFile | fsReadDir)
	if p.AllowExec {
		read |= fsExecute
	}
	// Everything a service needs in its own directory except to run a file, make a device, a socket or a link, or move
	// a file from one directory to another.
	write := uint64(fsWriteFile | fsReadFile | fsReadDir | fsRemoveDir | fsRemoveFile | fsMakeDir | fsMakeReg | fsTruncate)

	for _, path := range defaultReadOnly {
		if err := rs.allowPath(path, read); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("%s: %w", path, err)
		}
	}
	for _, path := range defaultReadWrite {
		if err := rs.allowPath(path, write); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("%s: %w", path, err)
		}
	}
	for _, path := range p.ReadOnly {
		if err := rs.allowPath(path, read); err != nil {
			return fmt.Errorf("read-only path %s: %w", path, err)
		}
	}
	for _, path := range p.ReadWrite {
		if err := rs.allowPath(path, write); err != nil {
			return fmt.Errorf("read-write path %s: %w", path, err)
		}
	}
	if handleNet&netBindTCP != 0 {
		for _, port := range p.BindTCP {
			if err := rs.allowPort(port, netBindTCP); err != nil {
				return err
			}
		}
	}
	if handleNet&netConnectTCP != 0 {
		for _, port := range p.ConnectTCP {
			if err := rs.allowPort(port, netConnectTCP); err != nil {
				return err
			}
		}
	}

	// A process may not gain new privileges, which is also what Landlock itself requires of an unprivileged caller.
	if err := setNoNewPrivsAllThreads(); err != nil {
		return err
	}
	if err := rs.enforce(); err != nil {
		return err
	}
	rep.LandlockFS = true
	rep.LandlockNet = handleNet != 0
	rep.LandlockScope = scoped != 0
	return nil
}
