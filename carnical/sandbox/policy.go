// Package sandbox confines the running process, from the inside, to what the proxy needs, so that an attacker who
// gets code running in it (through a bug that got past the rule set, or in a dependency) finds a process that cannot
// start a program, cannot read other services' files, cannot reach other services' ports, cannot inspect other
// processes and cannot load kernel code.
//
// It uses three kernel features that an unprivileged process can apply to itself and that cannot be undone:
//
//   - no_new_privs and a non-dumpable process (no ptrace or /proc/PID/mem by a process of the same user);
//   - Landlock (Linux 5.13 and later): file access limited to named directories, TCP connect and bind limited to named
//     ports, and abstract UNIX sockets and signals limited to the process's own domain;
//   - seccomp-BPF: the system calls an attacker needs after getting in (execve, ptrace, mount, bpf, io_uring,
//     memfd_create, namespace creation, kernel module loading, other socket families) end the process, which also
//     leaves a record in the audit log.
//
// None of it needs privileges, a C compiler or a library. It needs a binary built with CGO_ENABLED=0: the
// "all threads at once" system calls that the Go runtime provides do not work in a cgo binary, and a restriction that
// reaches only the calling thread leaves every other thread of the process unrestricted.
package sandbox

import "errors"

// ErrUnsupported is returned on systems this package does not support.
var ErrUnsupported = errors.New("sandbox: confinement is only supported on Linux (amd64 and arm64)")

// Policy says what the process may still do after Apply.
type Policy struct {
	// ReadOnly are files and directories (with everything beneath them) the process may read.
	ReadOnly []string
	// ReadWrite are directories (with everything beneath them) the process may read, write, create files in and
	// remove files from. No special files, symbolic links or executable files can be made in them.
	ReadWrite []string
	// BindTCP and ConnectTCP are the TCP ports the process may listen on and connect to. A nil list means no
	// restriction on that direction; an empty, non-nil list means none at all. Needs Landlock ABI 4 (Linux 6.7).
	BindTCP, ConnectTCP []uint16
	// AllowExec lets the process start programs. The proxy never does, so the default is that it cannot.
	AllowExec bool
	// Skip names layers not to apply: "landlock", "seccomp". It is for staged rollouts and for the tests that need a
	// weakened confinement to prove the checks can tell the difference. The Report says what was skipped.
	Skip []string
	// Require makes Apply fail if any layer cannot be applied (an old kernel without Landlock, or without the port rules
	// a port list needs) instead of applying the layers that are available and reporting which they were. Abstract-socket
	// and signal scoping, which needs Landlock ABI 6 (Linux 6.12), is not required: without it Notes says so.
	Require bool
}

// Report says what was applied.
type Report struct {
	NoNewPrivs bool
	Undumpable bool
	// LandlockABI is the Landlock version the kernel supports, and 0 if there is none (nothing was applied).
	LandlockABI int
	// LandlockFS, LandlockNet and LandlockScope say which kinds of access Landlock now restricts.
	LandlockFS, LandlockNet, LandlockScope bool
	Seccomp                                bool
	// Notes are layers that were skipped, and why.
	Notes []string
}

// defaultReadOnly are what the Go runtime, the resolver and TLS read once the process is running. Missing ones are
// skipped.
var defaultReadOnly = []string{
	"/etc/resolv.conf", "/etc/hosts", "/etc/nsswitch.conf", "/etc/host.conf", "/etc/gai.conf", "/etc/services", "/etc/protocols",
	"/etc/ssl", "/etc/ca-certificates", "/usr/share/ca-certificates", "/usr/lib/ssl", "/etc/pki",
	"/usr/share/zoneinfo", "/etc/localtime",
	"/proc/sys/net/core/somaxconn", "/proc/self", "/dev/urandom", "/dev/random",
}

// defaultReadWrite are files every program may write to.
var defaultReadWrite = []string{"/dev/null"}
