//go:build linux && (amd64 || arm64)

package sandbox

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

func setNoNewPrivsAllThreads() error {
	_, _, errno := syscall.AllThreadsSyscall(unix.SYS_PRCTL, unix.PR_SET_NO_NEW_PRIVS, 1, 0)
	if errno != 0 {
		if errno == syscall.ENOTSUP {
			return errNeedsStaticBuild
		}
		return fmt.Errorf("no_new_privs: %w", errno)
	}
	return nil
}

// Apply confines the process. Call it once, early in main, after the listeners are open and the keys and
// certificates are read, and before the first request is served. What was applied is in the Report; with
// Policy.Require, anything that could not be applied is an error and nothing is half-done silently.
//
// It cannot be undone, and it applies to every thread of the process.
func Apply(p Policy) (Report, error) {
	var rep Report
	fail := func(layer string, err error) (Report, error) {
		return rep, fmt.Errorf("sandbox: %s: %w", layer, err)
	}

	// 1. No new privileges: a setuid program or a file with capabilities gives nothing, and seccomp may be installed
	// without privilege.
	if err := setNoNewPrivsAllThreads(); err != nil {
		return fail("no_new_privs", err)
	}
	rep.NoNewPrivs = true

	// 2. Not dumpable: another process of the same user cannot ptrace this one or read /proc/PID/mem, and a crash
	// leaves no core file with keys in it. Per process, so one call is enough.
	if err := unix.Prctl(unix.PR_SET_DUMPABLE, 0, 0, 0, 0); err != nil {
		return fail("dumpable", err)
	}
	rep.Undumpable = true
	if err := unix.Setrlimit(unix.RLIMIT_CORE, &unix.Rlimit{Cur: 0, Max: 0}); err != nil {
		return fail("core size limit", err)
	}

	skip := func(layer string) bool {
		for _, s := range p.Skip {
			if s == layer {
				rep.Notes = append(rep.Notes, layer+" skipped on request")
				return true
			}
		}
		return false
	}

	// 3. Landlock.
	if skip("landlock") {
	} else if err := applyLandlock(p, &rep); err != nil {
		if errors.Is(err, errNeedsStaticBuild) || p.Require {
			return fail("landlock", err)
		}
		rep.Notes = append(rep.Notes, "Landlock skipped: "+err.Error())
	}

	// 4. seccomp, last: after it, calls the filter denies end the process, including the ones this function would make.
	if skip("seccomp") {
	} else if err := applySeccomp(p.AllowExec); err != nil {
		if p.Require {
			return fail("seccomp", err)
		}
		rep.Notes = append(rep.Notes, "seccomp skipped: "+err.Error())
	} else {
		rep.Seccomp = true
	}
	return rep, nil
}

// ThreadStatus is what the kernel says about one thread's restrictions.
type ThreadStatus struct {
	TID        int
	NoNewPrivs bool
	// Seccomp is 0 (none), 1 (strict) or 2 (filter), as in /proc/PID/status.
	Seccomp int
}

// Threads reads the restrictions of every thread of this process. A restriction that is on one thread and not the
// others is the commonest way for confinement to look applied and not be: it is checked here, from the kernel's own
// numbers, rather than assumed.
func Threads() ([]ThreadStatus, error) {
	dirs, err := filepath.Glob("/proc/self/task/*")
	if err != nil {
		return nil, err
	}
	var out []ThreadStatus
	for _, dir := range dirs {
		tid, err := strconv.Atoi(filepath.Base(dir))
		if err != nil {
			continue
		}
		f, err := os.Open(filepath.Join(dir, "status")) // #nosec G304 -- dir comes only from the fixed /proc/self/task/* glob with a numeric thread ID.
		if err != nil {
			continue // the thread ended while we were looking
		}
		st := ThreadStatus{TID: tid}
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			key, val, ok := strings.Cut(sc.Text(), ":")
			if !ok {
				continue
			}
			val = strings.TrimSpace(val)
			switch key {
			case "NoNewPrivs":
				st.NoNewPrivs = val == "1"
			case "Seccomp":
				st.Seccomp, _ = strconv.Atoi(val)
			}
		}
		if err := errors.Join(sc.Err(), f.Close()); err != nil {
			return nil, fmt.Errorf("read thread %d status: %w", tid, err)
		}
		out = append(out, st)
	}
	if len(out) == 0 {
		return nil, errors.New("no threads could be read from /proc/self/task")
	}
	return out, nil
}
