package host

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/YurilLAB/coraza/carnical/audit"
)

// ProcPolicy says what may run.
type ProcPolicy struct {
	// Services is, for each service user, the programs it may run. Anything else running as that user is a finding.
	Services map[string][]string
	// AllowPartial checks the processes that can be read even if some cannot. Without it a check that cannot see every
	// process (it is not running as root) reports that it could not run, because a check that sees a part and says "fine" has
	// not looked at the part that matters.
	AllowPartial bool
}

// DefaultProcs is what the units in deploy/systemd start.
var DefaultProcs = ProcPolicy{Services: map[string][]string{
	"carnical-edge":  {"/usr/local/bin/carnical"},
	"carnical-audit": {"/usr/local/bin/carnical-audit"},
}}

// interpreters are programs that a service which has been taken over runs: a shell, a scripting language, a tool for
// downloading or for making a connection. No Carnical service runs one.
var interpreters = map[string]bool{
	"sh": true, "bash": true, "dash": true, "zsh": true, "ash": true, "ksh": true, "csh": true, "tcsh": true, "fish": true, "busybox": true,
	"perl": true, "ruby": true, "php": true, "node": true, "lua": true, "awk": true, "gawk": true,
	"nc": true, "ncat": true, "netcat": true, "socat": true, "telnet": true, "curl": true, "wget": true, "tftp": true, "ssh": true, "scp": true,
	"gcc": true, "cc": true, "make": true,
}

func isInterpreter(exe string) bool {
	base := path.Base(strings.TrimSuffix(exe, " (deleted)"))
	if interpreters[base] {
		return true
	}
	for _, p := range []string{"python", "php", "ruby", "perl", "node"} { // python3.12, php8.3, ...
		if strings.HasPrefix(base, p) {
			return true
		}
	}
	return false
}

var writableDirs = []string{"/tmp/", "/var/tmp/", "/dev/shm/", "/run/user/"}

// Process is one running program, as /proc shows it.
type Process struct {
	PID int
	UID int
	Exe string
}

// Processes reads the process table. A process whose program cannot be read is counted, not guessed at.
func Processes(src Source) (procs []Process, unreadable int, err error) {
	dirs, err := src.Glob("/proc/[0-9]*")
	if err != nil {
		return nil, 0, err
	}
	for _, dir := range dirs {
		pid, err := strconv.Atoi(filepath.Base(dir))
		if err != nil {
			continue
		}
		status, err := src.ReadFile(dir + "/status")
		if err != nil {
			continue // it ended while we were looking
		}
		uid := -1
		sc := bufio.NewScanner(bytes.NewReader(status))
		for sc.Scan() {
			if rest, ok := strings.CutPrefix(sc.Text(), "Uid:"); ok {
				if f := strings.Fields(rest); len(f) > 0 {
					uid, _ = strconv.Atoi(f[0])
				}
				break
			}
		}
		exe, err := src.Readlink(dir + "/exe")
		if err != nil {
			if strings.Contains(err.Error(), "permission denied") {
				unreadable++
			}
			continue // a kernel thread has no program
		}
		procs = append(procs, Process{PID: pid, UID: uid, Exe: exe})
	}
	return procs, unreadable, nil
}

// Running checks what is running against what should be.
func Running(src Source, policy ProcPolicy) audit.Check {
	return audit.Check{
		Name: "host-processes", Zone: "",
		What: "Nothing runs from a deleted file, from memory, or from a world-writable directory, and a service user runs only its own program.",
		Run: func(ctx context.Context) audit.Outcome {
			if why := linux(); why != "" {
				return audit.Outcome{SkipReason: why}
			}
			procs, unreadable, err := Processes(src)
			if err != nil {
				return audit.Outcome{SkipReason: "cannot read the process table: " + err.Error()}
			}
			if len(procs) == 0 || (unreadable > 0 && !policy.AllowPartial) {
				return audit.Outcome{SkipReason: fmt.Sprintf("this needs root (or CAP_SYS_PTRACE): %d programs could not be read and %d could", unreadable, len(procs))}
			}
			uids, _ := users(src)
			byUID := map[int]string{}
			for name := range policy.Services {
				if u, ok := uids[name]; ok {
					byUID[u] = name
				}
			}
			var out audit.Outcome
			for _, p := range procs {
				out.Checked++
				who := fmt.Sprintf("pid %d (uid %d) runs %s", p.PID, p.UID, p.Exe)
				switch {
				case strings.HasPrefix(p.Exe, "/memfd:"): // such a file is always "deleted": the kernel never gave it a name
					out.Problems = append(out.Problems, who+": it runs from memory, not from a file")
				case strings.HasSuffix(p.Exe, " (deleted)"):
					out.Problems = append(out.Problems, who+": its program file has been deleted or replaced while it runs")
				}
				for _, dir := range writableDirs {
					if strings.HasPrefix(p.Exe, dir) {
						out.Problems = append(out.Problems, who+": it runs from a directory anyone can write to")
					}
				}
				if name, ok := byUID[p.UID]; ok {
					allowed := false
					for _, a := range policy.Services[name] {
						if p.Exe == a {
							allowed = true
						}
					}
					switch {
					case isInterpreter(p.Exe):
						out.Problems = append(out.Problems, fmt.Sprintf("pid %d: %s is running %s, a shell, interpreter or network tool", p.PID, name, p.Exe))
					case !allowed:
						out.Problems = append(out.Problems, fmt.Sprintf("pid %d: %s is running %s, which is not its program", p.PID, name, p.Exe))
					}
				}
			}
			sort.Strings(out.Problems)
			return out
		},
	}
}
