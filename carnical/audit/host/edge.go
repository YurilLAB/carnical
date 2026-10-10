package host

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/YurilLAB/coraza/carnical/audit"
)

// EdgeSpec says what a running edge must look like to the kernel.
type EdgeSpec struct {
	Exe  string
	User string
}

// DefaultEdge is what deploy/systemd/carnical-edge.service starts.
var DefaultEdge = EdgeSpec{Exe: "/usr/local/bin/carnical", User: "carnical-edge"}

// threadStatus is what /proc/PID/task/TID/status says about restrictions.
type threadStatus struct {
	uid        int
	noNewPrivs string
	seccomp    string
	capEff     string
	capBnd     string
}

func parseThreadStatus(data []byte) threadStatus {
	var t threadStatus
	t.uid = -1
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		k, v, ok := strings.Cut(sc.Text(), ":")
		if !ok {
			continue
		}
		v = strings.TrimSpace(v)
		switch k {
		case "Uid":
			if f := strings.Fields(v); len(f) > 0 {
				t.uid, _ = strconv.Atoi(f[0])
			}
		case "NoNewPrivs":
			t.noNewPrivs = v
		case "Seccomp":
			t.seccomp = v
		case "CapEff":
			t.capEff = v
		case "CapBnd":
			t.capBnd = v
		}
	}
	return t
}

// asksToConfine reports whether a command line (NUL-separated, as /proc shows it) turns -confine on. Flags are read as the Go
// flag package reads them: -confine or --confine, with an optional =value, and the last one given wins.
func asksToConfine(cmdline []byte) bool {
	on := false
	for _, arg := range strings.Split(string(cmdline), "\x00") {
		name, value, hasValue := strings.Cut(strings.TrimPrefix(strings.TrimPrefix(arg, "-"), "-"), "=")
		if !strings.HasPrefix(arg, "-") || name != "confine" {
			continue
		}
		if !hasValue {
			on = true
			continue
		}
		v, err := strconv.ParseBool(value)
		on = err == nil && v
	}
	return on
}

// Confined checks the running edge itself: every thread of it has no_new_privs and a seccomp filter, and holds no capability.
// The kernel reports this per thread, and a restriction that is on some threads and not others is the commonest way for
// confinement to look applied and not be, so every thread is read.
func Confined(src Source, spec EdgeSpec) audit.Check {
	return audit.Check{
		Name: "host-edge-confined", Zone: "",
		What: "The running edge was started with -confine, has no_new_privs, a seccomp filter and no capabilities on every one of its threads, and runs as its own user.",
		Run: func(ctx context.Context) audit.Outcome {
			if why := linux(); why != "" {
				return audit.Outcome{SkipReason: why}
			}
			procs, unreadable, err := Processes(src)
			if err != nil {
				return audit.Outcome{SkipReason: "cannot read the process table: " + err.Error()}
			}
			uids, _ := users(src)
			var edge []Process
			for _, p := range procs {
				if p.Exe == spec.Exe {
					edge = append(edge, p)
				}
			}
			if len(edge) == 0 {
				switch {
				case unreadable > 0:
					return audit.Outcome{SkipReason: fmt.Sprintf("no edge process was found, but %d programs could not be read (this needs root)", unreadable)}
				case geteuid() != 0:
					// Under hidepid another user's processes are not unreadable but missing.
					return audit.Outcome{SkipReason: "no edge process was seen; not as root, /proc may hide it (this needs root)"}
				}
				return audit.Outcome{SkipReason: "the edge is not running"}
			}
			var out audit.Outcome
			for _, p := range edge {
				// The unit's own NoNewPrivileges and system call filter put the same marks on every thread, so the threads
				// alone do not show that the edge confined itself: its command line has to ask for it.
				out.Checked++
				switch cmdline, err := src.ReadFile("/proc/" + strconv.Itoa(p.PID) + "/cmdline"); {
				case err != nil:
					out.Problems = append(out.Problems, fmt.Sprintf("pid %d: its command line cannot be read: %v", p.PID, err))
				case !asksToConfine(cmdline):
					out.Problems = append(out.Problems, fmt.Sprintf("pid %d was started without -confine, so it does not confine itself", p.PID))
				}
				tasks, _ := src.Glob("/proc/" + strconv.Itoa(p.PID) + "/task/[0-9]*")
				if len(tasks) == 0 {
					out.Problems = append(out.Problems, fmt.Sprintf("pid %d: its threads cannot be listed", p.PID))
					continue
				}
				for _, task := range tasks {
					data, err := src.ReadFile(filepath.Join(task, "status"))
					if err != nil {
						continue // the thread ended
					}
					out.Checked++
					st := parseThreadStatus(data)
					where := fmt.Sprintf("pid %d thread %s", p.PID, filepath.Base(task))
					if want, ok := uids[spec.User]; !ok || st.uid != want {
						out.Problems = append(out.Problems, fmt.Sprintf("%s runs as uid %d, not %s", where, st.uid, spec.User))
					}
					if st.noNewPrivs != "1" {
						out.Problems = append(out.Problems, where+" can gain new privileges (no_new_privs is not set)")
					}
					if st.seccomp != "2" {
						out.Problems = append(out.Problems, where+" has no seccomp filter")
					}
					if strings.Trim(st.capEff, "0") != "" || strings.Trim(st.capBnd, "0") != "" {
						out.Problems = append(out.Problems, fmt.Sprintf("%s holds capabilities (effective %s, bounding %s)", where, st.capEff, st.capBnd))
					}
				}
			}
			sort.Strings(out.Problems)
			return out
		},
	}
}
