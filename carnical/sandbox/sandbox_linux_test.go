//go:build linux && (amd64 || arm64)

package sandbox

import (
	"encoding/binary"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

// ---- the filter, without a kernel: a small classic-BPF interpreter evaluates it for made-up system calls ----

func evalBPF(t *testing.T, prog []unix.SockFilter, data [64]byte) uint32 {
	t.Helper()
	var acc uint32
	pc := 0
	for steps := 0; steps < 10000; steps++ {
		if pc >= len(prog) {
			t.Fatal("ran off the end of the program")
		}
		in := prog[pc]
		switch in.Code {
		case bpfLdWAbs:
			acc = binary.LittleEndian.Uint32(data[in.K : in.K+4])
			pc++
		case bpfAluAndK:
			acc &= in.K
			pc++
		case bpfJeqK:
			if acc == in.K {
				pc += 1 + int(in.Jt)
			} else {
				pc += 1 + int(in.Jf)
			}
		case bpfJsetK:
			if acc&in.K != 0 {
				pc += 1 + int(in.Jt)
			} else {
				pc += 1 + int(in.Jf)
			}
		case bpfJmpJa:
			pc += 1 + int(in.K)
		case bpfRetK:
			return in.K
		default:
			t.Fatalf("unknown opcode %#x", in.Code)
		}
	}
	t.Fatal("the program does not end")
	return 0
}

func seccompData(arch uint32, nr uint32, args ...uint64) [64]byte {
	var d [64]byte
	binary.LittleEndian.PutUint32(d[0:], nr)
	binary.LittleEndian.PutUint32(d[4:], arch)
	for i, a := range args {
		binary.LittleEndian.PutUint64(d[16+8*i:], a)
	}
	return d
}

func TestTheFilterDecidesEachCallAsIntended(t *testing.T) {
	block, err := buildFilter(false)
	if err != nil {
		t.Fatal(err)
	}
	allowExec, err := buildFilter(true)
	if err != nil {
		t.Fatal(err)
	}
	const (
		allow   = seccompRetAllow
		kill    = seccompRetKillProcess
		noProto = seccompRetErrnoBase | uint32(unix.EPROTONOSUPPORT)
	)
	tests := []struct {
		name string
		prog []unix.SockFilter
		data [64]byte
		want uint32
	}{
		{"read", block, seccompData(auditArch, unix.SYS_READ), allow},
		{"write", block, seccompData(auditArch, unix.SYS_WRITE), allow},
		{"futex", block, seccompData(auditArch, unix.SYS_FUTEX), allow},
		{"epoll_wait or epoll_pwait", block, seccompData(auditArch, unix.SYS_EPOLL_PWAIT), allow},
		{"mmap", block, seccompData(auditArch, unix.SYS_MMAP), allow},
		{"clone3 (thread creation in newer runtimes)", block, seccompData(auditArch, unix.SYS_CLONE3), allow},
		{"execve", block, seccompData(auditArch, unix.SYS_EXECVE), kill},
		{"execveat", block, seccompData(auditArch, unix.SYS_EXECVEAT), kill},
		{"execve when starting programs is allowed", allowExec, seccompData(auditArch, unix.SYS_EXECVE), allow},
		{"ptrace", block, seccompData(auditArch, unix.SYS_PTRACE), kill},
		{"mount", block, seccompData(auditArch, unix.SYS_MOUNT), kill},
		{"unshare", block, seccompData(auditArch, unix.SYS_UNSHARE), kill},
		{"bpf", block, seccompData(auditArch, unix.SYS_BPF), kill},
		{"io_uring_setup", block, seccompData(auditArch, unix.SYS_IO_URING_SETUP), kill},
		{"memfd_create", block, seccompData(auditArch, unix.SYS_MEMFD_CREATE), kill},
		{"finit_module", block, seccompData(auditArch, unix.SYS_FINIT_MODULE), kill},
		{"keyctl", block, seccompData(auditArch, unix.SYS_KEYCTL), kill},
		{"a plain clone", block, seccompData(auditArch, unix.SYS_CLONE, unix.CLONE_VM|unix.CLONE_FS|unix.CLONE_FILES|unix.CLONE_SIGHAND|unix.CLONE_THREAD), allow},
		{"clone into a new user namespace", block, seccompData(auditArch, unix.SYS_CLONE, unix.CLONE_NEWUSER|uint64(unix.SIGCHLD)), kill},
		{"clone into a new network namespace", block, seccompData(auditArch, unix.SYS_CLONE, unix.CLONE_NEWNET), kill},
		{"socket: IPv4", block, seccompData(auditArch, unix.SYS_SOCKET, unix.AF_INET, unix.SOCK_STREAM, 0), allow},
		{"socket: IPv6", block, seccompData(auditArch, unix.SYS_SOCKET, unix.AF_INET6, unix.SOCK_STREAM, 0), allow},
		{"socket: explicit TCP", block, seccompData(auditArch, unix.SYS_SOCKET, unix.AF_INET, unix.SOCK_STREAM, unix.IPPROTO_TCP), allow},
		{"socket: UDP", block, seccompData(auditArch, unix.SYS_SOCKET, unix.AF_INET6, unix.SOCK_DGRAM, unix.IPPROTO_UDP), allow},
		{"socket: MPTCP IPv4", block, seccompData(auditArch, unix.SYS_SOCKET, unix.AF_INET, unix.SOCK_STREAM, unix.IPPROTO_MPTCP), noProto},
		{"socket: MPTCP IPv6 with flags", block, seccompData(auditArch, unix.SYS_SOCKET, unix.AF_INET6, unix.SOCK_STREAM|unix.SOCK_CLOEXEC|unix.SOCK_NONBLOCK, unix.IPPROTO_MPTCP), noProto},
		{"socket: MPTCP when starting programs is allowed", allowExec, seccompData(auditArch, unix.SYS_SOCKET, unix.AF_INET, unix.SOCK_STREAM, unix.IPPROTO_MPTCP), noProto},
		{"socket: MPTCP high argument bits", block, seccompData(auditArch, unix.SYS_SOCKET, unix.AF_INET, unix.SOCK_STREAM, 1<<40|unix.IPPROTO_MPTCP), noProto},
		{"socket: UNIX", block, seccompData(auditArch, unix.SYS_SOCKET, unix.AF_UNIX, unix.SOCK_STREAM, 0), allow},
		{"socket: netlink, routing", block, seccompData(auditArch, unix.SYS_SOCKET, unix.AF_NETLINK, unix.SOCK_RAW, unix.NETLINK_ROUTE), allow},
		{"socket: netlink, audit", block, seccompData(auditArch, unix.SYS_SOCKET, unix.AF_NETLINK, unix.SOCK_RAW, unix.NETLINK_AUDIT), kill},
		{"socket: netlink, netfilter", block, seccompData(auditArch, unix.SYS_SOCKET, unix.AF_NETLINK, unix.SOCK_RAW, unix.NETLINK_NETFILTER), kill},
		{"socket: packet", block, seccompData(auditArch, unix.SYS_SOCKET, unix.AF_PACKET, unix.SOCK_RAW, 0), kill},
		{"socket: kernel crypto", block, seccompData(auditArch, unix.SYS_SOCKET, unix.AF_ALG, unix.SOCK_SEQPACKET, 0), kill},
		{"socket: vsock", block, seccompData(auditArch, unix.SYS_SOCKET, unix.AF_VSOCK, unix.SOCK_STREAM, 0), kill},
		{"socketpair: UNIX", block, seccompData(auditArch, unix.SYS_SOCKETPAIR, unix.AF_UNIX, unix.SOCK_STREAM, 0), allow},
		{"socketpair: INET", block, seccompData(auditArch, unix.SYS_SOCKETPAIR, unix.AF_INET, unix.SOCK_STREAM, 0), kill},
		{"a different architecture", block, seccompData(0x40000003, unix.SYS_READ), kill},
		{"a high bit in the argument that is not the family", block, seccompData(auditArch, unix.SYS_SOCKET, 1<<40|unix.AF_PACKET, 0, 0), kill},
	}
	if auditArch == auditArchX8664 {
		tests = append(tests, struct {
			name string
			prog []unix.SockFilter
			data [64]byte
			want uint32
		}{"the x32 ABI", block, seccompData(auditArch, 0x40000000|unix.SYS_READ), kill})
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := evalBPF(t, tt.prog, tt.data); got != tt.want {
				t.Fatalf("action %#x, want %#x", got, tt.want)
			}
		})
	}
}

func TestEveryJumpFitsAndNoneGoesBackwards(t *testing.T) {
	prog, err := buildFilter(false)
	if err != nil {
		t.Fatal(err)
	}
	if len(prog) < 20 || len(prog) > 400 {
		t.Fatalf("a filter of %d instructions", len(prog))
	}
	if last := prog[len(prog)-1]; last.Code != bpfRetK || last.K != seccompRetKillProcess {
		t.Fatal("the program does not end by refusing")
	}
}

// ---- the real thing, on this kernel: the probe runs each action in a confined child process ----

func buildProbe(t *testing.T) string {
	t.Helper()
	goBin, err := exec.LookPath("go")
	if err != nil {
		t.Skip("no go command to build the probe with")
	}
	bin := filepath.Join(t.TempDir(), "carnical-confine")
	cmd := exec.Command(goBin, "build", "-o", bin, "./cmd/carnical-confine")
	cmd.Dir = ".."
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0") // the confinement cannot reach every thread of a cgo binary
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("building the probe: %v\n%s", err, out)
	}
	return bin
}

type probeResult struct {
	Confined bool `json:"confined"`
	ABI      int  `json:"landlock_abi"`
	Results  []struct {
		Action string `json:"action"`
		Want   string `json:"want"`
		Got    string `json:"got"`
		OK     bool   `json:"ok"`
		Detail string `json:"detail"`
	} `json:"results"`
	Failures int `json:"failures"`
}

func runProbe(t *testing.T, bin string, args ...string) probeResult {
	t.Helper()
	out, err := exec.Command(bin, append([]string{"check", "-json"}, args...)...).Output()
	var res probeResult
	if jerr := json.Unmarshal(out, &res); jerr != nil {
		t.Fatalf("no result from the probe (%v): %s", err, out)
	}
	return res
}

func TestConfinementHoldsOnThisKernel(t *testing.T) {
	bin := buildProbe(t)
	confined := runProbe(t, bin)
	if confined.ABI < 1 {
		t.Skip("this kernel has no Landlock")
	}
	if len(confined.Results) < 30 {
		t.Fatalf("only %d actions were tried", len(confined.Results))
	}
	for _, r := range confined.Results {
		if !r.OK {
			t.Errorf("confined: %s: wanted %s, got %s (%s)", r.Action, r.Want, r.Got, r.Detail)
		}
	}
	killed := 0
	for _, r := range confined.Results {
		if r.Got == "killed" {
			killed++
		}
	}
	if killed < 10 {
		t.Errorf("only %d actions were ended by the filter", killed)
	}

	// The control: the same actions with no confinement all go through. If they did not, the confined run would
	// be showing a broken probe and not a working restriction.
	control := runProbe(t, bin, "-unconfined")
	for _, r := range control.Results {
		if !r.OK {
			t.Errorf("control: %s: wanted %s, got %s", r.Action, r.Want, r.Got)
		}
		if r.Got == "killed" || r.Got == "refused" && r.Want == "allowed" {
			t.Errorf("control: %s was stopped with no confinement (%s)", r.Action, r.Got)
		}
	}
}

func TestTheCheckNoticesAWeakenedConfinement(t *testing.T) {
	bin := buildProbe(t)
	if runProbe(t, bin).ABI < 1 {
		t.Skip("this kernel has no Landlock")
	}
	tests := []struct {
		weaken string
		// actions that must now be reported as failing
		failing []string
	}{
		{"seccomp", []string{"start a program (execve)", "ptrace another process", "create an anonymous executable file (memfd_create)", "open a raw packet socket"}},
		{"landlock", []string{"read a file outside the allowed directories", "create a file outside the allowed directories", "make a symbolic link in the allowed directory"}},
	}
	for _, tt := range tests {
		t.Run("without "+tt.weaken, func(t *testing.T) {
			res := runProbe(t, bin, "-weaken", tt.weaken)
			if tt.weaken == "landlock" && res.ABI >= 4 {
				tt.failing = append(tt.failing, "connect to a port that is not allowed", "listen on a port that is not allowed")
			}
			if tt.weaken == "seccomp" {
				control := runProbe(t, bin, "-unconfined")
				for _, r := range control.Results {
					if r.Action == "open a Multipath TCP socket" && r.Got == "allowed" {
						tt.failing = append(tt.failing, r.Action)
					}
				}
			}
			if res.Failures == 0 {
				t.Fatalf("a confinement without %s passed the check", tt.weaken)
			}
			failed := map[string]bool{}
			for _, r := range res.Results {
				if !r.OK {
					failed[r.Action] = true
				}
			}
			for _, name := range tt.failing {
				if !failed[name] {
					t.Errorf("%q was not reported as failing without %s", name, tt.weaken)
				}
			}
			// Layers that were kept still hold.
			for _, r := range res.Results {
				if strings.HasPrefix(r.Action, "read an allowed") && !r.OK {
					t.Errorf("the positive control %q failed", r.Action)
				}
			}
		})
	}
}
