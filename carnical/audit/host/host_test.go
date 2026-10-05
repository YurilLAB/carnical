package host

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/YurilLAB/coraza/carnical/audit"
)

// fake is a machine written out as data.
type fake struct {
	files map[string]string
	links map[string]string
	globs map[string][]string
	stats map[string]Info
	runs  map[string]string // "name arg arg" -> output
}

func (f *fake) ReadFile(p string) ([]byte, error) {
	if s, ok := f.files[p]; ok {
		return []byte(s), nil
	}
	return nil, &fs.PathError{Op: "open", Path: p, Err: fs.ErrNotExist}
}
func (f *fake) Glob(pattern string) ([]string, error) { return f.globs[pattern], nil }
func (f *fake) Readlink(p string) (string, error) {
	if s, ok := f.links[p]; ok {
		return s, nil
	}
	return "", &fs.PathError{Op: "readlink", Path: p, Err: fs.ErrNotExist}
}
func (f *fake) Stat(p string) (Info, error) {
	if i, ok := f.stats[p]; ok {
		return i, nil
	}
	return Info{}, &fs.PathError{Op: "stat", Path: p, Err: fs.ErrNotExist}
}
func (f *fake) Run(_ context.Context, name string, args ...string) ([]byte, error) {
	if s, ok := f.runs[strings.Join(append([]string{name}, args...), " ")]; ok {
		return []byte(s), nil
	}
	return nil, errors.New("not found: " + name)
}

func run(c audit.Check) audit.Result {
	return audit.Run(context.Background(), []audit.Check{c}, 10*time.Second).Results[0]
}

func needLinux(t *testing.T) {
	t.Helper()
	if runtime.GOOS != "linux" {
		t.Skip("the checks only run on Linux")
	}
}

// ---- sysctl and mounts ----

func TestSysctlAgainstAMachine(t *testing.T) {
	needLinux(t)
	baseline := []Setting{
		{"kernel.yama.ptrace_scope", 2, true, false},
		{"kernel.sysrq", 0, false, false},
		{"kernel.io_uring_disabled", 2, true, true}, // optional: older kernels have no such switch
	}
	machine := func(ptrace, sysrq string, uring *string) *fake {
		f := &fake{files: map[string]string{"/proc/sys/kernel/yama/ptrace_scope": ptrace, "/proc/sys/kernel/sysrq": sysrq}}
		if uring != nil {
			f.files["/proc/sys/kernel/io_uring_disabled"] = *uring
		}
		return f
	}
	zero := "0\n"
	tests := []struct {
		name     string
		f        *fake
		want     audit.Status
		contains string
	}{
		{"hardened", machine("2\n", "0\n", nil), audit.Pass, ""},
		{"stricter than needed", machine("3\n", "0\n", nil), audit.Pass, ""},
		{"ptrace too open", machine("1\n", "0\n", nil), audit.Fail, "kernel.yama.ptrace_scope is 1, should be at least 2"},
		{"an exact setting that is off", machine("2\n", "1\n", nil), audit.Fail, "kernel.sysrq is 1, should be 0"},
		{"an optional switch that is too loose", machine("2\n", "0\n", &zero), audit.Fail, "io_uring_disabled is 0"},
		{"an optional switch that is right", machine("2\n", "0\n", func() *string { s := "2\n"; return &s }()), audit.Pass, ""},
		{"a required setting the kernel does not have", &fake{files: map[string]string{"/proc/sys/kernel/sysrq": "0\n"}}, audit.Fail, "cannot be read"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := run(Sysctl(tt.f, baseline))
			if r.Status != tt.want || (tt.contains != "" && !strings.Contains(strings.Join(r.Problems, "\n"), tt.contains)) {
				t.Fatalf("%+v", r)
			}
		})
	}
}

// The baseline in Go and the file that sets the values must say the same thing, or the check would pass a machine that was set
// up from a file that disagrees with it.
func TestSysctlBaselineAndFileAgree(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "deploy", "sysctl", "90-carnical.conf"))
	if err != nil {
		t.Fatal(err)
	}
	inFile := map[string]int64{}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			t.Fatalf("a line that is not a setting: %q", line)
		}
		n, err := strconv.ParseInt(strings.TrimSpace(v), 10, 64)
		if err != nil {
			t.Fatalf("%s: %v", k, err)
		}
		inFile[strings.TrimSpace(k)] = n
	}
	inBaseline := map[string]bool{}
	for _, s := range Sysctls {
		inBaseline[s.Key] = true
		got, ok := inFile[s.Key]
		if !ok {
			t.Errorf("%s is checked but the file does not set it", s.Key)
		} else if !s.Satisfied(got) {
			t.Errorf("the file sets %s to %d, which the check would not accept (want %d, at least: %v)", s.Key, got, s.Want, s.AtLeast)
		}
	}
	for k := range inFile {
		if !inBaseline[k] {
			t.Errorf("the file sets %s but nothing checks it", k)
		}
	}
}

func TestMounts(t *testing.T) {
	needLinux(t)
	good := "tmpfs /tmp tmpfs rw,nosuid,nodev,noexec 0 0\ntmpfs /var/tmp tmpfs rw,nosuid,nodev,noexec 0 0\ntmpfs /dev/shm tmpfs rw,nosuid,nodev,noexec 0 0\nproc /proc proc rw,nosuid,nodev,noexec,hidepid=invisible 0 0\n"
	tests := []struct {
		name, mounts, contains string
		want                   audit.Status
	}{
		{"all set", good, "", audit.Pass},
		{"/tmp without noexec", strings.Replace(good, "/tmp tmpfs rw,nosuid,nodev,noexec", "/tmp tmpfs rw,nosuid,nodev", 1), "/tmp is mounted without noexec", audit.Fail},
		{"/tmp not a mount of its own", strings.Replace(good, "tmpfs /tmp tmpfs rw,nosuid,nodev,noexec 0 0\n", "", 1), "/tmp is not a mount of its own", audit.Fail},
		{"/proc shows everyone's processes", strings.Replace(good, ",hidepid=invisible", "", 1), "/proc shows every user's processes", audit.Fail},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := run(Mount(&fake{files: map[string]string{"/proc/self/mounts": tt.mounts}}, Mounts))
			if r.Status != tt.want || (tt.contains != "" && !strings.Contains(strings.Join(r.Problems, "\n"), tt.contains)) {
				t.Fatalf("%+v", r)
			}
		})
	}
}

// ---- services' sandboxes, network and audit rules ----

const showEdge = `LoadState=loaded
User=carnical-edge
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectProc=invisible
ProcSubset=pid
RestrictNamespaces=yes
RestrictSUIDSGID=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
SystemCallArchitectures=native
CapabilityBoundingSet=
RestrictAddressFamilies=AF_NETLINK AF_INET6 AF_INET AF_UNIX
`

func unitMachine(show, score string) *fake {
	keys := []string{"LoadState"}
	for k := range EdgeUnit.Expect {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return &fake{runs: map[string]string{
		"systemctl show --no-pager -p " + strings.Join(keys, ",") + " carnical-edge.service": show,
		"systemd-analyze security --no-pager carnical-edge.service":                          score,
	}}
}

func TestUnit(t *testing.T) {
	needLinux(t)
	ok := "→ Overall exposure level for carnical-edge.service: 1.4 OK 🙂\n"
	tests := []struct {
		name, show, score, contains string
		want                        audit.Status
	}{
		{"as asked", showEdge, ok, "", audit.Pass},
		{"the address families in another order", strings.Replace(showEdge, "AF_NETLINK AF_INET6 AF_INET AF_UNIX", "AF_UNIX AF_INET AF_INET6 AF_NETLINK", 1), ok, "", audit.Pass},
		{"new privileges allowed", strings.Replace(showEdge, "NoNewPrivileges=yes", "NoNewPrivileges=no", 1), ok, "NoNewPrivileges is \"no\"", audit.Fail},
		{"a capability left in", strings.Replace(showEdge, "CapabilityBoundingSet=\n", "CapabilityBoundingSet=cap_net_bind_service\n", 1), ok, "CapabilityBoundingSet", audit.Fail},
		{"a packet socket allowed", strings.Replace(showEdge, "AF_UNIX", "AF_UNIX AF_PACKET", 1), ok, "RestrictAddressFamilies", audit.Fail},
		{"running as root", strings.Replace(showEdge, "User=carnical-edge", "User=", 1), ok, "User is \"\"", audit.Fail},
		{"not installed", "LoadState=not-found\n", ok, "is not installed", audit.Fail},
		{"too exposed by systemd's own score", showEdge, "→ Overall exposure level for carnical-edge.service: 6.2 MEDIUM 😐\n", "scores its exposure at 6.2", audit.Fail},
		{"no score available", showEdge, "", "exposure score could not be read", audit.Fail},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := run(Unit(unitMachine(tt.show, tt.score), EdgeUnit))
			if r.Status != tt.want || (tt.contains != "" && !strings.Contains(strings.Join(r.Problems, "\n"), tt.contains)) {
				t.Fatalf("%+v", r)
			}
		})
	}
}

// The unit file in the repository must ask for exactly what the check demands.
func TestTheUnitFileAsksForWhatTheCheckDemands(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "deploy", "systemd", "carnical-edge.service"))
	if err != nil {
		t.Fatal(err)
	}
	set := map[string]string{}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if k, v, ok := strings.Cut(line, "="); ok && !strings.HasPrefix(line, "#") && !strings.HasPrefix(line, "ExecStart") {
			set[k] = strings.TrimSpace(v)
		}
	}
	for k, want := range EdgeUnit.Expect {
		got, ok := set[k]
		switch {
		case !ok && !(k == "CapabilityBoundingSet" && want == ""):
			t.Errorf("the check demands %s=%q but the unit file does not set it", k, want)
		case ok && setValued[k] && !sameSet(got, want):
			t.Errorf("%s: unit file %q, check %q", k, got, want)
		case ok && !setValued[k] && got != want:
			t.Errorf("%s: unit file %q, check %q", k, got, want)
		}
	}
}

const nftGood = `table inet carnical {
	set not_public4 { type ipv4_addr }
	set not_public6 { type ipv6_addr }
	chain input { type filter hook input priority filter; policy drop; }
	chain output { meta skuid 1001 jump edge_out ip daddr 169.254.169.254 drop }
	chain edge_out { ip daddr @not_public4 drop ip6 daddr @not_public6 drop fib daddr type local drop }
	chain internal_out { drop }
}`

func TestNFT(t *testing.T) {
	needLinux(t)
	m := func(s string) *fake { return &fake{runs: map[string]string{"nft list ruleset": s}} }
	if r := run(NFT(m(nftGood))); r.Status != audit.Pass {
		t.Fatalf("%+v", r)
	}
	for name, broken := range map[string]string{
		"no private-destination list": strings.ReplaceAll(nftGood, "@not_public4", "@x"),
		"no edge chain":               strings.ReplaceAll(nftGood, "edge_out", "other"),
		"input not refusing":          strings.Replace(nftGood, "policy drop", "policy accept", 1),
		"nothing loaded":              "",
	} {
		t.Run(name, func(t *testing.T) {
			if r := run(NFT(m(broken))); r.Status != audit.Fail {
				t.Fatalf("%+v", r)
			}
		})
	}
	// The tokens the check looks for must all be in the ruleset file.
	file, err := os.ReadFile(filepath.Join("..", "..", "deploy", "nftables", "carnical.nft"))
	if err != nil {
		t.Fatal(err)
	}
	for _, tok := range []string{"table inet carnical", "policy drop", "chain edge_out", "jump edge_out", "@not_public4", "@not_public6", "fib daddr type local", "169.254.169.254", "chain internal_out"} {
		if !strings.Contains(string(file), tok) {
			t.Errorf("the check looks for %q, which the ruleset file does not contain", tok)
		}
	}
}

func TestAuditd(t *testing.T) {
	needLinux(t)
	var rules strings.Builder
	for _, k := range AuditKeys {
		rules.WriteString("-a always,exit -S execve -k " + k + "\n")
	}
	m := func(status, list string) *fake {
		return &fake{runs: map[string]string{"auditctl -s": status, "auditctl -l": list}}
	}
	if r := run(Auditd(m("enabled 2\nfailure 1\n", rules.String()))); r.Status != audit.Pass {
		t.Fatalf("%+v", r)
	}
	if r := run(Auditd(m("enabled 1\n", rules.String()))); r.Status != audit.Fail || !strings.Contains(r.Problems[0], "not locked") {
		t.Fatalf("an unlocked audit system: %+v", r)
	}
	if r := run(Auditd(m("enabled 2\n", strings.ReplaceAll(rules.String(), "carnical_honey", "x")))); r.Status != audit.Fail {
		t.Fatalf("a missing rule: %+v", r)
	}
	// Every key must be in the rules file.
	file, _ := os.ReadFile(filepath.Join("..", "..", "deploy", "auditd", "carnical.rules"))
	for _, k := range AuditKeys {
		if !strings.Contains(string(file), "-k "+k) {
			t.Errorf("the check looks for the key %s, which the rules file does not set", k)
		}
	}
}

func TestOwnership(t *testing.T) {
	needLinux(t)
	passwd := "root:x:0:0::/root:/bin/sh\ncarnical-edge:x:990:990::/:/usr/sbin/nologin\n"
	rules := []FileRule{{"/usr/local/bin/carnical", "root", 0o755}, {"/var/lib/carnical/edge", "carnical-edge", 0o700}}
	good := &fake{files: map[string]string{"/etc/passwd": passwd}, stats: map[string]Info{
		"/usr/local/bin/carnical": {Mode: 0o755, UID: 0}, "/var/lib/carnical/edge": {Mode: fs.ModeDir | 0o700, UID: 990},
	}}
	if r := run(Ownership(good, rules)); r.Status != audit.Pass {
		t.Fatalf("%+v", r)
	}
	bad := &fake{files: map[string]string{"/etc/passwd": passwd}, stats: map[string]Info{
		"/usr/local/bin/carnical": {Mode: 0o775, UID: 990}, // the service owns, and can rewrite, its own program
		"/var/lib/carnical/edge":  {Mode: fs.ModeDir | 0o755, UID: 990},
	}}
	r := run(Ownership(bad, rules))
	joined := strings.Join(r.Problems, "\n")
	for _, want := range []string{"/usr/local/bin/carnical is owned by uid 990, should be root", "/usr/local/bin/carnical has mode 0775", "/var/lib/carnical/edge has mode 0755"} {
		if !strings.Contains(joined, want) {
			t.Errorf("missing %q in\n%s", want, joined)
		}
	}
	if r := run(Ownership(&fake{files: map[string]string{"/etc/passwd": passwd}}, rules)); r.Status != audit.Fail {
		t.Fatalf("files that do not exist: %+v", r)
	}
}

// ---- who is listening, and what is running ----

func TestParseNetTCP(t *testing.T) {
	// A real /proc/net/tcp: 127.0.0.1:8080 owned by uid 1000, 0.0.0.0:443 owned by root, and a connection that is not listening.
	data := `  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 11111 1 0 100 0
   1: 00000000:01BB 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 22222 1 0 100 0
   2: 0100007F:1F90 0100007F:D2C4 01 00000000:00000000 00:00000000 00000000  1000        0 33333 1 0 100 0
`
	ls, err := ParseNetTCP([]byte(data), false)
	if err != nil || len(ls) != 2 {
		t.Fatalf("%v %+v", err, ls)
	}
	if ls[0].Addr.String() != "127.0.0.1" || ls[0].Port != 8080 || ls[0].UID != 1000 {
		t.Fatalf("%+v", ls[0])
	}
	if ls[1].Addr.String() != "0.0.0.0" || ls[1].Port != 443 || ls[1].UID != 0 {
		t.Fatalf("%+v", ls[1])
	}
	v6 := `  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000000000000000000001000000:1F90 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 1 1 0 100 0
   1: 00000000000000000000000000000000:01BB 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 2 1 0 100 0
`
	ls, err = ParseNetTCP([]byte(v6), true)
	if err != nil || len(ls) != 2 || ls[0].Addr.String() != "::1" || ls[0].Port != 8080 || ls[1].Addr.String() != "::" || ls[1].Port != 443 {
		t.Fatalf("%v %+v", err, ls)
	}
}

func TestListeners(t *testing.T) {
	needLinux(t)
	tcp := `  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000:01BB 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1 1 0 100 0
   1: 0100007F:20FB 00000000:0000 0A 00000000:00000000 00:00000000 00000000   991        0 2 1 0 100 0
`
	passwd := "root:x:0:0::/root:/bin/sh\ncarnical-edge:x:990:990::/:/bin/false\ncarnical-ctl:x:991:991::/:/bin/false\n"
	m := &fake{files: map[string]string{"/proc/net/tcp": tcp, "/etc/passwd": passwd}}
	declared := []audit.Service{
		{Name: "edge", Addr: "0.0.0.0:443", User: "root,carnical-edge"}, // 0x01BB = 443; socket activation makes root the owner
		{Name: "ctl", Addr: "127.0.0.1:8443", User: "carnical-ctl"},     // 0x20FB = 8443
	}
	if r := run(Listeners(m, declared)); r.Status != audit.Pass || r.Checked != 2 {
		t.Fatalf("%+v", r)
	}
	tests := []struct {
		name     string
		declared []audit.Service
		contains string
	}{
		{"an undeclared listener", declared[:1], "127.0.0.1:8443 is listening, owned by carnical-ctl, and is not in the zone map"},
		{"owned by the wrong user", []audit.Service{declared[0], {Name: "ctl", Addr: "127.0.0.1:8443", User: "carnical-edge"}}, "owned by carnical-ctl, but ctl is declared to be run by carnical-edge"},
		{"wider than declared", []audit.Service{declared[0], {Name: "ctl", Addr: "10.0.0.5:8443", User: "carnical-ctl"}}, "it listens on 127.0.0.1, but 10.0.0.5:8443 is declared"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := run(Listeners(m, tt.declared))
			if r.Status != audit.Fail || !strings.Contains(strings.Join(r.Problems, "\n"), tt.contains) {
				t.Fatalf("%+v", r)
			}
		})
	}
	// Declared to listen on one address, found on every address.
	wide := &fake{files: map[string]string{"/proc/net/tcp": strings.Replace(tcp, "0100007F:20FB", "00000000:20FB", 1), "/etc/passwd": passwd}}
	if r := run(Listeners(wide, declared)); r.Status != audit.Fail || !strings.Contains(strings.Join(r.Problems, "\n"), "listens on every address") {
		t.Fatalf("%+v", r)
	}
}

func TestRunning(t *testing.T) {
	needLinux(t)
	passwd := "root:x:0:0::/root:/bin/sh\ncarnical-edge:x:990:990::/:/bin/false\n"
	proc := func(pid int, uid int, exe string, f *fake) {
		dir := "/proc/" + strconv.Itoa(pid)
		f.globs["/proc/[0-9]*"] = append(f.globs["/proc/[0-9]*"], dir)
		f.files[dir+"/status"] = fmt.Sprintf("Name:\tx\nUid:\t%d\t%d\t%d\t%d\n", uid, uid, uid, uid)
		f.links[dir+"/exe"] = exe
	}
	newMachine := func() *fake {
		f := &fake{files: map[string]string{"/etc/passwd": passwd}, links: map[string]string{}, globs: map[string][]string{}}
		proc(1, 0, "/usr/lib/systemd/systemd", f)
		proc(100, 990, "/usr/local/bin/carnical", f)
		return f
	}
	if r := run(Running(newMachine(), DefaultProcs)); r.Status != audit.Pass || r.Checked != 2 {
		t.Fatalf("an ordinary machine: %+v", r)
	}
	tests := []struct {
		name     string
		add      func(f *fake)
		contains string
	}{
		{"a program deleted while it runs", func(f *fake) { proc(200, 0, "/usr/bin/sleep (deleted)", f) }, "pid 200 (uid 0) runs /usr/bin/sleep (deleted): its program file has been deleted"},
		{"a program from memory", func(f *fake) { proc(201, 33, "/memfd:payload (deleted)", f) }, "runs from memory"},
		{"a program from /tmp", func(f *fake) { proc(202, 1000, "/tmp/.x/miner", f) }, "runs from a directory anyone can write to"},
		{"a shell run by the edge user", func(f *fake) { proc(203, 990, "/usr/bin/bash", f) }, "a shell, interpreter or network tool"},
		{"python run by the edge user", func(f *fake) { proc(204, 990, "/usr/bin/python3.12", f) }, "a shell, interpreter or network tool"},
		{"another program run by the edge user", func(f *fake) { proc(205, 990, "/opt/other", f) }, "which is not its program"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newMachine()
			tt.add(f)
			r := run(Running(f, DefaultProcs))
			if r.Status != audit.Fail || !strings.Contains(strings.Join(r.Problems, "\n"), tt.contains) {
				t.Fatalf("%+v", r)
			}
		})
	}
	// Not able to read a program is not the same as it being fine.
	f := newMachine()
	f.links = map[string]string{} // no program can be read
	if r := run(Running(f, DefaultProcs)); r.Status != audit.Skip && r.Status != audit.Fail {
		t.Fatalf("a check that saw nothing passed: %+v", r)
	}
}

// ---- manifests ----

func TestIntegrity(t *testing.T) {
	dir := t.TempDir()
	manifest := filepath.Join(dir, "integrity.json")
	prog, preload := filepath.Join(dir, "carnical"), filepath.Join(dir, "ld.so.preload")
	os.WriteFile(prog, []byte("the program"), 0o600)
	if err := WriteIntegrity(OS{}, manifest, []string{prog, preload}, false); err != nil {
		t.Fatal(err)
	}
	if err := WriteIntegrity(OS{}, manifest, []string{prog}, false); err == nil {
		t.Fatal("a manifest was replaced without being asked to")
	}
	check := func() audit.Result { return run(Integrity(OS{}, manifest)) }
	if r := check(); r.Status != audit.Pass || r.Checked != 2 {
		t.Fatalf("an unchanged machine: %+v", r)
	}
	os.WriteFile(prog, []byte("a different program"), 0o600)
	if r := check(); r.Status != audit.Fail || !strings.Contains(r.Problems[0], "has changed") {
		t.Fatalf("a changed file: %+v", r)
	}
	os.WriteFile(prog, []byte("the program"), 0o600)
	os.WriteFile(preload, []byte("/tmp/evil.so\n"), 0o600) // a file that must not exist
	if r := check(); r.Status != audit.Fail || !strings.Contains(r.Problems[0], "did not exist and now does") {
		t.Fatalf("a file that must not exist: %+v", r)
	}
	os.Remove(preload)
	os.Remove(prog)
	if r := check(); r.Status != audit.Fail || !strings.Contains(r.Problems[0], "has gone") {
		t.Fatalf("a deleted file: %+v", r)
	}
	if r := run(Integrity(OS{}, filepath.Join(dir, "none.json"))); r.Status != audit.Skip {
		t.Fatalf("no manifest must be a skip, not a pass: %+v", r)
	}
}

func TestSUID(t *testing.T) {
	needLinux(t)
	dir := t.TempDir()
	baseline := filepath.Join(dir, "suid.json")
	sudo := filepath.Join(dir, "sudo")
	os.WriteFile(sudo, []byte("sudo"), 0o755)
	// The machine has sudo; the baseline is written from it.
	src := &runFake{files: OS{}, out: sudo + "\x00"}
	if err := WriteSUID(context.Background(), src, baseline, false); err != nil {
		t.Fatal(err)
	}
	if r := run(SUID(src, baseline)); r.Status != audit.Pass || r.Checked != 1 {
		t.Fatalf("%+v", r)
	}
	src.out = sudo + "\x00" + filepath.Join(dir, "backdoor") + "\x00"
	if r := run(SUID(src, baseline)); r.Status != audit.Fail || !strings.Contains(r.Problems[0], "backdoor is a new setuid or setgid file") {
		t.Fatalf("a new setuid file: %+v", r)
	}
	src.out = sudo + "\x00"
	os.WriteFile(sudo, []byte("a patched sudo"), 0o755)
	if r := run(SUID(src, baseline)); r.Status != audit.Fail || !strings.Contains(r.Problems[0], "has changed") {
		t.Fatalf("a changed setuid file: %+v", r)
	}
	if r := run(SUID(src, filepath.Join(dir, "none.json"))); r.Status != audit.Skip {
		t.Fatalf("no baseline must be a skip: %+v", r)
	}
}

// runFake reads real files and answers find from a script.
type runFake struct {
	files OS
	out   string
}

func (r *runFake) ReadFile(p string) ([]byte, error) { return r.files.ReadFile(p) }
func (r *runFake) Glob(p string) ([]string, error)   { return r.files.Glob(p) }
func (r *runFake) Readlink(p string) (string, error) { return r.files.Readlink(p) }
func (r *runFake) Stat(p string) (Info, error)       { return r.files.Stat(p) }
func (r *runFake) Run(context.Context, string, ...string) ([]byte, error) {
	return []byte(r.out), nil
}

// ---- on this machine: positive controls the checks must catch ----

func TestRunningFindsARealProcessWhoseProgramWasDeleted(t *testing.T) {
	needLinux(t)
	sleep, err := os.ReadFile("/bin/sleep")
	if err != nil {
		t.Skip("no /bin/sleep")
	}
	dir := t.TempDir()
	prog := filepath.Join(dir, "sleep") // named as the multi-call coreutils binary expects
	if err := os.WriteFile(prog, sleep, 0o755); err != nil {
		t.Fatal(err)
	}
	cmd := execCommand(prog, "30")
	if err := cmd.Start(); err != nil {
		t.Skipf("cannot start a program from the temporary directory: %v", err)
	}
	defer func() { cmd.Process.Kill(); cmd.Wait() }()
	pid := cmd.Process.Pid

	policy := ProcPolicy{AllowPartial: true}
	problemsFor := func() string {
		r := run(Running(OS{}, policy))
		if r.Status == audit.Skip {
			t.Skip(r.Note)
		}
		var mine []string
		for _, p := range r.Problems {
			if strings.Contains(p, "pid "+strconv.Itoa(pid)+" ") {
				mine = append(mine, p)
			}
		}
		return strings.Join(mine, "\n")
	}
	// While the file exists the program is only running from a directory anyone can write to (the temporary directory).
	if got := problemsFor(); strings.Contains(got, "deleted") {
		t.Fatalf("flagged as deleted before it was: %s", got)
	}
	os.Remove(prog)
	if got := problemsFor(); !strings.Contains(got, "its program file has been deleted or replaced while it runs") {
		t.Fatalf("a process whose program was deleted while it ran was not found (pid %d): %q", pid, got)
	}
}

func TestListenersFindsARealListenerNobodyDeclared(t *testing.T) {
	needLinux(t)
	ln, port := listenOnce(t)
	defer ln.Close()
	self := currentUserName(t)
	declared := func(user string) []audit.Service {
		return []audit.Service{{Name: "test", Addr: "127.0.0.1:" + strconv.Itoa(port), User: user}}
	}
	problems := func(d []audit.Service) string {
		r := run(Listeners(OS{}, d))
		if r.Status == audit.Skip {
			t.Skip(r.Note)
		}
		return strings.Join(r.Problems, "\n")
	}
	needle := "127.0.0.1:" + strconv.Itoa(port) + " is listening"
	if got := problems(nil); !strings.Contains(got, needle) {
		t.Fatalf("a listener nobody declared was not found:\n%s", got)
	}
	if got := problems(declared(self)); strings.Contains(got, needle) || strings.Contains(got, "127.0.0.1:"+strconv.Itoa(port)+" (") {
		t.Fatalf("a declared listener owned by the right user was flagged:\n%s", got)
	}
	if got := problems(declared("somebody-else")); !strings.Contains(got, "declared to be run by somebody-else") {
		t.Fatalf("a listener owned by the wrong user was not found:\n%s", got)
	}
}

// A baseline made from this machine's own settings passes, and one that asks for something different does not: the check can
// tell the difference on a real kernel.
func TestSysctlOnThisKernelTellsTheDifference(t *testing.T) {
	needLinux(t)
	var own, other []Setting
	for _, key := range []string{"kernel.randomize_va_space", "kernel.sysrq", "vm.mmap_min_addr", "net.ipv4.tcp_syncookies"} {
		data, err := os.ReadFile("/proc/sys/" + strings.ReplaceAll(key, ".", "/"))
		if err != nil {
			continue
		}
		n, _ := strconv.ParseInt(strings.TrimSpace(string(data)), 10, 64)
		own = append(own, Setting{Key: key, Want: n})
		other = append(other, Setting{Key: key, Want: n + 7})
	}
	if len(own) == 0 {
		t.Skip("no settings to read")
	}
	if r := run(Sysctl(OS{}, own)); r.Status != audit.Pass {
		t.Fatalf("this machine's own settings: %+v", r)
	}
	if r := run(Sysctl(OS{}, other)); r.Status != audit.Fail {
		t.Fatalf("settings it does not have: %+v", r)
	}
}
