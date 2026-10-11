package host

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
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
	inBaseline := map[string]Setting{}
	for _, s := range Sysctls {
		inBaseline[s.Key] = s
		got, ok := inFile[s.Key]
		if !ok {
			t.Errorf("%s is checked but the file does not set it", s.Key)
		} else if !s.Satisfied(got) {
			t.Errorf("the file sets %s to %d, which the check would not accept (want %d, at least: %v)", s.Key, got, s.Want, s.AtLeast)
		}
	}
	// A line for every interface (net.ipv4.conf.*.x) is what the check reads in each interface's copy of net.ipv4.conf.all.x.
	for k, v := range inFile {
		allKey := strings.Replace(k, ".*.", ".all.", 1)
		s, checked := inBaseline[allKey]
		_, perInterface := PerInterface[allKey]
		switch {
		case !checked:
			t.Errorf("the file sets %s but nothing checks it", k)
		case k != allKey && !perInterface:
			t.Errorf("the file sets %s on every interface but the check does not read the interfaces' copies", k)
		case k != allKey && !s.Satisfied(v):
			t.Errorf("the file sets %s to %d, which the check would not accept", k, v)
		}
	}
	for k := range PerInterface {
		if _, ok := inFile[strings.Replace(k, ".all.", ".*.", 1)]; !ok {
			t.Errorf("the check reads every interface's copy of %s, but the file does not set them", k)
		}
	}
}

// A network card's own copy counts: for redirects if either it or "all" is on, for rp_filter the larger of the two.
func TestSysctlReadsEachInterface(t *testing.T) {
	needLinux(t)
	var baseline []Setting // the shipped settings, so that their rules are what is tested
	for _, s := range Sysctls {
		if s.Key == "net.ipv4.conf.all.rp_filter" || s.Key == "net.ipv4.conf.all.accept_redirects" {
			baseline = append(baseline, s)
		}
	}
	machine := func(eth0RP, eth0Redirects string) *fake {
		f := &fake{files: map[string]string{
			"/proc/sys/net/ipv4/conf/all/rp_filter": "1\n", "/proc/sys/net/ipv4/conf/all/accept_redirects": "0\n",
			"/proc/sys/net/ipv4/conf/default/rp_filter": "2\n", // not an interface: "default" is checked on its own
			"/proc/sys/net/ipv4/conf/lo/rp_filter":      "0\n", "/proc/sys/net/ipv4/conf/lo/accept_redirects": "0\n",
			"/proc/sys/net/ipv4/conf/eth0/rp_filter": eth0RP, "/proc/sys/net/ipv4/conf/eth0/accept_redirects": eth0Redirects,
		}, globs: map[string][]string{}}
		for _, leaf := range []string{"rp_filter", "accept_redirects"} {
			for _, d := range []string{"all", "default", "lo", "eth0"} {
				if _, ok := f.files["/proc/sys/net/ipv4/conf/"+d+"/"+leaf]; ok {
					f.globs["/proc/sys/net/ipv4/conf/*/"+leaf] = append(f.globs["/proc/sys/net/ipv4/conf/*/"+leaf], "/proc/sys/net/ipv4/conf/"+d+"/"+leaf)
				}
			}
		}
		return f
	}
	tests := []struct {
		name, rp, redirects, contains string
		want                          audit.Status
	}{
		{"every interface strict (lo at 0 still uses all's 1)", "1\n", "0\n", "", audit.Pass},
		{"an interface in loose mode", "2\n", "0\n", "net.ipv4.conf.eth0.rp_filter is 2, so the interface uses 2, should be 1", audit.Fail},
		{"an interface that accepts redirects", "1\n", "1\n", "net.ipv4.conf.eth0.accept_redirects is 1, should be 0", audit.Fail},
		{"an interface whose value is not a number", "x\n", "0\n", "eth0.rp_filter is not a number", audit.Fail},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := run(Sysctl(machine(tt.rp, tt.redirects), baseline))
			if r.Status != tt.want || (tt.contains != "" && !strings.Contains(strings.Join(r.Problems, "\n"), tt.contains)) {
				t.Fatalf("%+v", r)
			}
			if tt.want == audit.Pass && r.Checked != 6 {
				t.Fatalf("%d cases, want two settings and two interfaces each", r.Checked)
			}
		})
	}
	// rp_filter 2 in "all" is the loose mode, not a stricter setting.
	loose := machine("1\n", "0\n")
	loose.files["/proc/sys/net/ipv4/conf/all/rp_filter"] = "2\n"
	if r := run(Sysctl(loose, baseline)); r.Status != audit.Fail || !strings.Contains(strings.Join(r.Problems, "\n"), "net.ipv4.conf.all.rp_filter is 2, should be 1") {
		t.Fatalf("loose rp_filter: %+v", r)
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
	// IPAddressDeny is not among what the check reads back from the running unit, so the file itself is held to it here.
	deny := " " + set["IPAddressDeny"] + " "
	for _, want := range []string{"link-local", "168.63.129.16"} {
		if !strings.Contains(deny, " "+want+" ") {
			t.Errorf("the unit file's IPAddressDeny=%q does not refuse %s", set["IPAddressDeny"], want)
		}
	}
}

func readLF(t *testing.T, parts ...string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(parts...))
	if err != nil {
		t.Fatal(err)
	}
	return strings.ReplaceAll(string(data), "\r\n", "\n")
}

// TestNFT runs the check on what nft really prints for the shipped ruleset, and on that listing with one thing undone.
func TestNFT(t *testing.T) {
	needLinux(t)
	good := readLF(t, "testdata", "nft-ruleset.txt")
	goodJSON := readLF(t, "testdata", "nft-ruleset.json") // what nft -j prints for the same ruleset
	passwd := "root:x:0:0::/root:/bin/sh\ncarnical-edge:x:990:990::/:/usr/sbin/nologin\n"
	for i, u := range InternalUsers {
		passwd += fmt.Sprintf("%s:x:%d:%d::/:/usr/sbin/nologin\n", u, 991+i, 991+i)
	}
	both := func(s, js string) *fake {
		return &fake{files: map[string]string{"/etc/passwd": passwd}, runs: map[string]string{"nft list ruleset": s, "nft -j list ruleset": js}}
	}
	m := func(s string) *fake { return both(s, goodJSON) }
	edit := func(t *testing.T, old, new string) string {
		t.Helper()
		if n := strings.Count(good, old); n != 1 {
			t.Fatalf("the listing has %q %d times", old, n)
		}
		return strings.Replace(good, old, new, 1)
	}
	const edgeJump = "\t\tmeta skuid 990 jump edge_out\n"
	const edgeStart = "\tchain edge_out {\n"
	const internalJump = "\t\tmeta skuid { 991, 992, 993, 994 } jump internal_out\n"
	const privateBlock = `ip daddr @not_public4 counter name "egress_private_drop" jump edge_private_drop`
	const inputStart = "\t\ttype filter hook input priority filter; policy drop;\n"
	const forwardStart = "\t\ttype filter hook forward priority filter; policy drop;\n"
	const inline = "\t\t\tip daddr 10.0.0.0/8 accept\n\t\t\tip daddr 192.0.2.1 drop\n\t\t}\n" // the body of an inline chain
	chained := func(n int) string {                                                           // input jumps through n chains to one that accepts
		s := "\t\tjump c1\n\t}\n"
		for i := 1; i < n; i++ {
			s += fmt.Sprintf("\n\tchain c%d {\n\t\tjump c%d\n\t}\n", i, i+1)
		}
		return s + fmt.Sprintf("\n\tchain c%d {\n\t\taccept\n", n)
	}
	// other puts another table in front of the carnical one, with one chain on a hook and what else is given.
	other := func(table, hook, rules, more string) string {
		return "table " + table + " {\n\tchain late {\n\t\ttype " + hook + "; policy accept;\n" + rules + "\t}\n" + more + "}\ntable inet carnical {\n"
	}
	const rewrite = "\t\tmeta skuid 990 tcp dport 443 ip daddr set 10.0.0.5\n" // 990 is the edge
	const carnicalTable = "table inet carnical {\n"
	for _, tt := range []struct{ name, old, new string }{
		{"as listed", "", ""},
		{"the edge's user by name", edgeJump, "\t\tmeta skuid \"carnical-edge\" jump edge_out\n"},
		{"another table beside it", "table inet carnical {\n", "table ip other {\n\tchain input {\n\t\ttype filter hook input priority filter; policy accept;\n\t\taccept\n\t}\n}\ntable inet carnical {\n"},
		{"the site's own resolver", edgeStart + "\t\tip daddr { 127.0.0.53, 127.0.0.54 } udp dport 53 accept\n", edgeStart + "\t\tip daddr 10.0.0.2 udp dport 53 counter accept\n"},
		{"another named port after the blocks", "tcp dport { 80, 443 } accept", "tcp dport { 80, 443, 8443 } accept"},
		{"named origins after the blocks", "\t\ttcp dport { 80, 443 } accept\n", "\t\tip daddr { 192.0.2.10, 198.51.100.0/24 } tcp dport 443 ct state new counter accept\n\t\tip6 daddr @origins6 tcp dport 443 accept\n"},
		{"a log line after the blocks", "\t\ttcp dport { 80, 443 } accept\n", "\t\ttcp dport { 80, 443 } accept\n\t\tlimit rate 5/minute log prefix \"carnical-edge-egress \"\n"},
		{"an accept after input's last jump, which no packet reaches", "\t\tcounter name \"input_denied\" jump input_drop\n", "\t\tcounter name \"input_denied\" jump input_drop\n\t\taccept\n"},
		{"an accept after a drop, which no packet reaches", "level info\n\t\tdrop\n", "level info\n\t\tdrop\n\t\taccept\n"},
		{"replies accepted with a counter", "\tchain output {\n\t\ttype filter hook output priority filter; policy accept;\n\t\tct state established,related accept\n",
			"\tchain output {\n\t\ttype filter hook output priority filter; policy accept;\n\t\tct state established,related counter packets 0 bytes 0 accept\n"},
		{"IPv6 ranges merged by nft", "elements = { ::,\n\t\t\t     ::1,\n", "elements = { ::/127,\n"},
		{"replies written as a set, in input", "\t\ticmpv6 type echo-request jump echo_guard\n\t\tct state established,related accept\n", "\t\ticmpv6 type echo-request jump echo_guard\n\t\tct state { established, related } accept\n"},
		{"replies written as a set, in output", "\tchain output {\n\t\ttype filter hook output priority filter; policy accept;\n\t\tct state established,related accept\n",
			"\tchain output {\n\t\ttype filter hook output priority filter; policy accept;\n\t\tct state { established, related } accept\n"},
		{"another user held to the internal chain as well", internalJump, "\t\tmeta skuid { 991, 992, 993, 994, 65000 } jump internal_out\n"},
		{"the internal users by name", internalJump, "\t\tmeta skuid { \"carnical-portal\", \"carnical-ctl\", \"carnical-signer\", \"carnical-audit\" } jump internal_out\n"},
		{"another named port open", "\t\ttcp dport 443 accept\n", "\t\ttcp dport { 80, 443 } accept\n"},
		{"a logged accept", "\t\tiif \"lo\" accept\n", "\t\tiif \"lo\" log prefix \"lo \" level info accept\n"},
		{"administration from a range", "ip saddr 192.0.2.10 tcp dport 22", "ip saddr 198.51.100.0/24 tcp dport 22"},
		{"a NAT table that runs before the filter, as Docker's does", "table inet carnical {\n", "table ip nat {\n\tchain OUTPUT {\n\t\ttype nat hook output priority dstnat; policy accept;\n\t\tfib daddr type local jump DOCKER\n\t}\n\n\tchain DOCKER {\n\t}\n}\ntable inet carnical {\n"},
		{"a destination rewritten before the filter sees it", carnicalTable, other("ip early", "route hook output priority mangle", rewrite, "")},
		{"sources translated on the way out", carnicalTable, other("ip nat", "nat hook postrouting priority srcnat", "\t\toifname \"eth0\" masquerade\n\t\tip saddr 10.8.0.0/24 snat to 192.0.2.1\n", "")},
		{"a mark, a class and a source set on the way out", carnicalTable, other("inet qos", "filter hook postrouting priority filter", "\t\tmeta mark set 0x00000001 ip dscp set cs1\n\t\tip saddr set 192.0.2.1\n", "")},
		{"a later chain that only counts and logs", carnicalTable, other("inet watch", "filter hook output priority 100", "\t\ttcp dport 443 counter packets 0 bytes 0 log prefix \"was ip daddr set \"\n\t\tcounter comment \"no ip daddr set 10.0.0.5 here\"\n", "")},
		{"a rewrite before a filter that runs late", "\tchain output {\n\t\ttype filter hook output priority filter; policy accept;\n",
			"\tchain early {\n\t\ttype filter hook output priority 5; policy accept;\n" + rewrite + "\t}\n\n\tchain output {\n\t\ttype filter hook output priority 10; policy accept;\n"},
		{"incoming connections rewritten in a table whose chain on the way out picks a chain by port", carnicalTable,
			other("ip lb", "filter hook postrouting priority filter", "\t\ttcp dport vmap { 443 : jump count, 80 : goto count }\n", "\n\tchain count {\n\t\tcounter\n\t}\n\n\tchain pre {\n\t\ttype nat hook prerouting priority dstnat; policy accept;\n\t\tjump portfwd\n\t}\n\n\tchain portfwd {\n\t\ttcp dport 8080 dnat to 10.0.0.9:80\n\t}\n")},
		{"the same with the ports in a map of the table", carnicalTable,
			other("ip lb", "filter hook postrouting priority filter", "\t\ttcp dport vmap @byport\n", "\n\tmap byport {\n\t\ttype inet_service : verdict\n\t\telements = { 80 : jump count,\n\t\t\t     443 : jump count }\n\t}\n\n\tchain count {\n\t\tcounter\n\t}\n\n\tchain portfwd {\n\t\ttcp dport 8080 dnat to 10.0.0.9:80\n\t}\n")},
		{"a map filled from elsewhere, and a rewrite in a chain on the way in", carnicalTable,
			other("ip lb", "filter hook postrouting priority filter", "\t\ttcp dport vmap @later\n", "\n\tmap later {\n\t\ttype inet_service : verdict\n\t}\n\n\tchain pre {\n\t\ttype filter hook prerouting priority raw; policy accept;\n\t\ttcp dport 8080 ip daddr set 10.0.0.9\n\t}\n")},
		{"incoming connections rewritten in a table that also has a chain on the way out", carnicalTable,
			other("ip lb", "filter hook postrouting priority filter", "\t\tcounter\n", "\n\tchain pre {\n\t\ttype filter hook prerouting priority raw; policy accept;\n\t\tjump inbound\n\t}\n\n\tchain inbound {\n\t\ttcp dport 8080 ip daddr set 10.0.0.9\n\t}\n")},
		{"a card's ingress rewritten", carnicalTable, other("netdev in", "filter hook ingress device \"eth0\" priority filter", "\t\tether daddr set 02:00:00:00:00:05\n", "")},
	} {
		t.Run("passes: "+tt.name, func(t *testing.T) {
			listing := good
			if tt.old != "" {
				listing = edit(t, tt.old, tt.new)
			}
			if r := run(NFT(m(listing))); r.Status != audit.Pass {
				t.Fatalf("%+v", r)
			}
		})
	}
	for _, tt := range []struct{ name, old, new, says string }{
		{"input accepts by default", "hook input priority filter; policy drop;", "hook input priority filter; policy accept;", "input chain does not refuse"},
		{"forward accepts by default", "hook forward priority filter; policy drop;", "hook forward priority filter; policy accept;", "forward chain does not refuse"},
		{"input is no longer a base chain", "\t\ttype filter hook input priority filter; policy drop;\n", "", "not attached to the input hook"},
		{"input accepts everything first", "\t\tct state invalid drop\n", "\t\tcounter accept\n\t\tct state invalid drop\n", "accepts every packet"},
		{"input's last chain accepts", "log prefix \"carnical-in-drop \" level info\n\t\tdrop\n", "log prefix \"carnical-in-drop \" level info\n\t\taccept\n", "input chain accepts every packet"},
		{"forward jumps to a chain that accepts", "\t\ttype filter hook forward priority filter; policy drop;\n", "\t\ttype filter hook forward priority filter; policy drop;\n\t\tjump allow_all\n\t}\n\n\tchain allow_all {\n\t\taccept\n", "forward chain accepts every packet"},
		{"forward goes to a chain that accepts", "\t\ttype filter hook forward priority filter; policy drop;\n", "\t\ttype filter hook forward priority filter; policy drop;\n\t\tgoto allow_all\n\t}\n\n\tchain allow_all {\n\t\taccept\n", "forward chain accepts every packet"},
		{"input decides through a verdict map", "\t\tct state invalid drop\n", "\t\tct state invalid drop\n\t\tmeta l4proto vmap { tcp : accept, udp : accept }\n", "verdict map"},
		{"a chain input jumps to decides through a verdict map", "\tchain echo_guard {\n", "\tchain echo_guard {\n\t\tip saddr vmap { 10.0.0.0/8 : accept }\n", "input chain decides through a verdict map"},
		{"input accepts after setting a mark", inputStart, inputStart + "\t\tmeta mark set 0x00000001 accept\n", `input chain accepts "meta mark set 0x00000001"`},
		{"input accepts each address family", inputStart, inputStart + "\t\tmeta nfproto ipv4 accept\n\t\tmeta nfproto ipv6 accept\n", `input chain accepts "meta nfproto ipv4"`},
		{"input accepts a range of ports", "\t\ttcp dport 443 accept\n", "\t\ttcp dport 1-65535 accept\n", `input chain accepts "tcp dport 1-65535"`},
		{"input sends everything to the echo limit", "\t\ticmp type echo-request jump echo_guard\n", "\t\tjump echo_guard\n", `input chain accepts "limit rate 20/second burst 40 packets"`},
		{"input accepts nine chains down", inputStart, inputStart + chained(9), "input chain accepts every packet"},
		{"input jumps deeper than nft allows", inputStart, inputStart + chained(nftMaxJumps+2), "more chains than this check follows"},
		{"input accepts in an inline chain", inputStart, inputStart + "\t\tjump {\n\t\t\taccept\n\t\t}\n", "input chain decides through an inline chain"},
		{"input is a NAT chain", inputStart, "\t\ttype nat hook input priority filter; policy drop;\n", "input chain is not a filter chain"},
		{"forward accepts each address family", forwardStart, forwardStart + "\t\tmeta nfproto ipv4 accept\n\t\tmeta nfproto ipv6 accept\n", `forward chain accepts "meta nfproto ipv4"`},
		{"forward accepts a named port", forwardStart, forwardStart + "\t\ttcp dport 443 accept\n", `forward chain accepts "tcp dport 443"`},
		{"output is a NAT chain", "type filter hook output priority filter; policy accept;", "type nat hook output priority filter; policy accept;", "output chain is not a filter chain"},
		{"a NAT chain here rewrites the edge's connections", "\tchain output {\n", "\tchain natout {\n\t\ttype nat hook output priority srcnat; policy accept;\n\t\tmeta skuid 990 tcp dport 443 dnat ip to 10.0.0.5\n\t}\n\n\tchain output {\n", "NAT chain natout in table inet carnical"},
		{"a NAT chain at the filter's own priority may run after it", "table inet carnical {\n", "table ip natx {\n\tchain o {\n\t\ttype nat hook output priority filter; policy accept;\n\t}\n}\ntable inet carnical {\n", "NAT chain o in table ip natx"},
		{"another table's NAT chain rewrites them", "table inet carnical {\n", "table ip natx {\n\tchain o {\n\t\ttype nat hook output priority 100; policy accept;\n\t\tmeta skuid 990 dnat to 10.0.0.5\n\t}\n}\ntable inet carnical {\n", "NAT chain o in table ip natx"},
		{"another table rewrites the destination after the filter", carnicalTable, other("inet x", "filter hook output priority 100", rewrite, ""), `changed after the filter has passed them: "meta skuid 990 tcp dport 443 ip daddr set 10.0.0.5" in chain late of table inet x`},
		{"a rewrite at the filter's own priority may run after it", carnicalTable, other("ip x", "filter hook output priority filter", rewrite, ""), "in chain late of table ip x"},
		{"a rewrite at a priority this check cannot read", carnicalTable, other("ip x", "filter hook output priority somewhere", rewrite, ""), "in chain late of table ip x"},
		{"a rewrite at a priority this check cannot read, with a filter that runs late", "\tchain output {\n\t\ttype filter hook output priority filter; policy accept;\n",
			"\tchain late {\n\t\ttype filter hook output priority somewhere; policy accept;\n" + rewrite + "\t}\n\n\tchain output {\n\t\ttype filter hook output priority 10; policy accept;\n", "in chain late of table inet carnical"},
		{"a rewrite in the carnical table when another table is listed first", carnicalTable,
			"table ip first {\n\tchain c {\n\t\tcounter\n\t}\n}\ntable inet carnical {\n\tchain late {\n\t\ttype filter hook postrouting priority filter; policy accept;\n" + rewrite + "\t}\n\n", "in chain late of table inet carnical"},
		{"a rewrite in a route chain after the filter", carnicalTable, other("ip x", "route hook output priority 50", rewrite, ""), "in chain late of table ip x"},
		{"a rewrite on the way out", carnicalTable, other("ip x", "filter hook postrouting priority raw", rewrite, ""), "in chain late of table ip x"},
		{"a rewrite in a chain the later one jumps to", carnicalTable, other("inet x", "filter hook output priority 100", "\t\tmeta skuid 990 jump away\n", "\n\tchain away {\n"+rewrite+"\t}\n"), "in chain away of table inet x"},
		{"a rewrite in a chain the later one goes to", carnicalTable, other("inet x", "filter hook postrouting priority 100", "\t\tgoto away\n", "\n\tchain away {\n\t\tjump further\n\t}\n\n\tchain further {\n"+rewrite+"\t}\n"), "in chain further of table inet x"},
		{"a rewrite behind a verdict map", carnicalTable, other("inet x", "filter hook output priority 100", "\t\ttcp dport vmap { 443 : jump away }\n", "\n\tchain away {\n"+rewrite+"\t}\n"), "in chain away of table inet x"},
		{"a rewrite behind a verdict map of the table", carnicalTable, other("inet x", "filter hook output priority 100", "\t\ttcp dport vmap @byport\n", "\n\tmap byport {\n\t\ttype inet_service : verdict\n\t\telements = { 80 : jump count,\n\t\t\t     443 : goto away }\n\t}\n\n\tchain count {\n\t\tcounter\n\t}\n\n\tchain away {\n"+rewrite+"\t}\n"), "in chain away of table inet x"},
		{"a rewrite behind a verdict map filled from elsewhere", carnicalTable, other("inet x", "filter hook output priority 100", "\t\ttcp dport vmap @later\n", "\n\tmap later {\n\t\ttype inet_service : verdict\n\t}\n\n\tchain hidden {\n"+rewrite+"\t}\n"), "in chain hidden of table inet x"},
		{"a rewrite behind a verdict map this table does not have", carnicalTable, other("inet x", "filter hook output priority 100", "\t\ttcp dport vmap @gone\n", "\n\tchain hidden {\n"+rewrite+"\t}\n"), "in chain hidden of table inet x"},
		{"a rewrite behind the first chain a verdict map names", carnicalTable, other("inet x", "filter hook output priority 100", "\t\ttcp dport vmap { 80 : goto away, 443 : jump count }\n", "\n\tchain count {\n\t\tcounter\n\t}\n\n\tchain away {\n"+rewrite+"\t}\n"), "in chain away of table inet x"},
		{"a rewrite in a chain an inline chain jumps to", carnicalTable, other("inet x", "filter hook output priority 100", "\t\tmeta skuid 990 jump {\n\t\t\ttcp dport 443 jump away\n\t\t}\n", "\n\tchain away {\n"+rewrite+"\t}\n"), "in chain away of table inet x"},
		{"a rewrite in an inline chain", carnicalTable, other("inet x", "filter hook output priority 100", "\t\tmeta skuid 990 jump {\n\t\t\tip daddr set 10.0.0.5\n\t\t}\n", ""), "in chain late of table inet x"},
		{"the port rewritten after the filter", carnicalTable, other("inet x", "filter hook output priority 100", "\t\tmeta skuid 990 tcp dport set 5432\n", ""), "in chain late of table inet x"},
		{"the IPv6 destination rewritten after the filter", carnicalTable, other("ip6 x", "filter hook postrouting priority filter", "\t\tip6 daddr set fd00::5\n", ""), "in chain late of table ip6 x"},
		{"the header's bytes rewritten after the filter", carnicalTable, other("ip x", "filter hook postrouting priority filter", "\t\t@nh,128,32 set 0x0a000005\n", ""), "in chain late of table ip x"},
		{"a copy sent to another machine", carnicalTable, other("ip x", "filter hook postrouting priority filter", "\t\tmeta skuid 990 dup to 10.0.0.5\n", ""), "in chain late of table ip x"},
		{"packets handed to a program after the filter", carnicalTable, other("inet x", "filter hook output priority 100", "\t\tmeta skuid 990 queue flags bypass to 3\n", ""), "in chain late of table inet x"},
		{"the frame's destination rewritten on the card", carnicalTable, other("netdev x", "filter hook egress device \"eth0\" priority filter", "\t\tether daddr set 02:00:00:00:00:05\n", ""), "in chain late of table netdev x"},
		{"packets sent out of another card", carnicalTable, other("netdev x", "filter hook egress device \"eth0\" priority filter", "\t\tfwd to \"tap0\"\n", ""), "in chain late of table netdev x"},
		{"packets sent to another machine from the card", carnicalTable, other("netdev x", "filter hook egress device \"eth0\" priority filter", "\t\tfwd ip to 10.0.0.5 device \"tap0\"\n", ""), "in chain late of table netdev x"},
		{"a rewrite inside the edge's chain, after its blocks", "\t\ttcp dport { 80, 443 } accept\n", "\t\tip daddr set 10.0.0.5\n\t\ttcp dport { 80, 443 } accept\n", `"ip daddr set 10.0.0.5" in chain edge_out of table inet carnical`},
		{"a rewrite in the output chain itself", edgeJump, "\t\tmeta skuid 990 tcp dport 443 tcp dport set 5432\n" + edgeJump, "in chain output of table inet carnical"},
		{"a rewrite on a bridge's way out", carnicalTable, other("bridge x", "filter hook postrouting priority 0", "\t\tether daddr set 02:00:00:00:00:05\n", ""), "in chain late of table bridge x"},
		{"a chain in the carnical table rewrites after the filter", "\tchain output {\n", "\tchain late {\n\t\ttype filter hook postrouting priority filter; policy accept;\n" + rewrite + "\t}\n\n\tchain output {\n", "in chain late of table inet carnical"},
		{"a set's comment names the missing range", "\t\telements = { 0.0.0.0/8, 10.0.0.0/8,\n", "\t\tcomment \"elements = { 10.0.0.0/8 }\"\n\t\telements = { 0.0.0.0/8,\n", "do not include 10.0.0.0/8"},
		{"Azure's platform address left out", "\t\t\t     168.63.129.16, 169.254.0.0/16,\n", "\t\t\t     169.254.0.0/16,\n", "do not include 168.63.129.16"},
		{"the table is dormant", "table inet carnical {\n", "table inet carnical {\n\tflags dormant\n", "dormant"},
		{"private IPv4 destinations accepted", `ip daddr @not_public4 counter name "egress_private_drop" jump edge_private_drop`, "ip daddr @not_public4 accept", "lets private IPv4"},
		{"private IPv6 destinations accepted", `ip6 daddr @not_public6 counter name "egress_private_drop" jump edge_private_drop`, "ip6 daddr @not_public6 accept", "lets private IPv6"},
		{"this machine accepted", "fib daddr type local counter packets 0 bytes 0 jump edge_self_drop", "fib daddr type local accept", "lets this machine's own"},
		{"the block's chain accepts", "log prefix \"carnical-edge-private \"\n\t\tdrop\n", "log prefix \"carnical-edge-private \"\n\t\taccept\n", "lets private IPv4"},
		{"an accept ahead of the blocks", "tcp dport 53 accept\n", "tcp dport 53 accept\n\t\tip daddr 10.0.0.0/8 tcp dport 5432 accept\n", "ahead of the edge's blocks"},
		{"a jump ahead of the blocks", "tcp dport 53 accept\n", "tcp dport 53 accept\n\t\tjump input\n", "ahead of the edge's blocks"},
		{"an accept ahead of the blocks that names port 53 in a comment", edgeStart, edgeStart + "\t\tip daddr 10.0.0.0/8 accept comment \"dport 53\"\n", "ahead of the edge's blocks"},
		{"a port range from 53 ahead of the blocks", edgeStart, edgeStart + "\t\ttcp dport 53-65535 accept\n", "ahead of the edge's blocks"},
		{"a named verdict map ahead of the blocks", edgeStart, "\tmap bypass {\n\t\ttype ipv4_addr : verdict\n\t\tflags interval\n\t\telements = { 10.0.0.0/8 : accept }\n\t}\n\n" + edgeStart + "\t\tip daddr vmap @bypass\n", "ahead of the edge's blocks"},
		{"an inline chain ahead of the blocks", edgeStart, edgeStart + "\t\tjump {\n" + inline, "ahead of the edge's blocks"},
		{"name lookups to a whole set ahead of the blocks", edgeStart, edgeStart + "\t\tip daddr @not_public4 tcp dport 53 accept\n", "ahead of the edge's blocks"},
		{"name lookups to a range ahead of the blocks", edgeStart, edgeStart + "\t\tip daddr 10.0.0.0/8 udp dport 53 accept\n", "ahead of the edge's blocks"},
		{"the block's chain accepts in an inline chain", "log prefix \"carnical-edge-private \"\n\t\tdrop\n", "log prefix \"carnical-edge-private \"\n\t\tjump {\n" + inline + "\t\tdrop\n", "lets private IPv4"},
		{"the private block narrowed to one port", privateBlock, `ip daddr @not_public4 tcp dport 22 counter name "egress_private_drop" jump edge_private_drop`, "block on private IPv4 destinations does not cover"},
		{"the private block on the source", privateBlock, `ip saddr @not_public4 counter name "egress_private_drop" jump edge_private_drop`, "block on private IPv4 destinations does not cover"},
		{"the edge's chain does not end in a drop", "\t\tcounter name \"egress_edge_drop\" jump edge_egress_drop\n", "", "edge's chain does not end"},
		{"a verdict map after the blocks", "tcp dport { 80, 443 } accept", "tcp dport vmap { 80 : accept, 443 : accept }", "after the edge's blocks"},
		{"every connection accepted after the blocks", "\t\ttcp dport { 80, 443 } accept\n", "\t\ttcp dport { 80, 443 } accept\n\t\tcounter accept\n", `after the edge's blocks lets connections out in a way this check does not recognise: "counter accept"`},
		{"a return after the blocks", "\t\ttcp dport { 80, 443 } accept\n", "\t\treturn\n", "after the edge's blocks"},
		{"a range of ports after the blocks", "tcp dport { 80, 443 } accept", "tcp dport 1-65535 accept", "after the edge's blocks"},
		{"every port to one address after the blocks", "\t\ttcp dport { 80, 443 } accept\n", "\t\tip daddr 192.0.2.10 accept\n", "after the edge's blocks"},
		{"every address but one after the blocks", "\t\ttcp dport { 80, 443 } accept\n", "\t\tip daddr != 192.0.2.10 tcp dport 25 accept\n", "after the edge's blocks"},
		{"a jump after the blocks to a chain that accepts", "\t\ttcp dport { 80, 443 } accept\n", "\t\tjump echo_guard\n", "after the edge's blocks"},
		{"an inline chain after the blocks", "\t\ttcp dport { 80, 443 } accept\n", "\t\tjump {\n" + inline, "after the edge's blocks"},
		{"the internal chain does not end in a drop", "\t\tcounter name \"egress_internal_drop\" jump internal_egress_drop\n", "", "internal services' chain does not end"},
		{"the metadata service accepted", `ip daddr 169.254.169.254 meta skuid != 0 counter name "egress_imds_drop" jump imds_drop`, "ip daddr 169.254.169.254 accept", "metadata service"},
		{"the IPv6 metadata service accepted", `ip6 daddr fd00:ec2::254 meta skuid != 0 counter name "egress_imds_drop" jump imds_drop`, "ip6 daddr fd00:ec2::254 accept", "metadata service (fd00:ec2::254)"},
		{"the metadata block narrowed to one user", `ip daddr 169.254.169.254 meta skuid != 0 counter`, `ip daddr 169.254.169.254 meta skuid 1000 counter`, "metadata service (169.254.169.254)"},
		{"the edge accepted before its chain", edgeJump, "\t\tmeta skuid 990 accept\n" + edgeJump, "ahead of the edge's chain"},
		{"an inline chain before the edge's chain", edgeJump, "\t\tmeta skuid 990 jump {\n" + inline + edgeJump, "ahead of the edge's chain"},
		{"a verdict map before the edge's chain", edgeJump, "\t\tmeta skuid 990 ip daddr vmap { 10.0.0.0/8 : accept, 192.0.2.1 : drop }\n" + edgeJump, "ahead of the edge's chain"},
		{"another user sent to the edge's chain", edgeJump, "\t\tmeta skuid 12345 jump edge_out\n", "not sent to its chain"},
		{"the edge sent to its chain for one port", edgeJump, "\t\tmeta skuid 990 tcp dport 9 jump edge_out\n", "not sent to its chain"},
		{"the internal services sent nowhere", "jump internal_out", "accept", "jump internal_out"},
		{"the internal services sent to their chain for one port", internalJump, "\t\tmeta skuid { 991, 992, 993, 994 } tcp dport 9 jump internal_out\n", "jump internal_out"},
		{"an internal service accepted before their chain", internalJump, "\t\tmeta skuid 991 accept\n" + internalJump, "ahead of the internal services' chain"},
		{"another user sent to the internal chain", internalJump, "\t\tmeta skuid 65000 jump internal_out\n", "jump internal_out"},
		{"one internal service left out", internalJump, "\t\tmeta skuid { 991, 992, 993 } jump internal_out\n", "jump internal_out"},
		{"the internal chain accepts first", "\tchain internal_out {\n", "\tchain internal_out {\n\t\taccept\n", "internal services' chain lets connections out"},
		{"the internal chain looks names up elsewhere", "\t\tip daddr { 127.0.0.53, 127.0.0.54 } udp dport 53 accept\n\t\tcounter name \"egress_internal_drop\"", "\t\tip daddr 8.8.8.8 udp dport 53 accept\n\t\tcounter name \"egress_internal_drop\"", "internal services' chain lets connections out"},
		{"the internal chain returns", "\tchain internal_out {\n", "\tchain internal_out {\n\t\ttcp dport 25 return\n", "internal services' chain lets connections out"},
		{"a private IPv4 range dropped", " 10.0.0.0/8,", "", "do not include 10.0.0.0/8"},
		{"IPv6 loopback dropped", "\t\t\t     ::1,\n", "", "do not include ::1"},
		{"no carnical table", "table inet carnical {", "table inet other {", "no carnical table"},
	} {
		t.Run("fails: "+tt.name, func(t *testing.T) {
			r := run(NFT(m(edit(t, tt.old, tt.new))))
			if r.Status != audit.Fail || !strings.Contains(strings.Join(r.Problems, "\n"), tt.says) {
				t.Fatalf("want a failure saying %q: %+v", tt.says, r)
			}
		})
	}
	if r := run(NFT(m(""))); r.Status != audit.Fail {
		t.Fatalf("nothing loaded: %+v", r)
	}

	// nft lists names and strings as they are, so the listing is read only when nft -j shows none that could be misread.
	withJSON := func(objects ...string) string {
		return strings.Replace(goodJSON, `{"nftables": [`, `{"nftables": [`+strings.Join(objects, ", ")+", ", 1)
	}
	edgeRule := func(fields string) string {
		return `{"rule": {"family": "inet", "table": "carnical", "chain": "edge_out", "handle": 91, ` + fields + `}}`
	}
	for _, tt := range []struct{ name, js string }{
		{"a comment with spaces, braces and another script", withJSON(edgeRule(`"comment": "public {80, 443} only, édge", "expr": [{"accept": null}]`))},
		{"names with dashes, dots and slashes", withJSON(`{"chain": {"family": "inet", "table": "carnical", "name": "service-ULMVA6XW-default/kubernetes/tcp/https", "handle": 90}}`,
			`{"set": {"family": "inet", "name": "kube.cluster-ips", "table": "carnical", "type": "ipv4_addr", "handle": 92}}`)},
	} {
		t.Run("passes: "+tt.name, func(t *testing.T) {
			if r := run(NFT(both(good, tt.js))); r.Status != audit.Pass {
				t.Fatalf("%+v", r)
			}
		})
	}
	long := strings.Repeat("a", 70)
	for _, tt := range []struct{ name, js, says string }{
		{"a chain named with a space", withJSON(`{"chain": {"family": "inet", "table": "carnical", "name": "x drop", "handle": 90}}`), `name with a space, quote, brace, comma, semicolon, # or control character, which nft lists as it is, so the listing can be misread: "x drop"`},
		{"a jump to a name with a brace", withJSON(edgeRule(`"expr": [{"jump": {"target": "b}c"}}]`)), `misread: "b}c"`},
		{"a table named with #", withJSON(`{"table": {"family": "ip", "name": "t#1", "handle": 9}}`), `misread: "t#1"`},
		{"a device list with a comma", withJSON(`{"flowtable": {"family": "inet", "name": "f", "table": "carnical", "hook": "ingress", "prio": 0, "dev": ["eth0", "a,b"]}}`), `misread: "a,b"`},
		{"a comment with a quote", withJSON(edgeRule(`"comment": "q\"} accept", "expr": [{"accept": null}]`)), `string with a quote or control character, which nft lists as it is, so the listing can be misread: "q\"} accept"`},
		{"a comment with a line break", withJSON(edgeRule(`"comment": "line\nbreak", "expr": [{"accept": null}]`)), `misread: "line\nbreak"`},
		{"a log prefix with a quote", withJSON(edgeRule(`"expr": [{"log": {"prefix": "p\" drop"}}, {"accept": null}]`)), `misread: "p\" drop"`},
		{"an interface name with a quote", withJSON(edgeRule(`"expr": [{"match": {"op": "==", "left": {"meta": {"key": "iifname"}}, "right": "e\"} x"}}, {"accept": null}]`)), `misread: "e\"} x"`},
		{"a long comment, cut", withJSON(edgeRule(`"comment": "` + long + `\"", "expr": [{"accept": null}]`)), `misread: "` + long[:64] + `..."`},
		{"nft prints something that is not JSON", "nftables: {", "JSON listing could not be read"},
	} {
		t.Run("fails: "+tt.name, func(t *testing.T) {
			r := run(NFT(both(good, tt.js)))
			if r.Status != audit.Fail || !strings.Contains(strings.Join(r.Problems, "\n"), tt.says) {
				t.Fatalf("want a failure saying %q: %+v", tt.says, r)
			}
		})
	}
	t.Run("fails: nft cannot list as JSON", func(t *testing.T) {
		f := m(good)
		delete(f.runs, "nft -j list ruleset")
		if r := run(NFT(f)); r.Status != audit.Fail || !strings.Contains(strings.Join(r.Problems, "\n"), "could not list the ruleset as JSON") {
			t.Fatalf("%+v", r)
		}
	})
	// A chain named "x drop" lists as `jump x drop`, which reads as a drop that ends input's checks before an accept.
	t.Run("fails: a chain named like a drop, as nft really lists it", func(t *testing.T) {
		listing := strings.Replace(edit(t, inputStart, inputStart+"\t\tjump x drop\n\t\taccept\n"), edgeStart, "\tchain x drop {\n\t\taccept\n\t}\n\n"+edgeStart, 1)
		js := withJSON(`{"chain": {"family": "inet", "table": "carnical", "name": "x drop", "handle": 90}}`,
			`{"rule": {"family": "inet", "table": "carnical", "chain": "input", "handle": 93, "expr": [{"jump": {"target": "x drop"}}]}}`)
		if r := run(NFT(both(listing, js))); r.Status != audit.Fail || !strings.Contains(strings.Join(r.Problems, "\n"), `misread: "x drop"`) {
			t.Fatalf("%+v", r)
		}
	})
	t.Run("at most ten names are reported", func(t *testing.T) {
		var chains []string
		for i := range 12 {
			chains = append(chains, fmt.Sprintf(`{"chain": {"family": "inet", "table": "carnical", "name": "x %d", "handle": %d}}`, i, 100+i))
		}
		if r := run(NFT(both(good, withJSON(chains...)))); r.Status != audit.Fail || len(r.Problems) != 10 {
			t.Fatalf("want ten problems: %+v", r)
		}
	})
}

// TestNFTListingMatchesTheRulesetFile keeps the listing above, and the ranges the check asks for, tied to the shipped file.
func TestNFTListingMatchesTheRulesetFile(t *testing.T) {
	file, ok := parseNFTTable(readLF(t, "..", "..", "deploy", "nftables", "carnical.nft"), "inet", "carnical")
	listing, ok2 := parseNFTTable(readLF(t, "testdata", "nft-ruleset.txt"), "inet", "carnical")
	if !ok || !ok2 {
		t.Fatalf("the ruleset file has the table: %t; the listing has it: %t", ok, ok2)
	}
	if len(file.chains) != len(listing.chains) {
		t.Errorf("the ruleset file has %d chains and the listing %d: regenerate the listing", len(file.chains), len(listing.chains))
	}
	for name, c := range file.chains {
		l := listing.chains[name]
		if l == nil || len(l.rules) != len(c.rules) || l.hook != c.hook || l.policy != c.policy {
			t.Errorf("chain %s differs between the ruleset file and the listing: regenerate the listing", name)
		}
	}
	// The JSON listing is of the same ruleset: the same rules in the same chains.
	var js struct {
		Nftables []struct {
			Rule *struct{ Table, Chain string }
		}
	}
	if err := json.Unmarshal([]byte(readLF(t, "testdata", "nft-ruleset.json")), &js); err != nil {
		t.Fatal(err)
	}
	rules := map[string]int{}
	for _, o := range js.Nftables {
		if o.Rule != nil && o.Rule.Table == "carnical" {
			rules[o.Rule.Chain]++
		}
	}
	for name, c := range listing.chains {
		if rules[name] != len(c.rules) {
			t.Errorf("chain %s has %d rules in the JSON listing and %d in the listing: regenerate both", name, rules[name], len(c.rules))
		}
	}
	internal := nftUsers{}
	for _, u := range InternalUsers {
		internal.internal = append(internal.internal, []string{strconv.Quote(u)})
	}
	sent := false
	for _, r := range file.chains["output"].rules {
		if kind, target, before := verdict(r); kind == "jump" && target == "internal_out" {
			sent = internal.internalSet(conditions(before))
		}
	}
	if !sent {
		t.Errorf("the ruleset file does not send exactly %v to internal_out", InternalUsers)
	}
	for set, want := range map[string][]string{"not_public4": PrivateRanges4, "not_public6": PrivateRanges6} {
		_, elements, _ := strings.Cut(file.sets[set], "elements = {")
		var got []string
		for _, e := range strings.FieldsFunc(elements, func(r rune) bool { return r == ',' || r == ' ' || r == '}' }) {
			got = append(got, strings.TrimSuffix(e, "/128"))
		}
		sort.Strings(got)
		w := append([]string(nil), want...)
		sort.Strings(w)
		if strings.Join(got, " ") != strings.Join(w, " ") {
			t.Errorf("%s in the ruleset file is %v; the check asks for %v", set, got, w)
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
	// What auditctl -l really prints: a watch's key as -k, a system call rule's as -F key=.
	var listed strings.Builder
	for _, k := range AuditKeys {
		listed.WriteString("-a always,exit -F arch=b64 -S execve -F auid>=1000 -F key=" + k + "\n")
	}
	listed.WriteString("-w /etc/shadow -p wa -k carnical_honey\n")
	if r := run(Auditd(m("enabled 2\n", listed.String()))); r.Status != audit.Pass {
		t.Fatalf("rules as auditctl lists them: %+v", r)
	}
	// A key that only begins like the one wanted is not it.
	if r := run(Auditd(m("enabled 2\n", strings.ReplaceAll(rules.String(), "-k carnical_abuse\n", "-k carnical_abuse_old\n")))); r.Status != audit.Fail {
		t.Fatalf("a longer key: %+v", r)
	}
	// Every key must be in the rules file.
	file, _ := os.ReadFile(filepath.Join("..", "..", "deploy", "auditd", "carnical.rules"))
	for _, k := range AuditKeys {
		if !strings.Contains(string(file), "-k "+k) {
			t.Errorf("the check looks for the key %s, which the rules file does not set", k)
		}
	}
	// A system call name auditctl does not know stops the whole file loading, the lock included. These are the names, as
	// audit-userspace's own tables spell them, that each architecture a rule can name is known to have (b64 means
	// whichever 64-bit table the machine runs: x86_64 or aarch64, so only names both have). Numbers are always accepted.
	both := "execve execveat ptrace process_vm_readv process_vm_writev memfd_create bpf unshare setns init_module " +
		"finit_module delete_module kexec_load fchmod fchmodat"
	known := map[string]string{"b64": both, "x86_64": both + " chmod",
		"i386": "execve execveat ptrace process_vm_readv process_vm_writev memfd_create bpf unshare setns init_module " +
			"finit_module delete_module fchmod fchmodat chmod"}
	calls := regexp.MustCompile(`-F arch=(\S+) -S (\S+)`)
	syscallRules := 0
	for _, line := range strings.Split(string(file), "\n") {
		if !strings.HasPrefix(line, "-a ") {
			continue
		}
		m := calls.FindStringSubmatch(line)
		if m == nil {
			t.Errorf("a rule without an architecture before its system calls: %s", line)
			continue
		}
		syscallRules++
		names, ok := known[m[1]]
		if !ok {
			t.Errorf("an architecture this test does not know: %s", line)
		}
		for _, name := range strings.Split(m[2], ",") {
			if _, err := strconv.Atoi(name); err != nil && !slices.Contains(strings.Fields(names), name) {
				t.Errorf("%s may not be known to auditctl for %s (write it by number): %s", name, m[1], line)
			}
		}
	}
	if syscallRules == 0 {
		t.Error("no system call rules found in the rules file")
	}
	// Every call that can set a setuid bit, in each table the rules name (aarch64 has no chmod; fchmodat2 is written as 452).
	for _, want := range []string{"arch=b64 -S fchmod -F a1&06000", "arch=b64 -S fchmodat,452 -F a2&06000", "arch=x86_64 -S chmod -F a1&06000",
		"arch=i386 -S chmod,fchmod -F a1&06000", "arch=i386 -S fchmodat,452 -F a2&06000"} {
		if !strings.Contains(string(file), want) {
			t.Errorf("the rules file does not audit %q", want)
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
	for _, tt := range []struct {
		name     string
		mode     fs.FileMode
		link     string
		contains string
	}{
		{"setuid root program", fs.ModeSetuid | 0o755, "", "/usr/local/bin/carnical has mode 4755, more than 0755"},
		{"setgid program", fs.ModeSetgid | 0o755, "", "has mode 2755"},
		{"a link in place of the program", 0o755, "/home/someone/carnical", "/usr/local/bin/carnical is a symbolic link (to /home/someone/carnical)"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			f := &fake{files: map[string]string{"/etc/passwd": passwd}, links: map[string]string{}, stats: map[string]Info{
				"/usr/local/bin/carnical": {Mode: tt.mode, UID: 0}, "/var/lib/carnical/edge": {Mode: fs.ModeDir | 0o700, UID: 990},
			}}
			if tt.link != "" {
				f.links["/usr/local/bin/carnical"] = tt.link
			}
			if r := run(Ownership(f, rules)); r.Status != audit.Fail || !strings.Contains(strings.Join(r.Problems, "\n"), tt.contains) {
				t.Fatalf("%+v", r)
			}
		})
	}
}

// Every directory tmpfiles.d makes is one the ownership check looks at, with the same owner and mode.
func TestOwnershipCoversTheDirectoriesTmpfilesMakes(t *testing.T) {
	want := map[string]FileRule{}
	for _, r := range Files {
		want[r.Path] = r
	}
	for _, line := range strings.Split(readLF(t, "..", "..", "deploy", "tmpfiles.d", "carnical.conf"), "\n") {
		f := strings.Fields(line)
		if len(f) < 4 || f[0] != "d" {
			continue
		}
		mode, err := strconv.ParseUint(f[2], 8, 32)
		if err != nil {
			t.Fatalf("%q: %v", line, err)
		}
		r, ok := want[f[1]]
		switch {
		case !ok:
			t.Errorf("tmpfiles.d makes %s, which the ownership check does not look at", f[1])
		case r.Owner != f[3] || uint32(r.MaxMode) != uint32(mode):
			t.Errorf("%s: tmpfiles.d says %s %04o, the check %s %04o", f[1], f[3], mode, r.Owner, uint32(r.MaxMode))
		}
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
	// A line that is cut short is not passed over: it could be the listener.
	for _, bad := range []string{
		"h\n 0: 0100007F:1F90 00000000:0000 0A\n",
		"h\n 0: 0100007F:1F90 00000000:0000 0A 0:0 0:0 0 root 0 1 1 0 100 0\n", // an owner that is no number
		"h\n 0: 0100007F 00000000:0000 0A 0:0 0:0 0 1000 0 1 1 0 100 0\n",      // an address with no port
	} {
		if ls, err := ParseNetTCP([]byte(bad), false); err == nil {
			t.Fatalf("%q was read as %+v", bad, ls)
		}
	}
	if ls, err := ParseNetTCP([]byte("h\n\n"), false); err != nil || len(ls) != 0 {
		t.Fatalf("an empty line: %v %+v", err, ls)
	}
}

func TestParseNetUDP(t *testing.T) {
	// A real /proc/net/udp: the stub resolver on 127.0.0.53:53 (uid 992), a DHCP client on 0.0.0.0:68 (root), and a
	// socket connected to 192.0.2.1:53, which hears only that peer. The last line names a peer port and no peer address:
	// it would hear every address that sends from that port, so it is not left out.
	data := `   sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode ref pointer drops
  512: 3500007F:0035 00000000:0000 07 00000000:00000000 00:00000000 00000000   992        0 11111 2 0000000000000000 0
  580: 00000000:0044 00000000:0000 07 00000000:00000000 00:00000000 00000000     0        0 22222 2 0000000000000000 0
 4021: 0A00000A:D2C4 010200C0:0035 01 00000000:00000000 00:00000000 00000000   990        0 33333 2 0000000000000000 0
 4030: 00000000:1388 00000000:0035 01 00000000:00000000 00:00000000 00000000   990        0 44444 2 0000000000000000 0
`
	ls, err := ParseNetUDP([]byte(data), false)
	if err != nil || len(ls) != 3 {
		t.Fatalf("%v %+v", err, ls)
	}
	if ls[0] != (Listener{Addr: netip.MustParseAddr("127.0.0.53"), Port: 53, UID: 992}) {
		t.Fatalf("%+v", ls[0])
	}
	if ls[1] != (Listener{Addr: netip.MustParseAddr("0.0.0.0"), Port: 68, UID: 0}) {
		t.Fatalf("%+v", ls[1])
	}
	if ls[2] != (Listener{Addr: netip.MustParseAddr("0.0.0.0"), Port: 5000, UID: 990}) {
		t.Fatalf("%+v", ls[2])
	}
	// IPv6: a DHCPv6 client on [::]:546, a socket connected to [2001:db8::1]:53, and one connected to port 0 of a peer.
	v6 := `   sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode ref pointer drops
  546: 00000000000000000000000000000000:0222 00000000000000000000000000000000:0000 07 00000000:00000000 00:00000000 00000000   998        0 1 2 0000000000000000 0
 4022: 00000000000000000000000001000000:D2C5 B80D0120000000000000000001000000:0035 01 00000000:00000000 00:00000000 00000000   990        0 2 2 0000000000000000 0
 4023: 00000000000000000000000001000000:D2C6 B80D0120000000000000000001000000:0000 01 00000000:00000000 00:00000000 00000000   990        0 3 2 0000000000000000 0
`
	ls, err = ParseNetUDP([]byte(v6), true)
	if err != nil || len(ls) != 1 || ls[0] != (Listener{Addr: netip.MustParseAddr("::"), Port: 546, UID: 998}) {
		t.Fatalf("%v %+v", err, ls)
	}
	for _, bad := range []string{
		"h\n 1: 3500007F:0035 00000000 07 0:0 0:0 0 992 0 1 2 0 0\n",       // a peer with no port
		"h\n 1: 3500007F:0035 00000000:0000 07 0:0 0:0 0 root 0 1 2 0 0\n", // an owner that is no number
		"h\n 1: 3500007F 00000000:0000 07 0:0 0:0 0 992 0 1 2 0 0\n",       // an address with no port
		"h\n 1: 3500007F:0035 00000000:0000 07 0:0\n",                      // a line cut short
	} {
		if ls, err := ParseNetUDP([]byte(bad), false); err == nil {
			t.Fatalf("%q was read as %+v", bad, ls)
		}
	}
}

func TestParseSCTPEndpoints(t *testing.T) {
	// A real /proc/net/sctp/eps: a listening socket on 127.0.0.1:9000 (uid 1000), one bound to two addresses, one that
	// is bound and not listening, and one in the middle of an association of its own.
	data := ` ENDPT     SOCK   STY SST HBKT LPORT   UID INODE LADDRS
       0        0 2   10  29   9000   1000 5854707 127.0.0.1
       0        0 2   10  30   9001      0 5854708 10.0.0.5 2001:db8::5
       0        0 2   7   31   9002   1000 5854709 127.0.0.1
       0        0 0   1   32   9003   1000 5854710 127.0.0.1
`
	ls, err := ParseSCTPEndpoints([]byte(data))
	want := []Listener{
		{Addr: netip.MustParseAddr("127.0.0.1"), Port: 9000, UID: 1000},
		{Addr: netip.MustParseAddr("10.0.0.5"), Port: 9001, UID: 0},
		{Addr: netip.MustParseAddr("2001:db8::5"), Port: 9001, UID: 0},
	}
	if err != nil || len(ls) != len(want) {
		t.Fatalf("%v %+v", err, ls)
	}
	for i := range want {
		if ls[i] != want[i] {
			t.Fatalf("%d: %+v, want %+v", i, ls[i], want[i])
		}
	}
	// Every address is read as it would be reached: one written as an IPv4 address inside an IPv6 one is that IPv4 one.
	if ls, err := ParseSCTPEndpoints([]byte("h\n 0 0 2 10 1 9000 0 1 ::ffff:10.0.0.5 :: \n")); err != nil || len(ls) != 2 ||
		ls[0].Addr != netip.MustParseAddr("10.0.0.5") || ls[1].Addr != netip.MustParseAddr("::") {
		t.Fatalf("%v %+v", err, ls)
	}
	for _, bad := range []string{
		"h\n 0 0 2 10 29 9000 1000\n",                    // a line cut short
		"h\n 0 0 2 10 29 9000 1000 5854707\n",            // a listening socket on no address
		"h\n 0 0 2 10 29 90000 1000 5854707 127.0.0.1\n", // a port that is none
		"h\n 0 0 2 10 29 9000 root 5854707 127.0.0.1\n",  // an owner that is no number
		"h\n 0 0 2 10 29 9000 1000 5854707 localhost\n",  // an address that is none
	} {
		if ls, err := ParseSCTPEndpoints([]byte(bad)); err == nil {
			t.Fatalf("%q was read as %+v", bad, ls)
		}
	}
	if ls, err := ParseSCTPEndpoints([]byte("h\n\n")); err != nil || len(ls) != 0 {
		t.Fatalf("an empty line: %v %+v", err, ls)
	}
}

func TestListeners(t *testing.T) {
	needLinux(t)
	tcp := `  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000:01BB 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1 1 0 100 0
   1: 0100007F:20FB 00000000:0000 0A 00000000:00000000 00:00000000 00000000   991        0 2 1 0 100 0
`
	// The stub resolver on 127.0.0.53:53, and the edge's own query to it, which is connected and so is nobody's way in.
	udp := `   sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode ref pointer drops
  512: 3500007F:0035 00000000:0000 07 00000000:00000000 00:00000000 00000000   992        0 3 2 0000000000000000 0
 4021: 0100007F:D2C4 3500007F:0035 01 00000000:00000000 00:00000000 00000000   990        0 4 2 0000000000000000 0
`
	passwd := "root:x:0:0::/root:/bin/sh\ncarnical-edge:x:990:990::/:/bin/false\ncarnical-ctl:x:991:991::/:/bin/false\n" +
		"systemd-resolve:x:992:992::/:/bin/false\n"
	m := &fake{files: map[string]string{"/proc/net/tcp": tcp, "/proc/net/udp": udp, "/etc/passwd": passwd}}
	declared := []audit.Service{
		{Name: "edge", Addr: "0.0.0.0:443", User: "root,carnical-edge"}, // 0x01BB = 443; socket activation makes root the owner
		{Name: "ctl", Addr: "127.0.0.1:8443", User: "carnical-ctl"},     // 0x20FB = 8443
		{Name: "resolver", Addr: "127.0.0.53:53", Proto: "udp", User: "systemd-resolve"},
	}
	if r := run(Listeners(m, declared)); r.Status != audit.Pass || r.Checked != 3 {
		t.Fatalf("%+v", r)
	}
	tests := []struct {
		name     string
		declared []audit.Service
		contains string
	}{
		{"an undeclared listener", []audit.Service{declared[0], declared[2]}, "127.0.0.1:8443 is listening, owned by carnical-ctl, and is not in the zone map"},
		{"owned by the wrong user", []audit.Service{declared[0], declared[2], {Name: "ctl", Addr: "127.0.0.1:8443", User: "carnical-edge"}}, "owned by carnical-ctl, but ctl is declared to be run by carnical-edge"},
		{"wider than declared", []audit.Service{declared[0], declared[2], {Name: "ctl", Addr: "10.0.0.5:8443", User: "carnical-ctl"}}, "it listens on 127.0.0.1, but 10.0.0.5:8443 is declared"},
		// A service in another zone, declared by name with no user, says nothing about which socket here is it.
		{"declared by name with no user", []audit.Service{declared[0], declared[2], {Name: "remote-ctl", Addr: "control.internal:8443"}}, "remote-ctl is declared by name with no user"},
		{"an undeclared UDP socket", declared[:2], "127.0.0.53:53 (UDP) takes packets from any sender, owned by systemd-resolve, and is not in the zone map"},
		{"a UDP socket declared as TCP", []audit.Service{declared[0], declared[1], {Name: "resolver", Addr: "127.0.0.53:53", User: "systemd-resolve"}},
			"127.0.0.53:53 (UDP) takes packets from any sender"},
		{"a UDP socket said to be TCP", []audit.Service{declared[0], declared[1], {Name: "resolver", Addr: "127.0.0.53:53", Proto: "tcp", User: "systemd-resolve"}},
			"127.0.0.53:53 (UDP) takes packets from any sender"},
		{"a TCP listener declared as UDP", []audit.Service{declared[0], declared[2], {Name: "ctl", Addr: "127.0.0.1:8443", Proto: "udp", User: "carnical-ctl"}},
			"127.0.0.1:8443 is listening, owned by carnical-ctl, and is not in the zone map"},
		{"a UDP socket owned by the wrong user", []audit.Service{declared[0], declared[1], {Name: "resolver", Addr: "127.0.0.53:53", Proto: "udp", User: "root"}},
			"127.0.0.53:53 (UDP) (systemd-resolve): it is owned by systemd-resolve, but resolver is declared to be run by root"},
		{"a UDP socket on another address than declared", []audit.Service{declared[0], declared[1], {Name: "resolver", Addr: "127.0.0.54:53", Proto: "udp", User: "systemd-resolve"}},
			"127.0.0.53:53 (UDP) (systemd-resolve): it listens on 127.0.0.53, but 127.0.0.54:53 is declared"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := run(Listeners(m, tt.declared))
			if r.Status != audit.Fail || !strings.Contains(strings.Join(r.Problems, "\n"), tt.contains) {
				t.Fatalf("%+v", r)
			}
		})
	}
	// Declared by name with its user, the owner still tells it apart.
	if r := run(Listeners(m, []audit.Service{declared[0], declared[2], {Name: "ctl", Addr: "ctl.internal:8443", User: "carnical-ctl"}})); r.Status != audit.Pass {
		t.Fatalf("declared by name with a user: %+v", r)
	}
	// Declared to listen on one address, found on every address.
	wide := &fake{files: map[string]string{"/proc/net/tcp": strings.Replace(tcp, "0100007F:20FB", "00000000:20FB", 1), "/proc/net/udp": udp, "/etc/passwd": passwd}}
	if r := run(Listeners(wide, declared)); r.Status != audit.Fail || !strings.Contains(strings.Join(r.Problems, "\n"), "listens on every address") {
		t.Fatalf("%+v", r)
	}
	wideUDP := &fake{files: map[string]string{"/proc/net/tcp": tcp, "/proc/net/udp": strings.Replace(udp, "3500007F:0035 00000000:0000", "00000000:0035 00000000:0000", 1), "/etc/passwd": passwd}}
	if r := run(Listeners(wideUDP, declared)); r.Status != audit.Fail || len(r.Problems) != 1 ||
		!strings.Contains(r.Problems[0], "0.0.0.0:53 (UDP) (systemd-resolve): it listens on every address, but 127.0.0.53:53 is declared") {
		t.Fatalf("%+v", r)
	}
	// IPv6 sockets are read too, and written so that the port cannot be taken for part of the address.
	six := &fake{files: map[string]string{"/proc/net/tcp": tcp, "/proc/net/udp": udp, "/etc/passwd": passwd,
		"/proc/net/udp6": "h\n 546: 00000000000000000000000000000000:0222 00000000000000000000000000000000:0000 07 0:0 0:0 0 0 0 1 2 0 0\n"}}
	if r := run(Listeners(six, declared)); r.Status != audit.Fail || len(r.Problems) != 1 ||
		r.Problems[0] != "[::]:546 (UDP) takes packets from any sender, owned by root, and is not in the zone map" {
		t.Fatalf("%+v", r)
	}
	// UDP-Lite is a protocol of its own, with its own ports and its own tables, and any user may open a socket of it. No
	// service answers for one, a UDP service on the same port neither; a connected one is left out as for UDP.
	lite := &fake{files: map[string]string{"/proc/net/tcp": tcp, "/proc/net/udp": udp, "/etc/passwd": passwd,
		"/proc/net/udplite":  "h\n 1871: 0100007F:0035 00000000:0000 07 0:0 0:0 0 990 0 1 2 0 0\n 4069: 0100007F:9DC0 0100007F:0035 01 0:0 0:0 0 990 0 1 2 0 0\n",
		"/proc/net/udplite6": "h\n 1583: 00000000000000000000000001000000:940A 00000000000000000000000000000000:0000 07 0:0 0:0 0 0 0 1 2 0 0\n"}}
	withLite := append(append([]audit.Service{}, declared...), audit.Service{Name: "lite", Addr: "127.0.0.1:53", Proto: "udp", User: "carnical-edge"})
	if r := run(Listeners(lite, withLite)); r.Status != audit.Fail || len(r.Problems) != 2 ||
		r.Problems[0] != "127.0.0.1:53 (UDP-Lite) takes packets from any sender, owned by carnical-edge, and is not in the zone map" ||
		r.Problems[1] != "[::1]:37898 (UDP-Lite) takes packets from any sender, owned by root, and is not in the zone map" {
		t.Fatalf("%+v", r)
	}
	// SCTP is the same to a zone map: any user may listen with it, and no service is declared to. An endpoint that is not
	// listening takes no association, and is left out.
	sctp := &fake{files: map[string]string{"/proc/net/tcp": tcp, "/proc/net/udp": udp, "/etc/passwd": passwd,
		"/proc/net/sctp/eps": "h\n 0 0 2 10 29 8443 991 1 127.0.0.1 \n 0 0 2 7 30 9002 990 2 127.0.0.1 \n 0 0 2 10 31 9001 0 3 10.0.0.5 2001:db8::5 \n"}}
	if r := run(Listeners(sctp, declared)); r.Status != audit.Fail || len(r.Problems) != 3 ||
		r.Problems[0] != "10.0.0.5:9001 (SCTP) is listening, owned by root, and is not in the zone map" ||
		r.Problems[1] != "127.0.0.1:8443 (SCTP) is listening, owned by carnical-ctl, and is not in the zone map" ||
		r.Problems[2] != "[2001:db8::5]:9001 (SCTP) is listening, owned by root, and is not in the zone map" {
		t.Fatalf("%+v", r)
	}
	// A table that is there and cannot be read, or cannot be understood, is a finding, and what the other tables show is
	// still reported: a check that stopped there would hide a listener behind the table it did not read. Only the IPv6,
	// UDP-Lite and SCTP tables may be missing, on a machine that has none of those.
	all := map[string]string{"/proc/net/tcp": tcp, "/proc/net/udp": udp, "/proc/net/tcp6": "h\n", "/proc/net/udp6": "h\n",
		"/proc/net/udplite": "h\n", "/proc/net/udplite6": "h\n", "/proc/net/sctp/eps": "h\n", "/etc/passwd": passwd}
	with := func(path, content string) map[string]string {
		m := map[string]string{}
		for k, v := range all {
			m[k] = v
		}
		if content == "" {
			delete(m, path)
		} else {
			m[path] = content
		}
		return m
	}
	for _, tt := range []struct {
		name  string
		files map[string]string
		deny  string // a file that is there and may not be read
		want  string // "" if nothing but the listener nobody declared is reported
	}{
		{"every table", all, "", ""},
		{"no IPv6, UDP-Lite or SCTP", map[string]string{"/proc/net/tcp": tcp, "/proc/net/udp": udp, "/etc/passwd": passwd}, "", ""},
		{"no UDP table", with("/proc/net/udp", ""), "", "/proc/net/udp cannot be read, so its sockets were not checked"},
		{"a UDP table cut off", with("/proc/net/udp", "h\n 1: 3500007F:0035 0000 07\n 2: 3500007F:0035 00000000 07 0:0 0:0 0 992 0 1 2 0 0\n"), "",
			"/proc/net/udp cannot be read, so its sockets were not checked"},
		{"a UDP table that may not be read", all, "/proc/net/udp", "/proc/net/udp cannot be read, so its sockets were not checked"},
		{"a UDP6 table cut off", with("/proc/net/udp6", "h\n 1: 00:0035 00:0000 07 0:0 0:0 0 0 0 1 2 0 0\n"), "",
			"/proc/net/udp6 cannot be read, so its sockets were not checked"},
		{"a UDP6 table that may not be read", all, "/proc/net/udp6", "/proc/net/udp6 cannot be read, so its sockets were not checked"},
		{"a TCP6 table cut off", with("/proc/net/tcp6", "h\n 1: 00:01BB 00:0000 0A 0:0 0:0 0 0 0 1 1 0 100 0\n"), "",
			"/proc/net/tcp6 cannot be read, so its sockets were not checked"},
		{"a TCP6 table that may not be read", all, "/proc/net/tcp6", "/proc/net/tcp6 cannot be read, so its sockets were not checked"},
		{"a UDP-Lite table cut off", with("/proc/net/udplite", "h\n 1: 0100007F 00000000:0000 07 0:0 0:0 0 990 0 1 2 0 0\n"), "",
			"/proc/net/udplite cannot be read, so its sockets were not checked"},
		{"a UDP-Lite table that may not be read", all, "/proc/net/udplite6", "/proc/net/udplite6 cannot be read, so its sockets were not checked"},
		{"an SCTP table cut off", with("/proc/net/sctp/eps", "h\n 0 0 2 10 29 9000\n"), "", "/proc/net/sctp/eps cannot be read, so its sockets were not checked"},
		{"an SCTP table that may not be read", all, "/proc/net/sctp/eps", "/proc/net/sctp/eps cannot be read, so its sockets were not checked"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var src Source = &fake{files: tt.files}
			if tt.deny != "" {
				src = noRead{Source: src, path: tt.deny}
			}
			// The control service is not declared here: it must be reported whatever else could not be read.
			r := run(Listeners(src, []audit.Service{declared[0], declared[2]}))
			got := strings.Join(r.Problems, "\n")
			if r.Status != audit.Fail || !strings.Contains(got, "127.0.0.1:8443 is listening") {
				t.Fatalf("%+v", r)
			}
			if tt.want == "" && len(r.Problems) != 1 || !strings.Contains(got, tt.want) {
				t.Fatalf("%+v", r)
			}
		})
	}
	// Without the TCP table nothing can be said at all: the check did not run.
	if r := run(Listeners(&fake{files: with("/proc/net/tcp", "")}, declared)); r.Status != audit.Skip {
		t.Fatalf("no TCP table: %+v", r)
	}
}

// noRead is a machine on which one file is there and may not be read.
type noRead struct {
	Source
	path string
}

func (n noRead) ReadFile(p string) ([]byte, error) {
	if p == n.path {
		return nil, &fs.PathError{Op: "open", Path: p, Err: fs.ErrPermission}
	}
	return n.Source.ReadFile(p)
}

func TestRunning(t *testing.T) {
	needLinux(t)
	asRoot(t)
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
	// Not as root under hidepid: other users' processes are simply missing, with nothing unreadable to count. A shell run by
	// the edge would not be seen, so the check must not pass.
	geteuid = func() int { return 1000 }
	if r := run(Running(newMachine(), DefaultProcs)); r.Status != audit.Skip || !strings.Contains(r.Note, "needs root") {
		t.Fatalf("not as root: %+v", r)
	}
	if r := run(Running(newMachine(), ProcPolicy{Services: DefaultProcs.Services, AllowPartial: true})); r.Status != audit.Pass {
		t.Fatalf("not as root, partial allowed: %+v", r)
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

// privateDir is a temporary directory only this user can write, as a baseline directory must be.
func privateDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	return dir
}

// The audit believes its baselines, so it writes them only where no one else can, and refuses one that someone else could
// have changed.
func TestBaselinesAreKeptWhereOnlyTheAuditCanWrite(t *testing.T) {
	needLinux(t)
	dir := privateDir(t)
	manifest, prog := filepath.Join(dir, "integrity.json"), filepath.Join(dir, "carnical")
	if err := os.WriteFile(prog, []byte("the program"), 0o600); err != nil {
		t.Fatal(err)
	}
	// A link planted at the name earlier versions wrote through is left alone, and so is what it points at.
	victim := filepath.Join(t.TempDir(), "victim")
	if err := os.WriteFile(victim, []byte("untouched"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(victim, filepath.Join(dir, ".integrity.json.tmp")); err != nil {
		t.Fatal(err)
	}
	if err := WriteIntegrity(OS{}, manifest, []string{prog}, false); err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(victim); string(got) != "untouched" {
		t.Fatalf("writing the baseline wrote through a planted link: %q", got)
	}
	if r := run(Integrity(OS{}, manifest)); r.Status != audit.Pass {
		t.Fatalf("a private baseline: %+v", r)
	}

	// A directory others can write: nothing is written there, and a baseline found there is not believed.
	if err := os.Chmod(dir, 0o770); err != nil {
		t.Fatal(err)
	}
	if err := WriteIntegrity(OS{}, manifest, []string{prog}, true); err == nil || !strings.Contains(err.Error(), "others could replace") {
		t.Fatalf("a baseline was written to a group-writable directory: %v", err)
	}
	if r := run(Integrity(OS{}, manifest)); r.Status != audit.Fail || !strings.Contains(r.Problems[0], "cannot be trusted") {
		t.Fatalf("a baseline in a group-writable directory: %+v", r)
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(manifest, 0o666); err != nil {
		t.Fatal(err)
	}
	if r := run(Integrity(OS{}, manifest)); r.Status != audit.Fail || !strings.Contains(r.Problems[0], "has mode 0666") {
		t.Fatalf("a world-writable baseline: %+v", r)
	}
	if err := os.Chmod(manifest, 0o600); err != nil {
		t.Fatal(err)
	}
	// Owned by someone else (the segmentation audit's user, say).
	geteuid = func() int { return 4242 }
	defer func() { geteuid = os.Geteuid }()
	if r := run(Integrity(OS{}, manifest)); r.Status != audit.Fail || !strings.Contains(r.Problems[0], "someone other than this audit") {
		t.Fatalf("a baseline owned by another user: %+v", r)
	}
	if err := WriteIntegrity(OS{}, manifest, []string{prog}, true); err == nil || !strings.Contains(err.Error(), "not by this user") {
		t.Fatalf("a baseline was written to another user's directory: %v", err)
	}
	geteuid = os.Geteuid
	link := filepath.Join(privateDir(t), "integrity.json")
	if err := os.Symlink(manifest, link); err != nil {
		t.Fatal(err)
	}
	if r := run(Integrity(OS{}, link)); r.Status != audit.Fail || !strings.Contains(r.Problems[0], "is a symbolic link") {
		t.Fatalf("a baseline reached through a link: %+v", r)
	}
}

// A link whose target the audit cannot see (its own /tmp and /dev are private) is not the same as no file at all.
func TestIntegrityTellsADanglingLinkFromNothing(t *testing.T) {
	needLinux(t)
	dir := privateDir(t)
	manifest, preload := filepath.Join(dir, "integrity.json"), filepath.Join(dir, "ld.so.preload")
	if err := WriteIntegrity(OS{}, manifest, []string{preload}, false); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(dir, "not-visible-here", "evil.so.list"), preload); err != nil {
		t.Fatal(err)
	}
	if r := run(Integrity(OS{}, manifest)); r.Status != audit.Fail || !strings.Contains(r.Problems[0], "did not exist and now does") {
		t.Fatalf("a dangling link where nothing must be: %+v", r)
	}
}

// Reading never blocks on a FIFO and never reads a device: either would stop the audit or fill its memory.
func TestReadFileReadsOnlyRegularFiles(t *testing.T) {
	needLinux(t)
	fifo := filepath.Join(t.TempDir(), "integrity.json")
	if err := mkfifo(fifo); err != nil {
		t.Skipf("no FIFO here: %v", err)
	}
	done := make(chan error, 1)
	go func() { _, err := OS{}.ReadFile(fifo); done <- err }()
	select {
	case err := <-done:
		if err == nil || !strings.Contains(err.Error(), "not a regular file") {
			t.Fatalf("a FIFO: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("reading a FIFO blocked")
	}
	if _, err := (OS{}).ReadFile("/dev/zero"); err == nil || !strings.Contains(err.Error(), "not a regular file") {
		t.Fatalf("a device: %v", err)
	}
}

// TestRunReadsUntranslatedMessages: the setuid scan reads find's errors, so the tools run without the machine's language.
func TestRunReadsUntranslatedMessages(t *testing.T) {
	needLinux(t)
	t.Setenv("LC_ALL", "de_DE.UTF-8")
	out, err := (OS{}).Run(context.Background(), "env")
	if err != nil {
		t.Fatal(err)
	}
	if got := regexp.MustCompile(`(?m)^LC_ALL=.*$`).FindAllString(string(out), -1); len(got) != 1 || got[0] != "LC_ALL=C" {
		t.Fatalf("the tool saw %q", got)
	}
}

func TestSUIDRoots(t *testing.T) {
	mounts := `/dev/sda1 / ext4 rw,relatime 0 0
proc /proc proc rw,nosuid,nodev,noexec 0 0
/dev/sda2 /home ext4 rw,relatime 0 0
/dev/sda3 /srv/my\040data xfs rw 0 0
tmpfs /tmp tmpfs rw,nosuid,nodev,noexec 0 0
server:/export /mnt/nfs nfs4 rw 0 0
/dev/sda4 /var ext4 rw,nosuid 0 0
/dev/sda4 /var ext4 rw 0 0
`
	if got := strings.Join(suidRoots([]byte(mounts)), "|"); got != "/|/home|/srv/my data|/var" {
		t.Fatalf("roots %q", got)
	}
}

// suidFake answers find with a script, and the mount table from a fixture; the files are real.
type suidFake struct {
	runFake
	mounts string
	err    error
	ran    []string // the last command, with its arguments
}

func (s *suidFake) ReadFile(p string) ([]byte, error) {
	if p == "/proc/self/mounts" {
		return []byte(s.mounts), nil
	}
	return s.runFake.ReadFile(p)
}
func (s *suidFake) Run(_ context.Context, name string, args ...string) ([]byte, error) {
	s.ran = append([]string{name}, args...)
	return []byte(s.out), s.err
}

func TestSUIDScanThatCouldNotLookEverywhere(t *testing.T) {
	needLinux(t)
	dir := privateDir(t)
	baseline, sudo := filepath.Join(dir, "suid.json"), filepath.Join(dir, "sudo")
	if err := os.WriteFile(sudo, []byte("sudo"), 0o755); err != nil {
		t.Fatal(err)
	}
	// Mounts the scan leaves out: another user's FUSE mount, one whose name holds a quote, and one named with a backslash.
	mounts := "/dev/sda1 / ext4 rw 0 0\n/dev/sdb1 /srv ext4 rw 0 0\nu@h:/ /home/u/mnt fuse.sshfs rw,nosuid 0 0\n" +
		"u@h:/ /home/u/it\\047s fuse.sshfs rw,nosuid 0 0\ntmpfs /var/lib/m\\134 tmpfs rw,nosuid 0 0\n" +
		"u@h:/ /home/u/a\\011b fuse.sshfs rw,nosuid 0 0\nu@h:/ /home/u/x\x01y fuse.sshfs rw,nosuid 0 0\n"
	src := &suidFake{runFake: runFake{files: OS{}, out: sudo + "\x00"}, mounts: mounts}
	if err := WriteSUID(context.Background(), src, baseline, false); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(src.ran, " "); !strings.HasPrefix(got, "find / /srv -xdev -type f ") {
		t.Fatalf("find was run as %q", got)
	}
	// find as it really ends: 1 when it could not do everything, or killed.
	exited := func(script, stderr string) error {
		var exit *exec.ExitError
		if err := exec.Command("sh", "-c", script).Run(); !errors.As(err, &exit) {
			t.Fatalf("%q: %v", script, err)
		}
		exit.Stderr = []byte(stderr)
		return exit
	}
	for _, tt := range []struct {
		name, script, stderr string
		pass                 bool
	}{
		{"a file that went away while find looked", "exit 1", "find: '/tmp/x': No such file or directory\n", true},
		// Root cannot look at another user's FUSE mount, but find would not have gone into it anyway: it is another file system.
		{"a mount the scan leaves out", "exit 1", "find: '/home/u/mnt': Permission denied\n", true},
		{"a mount the scan leaves out, with a quote in its name", "exit 1", "find: '/home/u/it\\'s': Permission denied\n", true},
		{"a mount the scan leaves out, with a tab in its name", "exit 1", "find: '/home/u/a\\tb': Permission denied\n", true},
		{"a mount the scan leaves out, with an unprintable byte in its name", "exit 1", "find: '/home/u/x\\001y': Permission denied\n", true},
		{"a directory it could not read", "exit 1", "find: '/home/eve/hidden': Permission denied\n", false},
		{"a whole mount it could not read", "exit 1", "find: '/srv': Permission denied\n", false},
		{"a whole mount that is not there", "exit 1", "find: '/srv': No such file or directory\n", false},
		{"inside a mount it should not have entered", "exit 1", "find: '/home/u/mnt/x': Permission denied\n", false},
		{"a name that only looks like a left-out mount", "exit 1", "find: '/var/lib/m\\': x': Permission denied\n", false},
		{"quotes of another language", "exit 1", "find: ‘/home/u/mnt’: Permission denied\n", false},
		{"not find's form", "exit 1", "/home/u/mnt': Permission denied\n", false},
		{"find was killed", "kill -9 $$", "find: '/tmp/x': No such file or directory\n", false},
		{"find failed outright", "exit 2", "", false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			src.err = exited(tt.script, tt.stderr)
			r := run(SUID(src, baseline))
			if tt.pass != (r.Status == audit.Pass) || !tt.pass && !strings.Contains(strings.Join(r.Problems, "\n"), "could not look everywhere") {
				t.Fatalf("%+v", r)
			}
		})
	}
	// A file that went away is only harmless below where find started: here / is mounted nosuid, so /tmp was never a root.
	if why := findFailure(exited("exit 1", "find: '/tmp/x': No such file or directory\n"), []string{"/srv"}, mountTable([]byte("/dev/sda1 / ext4 rw,nosuid 0 0\n/dev/sdb1 /srv ext4 rw 0 0\n"))); why == "" {
		t.Fatal("a vanished file outside every root was taken as harmless")
	}
	src.err = exited("exit 1", "find: '/home/eve/hidden': Permission denied\n")
	if err := WriteSUID(context.Background(), src, filepath.Join(dir, "other.json"), false); err == nil {
		t.Fatal("a baseline was written from a scan that could not look everywhere")
	}
	// A setuid file that has been swapped for something that cannot be read is a finding, not silence.
	src.err = nil
	if err := os.Remove(sudo); err != nil {
		t.Fatal(err)
	}
	if err := mkfifo(sudo); err != nil {
		t.Skipf("no FIFO here: %v", err)
	}
	if r := run(SUID(src, baseline)); r.Status != audit.Fail || !strings.Contains(r.Problems[0], "cannot be read") {
		t.Fatalf("a setuid file that cannot be read: %+v", r)
	}
	// A remote mount where setuid works is not walked, so it is a finding; mounted nosuid, it is not.
	if err := os.Remove(sudo); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(sudo, []byte("sudo"), 0o755); err != nil {
		t.Fatal(err)
	}
	for _, opts := range []string{"rw", "rw,nosuid"} {
		src.mounts = mounts + "server:/x /mnt/nfs nfs4 " + opts + " 0 0\n"
		r := run(SUID(src, baseline))
		if found := strings.Contains(strings.Join(r.Problems, "\n"), "setuid files would work on /mnt/nfs (nfs4)"); found != (opts == "rw") {
			t.Fatalf("%s: %+v", opts, r)
		}
	}
}

func TestSUID(t *testing.T) {
	needLinux(t)
	dir := t.TempDir()
	baseline := filepath.Join(dir, "suid.json")
	sudo := filepath.Join(dir, "sudo")
	os.WriteFile(sudo, []byte("sudo"), 0o755)
	// The machine has sudo; the baseline is written from it. Its mounts are fixed, so the machine running the test does not
	// add findings of its own.
	src := &suidFake{runFake: runFake{files: OS{}, out: sudo + "\x00"}, mounts: "/dev/sda1 / ext4 rw 0 0\n"}
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

// A container's view of its image, and a snap's revision, are copies of a tree under a path that is new every time. A
// setuid program in one is not new when the baseline has the same program, with the same mode and owners, at the same
// place in another copy; anything else there still is.
func TestSUIDCopiesOfARecordedTree(t *testing.T) {
	needLinux(t)
	dir := privateDir(t)
	baseline := filepath.Join(dir, "suid.json")
	put := func(mode os.FileMode, content string, path ...string) string {
		t.Helper()
		full := filepath.Join(append([]string{dir}, path...)...)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(content), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(full, mode); err != nil {
			t.Fatal(err)
		}
		return full
	}
	const setuid, setgid = 0o755 | os.ModeSetuid, 0o755 | os.ModeSetgid
	// What was there when the baseline was written: an image layer on the machine's own disk, one container made from
	// it, and one revision of a snap.
	layer := put(setuid, "su", "layers", "l1", "diff", "usr", "bin", "su")
	wall := put(setgid, "wall", "layers", "l1", "diff", "usr", "bin", "wall")
	first := put(setuid, "su", "c1", "merged", "usr", "bin", "su")
	snap := put(setuid, "sudo", "snap", "core", "1974", "usr", "bin", "sudo")
	mounts := func(extra ...string) string {
		m := "/dev/sda1 / ext4 rw 0 0\n"
		for i := 0; i+1 < len(extra); i += 2 {
			m += "x " + filepath.Join(dir, extra[i]) + " " + extra[i+1] + " rw 0 0\n"
		}
		return m
	}
	list := func(paths ...string) string { return strings.Join(paths, "\x00") + "\x00" }
	recorded := list(layer, wall, first, snap)
	src := &suidFake{runFake: runFake{files: OS{}, out: recorded}, mounts: mounts("c1/merged", "overlay", "snap/core/1974", "squashfs")}
	if err := WriteSUID(context.Background(), src, baseline, false); err != nil {
		t.Fatal(err)
	}
	if r := run(SUID(src, baseline)); r.Status != audit.Pass || r.Checked != 4 || r.Note != "" {
		t.Fatalf("the machine as it was recorded: %+v", r)
	}
	withModes, err := os.ReadFile(baseline)
	if err != nil {
		t.Fatal(err)
	}
	var m Manifest
	if err := json.Unmarshal(withModes, &m); err != nil || m.Modes[wall] == "" || !strings.HasPrefix(m.Modes[layer], "4755 ") || !strings.HasPrefix(m.Modes[wall], "2755 ") {
		t.Fatalf("the baseline does not record modes: %v %+v", err, m.Modes)
	}
	m.Modes = nil
	withoutModes, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	for _, tt := range []struct {
		name    string
		make    func() string // the new file; "" for none
		mounts  []string
		problem string // "" if nothing is reported
		old     bool   // against a baseline from before modes were recorded
	}{
		{"a second container from the same image", func() string { return put(setuid, "su", "c2", "merged", "usr", "bin", "su") },
			[]string{"c2/merged", "overlay"}, "", false},
		{"the next revision of the snap, its program unchanged", func() string { return put(setuid, "sudo", "snap", "core", "2015", "usr", "bin", "sudo") },
			[]string{"snap/core/2015", "squashfs"}, "", false},
		// A baseline from before modes were recorded cannot say that a copy runs as the same user, so against one every
		// copy is new, as it always was.
		{"the same against an old baseline", func() string { return put(setuid, "sudo", "snap", "core", "2015", "usr", "bin", "sudo") },
			[]string{"snap/core/2015", "squashfs"}, "snap/core/2015/usr/bin/sudo is a new setuid or setgid file", true},
		{"a container whose program is another", func() string { return put(setuid, "su with a back door", "c2", "merged", "usr", "bin", "su") },
			[]string{"c2/merged", "overlay"}, "c2/merged/usr/bin/su is a new setuid or setgid file", false},
		{"the next revision with a changed program", func() string { return put(setuid, "sudo 1.9.16", "snap", "core", "2015", "usr", "bin", "sudo") },
			[]string{"snap/core/2015", "squashfs"}, "snap/core/2015/usr/bin/sudo is a new setuid or setgid file", false},
		{"the recorded program somewhere else in the container", func() string { return put(setuid, "su", "c2", "merged", "usr", "local", "bin", "su") },
			[]string{"c2/merged", "overlay"}, "c2/merged/usr/local/bin/su is a new setuid or setgid file", false},
		{"the recorded program under another name", func() string { return put(setuid, "su", "c2", "merged", "usr", "bin", "xsu") },
			[]string{"c2/merged", "overlay"}, "c2/merged/usr/bin/xsu is a new setuid or setgid file", false},
		{"a program that was setgid, now setuid, in a new container", func() string { return put(setuid, "wall", "c2", "merged", "usr", "bin", "wall") },
			[]string{"c2/merged", "overlay"}, "c2/merged/usr/bin/wall is a new setuid or setgid file", false},
		{"that program against an old baseline", func() string { return put(setuid, "wall", "c2", "merged", "usr", "bin", "wall") },
			[]string{"c2/merged", "overlay"}, "c2/merged/usr/bin/wall is a new setuid or setgid file", true},
		{"a copy on a disk of the machine's own", func() string { return put(setuid, "su", "c2", "merged", "usr", "bin", "su") },
			[]string{"c2/merged", "ext4"}, "c2/merged/usr/bin/su is a new setuid or setgid file", false},
		{"a copy on no mount of its own", func() string { return put(setuid, "su", "c2", "merged", "usr", "bin", "su") },
			nil, "c2/merged/usr/bin/su is a new setuid or setgid file", false},
		{"a copy on a disk mounted inside the container", func() string { return put(setuid, "su", "c2", "merged", "data", "usr", "bin", "su") },
			[]string{"c2/merged", "overlay", "c2/merged/data", "ext4"}, "c2/merged/data/usr/bin/su is a new setuid or setgid file", false},
		{"a mount that is the file itself", func() string { return put(setuid, "su", "c2", "one") },
			[]string{"c2/one", "overlay"}, "c2/one is a new setuid or setgid file", false},
		// The rest of the path, "erged/usr/bin/su", ends a recorded one, but c2/m is not a directory above the file.
		{"a mount whose name only begins the same", func() string { return put(setuid, "su", "c2", "merged", "usr", "bin", "su") },
			[]string{"c2/m", "overlay"}, "c2/merged/usr/bin/su is a new setuid or setgid file", false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			content := withModes
			if tt.old {
				content = withoutModes
			}
			if err := os.WriteFile(baseline, content, 0o600); err != nil {
				t.Fatal(err)
			}
			added := tt.make()
			defer os.RemoveAll(filepath.Join(dir, "c2"))
			defer os.RemoveAll(filepath.Join(dir, "snap", "core", "2015"))
			src := &suidFake{runFake: runFake{files: OS{}, out: recorded + list(added)},
				mounts: mounts(append([]string{"c1/merged", "overlay", "snap/core/1974", "squashfs"}, tt.mounts...)...)}
			r := run(SUID(src, baseline))
			if tt.problem == "" {
				if r.Status != audit.Pass || r.Checked != 5 {
					t.Fatalf("%+v", r)
				}
				return
			}
			if r.Status != audit.Fail || len(r.Problems) != 1 || r.Problems[0] != filepath.Join(dir, filepath.FromSlash(strings.Fields(tt.problem)[0]))+strings.TrimPrefix(tt.problem, strings.Fields(tt.problem)[0]) {
				t.Fatalf("%+v", r)
			}
		})
	}

	// A recorded file whose contents are the same but which is setuid where it was setgid, or belongs to someone else,
	// has changed. A baseline from before modes were recorded cannot say so, and says nothing.
	if err := os.WriteFile(baseline, withModes, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(wall, setuid|os.ModeSetgid); err != nil {
		t.Fatal(err)
	}
	r := run(SUID(src, baseline))
	if r.Status != audit.Fail || len(r.Problems) != 1 || !strings.HasPrefix(r.Problems[0], wall+" is a setuid or setgid file whose mode or owner has changed: it was 2755 ") ||
		!strings.Contains(r.Problems[0], " and is 6755 ") {
		t.Fatalf("a setgid file made setuid: %+v", r)
	}
	if err := os.WriteFile(baseline, withoutModes, 0o600); err != nil {
		t.Fatal(err)
	}
	// It passes, as it did before modes were recorded, and says beside the result what it cannot see.
	if r := run(SUID(src, baseline)); r.Status != audit.Pass || !strings.Contains(r.Note, "written before modes and owners were recorded") {
		t.Fatalf("the same against an old baseline: %+v", r)
	}
	if err := os.Chmod(wall, setgid); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(baseline, withModes, 0o600); err != nil {
		t.Fatal(err)
	}
	owned := &ownedBy{Source: src, path: layer, uid: 4242}
	r = run(SUID(owned, baseline))
	if r.Status != audit.Fail || len(r.Problems) != 1 || !strings.HasPrefix(r.Problems[0], layer+" is a setuid or setgid file whose mode or owner has changed: it was 4755 ") ||
		!strings.Contains(r.Problems[0], " and is 4755 4242:") {
		t.Fatalf("a setuid file that changed hands: %+v", r)
	}
	gone := &ownedBy{Source: src, path: layer, uid: -1}
	if r := run(SUID(gone, baseline)); r.Status != audit.Fail || len(r.Problems) != 1 || !strings.Contains(r.Problems[0], layer+" is a setuid or setgid file that cannot be examined") {
		t.Fatalf("a setuid file that cannot be examined: %+v", r)
	}
	// A new container's copy that cannot be examined is new. Against an old baseline, which has no mode to compare,
	// nothing else would say so.
	if err := os.WriteFile(baseline, withoutModes, 0o600); err != nil {
		t.Fatal(err)
	}
	second := put(setuid, "su", "c2", "merged", "usr", "bin", "su")
	unseen := &ownedBy{Source: &suidFake{runFake: runFake{files: OS{}, out: recorded + list(second)},
		mounts: mounts("c1/merged", "overlay", "snap/core/1974", "squashfs", "c2/merged", "overlay")}, path: second, uid: -1}
	if r := run(SUID(unseen, baseline)); r.Status != audit.Fail || len(r.Problems) != 1 || r.Problems[0] != second+" is a new setuid or setgid file" {
		t.Fatalf("a copy that cannot be examined: %+v", r)
	}
}

// What is recorded of a setuid file besides its contents: every bit that decides whom it runs as, and its owners.
func TestSUIDMode(t *testing.T) {
	for _, tt := range []struct {
		name string
		info Info
		want string
	}{
		{"setuid root", Info{Mode: 0o755 | fs.ModeSetuid}, "4755 0:0"},
		{"setgid to a group", Info{Mode: 0o755 | fs.ModeSetgid, GID: 5}, "2755 0:5"},
		{"both, owned by a user", Info{Mode: 0o750 | fs.ModeSetuid | fs.ModeSetgid, UID: 1000, GID: 1000}, "6750 1000:1000"},
		{"sticky", Info{Mode: 0o755 | fs.ModeSticky}, "1755 0:0"},
		{"every bit", Info{Mode: 0o777 | fs.ModeSetuid | fs.ModeSetgid | fs.ModeSticky, UID: 1, GID: 2}, "7777 1:2"},
		{"no special bit", Info{Mode: 0o644, UID: 3, GID: 4}, "0644 3:4"},
		{"no permission at all", Info{Mode: fs.ModeSetuid}, "4000 0:0"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got, err := suidMode(&fake{stats: map[string]Info{"/f": tt.info}}, "/f")
			if err != nil || got != tt.want {
				t.Fatalf("%q (%v), want %q", got, err, tt.want)
			}
		})
	}
	if got, err := suidMode(&fake{}, "/f"); err == nil {
		t.Fatalf("a file that cannot be examined has mode %q", got)
	}
}

// ownedBy is a machine on which one file belongs to another user (uid -1: it cannot be examined at all).
type ownedBy struct {
	Source
	path string
	uid  int
}

func (o *ownedBy) Stat(p string) (Info, error) {
	info, err := o.Source.Stat(p)
	if p != o.path || err != nil {
		return info, err
	}
	if o.uid < 0 {
		return Info{}, &fs.PathError{Op: "stat", Path: p, Err: fs.ErrPermission}
	}
	info.UID = o.uid
	return info, nil
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

	// The same for UDP: a socket that is bound and takes packets from anyone is found, a declared one is not, and one
	// that is connected to a peer is nobody's way in.
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	open := pc.LocalAddr().(*net.UDPAddr).Port
	conn, err := net.Dial("udp", pc.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	connected := conn.LocalAddr().(*net.UDPAddr).Port
	udp := func(proto, user string) []audit.Service {
		return []audit.Service{{Name: "test", Addr: "127.0.0.1:" + strconv.Itoa(open), Proto: proto, User: user}}
	}
	needle = "127.0.0.1:" + strconv.Itoa(open) + " (UDP) takes packets from any sender"
	if got := problems(nil); !strings.Contains(got, needle) {
		t.Fatalf("a UDP socket nobody declared was not found:\n%s", got)
	}
	if got := problems(nil); strings.Contains(got, "127.0.0.1:"+strconv.Itoa(connected)+" (UDP)") {
		t.Fatalf("a connected UDP socket was reported:\n%s", got)
	}
	if got := problems(udp("udp", self)); strings.Contains(got, "127.0.0.1:"+strconv.Itoa(open)+" (UDP)") {
		t.Fatalf("a declared UDP socket owned by the right user was flagged:\n%s", got)
	}
	if got := problems(udp("", self)); !strings.Contains(got, needle) {
		t.Fatalf("a TCP service answered for a UDP socket:\n%s", got)
	}
	if got := problems(udp("udp", "somebody-else")); !strings.Contains(got, "127.0.0.1:"+strconv.Itoa(open)+" (UDP) ("+self+"): it is owned by "+self) {
		t.Fatalf("a UDP socket owned by the wrong user was not found:\n%s", got)
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
