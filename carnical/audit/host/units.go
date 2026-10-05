package host

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io/fs"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/YurilLAB/coraza/carnical/audit"
)

// UnitSpec is what a service's sandbox must be, as systemd reports it for the running unit.
type UnitSpec struct {
	Name   string
	Expect map[string]string
	// MaxExposure is the highest overall score `systemd-analyze security` may give the unit (0 to 10, lower is tighter).
	MaxExposure float64
}

// setValued are properties whose value is a list: compared as a set, because systemd may print it in any order.
var setValued = map[string]bool{"RestrictAddressFamilies": true}

// EdgeUnit is the sandbox the edge's unit file sets (deploy/systemd/carnical-edge.service).
var EdgeUnit = UnitSpec{
	Name: "carnical-edge.service",
	Expect: map[string]string{
		"User": "carnical-edge", "NoNewPrivileges": "yes", "ProtectSystem": "strict", "ProtectHome": "yes", "PrivateTmp": "yes",
		"PrivateDevices": "yes", "ProtectKernelTunables": "yes", "ProtectKernelModules": "yes", "ProtectKernelLogs": "yes",
		"ProtectControlGroups": "yes", "ProtectClock": "yes", "ProtectProc": "invisible", "ProcSubset": "pid",
		"RestrictNamespaces": "yes", "RestrictSUIDSGID": "yes", "LockPersonality": "yes", "MemoryDenyWriteExecute": "yes",
		"SystemCallArchitectures": "native", "CapabilityBoundingSet": "",
		"RestrictAddressFamilies": "AF_UNIX AF_INET AF_INET6 AF_NETLINK",
	},
	MaxExposure: 2.0,
}

var exposureRe = regexp.MustCompile(`Overall exposure level for [^:]+: ([0-9.]+)`)

func parseShow(data []byte) map[string]string {
	out := map[string]string{}
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		if k, v, ok := strings.Cut(sc.Text(), "="); ok {
			out[k] = v
		}
	}
	return out
}

func sameSet(a, b string) bool {
	set := func(s string) string {
		f := strings.Fields(s)
		sort.Strings(f)
		return strings.Join(f, " ")
	}
	return set(a) == set(b)
}

// Unit checks that a running service has the sandbox its unit file asks for. A unit file can say anything: what matters is
// what systemd applied, which is what is read here.
func Unit(src Source, spec UnitSpec) audit.Check {
	return audit.Check{
		Name: "host-unit-" + strings.TrimSuffix(spec.Name, ".service"), Zone: "",
		What: "The service runs with the sandbox its unit file asks for: no new privileges, a read-only machine, no capabilities, few system calls.",
		Run: func(ctx context.Context) audit.Outcome {
			if why := linux(); why != "" {
				return audit.Outcome{SkipReason: why}
			}
			expectKeys := make([]string, 0, len(spec.Expect))
			for k := range spec.Expect {
				expectKeys = append(expectKeys, k)
			}
			sort.Strings(expectKeys)
			asked := append([]string{"LoadState"}, expectKeys...)
			sort.Strings(asked)
			data, err := src.Run(ctx, "systemctl", "show", "--no-pager", "-p", strings.Join(asked, ","), spec.Name)
			if err != nil {
				return audit.Outcome{SkipReason: "systemctl could not be run: " + err.Error()}
			}
			got := parseShow(data)
			var out audit.Outcome
			out.Checked++
			if got["LoadState"] != "loaded" {
				return audit.Outcome{Checked: 1, Problems: []string{spec.Name + " is not installed (" + got["LoadState"] + ")"}}
			}
			for _, k := range expectKeys {
				want, have := spec.Expect[k], got[k]
				ok := have == want
				if setValued[k] {
					ok = sameSet(have, want)
				}
				out.Checked++
				if !ok {
					out.Problems = append(out.Problems, fmt.Sprintf("%s: %s is %q, should be %q", spec.Name, k, have, want))
				}
			}
			if spec.MaxExposure > 0 {
				out.Checked++
				scored, err := src.Run(ctx, "systemd-analyze", "security", "--no-pager", spec.Name)
				m := exposureRe.FindSubmatch(scored)
				switch {
				case err != nil && len(m) == 0:
					out.Problems = append(out.Problems, spec.Name+": the exposure score could not be read: "+err.Error())
				case len(m) == 0:
					out.Problems = append(out.Problems, spec.Name+": the exposure score could not be read")
				default:
					if v, _ := strconv.ParseFloat(string(m[1]), 64); v > spec.MaxExposure {
						out.Problems = append(out.Problems, fmt.Sprintf("%s: systemd scores its exposure at %.1f, more than %.1f", spec.Name, v, spec.MaxExposure))
					}
				}
			}
			sort.Strings(out.Problems)
			return out
		},
	}
}

// NFT checks that the network policy is loaded: the input chain refuses by default and the edge's output chain refuses private
// destinations.
func NFT(src Source) audit.Check {
	return audit.Check{
		Name: "host-nft", Zone: "",
		What: "The per-service network policy is loaded: the host refuses by default, and the edge cannot reach private addresses, this machine or the metadata service.",
		Run: func(ctx context.Context) audit.Outcome {
			if why := linux(); why != "" {
				return audit.Outcome{SkipReason: why}
			}
			data, err := src.Run(ctx, "nft", "list", "ruleset")
			if err != nil {
				return audit.Outcome{SkipReason: "nft could not be run: " + err.Error()}
			}
			text := string(data)
			var out audit.Outcome
			need := []struct{ what, token string }{
				{"the carnical table", "table inet carnical"},
				{"the input chain refusing by default", "policy drop"},
				{"the edge's output chain", "chain edge_out"},
				{"the edge being sent to that chain", "jump edge_out"},
				{"the list of private IPv4 destinations", "@not_public4"},
				{"the list of private IPv6 destinations", "@not_public6"},
				{"the block on this machine's own addresses", "fib daddr type local"},
				{"the block on the metadata service", "169.254.169.254"},
				{"the internal services' output chain", "chain internal_out"},
			}
			for _, n := range need {
				out.Checked++
				if !strings.Contains(text, n.token) {
					out.Problems = append(out.Problems, "the loaded rules have no "+n.what)
				}
			}
			return out
		},
	}
}

// AuditKeys are the audit rule keys that deploy/auditd/carnical.rules sets.
var AuditKeys = []string{"carnical_svc_exec", "carnical_abuse", "carnical_setuid", "carnical_persist", "carnical_priv", "carnical_ssh", "carnical_self", "carnical_honey"}

var auditEnabledRe = regexp.MustCompile(`(?m)^enabled\s+(\d)`)

// Auditd checks that the audit rules are loaded and locked until the next boot.
func Auditd(src Source) audit.Check {
	return audit.Check{
		Name: "host-auditd", Zone: "",
		What: "The audit rules for exec by a service, abuse of system calls, persistence and honeytokens are loaded and cannot be switched off without a reboot.",
		Run: func(ctx context.Context) audit.Outcome {
			if why := linux(); why != "" {
				return audit.Outcome{SkipReason: why}
			}
			status, err := src.Run(ctx, "auditctl", "-s")
			if err != nil {
				return audit.Outcome{SkipReason: "auditctl could not be run: " + err.Error()}
			}
			rules, err := src.Run(ctx, "auditctl", "-l")
			if err != nil {
				return audit.Outcome{SkipReason: "auditctl could not list the rules: " + err.Error()}
			}
			var out audit.Outcome
			out.Checked++
			switch m := auditEnabledRe.FindSubmatch(status); {
			case m == nil:
				out.Problems = append(out.Problems, "the audit system's state could not be read")
			case string(m[1]) != "2":
				out.Problems = append(out.Problems, fmt.Sprintf("auditing is %s, not locked (2): a process with root can switch it off", m[1]))
			}
			for _, key := range AuditKeys {
				out.Checked++
				if !bytes.Contains(rules, []byte("-k "+key)) {
					out.Problems = append(out.Problems, "no audit rule with the key "+key)
				}
			}
			return out
		},
	}
}

// FileRule is who may own a file and how much access it may give.
type FileRule struct {
	Path string
	// Owner is a user name ("root" or a service user).
	Owner string
	// MaxMode is the most permissive mode allowed: any bit outside it is a problem.
	MaxMode fs.FileMode
}

// Files are the files and directories whose ownership and mode the segmentation depends on. A service that can write its own
// program, or another service's data, has no wall around it.
var Files = []FileRule{
	{"/usr/local/bin/carnical", "root", 0o755},
	{"/usr/local/bin/carnical-audit", "root", 0o755},
	{"/etc/carnical", "root", 0o755},
	{"/etc/carnical/zones.json", "root", 0o644},
	{"/etc/carnical/edge.env", "root", 0o640},
	{"/etc/carnical/signer", "carnical-signer", 0o700},
	{"/etc/systemd/system/carnical-edge.service", "root", 0o644},
	{"/etc/systemd/system/carnical-edge.socket", "root", 0o644},
	{"/var/lib/carnical/edge", "carnical-edge", 0o700},
	{"/var/lib/carnical/edge/uploads", "carnical-edge", 0o700},
	{"/var/lib/carnical/portal", "carnical-portal", 0o700},
	{"/var/lib/carnical/ctl", "carnical-ctl", 0o700},
	{"/var/lib/carnical/signer", "carnical-signer", 0o700},
	{"/var/lib/carnical/audit", "carnical-audit", 0o700},
}

// Ownership checks the files above.
func Ownership(src Source, rules []FileRule) audit.Check {
	return audit.Check{
		Name: "host-ownership", Zone: "",
		What: "Each service's program is owned by root and cannot be written by the service, and each service's data can be read by that service only.",
		Run: func(ctx context.Context) audit.Outcome {
			if why := linux(); why != "" {
				return audit.Outcome{SkipReason: why}
			}
			uids, err := users(src)
			if err != nil {
				return audit.Outcome{SkipReason: "cannot read /etc/passwd: " + err.Error()}
			}
			var out audit.Outcome
			for _, r := range rules {
				out.Checked++
				info, err := src.Stat(r.Path)
				if err != nil {
					out.Problems = append(out.Problems, r.Path+" does not exist")
					continue
				}
				want, known := uids[r.Owner]
				switch {
				case !known:
					out.Problems = append(out.Problems, fmt.Sprintf("%s: the user %s does not exist", r.Path, r.Owner))
				case info.UID != want:
					out.Problems = append(out.Problems, fmt.Sprintf("%s is owned by uid %d, should be %s", r.Path, info.UID, r.Owner))
				}
				if extra := info.Mode.Perm() &^ r.MaxMode; extra != 0 {
					out.Problems = append(out.Problems, fmt.Sprintf("%s has mode %04o, more than %04o", r.Path, info.Mode.Perm(), r.MaxMode))
				}
			}
			sort.Strings(out.Problems)
			return out
		},
	}
}

// users reads /etc/passwd into name to uid.
func users(src Source) (map[string]int, error) {
	data, err := src.ReadFile("/etc/passwd")
	if err != nil {
		return nil, err
	}
	out := map[string]int{}
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		f := strings.Split(sc.Text(), ":")
		if len(f) >= 3 {
			if uid, err := strconv.Atoi(f[2]); err == nil {
				out[f[0]] = uid
			}
		}
	}
	return out, nil
}
