package host

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/YurilLAB/coraza/carnical/audit"
)

// Manifest is a record of the state of a set of files, written when the machine was known to be good: a hash for each file that
// exists, "absent" for a file that must not.
type Manifest struct {
	Created string            `json:"created"`
	Files   map[string]string `json:"files"`
}

const absent = "absent"

// IntegrityFiles are the files whose change is an incident: the programs, their configuration, who may log in, who may become
// root, how libraries are loaded. A file that must not exist (ld.so.preload) is recorded as absent, and its appearance is a
// finding.
var IntegrityFiles = []string{
	"/usr/local/bin/carnical", "/usr/local/bin/carnical-audit", "/usr/local/bin/carnical-confine",
	"/etc/systemd/system/carnical-edge.service", "/etc/systemd/system/carnical-edge.socket",
	"/etc/systemd/system/carnical-audit.service", "/etc/systemd/system/carnical-audit.timer",
	"/etc/systemd/system/carnical-host-audit.service", "/etc/systemd/system/carnical-host-audit.timer",
	"/etc/carnical/zones.json", "/etc/carnical/edge.env",
	"/etc/nftables.conf", "/etc/sysctl.d/90-carnical.conf", "/etc/audit/rules.d/carnical.rules", "/etc/modprobe.d/carnical.conf",
	"/etc/ssh/sshd_config", "/root/.ssh/authorized_keys",
	"/etc/passwd", "/etc/group", "/etc/shadow", "/etc/sudoers",
	"/etc/ld.so.preload", "/etc/ld.so.conf",
}

func hashFile(src Source, p string) (string, error) {
	data, err := src.ReadFile(p)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			// A link to something this check cannot see is not nothing: the audit runs with its own /tmp and /dev, where the
			// target of a link can be missing that every other process finds.
			if target, lerr := src.Readlink(p); lerr == nil {
				return "a link to " + target + ", which cannot be read here", nil
			}
			return absent, nil
		}
		return "", err
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}

// baselineProblem says why a baseline cannot be trusted, or "" if it can. The audit runs as root and believes what the
// baseline says, so the file and its directory must be ones that nobody else could have written or replaced.
func baselineProblem(src Source, path string) string {
	if runtime.GOOS == "windows" {
		return "" // no Unix owner or mode to check
	}
	for _, p := range []string{filepath.Dir(path), path} {
		if _, err := src.Readlink(p); err == nil {
			return p + " is a symbolic link"
		}
		info, err := src.Stat(p)
		switch {
		case err != nil:
			return p + " cannot be examined: " + err.Error()
		case info.UID != geteuid():
			return fmt.Sprintf("%s is owned by uid %d, so someone other than this audit (uid %d) can change it", p, info.UID, geteuid())
		case info.Mode.Perm()&0o022 != 0:
			return fmt.Sprintf("%s has mode %04o, so others can change it", p, info.Mode.Perm())
		}
	}
	return ""
}

// WriteIntegrity records the current state of the files. It refuses to replace an existing manifest unless asked, because a
// manifest rewritten by whoever changed the files proves nothing.
func WriteIntegrity(src Source, path string, files []string, replace bool) error {
	if _, err := os.Stat(path); err == nil && !replace {
		return fmt.Errorf("%s already exists: it is not replaced unless you say so", path)
	}
	m := Manifest{Created: time.Now().UTC().Format(time.RFC3339), Files: map[string]string{}}
	for _, f := range files {
		h, err := hashFile(src, f)
		if err != nil {
			return fmt.Errorf("%s: %w", f, err)
		}
		m.Files[f] = h
	}
	return writeJSON(path, m)
}

// writeJSON replaces a baseline. Only a directory that no one else can change is written to, and the new file is made under a
// name that no one could have prepared a link at.
func writeJSON(path string, v any) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	dir := filepath.Dir(path)
	if err := checkPrivateDir(dir); err != nil {
		return fmt.Errorf("the baseline directory: %w", err)
	}
	f, err := os.CreateTemp(dir, "."+filepath.Base(path)+".*.tmp")
	if err != nil {
		return err
	}
	_, err = f.Write(data)
	if err == nil {
		err = f.Sync()
	}
	if err = errors.Join(err, f.Close()); err == nil {
		err = os.Rename(f.Name(), path)
	}
	if err != nil {
		if rmErr := os.Remove(f.Name()); rmErr != nil && !errors.Is(rmErr, fs.ErrNotExist) {
			err = errors.Join(err, rmErr)
		}
	}
	return err
}

// Integrity compares the files with the manifest.
func Integrity(src Source, manifestPath string) audit.Check {
	return audit.Check{
		Name: "host-integrity", Zone: "",
		What: "The programs, units, rules and account files are the ones that were recorded when the machine was known to be good.",
		Run: func(ctx context.Context) audit.Outcome {
			data, err := src.ReadFile(manifestPath)
			if err != nil {
				return audit.Outcome{SkipReason: "no manifest at " + manifestPath + " (write one when the machine is known to be good: carnical-audit -write-baseline)"}
			}
			if why := baselineProblem(src, manifestPath); why != "" {
				return audit.Outcome{Checked: 1, Problems: []string{"the manifest cannot be trusted: " + why}}
			}
			var m Manifest
			if err := json.Unmarshal(data, &m); err != nil || len(m.Files) == 0 {
				return audit.Outcome{Problems: []string{manifestPath + " cannot be read, or lists nothing"}}
			}
			var out audit.Outcome
			for p, want := range m.Files {
				out.Checked++
				got, err := hashFile(src, p)
				switch {
				case err != nil:
					out.Problems = append(out.Problems, fmt.Sprintf("%s cannot be read: %v", p, err))
				case got == want:
				case want == absent:
					out.Problems = append(out.Problems, p+" did not exist and now does")
				case got == absent:
					out.Problems = append(out.Problems, p+" existed and has gone")
				default:
					out.Problems = append(out.Problems, p+" has changed")
				}
			}
			sort.Strings(out.Problems)
			return out
		},
	}
}

// kernelTypes are the kernel's own views, which hold no files: the setuid scan leaves them out.
var kernelTypes = map[string]bool{
	"proc": true, "sysfs": true, "devtmpfs": true, "devpts": true, "cgroup": true, "cgroup2": true, "debugfs": true, "tracefs": true,
	"securityfs": true, "pstore": true, "bpf": true, "mqueue": true, "hugetlbfs": true, "configfs": true, "fusectl": true,
	"binfmt_misc": true, "autofs": true, "efivarfs": true, "nsfs": true, "selinuxfs": true, "rpc_pipefs": true,
}

// remoteTypes are other machines' files, which can be slow to walk: the setuid scan leaves them out, and says so when a
// setuid file would work there (they should be mounted nosuid).
var remoteTypes = map[string]bool{
	"nfs": true, "nfs4": true, "cifs": true, "smb3": true, "smbfs": true, "ceph": true, "glusterfs": true, "9p": true, "drvfs": true,
	"fuse.sshfs": true,
}

// unescapeMount undoes the octal escapes /proc/self/mounts writes for a space, a tab, a newline and a backslash in a path.
func unescapeMount(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+4 <= len(s) {
			if n, err := strconv.ParseUint(s[i+1:i+4], 8, 8); err == nil {
				b.WriteByte(byte(n))
				i += 3
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

type mount struct{ fstype, opts string }

// setuidWorks reports whether a setuid file on a mount would be honoured: it is not mounted nosuid.
func (m mount) setuidWorks() bool {
	for _, o := range strings.Split(m.opts, ",") {
		if o == "nosuid" {
			return false
		}
	}
	return true
}

// scanned reports whether the setuid scan looks inside a mount: one where setuid works, and not the kernel's or a remote one.
func (m mount) scanned() bool {
	return m.setuidWorks() && !kernelTypes[m.fstype] && !remoteTypes[m.fstype]
}

// unscannedSUIDMounts are the mounts where a setuid file would work but the scan does not walk.
func unscannedSUIDMounts(mounts []byte) []string {
	var out []string
	for dir, m := range mountTable(mounts) {
		if m.setuidWorks() && remoteTypes[m.fstype] {
			out = append(out, fmt.Sprintf("%s (%s)", dir, m.fstype))
		}
	}
	sort.Strings(out)
	return out
}

// mountTable is each mount point in /proc/self/mounts with the mount in force there.
func mountTable(mounts []byte) map[string]mount {
	last := map[string]mount{}
	for _, line := range strings.Split(string(mounts), "\n") {
		f := strings.Fields(line)
		if len(f) < 4 {
			continue
		}
		last[unescapeMount(f[1])] = mount{f[2], f[3]} // a later line for the same mount point is the one in force
	}
	return last
}

// suidRoots are the mount points the setuid scan starts from: every mount it looks inside.
func suidRoots(mounts []byte) []string {
	var roots []string
	for dir, m := range mountTable(mounts) {
		if m.scanned() && strings.HasPrefix(dir, "/") {
			roots = append(roots, dir)
		}
	}
	sort.Strings(roots)
	return roots
}

// errScanIncomplete is a setuid scan that could not look everywhere it should have.
var errScanIncomplete = errors.New("the setuid scan could not look everywhere")

// findMessage splits a line of find's errors into the path it names and what it says, undoing find's quoting (in the C
// locale: the path in single quotes, with a quote, a backslash or an unprintable byte escaped by a backslash).
func findMessage(line string) (path, msg string, ok bool) {
	rest, ok := strings.CutPrefix(line, "find: '")
	if !ok {
		return "", "", false
	}
	var b strings.Builder
	for i := 0; i < len(rest); i++ {
		switch c := rest[i]; c {
		case '\'':
			msg, ok := strings.CutPrefix(rest[i+1:], ": ")
			return b.String(), msg, ok
		case '\\':
			if i+1 >= len(rest) {
				return "", "", false
			}
			i++
			switch e := rest[i]; {
			case e >= '0' && e <= '7':
				if i+3 > len(rest) {
					return "", "", false
				}
				n, err := strconv.ParseUint(rest[i:i+3], 8, 8)
				if err != nil {
					return "", "", false
				}
				b.WriteByte(byte(n))
				i += 2
			case strings.IndexByte(`\'"?`, e) >= 0:
				b.WriteByte(e)
			case strings.IndexByte("abfnrtv", e) >= 0:
				b.WriteByte("\a\b\f\n\r\t\v"[strings.IndexByte("abfnrtv", e)])
			default:
				return "", "", false
			}
		default:
			b.WriteByte(c)
		}
	}
	return "", "", false
}

// findFailure is what find said it could not do; "" if that was only files that went away while it looked, below where it
// started, and mount points the scan leaves out (root cannot look at another user's FUSE mount, but -xdev would not have
// gone into it). A find that did not finish (killed, or failed outright) is a failure whatever it said.
func findFailure(err error, roots []string, table map[string]mount) string {
	var exit *exec.ExitError
	if !errors.As(err, &exit) {
		return err.Error()
	}
	if exit.ExitCode() != 1 {
		return "find did not finish: " + exit.String()
	}
	for _, line := range strings.Split(string(exit.Stderr), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		path, msg, ok := findMessage(line)
		below := slices.ContainsFunc(roots, func(r string) bool { return strings.HasPrefix(path, strings.TrimSuffix(r, "/")+"/") })
		m, isMount := table[path]
		switch {
		case !ok || slices.Contains(roots, path): // a whole mount was not looked at
		case msg == "No such file or directory" && below:
			continue
		case isMount && !m.scanned():
			continue
		}
		return line
	}
	if len(exit.Stderr) == 0 {
		return "find failed and said nothing"
	}
	return ""
}

// SUIDFiles lists the setuid and setgid files on every mount where they would work. Each is a way to become another user, so a
// new one, or a changed one, is a finding.
func SUIDFiles(ctx context.Context, src Source) ([]string, error) {
	mounts, err := src.ReadFile("/proc/self/mounts")
	if err != nil {
		return nil, fmt.Errorf("the mount table: %w", err)
	}
	roots := suidRoots(mounts)
	if len(roots) == 0 {
		return nil, errors.New("the mount table has no mount where a setuid file would work")
	}
	args := append(append([]string(nil), roots...), "-xdev", "-type", "f", "(", "-perm", "-4000", "-o", "-perm", "-2000", ")", "-print0")
	data, err := src.Run(ctx, "find", args...)
	if err != nil {
		var exit *exec.ExitError
		if !errors.As(err, &exit) {
			return nil, err
		}
		if why := findFailure(err, roots, mountTable(mounts)); why != "" {
			return nil, fmt.Errorf("%w: %s", errScanIncomplete, why)
		}
	}
	var out []string
	for _, p := range bytes.Split(data, []byte{0}) {
		if s := strings.TrimSpace(string(p)); s != "" {
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out, nil
}

// WriteSUID records the current set.
func WriteSUID(ctx context.Context, src Source, path string, replace bool) error {
	if _, err := os.Stat(path); err == nil && !replace {
		return fmt.Errorf("%s already exists: it is not replaced unless you say so", path)
	}
	files, err := SUIDFiles(ctx, src)
	if err != nil {
		return err
	}
	m := Manifest{Created: time.Now().UTC().Format(time.RFC3339), Files: map[string]string{}}
	for _, f := range files {
		h, err := hashFile(src, f)
		if err != nil {
			return fmt.Errorf("%s: %w", f, err)
		}
		m.Files[f] = h
	}
	return writeJSON(path, m)
}

// SUID checks the set of setuid and setgid files against the recorded one.
func SUID(src Source, manifestPath string) audit.Check {
	return audit.Check{
		Name: "host-suid", Zone: "",
		What: "No setuid or setgid file has appeared or changed since the machine was known to be good.",
		Run: func(ctx context.Context) audit.Outcome {
			if why := linux(); why != "" {
				return audit.Outcome{SkipReason: why}
			}
			data, err := src.ReadFile(manifestPath)
			if err != nil {
				return audit.Outcome{SkipReason: "no baseline at " + manifestPath + " (write one when the machine is known to be good: carnical-audit -write-baseline)"}
			}
			if why := baselineProblem(src, manifestPath); why != "" {
				return audit.Outcome{Checked: 1, Problems: []string{"the baseline cannot be trusted: " + why}}
			}
			var m Manifest
			if err := json.Unmarshal(data, &m); err != nil {
				return audit.Outcome{Problems: []string{manifestPath + " cannot be read"}}
			}
			now, err := SUIDFiles(ctx, src)
			switch {
			case errors.Is(err, errScanIncomplete):
				return audit.Outcome{Checked: 1, Problems: []string{err.Error()}} // what was not looked at could hold the new one
			case err != nil:
				return audit.Outcome{SkipReason: "find could not be run: " + err.Error()}
			}
			var out audit.Outcome
			if mounts, err := src.ReadFile("/proc/self/mounts"); err == nil {
				for _, m := range unscannedSUIDMounts(mounts) {
					out.Problems = append(out.Problems, "setuid files would work on "+m+", which the scan does not walk: mount it nosuid")
				}
			}
			seen := map[string]bool{}
			for _, f := range now {
				out.Checked++
				seen[f] = true
				want, known := m.Files[f]
				if !known {
					out.Problems = append(out.Problems, f+" is a new setuid or setgid file")
					continue
				}
				switch got, err := hashFile(src, f); {
				case err != nil:
					out.Problems = append(out.Problems, fmt.Sprintf("%s is a setuid or setgid file that cannot be read: %v", f, err))
				case got != want:
					out.Problems = append(out.Problems, f+" is a setuid or setgid file that has changed")
				}
			}
			for f := range m.Files {
				if !seen[f] {
					out.Checked++ // a file that has gone is not a danger, but it is a change worth knowing
				}
			}
			sort.Strings(out.Problems)
			return out
		},
	}
}
