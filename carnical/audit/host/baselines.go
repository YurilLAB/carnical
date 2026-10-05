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
	"path/filepath"
	"sort"
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
			return absent, nil
		}
		return "", err
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
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

func writeJSON(path string, v any) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	tmp := filepath.Join(filepath.Dir(path), "."+filepath.Base(path)+".tmp")
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
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

// SUIDBaseline is the setuid and setgid files that exist on a good machine. Each is a way to become another user, so a new one,
// or a changed one, is a finding.
func SUIDFiles(ctx context.Context, src Source) ([]string, error) {
	data, err := src.Run(ctx, "find", "/", "-xdev", "-type", "f", "(", "-perm", "-4000", "-o", "-perm", "-2000", ")", "-print0")
	if err != nil && len(data) == 0 {
		return nil, err // find exits non-zero when it could not look somewhere, but its list is still the list
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
			var m Manifest
			if err := json.Unmarshal(data, &m); err != nil {
				return audit.Outcome{Problems: []string{manifestPath + " cannot be read"}}
			}
			now, err := SUIDFiles(ctx, src)
			if err != nil {
				return audit.Outcome{SkipReason: "find could not be run: " + err.Error()}
			}
			var out audit.Outcome
			seen := map[string]bool{}
			for _, f := range now {
				out.Checked++
				seen[f] = true
				want, known := m.Files[f]
				if !known {
					out.Problems = append(out.Problems, f+" is a new setuid or setgid file")
					continue
				}
				if got, err := hashFile(src, f); err == nil && got != want {
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
