// SPDX-License-Identifier: Apache-2.0

package importers

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/YurilLAB/coraza/carnical/vpatch"
)

// FileConverter converts the contents of one rule file. It adds to rep what it read, skipped and dropped, and returns the
// signatures in the order the rules appear. It must not call rep.AddSignatures: Run does that after de-duplicating IDs and
// validating. name is the file's base name, used in messages and as a fall-back revision source; it never holds a path.
type FileConverter func(name string, data []byte, opts Options, rep *Report) []vpatch.Signature

// Format describes one input format to Run.
type Format struct {
	// Name is the format's name: "crowdsec", "suricata", "nuclei", "seclang".
	Name string
	// Extensions are the file name endings (lower case, with the dot) that a directory walk picks up.
	Extensions []string
	Convert    FileConverter
}

// Run converts a file, or every matching file under a directory (in sorted order, so output is deterministic), and returns the
// signatures and the report. Symbolic links are not followed, files over Limits.MaxFileBytes are skipped and reported, and a
// conversion that panics is caught, reported and skipped, so one bad rule cannot end a run over a whole feed.
func Run(f Format, root string, opts Options) (Result, error) {
	opts.Limits = opts.Limits.Normalize()
	rep := NewReport(f.Name)
	files, err := collectFiles(root, f.Extensions, opts.Limits.MaxFiles, rep)
	if err != nil {
		return Result{}, err
	}
	var sigs []vpatch.Signature
	seen := map[string]bool{}
	for _, path := range files {
		name := filepath.Base(path)
		data, err := readBounded(path, opts.Limits.MaxFileBytes)
		if err != nil {
			rep.FilesSkipped++
			rep.Error(SafeName(name) + ": " + err.Error())
			continue
		}
		rep.FilesRead++
		got := convertSafely(f, name, data, opts, rep)
		for _, s := range got {
			if err := Validate(s, opts.Limits.MaxPatternBytes, opts.Limits.MaxConditions); err != nil {
				rep.PartialSkip("invalid-output")
				rep.Error("invalid signature " + SafeName(s.ID) + ": " + err.Error())
				continue
			}
			if seen[s.ID] {
				rep.PartialSkip("duplicate-id")
				rep.Error("duplicate id " + SafeName(s.ID))
				continue
			}
			seen[s.ID] = true
			sigs = append(sigs, s)
		}
	}
	rep.AddSignatures(sigs)
	return Result{Signatures: sigs, Report: *rep}, nil
}

// ConvertBytes runs a format's converter over one in-memory file, with the same checks as Run. It is for tests and for callers that
// already hold the bytes.
func ConvertBytes(f Format, name string, data []byte, opts Options) Result {
	opts.Limits = opts.Limits.Normalize()
	rep := NewReport(f.Name)
	rep.FilesRead = 1
	got := convertSafely(f, name, data, opts, rep)
	var sigs []vpatch.Signature
	seen := map[string]bool{}
	for _, s := range got {
		if err := Validate(s, opts.Limits.MaxPatternBytes, opts.Limits.MaxConditions); err != nil {
			rep.PartialSkip("invalid-output")
			rep.Error("invalid signature " + SafeName(s.ID) + ": " + err.Error())
			continue
		}
		if seen[s.ID] {
			rep.PartialSkip("duplicate-id")
			continue
		}
		seen[s.ID] = true
		sigs = append(sigs, s)
	}
	rep.AddSignatures(sigs)
	return Result{Signatures: sigs, Report: *rep}
}

func convertSafely(f Format, name string, data []byte, opts Options, rep *Report) (out []vpatch.Signature) {
	defer func() {
		if r := recover(); r != nil {
			rep.Skip("internal-error", name)
			rep.Error(fmt.Sprintf("%s: converter panic (%T)", SafeName(name), r))
			out = nil
		}
	}()
	return f.Convert(name, data, opts, rep)
}

func hasExt(name string, exts []string) bool {
	l := strings.ToLower(name)
	for _, e := range exts {
		if strings.HasSuffix(l, e) {
			return true
		}
	}
	return false
}

func collectFiles(root string, exts []string, maxFiles int, rep *Report) ([]string, error) {
	info, err := os.Lstat(root)
	if err != nil {
		return nil, fmt.Errorf("input: %w", err)
	}
	if info.Mode()&fs.ModeSymlink != 0 {
		return nil, fmt.Errorf("input is a symbolic link; give the real path")
	}
	if !info.IsDir() {
		return []string{root}, nil
	}
	var files []string
	err = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			rep.Error("walk: " + SafeName(filepath.Base(path)) + ": " + err.Error())
			return nil
		}
		if d.IsDir() {
			if path != root && strings.HasPrefix(d.Name(), ".") {
				return filepath.SkipDir
			}
			return nil
		}
		if d.Type()&fs.ModeSymlink != 0 || !d.Type().IsRegular() {
			return nil
		}
		if !hasExt(d.Name(), exts) {
			return nil
		}
		if len(files) >= maxFiles {
			rep.Error(fmt.Sprintf("more than %d files; the rest were not read", maxFiles))
			return fs.SkipAll
		}
		files = append(files, path)
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Strings(files)
	return files, nil
}

// readBounded reads a whole file, but refuses one larger than max bytes (and never reads more than max+1 bytes to find out).
func readBounded(path string, max int64) ([]byte, error) {
	// #nosec G304 -- Read-only local conversion inputs/repository metadata; the operator selects the conversion root, and files must be regular and size-limited.
	fh, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer fh.Close()
	st, err := fh.Stat()
	if err != nil {
		return nil, err
	}
	if !st.Mode().IsRegular() {
		return nil, fmt.Errorf("not a regular file")
	}
	if st.Size() > max {
		return nil, fmt.Errorf("larger than the %d byte limit", max)
	}
	data, err := io.ReadAll(io.LimitReader(fh, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > max {
		return nil, fmt.Errorf("larger than the %d byte limit", max)
	}
	return data, nil
}

// ContentRevision is the first 12 hex characters of the SHA-256 of data: the revision a converter writes into Sources when the
// format carries none and the caller gave none.
func ContentRevision(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])[:12]
}

// RevisionOr returns opts.Revision, or the content hash of data when that is empty.
func (o Options) RevisionOr(data []byte) string {
	if o.Revision != "" {
		return SafeRevision(o.Revision)
	}
	return ContentRevision(data)
}

// SafeRevision keeps a revision to characters that are safe inside a Sources entry.
func SafeRevision(s string) string { return SafeToken(s, 40) }

// SafeToken keeps the letters, digits, ".", "-" and "_" of s, up to max of them, so that it is safe inside a Sources entry or an ID.
func SafeToken(s string, max int) string {
	var b strings.Builder
	for _, r := range s {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '.' || r == '-' || r == '_' {
			b.WriteRune(r)
		}
		if b.Len() >= max {
			break
		}
	}
	return b.String()
}

// DiscoverRevision looks for a git checkout at or above dir (up to six levels) and returns the first 12 hex characters of the
// commit its HEAD names, or "" when there is none. It reads the files in .git; it does not run git.
func DiscoverRevision(dir string) string {
	abs, err := filepath.Abs(dir)
	if err != nil {
		return ""
	}
	if st, err := os.Stat(abs); err == nil && !st.IsDir() {
		abs = filepath.Dir(abs)
	}
	for i := 0; i < 6; i++ {
		gitDir := filepath.Join(abs, ".git")
		if st, err := os.Stat(gitDir); err == nil && st.IsDir() {
			return readHead(gitDir)
		}
		parent := filepath.Dir(abs)
		if parent == abs {
			break
		}
		abs = parent
	}
	return ""
}

func readHead(gitDir string) string {
	b, err := readBounded(filepath.Join(gitDir, "HEAD"), 4096)
	if err != nil {
		return ""
	}
	head := strings.TrimSpace(string(b))
	if !strings.HasPrefix(head, "ref: ") {
		return hexPrefix(head)
	}
	ref := strings.TrimSpace(strings.TrimPrefix(head, "ref: "))
	if strings.Contains(ref, "..") || strings.HasPrefix(ref, "/") {
		return ""
	}
	if rb, err := readBounded(filepath.Join(gitDir, filepath.FromSlash(ref)), 4096); err == nil {
		return hexPrefix(strings.TrimSpace(string(rb)))
	}
	if pb, err := readBounded(filepath.Join(gitDir, "packed-refs"), 8<<20); err == nil {
		for _, line := range strings.Split(string(pb), "\n") {
			f := strings.Fields(line)
			if len(f) == 2 && f[1] == ref {
				return hexPrefix(f[0])
			}
		}
	}
	return ""
}

func hexPrefix(s string) string {
	if len(s) < 12 {
		return ""
	}
	for _, c := range s[:12] {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return ""
		}
	}
	return s[:12]
}
