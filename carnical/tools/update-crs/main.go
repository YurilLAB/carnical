// Command update-crs fetches an OWASP Core Rule Set release, verifies it and replaces the embedded copy.
//
//	go run ./tools/update-crs -version 4.30.0
//
// What it checks before anything is written:
//   - the archive comes from github.com (https only, redirects only to GitHub's own hosts, size capped);
//   - its detached GPG signature is good, and was made by the CRS release key whose fingerprint is pinned below
//     (the key itself is kept in crs/owasp-crs-release-key.asc and read into a throwaway keyring, never your own);
//   - only expected regular files are extracted, with no paths that could leave the output folder.
//
// It then writes crs/owasp_crs/ and crs/provenance.json (version, archive hash, signer, hash of every file).
package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

// The CRS project publishes this fingerprint in its SECURITY.md (https://github.com/coreruleset/coreruleset).
const pinnedFingerprint = "36006F0E0BA167832158821138EEACA1AB8A6E72"

const (
	maxArchive = 16 << 20 // bytes
	maxFile    = 4 << 20
	maxFiles   = 200
)

var (
	versionShape = regexp.MustCompile(`^4\.[0-9]{1,3}\.[0-9]{1,3}$`)
	entryShape   = regexp.MustCompile(`^coreruleset-[0-9.]+/(rules/[A-Za-z0-9._-]+|crs-setup\.conf\.example|LICENSE)$`)
)

type provenance struct {
	Version              string            `json:"version"`
	Source               string            `json:"source"`
	ArchiveSHA256        string            `json:"archive_sha256"`
	SignatureSHA256      string            `json:"signature_sha256"`
	SignerFingerprint    string            `json:"signer_fingerprint"`
	SignatureVerifiedUTC string            `json:"signature_verified_utc"`
	Files                map[string]string `json:"files"`
}

func main() {
	version := flag.String("version", "", "CRS release to embed, such as 4.30.0")
	out := flag.String("out", "crs", "the crs package folder")
	gpg := flag.String("gpg", envOr("GPG", "gpg"), "gpg program")
	archivePath := flag.String("archive", "", "use this local archive instead of downloading (its .asc must sit beside it)")
	flag.Parse()
	if !versionShape.MatchString(*version) {
		fatal("give -version as 4.x.y")
	}
	archive, sig, source := fetch(*version, *archivePath)
	if err := verify(*gpg, filepath.Join(*out, "owasp-crs-release-key.asc"), archive, sig); err != nil {
		fatal("signature check failed, nothing written: %v", err)
	}
	files := extract(archive, *version)
	if err := install(*out, *version, source, archive, sig, files); err != nil {
		fatal("%v", err)
	}
	fmt.Printf("embedded CRS %s: %d files, archive sha256 %s\n", *version, len(files), hash(archive))
}

func envOr(name, fallback string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return fallback
}

func fatal(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "update-crs: "+format+"\n", args...)
	os.Exit(1)
}

func check(err error) {
	if err != nil {
		fatal("%v", err)
	}
}

func hash(data []byte) string { sum := sha256.Sum256(data); return hex.EncodeToString(sum[:]) }

func fetch(version, local string) (archive, sig []byte, source string) {
	name := "coreruleset-" + version + "-minimal.tar.gz"
	if local != "" {
		a, err := os.ReadFile(local)
		check(err)
		s, err := os.ReadFile(local + ".asc")
		check(err)
		return a, s, "local file " + filepath.Base(local)
	}
	base := "https://github.com/coreruleset/coreruleset/releases/download/v" + version + "/"
	return download(base + name), download(base + name + ".asc"), base + name
}

func download(rawURL string) []byte {
	client := &http.Client{Timeout: 60 * time.Second, CheckRedirect: func(req *http.Request, via []*http.Request) error {
		host := req.URL.Hostname()
		if req.URL.Scheme != "https" || !(host == "github.com" || strings.HasSuffix(host, ".githubusercontent.com")) || len(via) > 5 {
			return fmt.Errorf("refusing redirect to %s", req.URL.Redacted())
		}
		return nil
	}}
	u, err := url.Parse(rawURL)
	check(err)
	if u.Scheme != "https" || u.Hostname() != "github.com" {
		fatal("only https://github.com downloads are allowed")
	}
	resp, err := client.Get(rawURL)
	check(err)
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		fatal("%s: %s", rawURL, resp.Status)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxArchive+1))
	check(err)
	if len(data) > maxArchive {
		fatal("%s is larger than %d bytes", rawURL, maxArchive)
	}
	return data
}

// verify checks a detached signature with a throwaway keyring holding only the pinned release key.
// gpg runs inside a temporary folder and is given only relative names: gpg from Git for Windows (an MSYS
// program) and a native Windows gpg disagree about absolute paths, and relative names work for both.
func verify(gpg, keyFile string, archive, sig []byte) error {
	work, err := os.MkdirTemp("", "crs-verify-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(work)
	key, err := os.ReadFile(keyFile)
	if err != nil {
		return err
	}
	for name, data := range map[string][]byte{"key.asc": key, "a.tar.gz": archive, "a.tar.gz.asc": sig} {
		if err := os.WriteFile(filepath.Join(work, name), data, 0o600); err != nil {
			return err
		}
	}
	if err := os.Mkdir(filepath.Join(work, "home"), 0o700); err != nil {
		return err
	}
	run := func(args ...string) (string, error) {
		cmd := exec.Command(gpg, append([]string{"--homedir", "home", "--batch", "--no-tty"}, args...)...)
		cmd.Dir = work
		var buf bytes.Buffer
		cmd.Stdout, cmd.Stderr = &buf, &buf
		err := cmd.Run()
		return buf.String(), err
	}
	if out, err := run("--import", "key.asc"); err != nil {
		return fmt.Errorf("importing the pinned key: %v\n%s", err, out)
	}
	out, err := run("--with-colons", "--fingerprint")
	if err != nil {
		return err
	}
	var keyFingerprint string
	for _, line := range strings.Split(out, "\n") {
		if strings.HasPrefix(line, "fpr:") {
			keyFingerprint = strings.Split(line, ":")[9]
			break
		}
	}
	if keyFingerprint != pinnedFingerprint {
		return fmt.Errorf("the key file holds %s, not the pinned %s", keyFingerprint, pinnedFingerprint)
	}
	out, err = run("--status-fd", "1", "--verify", "a.tar.gz.asc", "a.tar.gz")
	if err != nil {
		return fmt.Errorf("gpg: %v\n%s", err, out)
	}
	valid := false
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 || fields[0] != "[GNUPG:]" {
			continue
		}
		switch fields[1] {
		case "BADSIG", "ERRSIG", "EXPSIG", "EXPKEYSIG", "REVKEYSIG", "NO_PUBKEY":
			return fmt.Errorf("gpg reported %s", fields[1])
		case "VALIDSIG":
			if len(fields) < 12 || !strings.EqualFold(fields[2], pinnedFingerprint) || !strings.EqualFold(fields[len(fields)-1], pinnedFingerprint) {
				return fmt.Errorf("the signature was not made by the pinned key: %s", line)
			}
			valid = true
		}
	}
	if !valid {
		return fmt.Errorf("no valid signature reported:\n%s", out)
	}
	return nil
}

// extract returns the wanted files by their embedded name.
func extract(archive []byte, version string) map[string][]byte {
	zr, err := gzip.NewReader(bytes.NewReader(archive))
	check(err)
	tr := tar.NewReader(zr)
	files := map[string][]byte{}
	prefix := "coreruleset-" + version + "/"
	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		check(err)
		if header.Typeflag != tar.TypeReg {
			continue // directories; links and anything else are never extracted
		}
		if !strings.HasPrefix(header.Name, prefix) || !entryShape.MatchString(header.Name) {
			continue
		}
		if header.Size > maxFile || len(files) >= maxFiles {
			fatal("%s is too large or the archive holds too many files", header.Name)
		}
		data, err := io.ReadAll(io.LimitReader(tr, maxFile+1))
		check(err)
		name := strings.TrimPrefix(strings.TrimPrefix(header.Name, prefix), "rules/")
		files[name] = data
	}
	if _, ok := files["REQUEST-901-INITIALIZATION.conf"]; !ok || files["crs-setup.conf.example"] == nil {
		fatal("the archive does not look like release %s of the CRS", version)
	}
	return files
}

func install(out, version, source string, archive, sig []byte, files map[string][]byte) error {
	staging := filepath.Join(out, ".owasp_crs.new")
	if err := os.RemoveAll(staging); err != nil {
		return err
	}
	if err := os.MkdirAll(staging, 0o755); err != nil {
		return err
	}
	sums := map[string]string{}
	for name, data := range files {
		if strings.ContainsAny(name, `/\`) || name == "" || name[0] == '.' || name[0] == '_' {
			return fmt.Errorf("unexpected file name %q", name)
		}
		if err := os.WriteFile(filepath.Join(staging, name), data, 0o644); err != nil {
			return err
		}
		sums[name] = hash(data)
	}
	final := filepath.Join(out, "owasp_crs")
	if err := os.RemoveAll(final); err != nil {
		return err
	}
	if err := os.Rename(staging, final); err != nil {
		return err
	}
	names := make([]string, 0, len(sums))
	for n := range sums {
		names = append(names, n)
	}
	sort.Strings(names)
	p := provenance{Version: version, Source: source, ArchiveSHA256: hash(archive), SignatureSHA256: hash(sig),
		SignerFingerprint: pinnedFingerprint, SignatureVerifiedUTC: time.Now().UTC().Format(time.RFC3339), Files: sums}
	raw, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(out, "provenance.json"), append(raw, '\n'), 0o644)
}
