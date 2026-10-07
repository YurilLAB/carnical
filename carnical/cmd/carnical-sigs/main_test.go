// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

type failedOutput struct{}

func (failedOutput) Write([]byte) (int, error) { return 0, io.ErrClosedPipe }

// This command had no test home. Its exit status on output failure is a CLI
// contract, independent of the importer or file-serialization implementation.
func TestCommandOutput(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rule.conf")
	if err := os.WriteFile(path, []byte(`SecRule ARGS "@contains attack" "id:1,phase:2,deny"`), 0600); err != nil {
		t.Fatal(err)
	}
	for _, broken := range []bool{false, true} {
		t.Run(map[bool]string{false: "output delivered", true: "output failed"}[broken], func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			var output io.Writer = &stdout
			if broken {
				output = failedOutput{}
			}
			code := run([]string{"convert", "-format", "seclang", "-in", path, "-out", "-"}, output, &stderr)
			if broken {
				if code != 1 || !strings.Contains(stderr.String(), "output:") {
					t.Fatalf("failed output reported as %d: %s", code, stderr.String())
				}
			} else if code != 0 || stdout.Len() == 0 {
				t.Fatalf("valid conversion failed: %d: %s", code, stderr.String())
			}
		})
	}
	t.Run("private file outputs", func(t *testing.T) {
		for _, existing := range []os.FileMode{0, 0600, 0644} {
			t.Run(existing.String(), func(t *testing.T) {
				dir := t.TempDir()
				out, report, comparison := filepath.Join(dir, "signatures.jsonl"), filepath.Join(dir, "report.json"), filepath.Join(dir, "comparison.json")
				if existing != 0 {
					for _, name := range []string{out, report, comparison} {
						if err := os.WriteFile(name, []byte("previous output"), existing); err != nil {
							t.Fatal(err)
						}
					}
				}
				var stdout, stderr bytes.Buffer
				if code := run([]string{"convert", "-format", "seclang", "-in", path, "-out", out, "-report", report}, &stdout, &stderr); code != 0 {
					t.Fatalf("conversion failed: %d: %s", code, stderr.String())
				}
				lib := filepath.Join(dir, "legacy.jsonl")
				if err := os.WriteFile(lib, nil, 0600); err != nil {
					t.Fatal(err)
				}
				if code := run([]string{"legacy", "-format", "crowdsec", "-sigs", out, "-legacy", lib, "-out", comparison}, &stdout, &stderr); code != 0 {
					t.Fatalf("comparison failed: %d: %s", code, stderr.String())
				}
				for _, name := range []string{out, report, comparison} {
					data, err := os.ReadFile(name)
					if err != nil {
						t.Fatal(err)
					}
					if !json.Valid(bytes.TrimSpace(data)) {
						t.Fatalf("invalid output in %s: %s", name, data)
					}
					info, err := os.Stat(name)
					if err != nil {
						t.Fatal(err)
					}
					if runtime.GOOS != "windows" && info.Mode().Perm() != 0600 {
						t.Errorf("%s permission = %o, want 600", name, info.Mode().Perm())
					}
				}
				leftovers, err := filepath.Glob(filepath.Join(dir, ".carnical-sigs-*"))
				if err != nil || len(leftovers) != 0 {
					t.Fatalf("temporary outputs remain: %v, %v", leftovers, err)
				}
			})
		}
	})
	t.Run("rename failure preserves previous output", func(t *testing.T) {
		dir := t.TempDir()
		out := filepath.Join(dir, "existing")
		if err := os.Mkdir(out, 0700); err != nil {
			t.Fatal(err)
		}
		previous := filepath.Join(out, "previous")
		if err := os.WriteFile(previous, []byte("keep"), 0600); err != nil {
			t.Fatal(err)
		}
		var stdout, stderr bytes.Buffer
		if code := run([]string{"convert", "-format", "seclang", "-in", path, "-out", out}, &stdout, &stderr); code != 1 {
			t.Fatalf("rename failure returned %d: %s", code, stderr.String())
		}
		data, err := os.ReadFile(previous)
		if err != nil || string(data) != "keep" {
			t.Fatalf("previous output changed: %q, %v", data, err)
		}
		leftovers, err := filepath.Glob(filepath.Join(dir, ".carnical-sigs-*"))
		if err != nil || len(leftovers) != 0 {
			t.Fatalf("temporary outputs remain: %v, %v", leftovers, err)
		}
	})
}
