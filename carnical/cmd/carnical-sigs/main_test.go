// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
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
}
