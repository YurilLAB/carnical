// SPDX-License-Identifier: Apache-2.0

package nuclei

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/YurilLAB/coraza/carnical/vpatch/importers"
)

// upstreamDir is where the nuclei-templates checkout the numbers in docs/signature-formats.md were measured on lives (outside the
// carnical tree). The test is skipped when it is absent.
const upstreamDir = "../../../../.attack/upstream/nuclei-templates/http"

func TestUpstream(t *testing.T) {
	if _, err := os.Stat(upstreamDir); err != nil {
		t.Skip("no nuclei-templates checkout at " + upstreamDir)
	}
	res, err := Convert(upstreamDir, importers.Options{})
	if err != nil {
		t.Fatal(err)
	}
	r := res.Report
	b, _ := json.MarshalIndent(r, "", "  ")
	t.Logf("%s", b)
	if r.FilesRead == 0 || r.Signatures == 0 {
		t.Fatalf("nothing converted: %+v", r)
	}
	for _, k := range []string{"invalid-output", "duplicate-id"} {
		if r.Partial[k] != 0 {
			t.Errorf("%s: %d (errors: %v)", k, r.Partial[k], r.Errors)
		}
	}
	for _, k := range []string{"internal-error", "yaml-invalid", "yaml-unsafe", "yaml-too-slow", "yaml-too-large", "invalid-template"} {
		if r.Skipped[k] != 0 {
			t.Errorf("%s: %d (%v)", k, r.Skipped[k], r.Examples[k])
		}
	}
}
