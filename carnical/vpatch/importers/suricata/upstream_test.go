// SPDX-License-Identifier: Apache-2.0

package suricata

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/YurilLAB/coraza/carnical/vpatch/importers"
)

// upstreamDir is where the Emerging Threats Open rules the numbers in docs/signature-formats.md were measured on live (outside the
// carnical tree). The test is skipped when it is absent.
const upstreamDir = "../../../../.attack/upstream/et-open"

func TestUpstream(t *testing.T) {
	if _, err := os.Stat(upstreamDir); err != nil {
		t.Skip("no Emerging Threats checkout at " + upstreamDir)
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
	for _, k := range []string{"internal-error", "malformed-rule", "invalid-rule"} {
		if r.Skipped[k] != 0 {
			t.Errorf("%s: %d (%v)", k, r.Skipped[k], r.Examples[k])
		}
	}
}
