// SPDX-License-Identifier: Apache-2.0

package seclang

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/YurilLAB/coraza/carnical/vpatch/importers"
)

// crsDir is the OWASP Core Rule Set embedded in the carnical tree (Apache-2.0): the largest real SecLang there is to run this on.
const crsDir = "../../../crs/owasp_crs"

func TestCRS(t *testing.T) {
	if _, err := os.Stat(crsDir); err != nil {
		t.Skip("no CRS at " + crsDir)
	}
	res, err := Convert(crsDir, importers.Options{})
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
	for _, k := range []string{"internal-error", "malformed-rule", "invalid-rule", "unterminated-quote", "chain-unterminated"} {
		if r.Skipped[k] != 0 {
			t.Errorf("%s: %d (%v)", k, r.Skipped[k], r.Examples[k])
		}
	}
}
