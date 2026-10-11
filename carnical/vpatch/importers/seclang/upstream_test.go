// SPDX-License-Identifier: Apache-2.0

package seclang

import (
	"encoding/json"
	"os"
	"reflect"
	"testing"

	"github.com/YurilLAB/coraza/carnical/vpatch"
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

// TestRuleMapping converts one rule at a time and checks the conditions it becomes; TestCRS above checks only the totals.
func TestRuleMapping(t *testing.T) {
	tests := []struct {
		name string
		rule string
		want []vpatch.Condition // the main condition, then Also
	}{
		{name: "@rx keeps Coraza's dot-all and multi-line flags", rule: `SecRule ARGS:q "@rx union.*select" "id:1,phase:2,deny,t:lowercase"`,
			want: []vpatch.Condition{{Operator: "rx", Pattern: "union.*select", Flags: "sm", Targets: []string{"arg:q"}, Transforms: []string{"lowercase"}}}},
		{name: "@within is a word list for the whole value, not an @rx", rule: `SecRule REQUEST_METHOD "!@within GET POST" "id:2,phase:1,deny"`,
			want: []vpatch.Condition{{Operator: "rx", Pattern: "^(?:GET|POST)$", Targets: []string{"method"}, Negate: true}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res := ConvertBytes("t.conf", []byte(tt.rule+"\n"), importers.Options{Revision: "t1"})
			if len(res.Signatures) != 1 {
				t.Fatalf("signatures %d, skipped %v, errors %v", len(res.Signatures), res.Report.Skipped, res.Report.Errors)
			}
			s := res.Signatures[0]
			if got := append([]vpatch.Condition{s.Condition}, s.Also...); !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("got\n  %+v\nwant\n  %+v", got, tt.want)
			}
		})
	}
}
