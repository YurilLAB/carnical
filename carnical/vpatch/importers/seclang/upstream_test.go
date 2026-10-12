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
		skip string             // or why the rule is refused
		each []vpatch.Condition // or, when the rule becomes one signature per alternative, the condition of each
	}{
		{name: "@rx keeps Coraza's dot-all and multi-line flags", rule: `SecRule ARGS:q "@rx union.*select" "id:1,phase:2,deny,t:lowercase"`,
			want: []vpatch.Condition{{Operator: "rx", Pattern: "union.*select", Flags: "sm", Targets: []string{"arg:q"}, Transforms: []string{"lowercase"}}}},
		{name: "@within is a word list for the whole value, not an @rx", rule: `SecRule REQUEST_METHOD "!@within GET POST" "id:2,phase:1,deny"`,
			want: []vpatch.Condition{{Operator: "rx", Pattern: "^(?:GET|POST)$", Targets: []string{"method"}, Negate: true}}},
		{name: "a negated test of a named argument is refused, as a request may repeat it", rule: `SecRule ARGS:role "!@streq user" "id:3,phase:2,deny"`,
			skip: "negated-on-many-values"},
		{name: "a quote after an even run of backslashes closes the operator, as in Coraza", rule: `SecRule ARGS:f "@rx \.\.\\" "id:4,phase:2,deny"`,
			want: []vpatch.Condition{{Operator: "rx", Pattern: `\.\.\\`, Flags: "sm", Targets: []string{"arg:f"}}}},
		{name: "white space around the operator argument is trimmed, as in Coraza", rule: `SecRule REQUEST_METHOD "@streq PUT " "id:5,phase:1,deny"`,
			want: []vpatch.Condition{{Operator: "equals", Pattern: "PUT", Targets: []string{"method"}}}},
		{name: "a chained link with its own id is still checked, so its multiMatch is refused",
			rule: "SecRule REQUEST_FILENAME \"@streq /a\" \"id:6,phase:2,deny,chain\"\nSecRule ARGS:x \"@rx ^%41$\" \"id:7,multiMatch,t:urlDecode\"",
			skip: "multimatch"},
		{name: "a negated test of the body is not guarded, as Coraza's REQUEST_BODY is an empty value when there is none",
			rule: `SecRule REQUEST_BODY "!@rx ^token=" "id:8,phase:2,deny"`,
			want: []vpatch.Condition{{Operator: "rx", Pattern: "^token=", Flags: "sm", Targets: []string{"body"}, Negate: true}}},
		{name: "a negated test of several variables fires when any one fails, as in Coraza",
			rule: `SecRule REQUEST_BODY|REQUEST_URI "!@rx zzz" "id:9,phase:2,deny"`,
			each: []vpatch.Condition{{Operator: "rx", Pattern: "zzz", Flags: "sm", Targets: []string{"body"}, Negate: true},
				{Operator: "rx", Pattern: "zzz", Flags: "sm", Targets: []string{"uri"}, Negate: true}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res := ConvertBytes("t.conf", []byte(tt.rule+"\n"), importers.Options{Revision: "t1"})
			if tt.skip != "" {
				if len(res.Signatures) != 0 || res.Report.Skipped[tt.skip] != 1 {
					t.Fatalf("signatures %d, skipped %v, want it skipped as %s", len(res.Signatures), res.Report.Skipped, tt.skip)
				}
				return
			}
			if tt.each != nil {
				var got []vpatch.Condition
				for _, s := range res.Signatures {
					got = append(got, s.Condition)
				}
				if !reflect.DeepEqual(got, tt.each) {
					t.Fatalf("got\n  %+v\nwant\n  %+v", got, tt.each)
				}
				return
			}
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
