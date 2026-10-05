// SPDX-License-Identifier: Apache-2.0

package apiguard

import (
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// The documentation is part of the product: the table of verdict identifiers in docs/apiguard.md must be the one the code has, and
// the defaults it states must be the defaults the code uses.
func TestTheVerdictTableInTheDocumentationIsTheCodesTable(t *testing.T) {
	data, err := os.ReadFile("../docs/apiguard.md")
	if err != nil {
		t.Fatal(err)
	}
	row := regexp.MustCompile(`^\|\s*(5003\d{3})\s*\|([^|]*)\|([^|]*)\|([^|]*)\|([^|]*)\|`)
	documented := map[int][]string{}
	for _, line := range strings.Split(string(data), "\n") {
		if m := row.FindStringSubmatch(line); m != nil {
			id, _ := strconv.Atoi(m[1])
			if _, dup := documented[id]; dup {
				t.Errorf("%d is in the table twice", id)
			}
			documented[id] = []string{strings.TrimSpace(m[2]), strings.TrimSpace(m[3]), strings.TrimSpace(m[4]), strings.TrimSpace(m[5])}
		}
	}
	inCode := map[int]VerdictInfo{}
	for _, v := range Verdicts() {
		inCode[v.ID] = v
		if v.ID < 5003000 || v.ID > 5003999 {
			t.Errorf("%d is outside the range 5003000 to 5003999", v.ID)
		}
	}
	for id, v := range inCode {
		d, ok := documented[id]
		if !ok {
			t.Errorf("%d (%s) is not in docs/apiguard.md", id, v.Name)
			continue
		}
		if d[0] != v.Name {
			t.Errorf("%d is %q in the code and %q in the documentation", id, v.Name, d[0])
		}
		if d[1] != v.Group {
			t.Errorf("%d: the documentation says group %q, the code %q", id, d[1], v.Group)
		}
		if st := strconv.Itoa(v.Status); v.Status != 0 && d[2] != st {
			t.Errorf("%d: the documentation says status %q, the code %s", id, d[2], st)
		}
	}
	for id := range documented {
		if _, ok := inCode[id]; !ok {
			t.Errorf("%d is in docs/apiguard.md and not in the code", id)
		}
	}
}

func TestEveryVerdictIDIsUniqueAndHasAGroupThatExists(t *testing.T) {
	seen := map[int]bool{}
	groups := map[string]bool{"Methods": true, "BodySize": true, "AuthRate": true, "Rate": true, "Format": true, "MassAssign": true, "Spec": true, "Learned": true, "-": true}
	for _, v := range Verdicts() {
		if seen[v.ID] {
			t.Errorf("%d is listed twice", v.ID)
		}
		seen[v.ID] = true
		if !groups[v.Group] {
			t.Errorf("%d has group %q", v.ID, v.Group)
		}
		if v.Meaning == "" || v.Name == "" || v.Severity == "" {
			t.Errorf("%d is not fully described: %+v", v.ID, v)
		}
		if v.Level == 1 && !strings.HasPrefix(v.Group, "Spec") || v.Level == 2 && v.Group != "Learned" {
			t.Errorf("%d is level %d with group %s", v.ID, v.Level, v.Group)
		}
	}
	// Every verdict a check can produce is in the table.
	for _, set := range []*idSet{&declaredIDs, &learnedIDs} {
		for _, id := range []int{set.pathParam, set.queryParam, set.headerParam, set.cookieParam, set.missingParam, set.contentType, set.bodySchema,
			set.unknownProp, set.readOnly, set.missingProp, set.bodyMissing, set.unexpectedBody, set.unknownQuery, set.tooComplex, set.noCredential} {
			if id != 0 && verdictByID[id] == nil {
				t.Errorf("a check can produce %d, which is not in the table", id)
			}
		}
	}
}
