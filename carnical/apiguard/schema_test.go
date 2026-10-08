// SPDX-License-Identifier: Apache-2.0

package apiguard

import (
	"fmt"
	"regexp"
	"strings"
	"testing"
)

// schemaFrom compiles a JSON schema the way an import does (OpenAPI 3.0 rules unless the version is changed).
func schemaFrom(t testing.TB, js string, version ...string) *Schema {
	t.Helper()
	ver := "3.0"
	if len(version) > 0 {
		ver = version[0]
	}
	im := &importer{root: map[string]any{}, ver: ver, rep: &Report{}, budget: importBudget, memo: map[string]*refMemo{}, inProgress: map[string]bool{}, ignored: map[string]int{}}
	s := im.schema(mustParse(t, js), 0)
	if im.err != nil {
		t.Fatal(im.err)
	}
	dropped := 0
	s.prepare(map[*Schema]bool{}, map[string]*regexp.Regexp{}, &dropped)
	return s
}

func TestSchemaValidation(t *testing.T) {
	user := `{"type":"object","required":["name"],"additionalProperties":false,"properties":{
		"id":{"type":"integer","readOnly":true},"name":{"type":"string","minLength":2,"maxLength":8},
		"age":{"type":"integer","minimum":0,"maximum":150},"email":{"type":"string","format":"email"},
		"tags":{"type":"array","items":{"type":"string"},"maxItems":2,"uniqueItems":true}}}`
	tests := []struct {
		name   string
		schema string
		doc    string
		req    bool
		want   vkind
	}{
		{"object that fits", user, `{"name":"alice","age":30,"email":"a@b.example","tags":["x","y"]}`, true, vkNone},
		{"wrong type", user, `{"name":42}`, true, vkType},
		{"required property missing", user, `{"age":3}`, true, vkRequired},
		{"unknown property when additionalProperties is false", user, `{"name":"alice","admin":true}`, true, vkUnknownProp},
		{"read-only property sent in a request", user, `{"name":"alice","id":7}`, true, vkReadOnly},
		{"read-only property in a response is fine", user, `{"name":"alice","id":7}`, false, vkNone},
		{"string too short", user, `{"name":"a"}`, true, vkLength},
		{"string too long", user, `{"name":"abcdefghi"}`, true, vkLength},
		{"number below minimum", user, `{"name":"alice","age":-1}`, true, vkBounds},
		{"number above maximum", user, `{"name":"alice","age":151}`, true, vkBounds},
		{"integer given a fraction", user, `{"name":"alice","age":3.5}`, true, vkType},
		{"integer given 3.0 is an integer", user, `{"name":"alice","age":3.0}`, true, vkNone},
		{"bad email format", user, `{"name":"alice","email":"not-an-email"}`, true, vkFormat},
		{"too many items", user, `{"name":"alice","tags":["a","b","c"]}`, true, vkLength},
		{"repeated items that must be unique", user, `{"name":"alice","tags":["a","a"]}`, true, vkUnique},
		{"item of the wrong type", user, `{"name":"alice","tags":[1]}`, true, vkType},
		{"enum member", `{"enum":["a","b"]}`, `"a"`, true, vkNone},
		{"not an enum member", `{"enum":["a","b"]}`, `"c"`, true, vkEnum},
		{"enum compares numbers by value", `{"enum":[1,2]}`, `2.0`, true, vkNone},
		{"large integer enum member", `{"type":"integer","enum":[9007199254740992]}`, `9007199254740992`, true, vkNone},
		{"distinct large integer is not an enum member", `{"type":"integer","enum":[9007199254740992]}`, `9007199254740993`, true, vkEnum},
		{"const distinguishes large integers", "{\"const\":9007199254740992}", "9007199254740993", true, vkEnum},
		{"exclusive decimal minimum", "{\"type\":\"number\",\"exclusiveMinimum\":1}", "1.0000000000000001", true, vkNone},
		{"exclusive decimal maximum", "{\"type\":\"number\",\"exclusiveMaximum\":1}", "0.99999999999999999", true, vkNone},
		{"tiny nonzero number is not zero", `{"enum":[0]}`, `1e-400`, true, vkEnum},
		{"rounded fraction is not an integer", `{"type":"integer"}`, `1.0000000000000001`, true, vkType},
		{"fraction just above the maximum", `{"type":"number","maximum":1}`, `1.0000000000000001`, true, vkBounds},
		{"fraction just below the minimum", `{"type":"number","minimum":1}`, `0.99999999999999999`, true, vkBounds},
		{"large amount is not a multiple of a cent", `{"type":"number","multipleOf":0.01}`, `10000000.001`, true, vkBounds},
		{"exact decimal multiple of a cent", `{"type":"number","multipleOf":0.01}`, `0.29`, true, vkNone},
		{"numeric spellings must be unique", `{"type":"array","uniqueItems":true}`, `[1,1.0]`, true, vkUnique},
		{"nested numeric spellings must be unique", `{"type":"array","uniqueItems":true}`, `[{"a":1},{"a":1e0}]`, true, vkUnique},
		{"distinct large integers are unique", `{"type":"array","uniqueItems":true}`, `[9007199254740992,9007199254740993]`, true, vkNone},
		{"pattern match", `{"type":"string","pattern":"^[a-z]+$"}`, `"abc"`, true, vkNone},
		{"pattern mismatch", `{"type":"string","pattern":"^[a-z]+$"}`, `"abc1"`, true, vkPattern},
		{"a pattern is not anchored unless it says so", `{"type":"string","pattern":"b"}`, `"abc"`, true, vkNone},
		{"multipleOf", `{"type":"number","multipleOf":0.5}`, `1.5`, true, vkNone},
		{"not a multiple", `{"type":"number","multipleOf":0.5}`, `1.3`, true, vkBounds},
		{"exclusive minimum (3.0 boolean form)", `{"type":"integer","minimum":5,"exclusiveMinimum":true}`, `5`, true, vkBounds},
		{"exclusive minimum allows more", `{"type":"integer","minimum":5,"exclusiveMinimum":true}`, `6`, true, vkNone},
		{"nullable accepts null", `{"type":"string","nullable":true}`, `null`, true, vkNone},
		{"not nullable refuses null", `{"type":"string"}`, `null`, true, vkType},
		{"oneOf exactly one", `{"oneOf":[{"type":"string"},{"type":"integer"}]}`, `3`, true, vkNone},
		{"oneOf with two matches", `{"oneOf":[{"type":"number"},{"type":"integer"}]}`, `3`, true, vkCombinator},
		{"oneOf with none", `{"oneOf":[{"type":"string"},{"type":"integer"}]}`, `true`, true, vkCombinator},
		{"anyOf with one", `{"anyOf":[{"type":"string"},{"type":"integer"}]}`, `"x"`, true, vkNone},
		{"anyOf with none", `{"anyOf":[{"type":"string"},{"type":"integer"}]}`, `1.5`, true, vkCombinator},
		{"allOf all pass", `{"allOf":[{"type":"object","required":["a"]},{"type":"object","required":["b"]}]}`, `{"a":1,"b":2}`, true, vkNone},
		{"allOf one fails", `{"allOf":[{"type":"object","required":["a"]},{"type":"object","required":["b"]}]}`, `{"a":1}`, true, vkRequired},
		{"not passes when the inner fails", `{"not":{"type":"string"}}`, `3`, true, vkNone},
		{"not fails when the inner passes", `{"not":{"type":"string"}}`, `"x"`, true, vkCombinator},
		{"const (3.1)", `{"const":"v1"}`, `"v2"`, true, vkEnum},
		{"additionalProperties as a schema", `{"type":"object","additionalProperties":{"type":"integer"}}`, `{"a":1,"b":"x"}`, true, vkType},
		{"minProperties", `{"type":"object","minProperties":2}`, `{"a":1}`, true, vkLength},
		{"uuid format", `{"type":"string","format":"uuid"}`, `"123e4567-e89b-12d3-a456-426614174000"`, true, vkNone},
		{"bad uuid", `{"type":"string","format":"uuid"}`, `"123e4567-e89b-12d3-a456"`, true, vkFormat},
		{"date format", `{"type":"string","format":"date"}`, `"2026-02-30"`, true, vkFormat},
		{"date-time format", `{"type":"string","format":"date-time"}`, `"2026-02-03T04:05:06Z"`, true, vkNone},
		{"ipv4 format", `{"type":"string","format":"ipv4"}`, `"10.0.0.256"`, true, vkFormat},
		{"uri format", `{"type":"string","format":"uri"}`, `"https://x.example/a?b=c"`, true, vkNone},
		{"int32 range", `{"type":"integer","format":"int32"}`, `2147483648`, true, vkFormat},
		{"unknown format is accepted", `{"type":"string","format":"made-up"}`, `"x"`, true, vkNone},
		{"a keyword for another type is ignored", `{"minLength":5}`, `3`, true, vkNone},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := mustParse(t, tt.doc)
			viol, ok, over := schemaFrom(t, tt.schema, "3.1").validateBody(v, tt.req)
			if over {
				t.Fatal("budget exceeded")
			}
			if ok != (tt.want == vkNone) || viol.kind != tt.want {
				t.Fatalf("got ok=%v kind=%v (%q), want %v", ok, viol.kind, viol.where, tt.want)
			}
		})
	}
}

func TestSchemaViolationNamesComeOnlyFromTheSchema(t *testing.T) {
	s := schemaFrom(t, `{"type":"object","properties":{"address":{"type":"object","properties":{"zip":{"type":"string"}}}}}`)
	viol, ok, _ := s.validateBody(mustParse(t, `{"address":{"zip":5}}`), true)
	if ok || viol.where != "address.zip" {
		t.Fatalf("where = %q", viol.where)
	}
	// A free-form map's key is the visitor's: it must not appear.
	s = schemaFrom(t, `{"type":"object","additionalProperties":{"type":"integer"}}`)
	viol, ok, _ = s.validateBody(mustParse(t, `{"SECRET-KEY-FROM-VISITOR":"x"}`), true)
	if ok || strings.Contains(viol.where, "SECRET") {
		t.Fatalf("where = %q", viol.where)
	}
}

func TestSchemaValidationIsBoundedInWork(t *testing.T) {
	t.Run("numeric work does not expand exponents", func(t *testing.T) {
		s := schemaFrom(t, "{\"type\":\"number\",\"multipleOf\":0.03}")
		for _, raw := range []string{"1e1000000000", "1e-1000000000", "1e999999999999999999999999999999", "0." + strings.Repeat("0", 100000) + "1"} {
			_, ok, over := s.validateBody(Num(raw), true)
			if ok && !over {
				t.Fatalf("unsupported or nonmultiple number accepted")
			}
		}
		unique := schemaFrom(t, "{\"type\":\"array\",\"uniqueItems\":true}")
		if _, _, over := unique.validateBody([]any{Num("0e1000000001"), Num("0")}, true); !over {
			t.Fatal("unsupported numeric uniqueness was not stopped")
		}
		enums := &Schema{enumV: make([]any, 1000)}
		for i := range enums.enumV {
			enums.enumV[i] = Num(fmt.Sprint(i + 1))
		}
		if _, _, over := enums.validateBody(Num("0."+strings.Repeat("0", 50000)+"1"), true); !over {
			t.Fatal("numeric enum comparisons bypassed work limit")
		}
	})

	sc := schemaFrom(t, `{"anyOf":[{"type":"object","properties":{"a":{"type":"integer"}}},{"type":"array","items":{"type":"string"}}]}`)
	big := "[" + strings.Repeat(`"x",`, 50000) + `"x"]`
	start := nowNano()
	_, _, over := sc.validateBody(mustParse(t, big), true)
	if over {
		t.Fatal("an ordinary large body should not exceed the budget")
	}
	// Twenty alternatives, one of which fits, tried for each of 30,000 values: more work than a body is worth.
	branches := strings.Repeat(`{"type":"string"},`, 19) + `{"type":"integer"}`
	dsc := schemaFrom(t, `{"type":"array","items":{"oneOf":[`+branches+`]}}`)
	_, _, over = dsc.validateBody(mustParse(t, "["+strings.Repeat("1,", 30000)+"1]"), true)
	if !over {
		t.Fatal("work that multiplies a large body by many alternatives was not stopped by the work limit")
	}
	if elapsed := nowNano() - start; elapsed > 2e9 {
		t.Fatalf("took %v ns", elapsed)
	}
}

func TestPatternsAreRE2AndBounded(t *testing.T) {
	tests := []struct {
		name string
		p    string
		ok   bool
	}{
		{"simple", `^[a-z]+$`, true},
		{"anchors and classes", `^\d{3}-\d{4}$`, true},
		{"alternation", `^(a|b|c)$`, true},
		{"lookahead is not RE2", `^(?=a)a$`, false},
		{"backreference is not RE2", `^(a)\1$`, false},
		{"possessive quantifier is not RE2", `a++`, false},
		{"unbalanced", `(a`, false},
		{"nested counted repeats multiply", `((a{100}){100}){100}`, false},
		{"one large counted repeat", `a{1000}`, true},
		{"too long", strings.Repeat("a", 600), false},
		{"empty", ``, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := compilePattern(tt.p)
			if (err == nil) != tt.ok {
				t.Fatalf("err = %v, want ok=%v", err, tt.ok)
			}
		})
	}
	// A pattern that cannot run is dropped, and the schema accepts what the pattern would have refused.
	s := schemaFrom(t, `{"type":"string","pattern":"^(?=a)a$"}`)
	if _, ok, _ := s.validateBody("zzz", true); !ok {
		t.Fatal("a dropped pattern must not refuse")
	}
}

func TestPatternMatchingRefusesVeryLongSubjects(t *testing.T) {
	s := schemaFrom(t, `{"type":"string","pattern":"^a+$"}`)
	long := `"` + strings.Repeat("a", maxPatternSubject+1) + `"`
	if viol, ok, _ := s.validateBody(mustParse(t, long), true); ok || viol.kind != vkPattern {
		t.Fatal("a subject longer than the limit must not be matched against a pattern")
	}
}
