// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"bytes"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestDefaultIsValidAndCompiles(t *testing.T) {
	d := Default()
	wantValid(t, d.Validate())
	if _, err := Compile(d); err != nil {
		t.Fatalf("Compile(Default()): %v", err)
	}
	if d.Mode != ModeBlock || d.Sensitivity != SensitivityNormal || d.WordPress.Enabled {
		t.Fatalf("Default is not block mode, normal sensitivity, WordPress off: %+v", d)
	}
	out, err := Decode([]byte(`{}`))
	wantValid(t, err)
	if !reflect.DeepEqual(out, d.Normalize()) {
		t.Fatalf("an empty document is not Default:\n%+v\n%+v", out, d.Normalize())
	}
}

func TestDecodingLimitsAndStrictness(t *testing.T) {
	long := strings.Repeat("a", MaxStringBytes+1)
	deep := strings.Repeat("[", MaxDepth+2) + strings.Repeat("]", MaxDepth+2)
	hosts := func(n int) string {
		parts := make([]string, n)
		for i := range parts {
			parts[i] = fmt.Sprintf(`"h%d.example.test"`, i)
		}
		return `{"allowed_hosts":[` + strings.Join(parts, ",") + `]}`
	}
	nested := func(depth int) string {
		return `{"api":` + strings.Repeat(`{"a":`, depth) + `1` + strings.Repeat(`}`, depth) + `}`
	}
	tests := []struct {
		name string
		in   string
		path string // "" means it must be accepted
	}{
		{"an empty object", `{}`, ""},
		{"surrounding white space", " \n\t{} \n", ""},
		{"an empty input", ``, "$"},
		{"only white space", "  \n", "$"},
		{"not JSON", `nope`, "$"},
		{"an array", `[]`, "$"},
		{"a string", `"mode"`, "$"},
		{"null", `null`, "$"},
		{"a byte order mark", "\xef\xbb\xbf{}", "$"},
		{"invalid UTF-8 in a note", "{\"note\":\"\xff\"}", "$"},
		{"two documents", `{} {}`, "$"},
		{"trailing text", `{}x`, "$"},
		{"a truncated document", `{"mode":`, "$"},
		{"a trailing comma", `{"mode":"block",}`, "$"},
		{"single quotes", `{'mode':'block'}`, "$"},
		{"an unknown top-level field", `{"colour":"red"}`, "$"},
		{"an unknown nested field", `{"body":{"max_upload_bytes":4096,"x":1}}`, "$"},
		{"an unknown field in a list entry", `{"exclusions":[{"path":"/a/","categories":["xss"],"x":1}]}`, "$"},
		{"a field of another case", `{"Mode":"block"}`, ""}, // encoding/json matches field names without regard to case; the value is what is checked
		{"a repeated field with different case", `{"mode":"block","Mode":"off"}`, "$"},
		{"a repeated field with reversed case", `{"Mode":"off","mode":"block"}`, "$"},
		{"a repeated nested field with different case", `{"wordpress":{"enabled":true,"Enabled":false}}`, "$"},
		{"a repeated field in a list with different case", `{"exclusions":[{"path":"/a/","Path":"/b/","categories":["xss"]}]}`, "$"},
		{"a repeated field with Unicode case folding", `{"schema":1,"ſchema":1}`, "$"},
		{"a repeated field with Kelvin-sign case folding", `{"block_ips":[],"blocK_ips":[]}`, "$"},
		{"a single field with Unicode case folding", `{"ſchema":1}`, ""},
		{"case-sensitive names inside opaque sections", `{"api":{"a":null,"A":{"b":1,"B":2}},"body_formats":{"x":1,"X":2}}`, ""},
		{"case-sensitive nested properties in a mixed-case API section", `{"API":{"properties":{"mode":null,"Mode":true},"nested":[{"a":1,"A":2}]}}`, ""},
		{"typed fields remain strict after an opaque section", `{"api":{"enabled":true,"Enabled":false},"wordpress":{"enabled":true,"Enabled":false}}`, "$"},
		{"an opaque section repeated with different case", `{"api":{},"API":{}}`, "$"},
		{"a repeated opaque property", `{"api":{"a":1,"a":2}}`, "$"},
		{"mixed-case nullable threshold", `{"Threshold":null}`, ""},
		{"case aliases in rule groups", `{"rule_groups":{"sqli":"off","SQLI":"log"}}`, "$"},
		{"a repeated field", `{"mode":"block","mode":"off"}`, "$"},
		{"a repeated nested field", `{"body":{"max_upload_bytes":2048,"max_upload_bytes":4096}}`, "$"},
		{"a repeated field inside a list entry", `{"exclusions":[{"path":"/a/","path":"/b/","categories":["xss"]}]}`, "$"},
		{"null for a string", `{"mode":null}`, "$"},
		{"null for a list", `{"allowed_hosts":null}`, "$"},
		{"null for a section", `{"body":null}`, "$"},
		{"null for the threshold, which may be null", `{"threshold":null}`, ""},
		{"null inside another package's section", `{"api":{"a":null}}`, ""},
		{"a number for a string", `{"mode":1}`, "mode"},
		{"a string for a number", `{"body":{"max_upload_bytes":"4096"}}`, "body.max_upload_bytes"},
		{"a fraction for a whole number", `{"body":{"max_upload_bytes":4096.5}}`, "body.max_upload_bytes"},
		{"an exponent for a whole number", `{"body":{"max_upload_bytes":4e3}}`, "body.max_upload_bytes"},
		{"a number too big for any integer", `{"body":{"max_upload_bytes":99999999999999999999}}`, "body.max_upload_bytes"},
		{"a number of enormous length", `{"threshold":` + strings.Repeat("9", 40) + `}`, "$"},
		{"a negative number where one is needed", `{"body":{"max_upload_bytes":-1}}`, "body.max_upload_bytes"},
		{"a boolean for a string", `{"mode":true}`, "mode"},
		{"an object for a list", `{"allowed_hosts":{"a":1}}`, "allowed_hosts"},
		{"a list for an object", `{"body":[]}`, "body"},
		{"a string longer than allowed", `{"note":"` + long + `"}`, "$"},
		{"nesting deeper than allowed", `{"allowed_hosts":` + deep + `}`, "$"},
		{"a section nested at its limit", nested(MaxSectionDepth - 1), ""},
		{"a section nested past its limit", nested(MaxSectionDepth + 1), "api"},
		{"a section that is not an object", `{"api":[1,2]}`, "api"},
		{"a section field name with a space", `{"api":{"a b":1}}`, "api"},
		{"a section field name with a quote", `{"api":{"a\"b":1}}`, "api"},
		{"a section field name that is too long", `{"api":{"` + strings.Repeat("k", MaxSectionKeyBytes+1) + `":1}}`, "api"},
		{"a section field name with a control character", `{"api":{"a\u0001b":1}}`, "api"},
		{"a section field name with an override character", `{"api":{"a\u202eb":1}}`, "api"},
		{"a section field name that is a path", `{"api":{"/v1/users/{id}":{"limit":5}}}`, ""},
		{"a section over its size", `{"api":{"k":"` + strings.Repeat("v", 200) + `","big":[` + strings.Repeat(`"`+strings.Repeat("x", 100)+`",`, 3000) + `"x"]}}`, "api"},
		{"a document over the size limit", `{"note":"` + strings.Repeat("a", MaxPolicyBytes) + `"}`, "$"},
		{"the wrong schema", `{"schema":2}`, "schema"},
		{"schema zero", `{"schema":0}`, "schema"},
		{"a hundred hosts", hosts(MaxHosts), ""},
		{"more hosts than allowed", hosts(MaxHosts + 1), "allowed_hosts"},
		{"a note with a control character", `{"note":"a\u0000b"}`, "note"},
		{"a note with a line break, which is allowed", `{"note":"a\nb"}`, ""},
		{"a note with a carriage return", `{"note":"a\rb"}`, "note"},
	}
	if len(tests) < 15 {
		t.Fatal("the table lost rows")
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p, err := Decode([]byte(tc.in))
			if tc.path == "" {
				wantValid(t, err)
				return
			}
			wantInvalid(t, err, tc.path)
			if !reflect.DeepEqual(p, Policy{}) {
				t.Fatalf("a refused document returned a policy: %+v", p)
			}
		})
	}
}

// A document made to cost a lot must cost little: it is bounded by its size, which is bounded.
func TestDecodingAHostileDocumentIsFast(t *testing.T) {
	docs := map[string]string{
		"many short strings":    `{"allowed_hosts":[` + strings.Repeat(`"a",`, 200000) + `"a"]}`,
		"many empty arrays":     `{"allowed_hosts":[` + strings.Repeat(`[],`, 200000) + `[]]}`,
		"many fields":           `{"api":{` + strings.Repeat(`"k":1,`, 1) + `"z":1}}`,
		"deep and wide section": `{"api":` + strings.Repeat(`{"a":[`, 11) + strings.Repeat(`1,`, 50000) + `1` + strings.Repeat(`]}`, 11) + `}`,
	}
	for name, doc := range docs {
		t.Run(name, func(t *testing.T) {
			if len(doc) > MaxPolicyBytes {
				t.Skipf("the document is %d bytes, over the size limit, which is the first check", len(doc))
			}
			start := time.Now()
			Decode([]byte(doc))
			if d := time.Since(start); d > 3*time.Second {
				t.Fatalf("took %s", d)
			}
		})
	}
}

func TestADocumentRoundTripsAndKeepsItsMeaning(t *testing.T) {
	full := `{
	  "schema": 1, "revision": 41, "mode": "monitor", "sensitivity": "strict", "threshold": 7,
	  "body": {"max_upload_bytes": 8388608, "max_form_bytes": 262144},
	  "allowed_methods": ["put","POST","get","delete"],
	  "allowed_hosts": ["WWW.Example.test", "example.test", "www.example.test"],
	  "rule_groups": {"xss": "log", "sqli": "on", "lfi": "off"},
	  "exclusions": [
	    {"path": "/editor/", "categories": ["xss","sqli"], "targets": ["ARG:Content", "args"], "note": " keeps the editor working "},
	    {"path": "/api/", "categories": ["rce"]}],
	  "custom_rules": [
	    {"id": 9, "field": "Header:Referer", "operator": "contains", "value": "casino", "action": "block", "note": "spam"},
	    {"id": 2, "field": "args", "operator": "pm", "values": ["poker","viagra","poker"], "action": "log"},
	    {"id": 5, "field": "path", "operator": "rx", "value": "^/old-(admin|panel)/", "case_sensitive": true, "action": "block"}],
	  "allow_ips": ["203.0.113.9", "198.51.100.77/24", "::ffff:192.0.2.1"],
	  "block_ips": ["192.0.2.0/24", "2001:DB8:BAD::/48"],
	  "allow_paths": ["/webhook/stripe", "/hooks/"],
	  "paths": {"allow_encoded_slash": true},
	  "uploads": {"allow_script_names": false},
	  "wordpress": {"enabled": true, "login_per_minute": 5},
	  "responses": {"inspect": true},
	  "deny_headers": ["X_Forwarded_Host", "next-action"],
	  "framework": {"deny_next_action": true},
	  "vpatch": {"tiers": ["Verified","community"], "software": ["WordPress", "woocommerce@9.3"]},
	  "api_mode": "monitor",
	  "api": {"z": [3,2,1], "a": {"y": 1.50, "x": "<tag>"}},
	  "body_formats": {"allowed_types": ["application/json"]},
	  "note": "  my policy\nsecond line  "
	}`
	p, err := Decode([]byte(full))
	wantValid(t, err)
	if p.Revision != 41 || *p.Threshold != 7 || p.Sensitivity != SensitivityStrict {
		t.Fatalf("scalars: %+v", p)
	}
	if !reflect.DeepEqual(p.AllowedMethods, []string{"DELETE", "GET", "POST", "PUT"}) {
		t.Errorf("methods %v", p.AllowedMethods)
	}
	if !reflect.DeepEqual(p.AllowedHosts, []string{"example.test", "www.example.test"}) {
		t.Errorf("hosts %v", p.AllowedHosts)
	}
	if !reflect.DeepEqual(p.AllowIPs, []string{"192.0.2.1/32", "198.51.100.0/24", "203.0.113.9/32"}) {
		t.Errorf("allow_ips %v (an IPv4-mapped address is the IPv4 address; host bits are cleared)", p.AllowIPs)
	}
	if !reflect.DeepEqual(p.BlockIPs, []string{"192.0.2.0/24", "2001:db8:bad::/48"}) {
		t.Errorf("block_ips %v", p.BlockIPs)
	}
	if !reflect.DeepEqual(p.DenyHeaders, []string{"next-action", "x-forwarded-host"}) {
		t.Errorf("deny_headers %v", p.DenyHeaders)
	}
	if !reflect.DeepEqual(p.VPatch, VPatchOptions{Tiers: []string{"community", "verified"}, Software: []string{"woocommerce@9.3", "wordpress"}}) {
		t.Errorf("vpatch %+v", p.VPatch)
	}
	if p.CustomRules[0].ID != 2 || !reflect.DeepEqual(p.CustomRules[0].Values, []string{"poker", "viagra"}) || p.CustomRules[1].Field != "path" || p.CustomRules[2].Field != "header:referer" {
		t.Errorf("custom rules %+v", p.CustomRules)
	}
	if p.Exclusions[0].Path != "/api/" || !reflect.DeepEqual(p.Exclusions[1].Targets, []string{"arg:content", "args"}) || p.Exclusions[1].Note != "keeps the editor working" {
		t.Errorf("exclusions %+v", p.Exclusions)
	}
	if _, on := p.RuleGroups["sqli"]; on || p.RuleGroups["xss"] != GroupLog || p.RuleGroups["lfi"] != GroupOff {
		t.Errorf("rule groups %v: a group that is on is left out", p.RuleGroups)
	}
	if string(p.API) != `{"a":{"x":"\u003ctag\u003e","y":1.50},"z":[3,2,1]}` {
		t.Errorf("api is not in canonical form: %s", p.API)
	}
	if p.Note != "my policy\nsecond line" {
		t.Errorf("note %q", p.Note)
	}

	enc, err := Encode(p)
	wantValid(t, err)
	again, err := Decode(enc)
	wantValid(t, err)
	if !reflect.DeepEqual(again, p) {
		t.Fatalf("Decode(Encode(p)) is not p:\n%+v\n%+v", again, p)
	}
	enc2, _ := Encode(again)
	if !bytes.Equal(enc, enc2) {
		t.Fatalf("the encoding is not stable:\n%s\n%s", enc, enc2)
	}
	if !json.Valid(enc) {
		t.Fatal("the encoding is not JSON")
	}
	if !reflect.DeepEqual(p.Normalize(), p) {
		t.Fatal("a decoded policy is not in normal form")
	}
}

func TestNormalizeIsIdempotentAndHashIsContentOnly(t *testing.T) {
	t.Run("ambiguous group names remain invalid and deterministic", func(t *testing.T) {
		p := Default()
		p.RuleGroups = map[string]GroupState{"sqli": GroupOff, "SQLI": GroupLog}
		before, _ := json.Marshal(p)
		q := p.Normalize()
		if len(q.RuleGroups) != 2 {
			t.Fatal("normalization discarded an ambiguous group name")
		}
		for i := 0; i < 128; i++ {
			if !reflect.DeepEqual(q, p.Normalize()) || !reflect.DeepEqual(q, q.Normalize()) || p.Hash() != q.Hash() {
				t.Fatal("ambiguous policy normalization or hashing is not stable")
			}
		}
		after, _ := json.Marshal(p)
		if !bytes.Equal(before, after) {
			t.Fatal("normalization modified the original group map")
		}
	})
	a, err := Decode([]byte(`{"allowed_methods":["POST","GET"],"allowed_hosts":["B.test","a.test"],"block_ips":["10.1.2.3/8","192.0.2.1"],"revision":3}`))
	wantValid(t, err)
	b, err := Decode([]byte(`{"revision":99,"block_ips":["192.0.2.1/32","10.0.0.0/8","10.9.9.9/8"],"allowed_hosts":["a.test","b.test","A.TEST"],"allowed_methods":["get","post"]}`))
	wantValid(t, err)
	if a.Hash() != b.Hash() {
		t.Errorf("the same policy written two ways has two hashes:\n%s\n%s", a.Hash(), b.Hash())
	}
	if len(a.Hash()) != 64 {
		t.Errorf("hash %q is not a SHA-256 in hexadecimal", a.Hash())
	}
	c := a
	c.Note = "changed"
	if c.Hash() == a.Hash() {
		t.Error("a change of note did not change the hash")
	}
	d := a
	d.Mode = ModeMonitor
	if d.Hash() == a.Hash() {
		t.Error("a change of mode did not change the hash")
	}
	if !reflect.DeepEqual(a.Normalize().Normalize(), a.Normalize()) {
		t.Error("Normalize is not idempotent")
	}
	withDefaults := Default()
	withDefaults.RuleGroups = map[string]GroupState{"SQLI": GroupOn}
	if withDefaults.Hash() != Default().Hash() {
		t.Error("a known default group changed the policy hash")
	}
	if Default().Hash() == "" || Default().Hash() != Default().Hash() {
		t.Error("the hash of Default is not stable")
	}
	bad := Default()
	bad.API = json.RawMessage(`{not json`)
	if bad.Hash() != "" {
		t.Error("a policy that cannot be encoded has a hash")
	}
	if _, err := Encode(bad); err == nil {
		t.Error("Encode accepted an invalid policy")
	}
}

func TestNormalizeDoesNotChangeItsInput(t *testing.T) {
	p := Default()
	p.AllowedMethods = []string{"post", "get"}
	p.AllowIPs = []string{"192.0.2.9", "10.0.0.1"}
	p.CustomRules = []CustomRule{{ID: 2, Field: "ARGS", Operator: OpPM, Values: []string{"b", "a"}, Action: ActionLog}, {ID: 1, Field: "args", Operator: OpContains, Value: "x", Action: ActionLog}}
	th := 4
	p.Threshold = &th
	before, _ := json.Marshal(p)
	q := p.Normalize()
	q.AllowedMethods[0] = "X"
	q.CustomRules[0].Value = "changed"
	*q.Threshold = 99
	after, _ := json.Marshal(p)
	if !bytes.Equal(before, after) {
		t.Fatalf("Normalize changed what it was given:\n%s\n%s", before, after)
	}
}

// Limits that are checked before anything is decoded say so in their own words, so a limit that stops being checked is noticed
// even when a later check would refuse the same document for another reason.
func TestLimitsAreCheckedBeforeDecodingAndSaySo(t *testing.T) {
	tokens := `{"allowed_hosts":[` + strings.Repeat("0,", MaxTokens+10) + `0]}`
	tests := []struct {
		name string
		doc  []byte
		want string
	}{
		{"a document over the size limit", bytes.Repeat([]byte(" "), MaxPolicyBytes+1), "larger than"},
		{"more values than allowed", []byte(tokens), "more than"},
		{"nesting past the limit", []byte(strings.Repeat("[", MaxDepth+1)), "deeper than"},
		{"a field given twice", []byte(`{"mode":"block","mode":"block"}`), "given twice"},
		{"null where a value is needed", []byte(`{"mode":null}`), "null"},
		{"text that is not UTF-8", []byte("{\"note\":\"\xff\"}"), "UTF-8"},
		{"a string over the limit", []byte(`{"note":"` + strings.Repeat("a", MaxStringBytes+1) + `"}`), "longer than"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if len(tc.doc) > MaxPolicyBytes+1 {
				t.Skipf("the document is %d bytes", len(tc.doc))
			}
			_, err := Decode(tc.doc)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got %v, want a message with %q", err, tc.want)
			}
		})
	}
}
