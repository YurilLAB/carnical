// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"bytes"
	"encoding/json"
	"reflect"
	"regexp"
	"strings"
	"testing"
	"unicode/utf8"
)

// FuzzDecode feeds the policy decoder arbitrary bytes. It must never panic. Whatever it accepts must be valid, must be in normal
// form, must survive a round trip through its own encoding, must compile, and must compile to rules that pass the line check.
func FuzzDecode(f *testing.F) {
	f.Add([]byte(`{}`))
	f.Add([]byte(`{"mode":"monitor","sensitivity":"strict","threshold":7}`))
	f.Add([]byte(`{"custom_rules":[{"id":1,"field":"args","operator":"rx","value":"^a(b|c)$","action":"block"}]}`))
	f.Add([]byte(`{"exclusions":[{"path":"/a/","categories":["xss","sqli"],"targets":["arg:x"]}],"allow_ips":["10.1.2.3/16"],"block_ips":["::ffff:1.2.3.4"]}`))
	f.Add([]byte(`{"api":{"a":null,"b":[1,2,{"c":"d"}]},"body_formats":{"x":1},"api_mode":"enforce"}`))
	f.Add([]byte(`{"mode":"block","mode":"off"}`))
	f.Add([]byte(`{"note":"` + strings.Repeat("a", 100) + `"}`))
	f.Add(readFixtureBytes("testdata/console_policy_bare.json"))
	f.Fuzz(func(t *testing.T, data []byte) {
		p, err := Decode(data)
		if err != nil {
			var e *Error
			if !asError(err, &e) {
				t.Fatalf("an error that is not an *Error: %v", err)
			}
			return
		}
		if err := p.Validate(); err != nil {
			t.Fatalf("Decode accepted a policy that Validate refuses: %v", err)
		}
		if !reflect.DeepEqual(p.Normalize(), p) {
			t.Fatal("a decoded policy is not in normal form")
		}
		enc, err := Encode(p)
		if err != nil {
			t.Fatalf("Encode: %v", err)
		}
		back, err := Decode(enc)
		if err != nil {
			t.Fatalf("Decode(Encode(p)): %v", err)
		}
		if !reflect.DeepEqual(back, p) || p.Hash() != back.Hash() || p.Hash() == "" {
			t.Fatal("the policy changed through its own encoding")
		}
		if again, _ := Encode(back); !bytes.Equal(enc, again) {
			t.Fatal("the encoding is not stable")
		}
		c, err := Compile(p)
		if err != nil {
			t.Fatalf("Compile of a decoded policy: %v", err)
		}
		for _, line := range strings.Split(c.CRS.Before, "\n") {
			if line != "" && !strings.HasPrefix(line, "SecRule ") {
				t.Fatalf("a line of generated SecLang that is not a rule: %q", line)
			}
		}
		if len(Diff(p, p)) != 0 {
			t.Fatal("a policy differs from itself")
		}
	})
}

func asError(err error, target **Error) bool {
	e, ok := err.(*Error)
	if ok {
		*target = e
	}
	return ok
}

func readFixtureBytes(path string) []byte {
	b, _ := readFile(path)
	return b
}

// FuzzGeneratedDirectives builds a policy out of fuzzed strings, keeps every part of it that Validate accepts, compiles it, and
// asserts the property the generated SecLang exists for: the text is exactly as many lines as there are rules, each line passes
// the line check, and the engine reads exactly that many rules from it.
func FuzzGeneratedDirectives(f *testing.F) {
	for _, h := range hostile {
		f.Add(h, "a", "/a/", uint8(0))
		f.Add("x", h, "/a/", uint8(3))
		f.Add("x", "a", h, uint8(5))
	}
	f.Add("a\"\nSecRuleEngine Off", "arg:x", "/%{tx.a}/", uint8(4))
	f.Fuzz(func(t *testing.T, value, name, path string, kind uint8) {
		ops := []Operator{OpContains, OpEquals, OpBeginsWith, OpEndsWith, OpPM, OpRX}
		fields := []string{"args", "path", "uri", "query", "headers", "body", "host", "arg:" + name, "cookie:" + name, "header:" + name, "method", "useragent"}
		p := Default()
		expect := 0
		try := func(change func(*Policy), rules int) {
			cand := deepCopyPolicy(p)
			change(&cand)
			if cand.Validate() == nil {
				p = cand
				expect += rules
			}
		}
		op := ops[int(kind)%len(ops)]
		field := fields[int(kind>>3)%len(fields)]
		rule := CustomRule{ID: 1 + int(kind)%9999, Field: field, Operator: op, CaseSensitive: kind&1 == 1, Action: []Action{ActionBlock, ActionLog}[int(kind>>2)%2]}
		if op == OpPM {
			rule.Values = []string{value, value + "x"}
		} else {
			rule.Value = value
		}
		try(func(q *Policy) { q.CustomRules = []CustomRule{rule} }, 1)
		try(func(q *Policy) {
			q.Exclusions = []Exclusion{{Path: path, Categories: []string{"xss", "sqli"}, Targets: []string{"arg:" + name}}}
		}, 2)
		try(func(q *Policy) { q.AllowPaths = []string{path} }, 1)
		try(func(q *Policy) { q.AllowIPs = []string{value} }, 1)
		try(func(q *Policy) { q.BlockIPs = []string{name} }, 1)
		before, n, err := renderBefore(p.Normalize())
		if err != nil {
			t.Fatalf("a valid policy did not render: %v", err)
		}
		if n != expect {
			t.Fatalf("renderBefore made %d rules, the structure says %d", n, expect)
		}
		lines := 0
		if before != "" {
			lines = strings.Count(before, "\n") + 1
		}
		if lines != expect {
			t.Fatalf("%d lines for %d rules:\n%s", lines, expect, before)
		}
		for _, l := range strings.Split(before, "\n") {
			if l == "" {
				continue
			}
			if !strings.HasPrefix(l, "SecRule ") || strings.Count(l, `"`) != 4 {
				t.Fatalf("a line that is not one rule: %q", l)
			}
		}
		_, rules, err := wafWith(t, before)
		if err != nil {
			t.Fatalf("the engine refused generated rules: %v\n%s", err, before)
		}
		if rules != expect {
			t.Fatalf("the engine read %d rules from %d:\n%s", rules, expect, before)
		}
	})
}

func deepCopyPolicy(p Policy) Policy {
	b, _ := json.Marshal(p)
	var q Policy
	json.Unmarshal(b, &q)
	return q
}

// FuzzCanonRx asserts the two properties an escaper for regular expressions needs: it never panics, and whatever it accepts means
// what the customer's expression meant (the same answer on probes) and passes the check on its own text.
func FuzzCanonRx(f *testing.F) {
	for _, s := range []string{`a`, `^a$`, `(?i)ab+c`, `[^"]`, `\"`, `a\\`, `%{x}`, `\p{Han}`, `a|b|c`, `(a{3}){4}`, `(?m:^x$)`, `\Q"%\E`, "a\nb", `\x41`, `[a-z]+@x\.com`} {
		f.Add(s)
	}
	for _, h := range hostile {
		f.Add(h)
	}
	probes := []string{"", "a", "ab", "abc", "ABC", "x", `"`, `\`, "%", "%{x}", "a b", "a\nb", "\u00e9", "\u65e5\u672c", "aaa", "b", "xyz", "a@x.com", "x\n", "\nx"}
	f.Fuzz(func(t *testing.T, pattern string) {
		out, err := canonRx(pattern)
		if err != nil {
			return
		}
		if err := checkEmittable(out); err != nil {
			t.Fatalf("canonRx made text that fails its own check: %v: %q", err, out)
		}
		if strings.ContainsAny(out, "\n\r\x00\"' ") || !utf8.ValidString(out) {
			t.Fatalf("canonRx made text with a character it must not: %q", out)
		}
		orig, err1 := regexp.Compile(engineFlags + pattern)
		canon, err2 := regexp.Compile(engineFlags + out)
		if err1 != nil || err2 != nil {
			t.Fatalf("a pattern was accepted whose text does not compile: %v %v", err1, err2)
		}
		for _, probe := range append(probes, pattern) {
			if orig.MatchString(probe) != canon.MatchString(probe) {
				t.Fatalf("pattern %q and its written form %q disagree about %q", pattern, out, probe)
			}
		}
	})
}

// FuzzPolicyValues builds a Policy from arbitrary JSON without the strict decoder, as code does, and checks that nothing panics,
// that Normalize is idempotent, that Validate is consistent with Compile, and that Diff and Weakens work on anything.
func FuzzPolicyValues(f *testing.F) {
	f.Add([]byte(`{}`))
	f.Add([]byte(`{"mode":"x","allowed_hosts":["A"],"block_ips":["1.2.3.4/8","bad"],"custom_rules":[{"id":-1,"operator":"rx","value":"("}]}`))
	f.Add([]byte(`{"exclusions":[{"path":"/","categories":[]}],"rule_groups":{"x":"y","sqli":"off"},"api":{"a":1}}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		var p Policy
		if json.Unmarshal(data, &p) != nil {
			return
		}
		n := p.Normalize()
		if !reflect.DeepEqual(n.Normalize(), n) {
			t.Fatal("Normalize is not idempotent")
		}
		verr := p.Validate()
		_, cerr := Compile(p)
		if (verr == nil) != (cerr == nil) {
			t.Fatalf("Validate says %v and Compile says %v", verr, cerr)
		}
		_ = p.Hash()
		_ = Diff(p, Default())
		_ = Weakens(Default(), p)
		_ = Confirm(p, Default())
		if verr == nil {
			if _, err := Encode(p); err != nil {
				t.Fatalf("Encode of a valid policy: %v", err)
			}
		}
	})
}

// FuzzFromConsoleExport feeds the converter arbitrary bytes: no panic, and whatever it returns is a policy that Validate accepts and
// Compile compiles.
func FuzzFromConsoleExport(f *testing.F) {
	for _, name := range []string{"console_export_defaults.json", "console_export_tuned.json", "console_policy_bare.json"} {
		f.Add(readFixtureBytes("testdata/" + name))
	}
	f.Add([]byte(`{"site_firewall_policy":1,"policy":{"rules":[{"id":"SITE-0001","action":"block","score":9,"targets":["a","b","uploads","path"],"operator":"rx","pattern":"(","transforms":["x"]}]}}`))
	f.Add([]byte(`{"site_firewall_policy":1,"policy":{"exclusions":[{"path":"/a/","categories":["x"],"targets":["uploads"]}],"allow_ips":["1.2.3.4/0",5,null]}}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		p, skipped, err := FromConsoleExport(data)
		if err != nil {
			if len(skipped) != 0 {
				t.Fatal("an error with a list")
			}
			return
		}
		if err := p.Validate(); err != nil {
			t.Fatalf("a converted policy is not valid: %v", err)
		}
		if _, err := Compile(p); err != nil {
			t.Fatalf("a converted policy does not compile: %v", err)
		}
		if len(skipped) > 500 {
			t.Fatalf("%d lines", len(skipped))
		}
		for _, s := range skipped {
			if strings.ContainsAny(s, "\n\r") || !utf8.ValidString(s) {
				t.Fatalf("a line that is not plain text: %q", s)
			}
		}
	})
}
