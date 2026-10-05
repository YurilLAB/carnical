// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"fmt"
	"reflect"
	"sort"
	"strings"
	"testing"
)

func skippedHas(skipped []string, parts ...string) bool {
	for _, s := range skipped {
		ok := true
		for _, p := range parts {
			ok = ok && strings.Contains(s, p)
		}
		if ok {
			return true
		}
	}
	return false
}

// The export of a new site: nothing set. The result is Default, except for the mode, which the PHP console takes from config.php
// (built-in default monitor), and the list says so.
func TestConsoleExportOfTheDefaults(t *testing.T) {
	p, skipped, err := FromConsoleExport(readFixture(t, "console_export_defaults.json"))
	wantValid(t, err)
	want := Default()
	want.Mode = ModeMonitor
	if !reflect.DeepEqual(p, want.Normalize()) {
		t.Fatalf("not the default policy in monitor mode:\n%+v\n%+v", p, want.Normalize())
	}
	if len(skipped) != 1 || !skippedHas(skipped, "mode:", "monitor") {
		t.Fatalf("skipped = %v: want one line, about the mode", skipped)
	}
	if _, err := Compile(p); err != nil {
		t.Fatal(err)
	}
}

// A real export of a tuned site, written by the PHP console's own code (testdata/make_exports.php builds it from Policy::blank()
// and Policy::ruleFromForm), with every setting that cannot be carried over exactly.
func TestConsoleExportOfATunedSite(t *testing.T) {
	p, skipped, err := FromConsoleExport(readFixture(t, "console_export_tuned.json"))
	wantValid(t, err)

	t.Run("what is carried", func(t *testing.T) {
		if p.Mode != ModeBlock || p.Sensitivity != SensitivityRelaxed {
			t.Errorf("mode %s, sensitivity %s", p.Mode, p.Sensitivity)
		}
		// threshold 6, relaxed: the PHP firewall stops at ceil(6 * 3 / 2) = 9
		if p.Threshold == nil || *p.Threshold != 9 {
			t.Errorf("threshold %v, want 9", p.Threshold)
		}
		if got := map[string]GroupState{"xss": GroupLog, "lfi": GroupOff, "protocol": GroupLog}; !reflect.DeepEqual(p.RuleGroups, got) {
			t.Errorf("rule groups %v, want %v", p.RuleGroups, got)
		}
		if !p.Responses.Inspect {
			t.Error("outbound.inspect was not carried")
		}
		if !reflect.DeepEqual(p.AllowIPs, []string{"198.51.100.0/24", "203.0.113.9/32", "2001:db8::/32"}) {
			t.Errorf("allow_ips %v", p.AllowIPs)
		}
		if !reflect.DeepEqual(p.BlockIPs, []string{"192.0.2.0/24", "2001:db8:bad::/48"}) {
			t.Errorf("block_ips %v", p.BlockIPs)
		}
		if !reflect.DeepEqual(p.AllowPaths, []string{"/webhook/stripe"}) {
			t.Errorf("allow_paths %v", p.AllowPaths)
		}
	})

	t.Run("exclusions are never widened", func(t *testing.T) {
		// /api/ whole request; /editor/ xss+sqli on two targets; /mixed/ xss on args (upload dropped); /files/ lfi on filenames (uploads dropped).
		// /upload/ (only an upload category) and "/odd path/" are left out.
		var got []string
		for _, e := range p.Exclusions {
			got = append(got, fmt.Sprintf("%s %v %v", e.Path, e.Categories, e.Targets))
		}
		want := []string{
			"/api/ [rce] []",
			"/editor/ [sqli xss] [arg:content cookie:session]",
			"/files/ [lfi] [filenames]",
			"/mixed/ [xss] [args]",
		}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("exclusions\n%v\nwant\n%v", got, want)
		}
	})

	t.Run("custom rules", func(t *testing.T) {
		type r struct {
			id     int
			field  string
			op     Operator
			action Action
			cs     bool
		}
		var got []r
		for _, c := range p.CustomRules {
			got = append(got, r{c.ID, c.Field, c.Operator, c.Action, c.CaseSensitive})
		}
		want := []r{
			{1, "path", OpRX, ActionLog, false},                 // score 6 is under the 9 that stops a request there: log only
			{2, "header:referer", OpContains, ActionLog, false}, // score 2
			{3, "query", OpRX, ActionBlock, false},              // score 9: blocks alone
			{5, "uri", OpRX, ActionLog, true},                   // a log rule, exact case
			{8, "args", OpPM, ActionLog, false},                 // score 8, under 9
			{9, "cookies", OpRX, ActionBlock, false},            // the second target of rule 3, as a rule of its own
		}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("custom rules\n%+v\nwant\n%+v", got, want)
		}
		for _, c := range p.CustomRules {
			if c.ID == 1 && c.Note != "Old admin area" {
				t.Errorf("the description was not carried as the note: %q", c.Note)
			}
		}
	})

	t.Run("what is not carried is said, one line each, by setting", func(t *testing.T) {
		for _, want := range [][]string{
			{"sensitivity:", "relaxed"},
			{"threshold:", "6", "9"},
			{"block_oversize:"},
			{"contact:"},
			{"timezone:"},
			{"rule_groups.upload"}, {"rule_groups.cve"}, {"rule_groups.wordpress"}, {"rule_groups.probe"},
			{"disabled:", "CRS-942100", "FW-SQLI-0007"},
			{"overrides:", "CRS-941100", "FW-XSS-0003"},
			{"exclusions[3]", "upload"},  // /upload/: no category with a rule group
			{"exclusions[4]", "upload"},  // /mixed/: the upload category dropped
			{"exclusions[5]", "uploads"}, // /files/: the uploads target dropped
			{"exclusions[6]", "path"},    // "/odd path/"
			{"allow_ips:", "0.0.0.0/0"},
			{"allow_ips:", "not an address"},
			{"block_ips:", "10.0.0.0/4"},
			{"allow_paths:", "pay?ment"},
			{"reputation:"},
			{"ips:", "ban_score", "enabled", "login_paths"},
			{"outbound.max_kb"},
			{"stats:", "keep_days"},
			{"log:", "truncate_ip"},
			{"SITE-0001", "score of 6", "log only"},
			{"SITE-0002", "score of 2", "log only"},
			{"SITE-0003", "several parts", "became rules 3, 9"},
			{"SITE-0004", "cannot be used here"},
			{"SITE-0006", "further condition"},
			{"SITE-0007", "base64decode"},
			{"SITE-0008", "score of 8", "log only"},
		} {
			if !skippedHas(skipped, want...) {
				t.Errorf("no line in the list has %q\n%s", want, strings.Join(skipped, "\n"))
			}
		}
		seen := map[string]bool{}
		for _, s := range skipped {
			if seen[s] {
				t.Errorf("a line is given twice: %s", s)
			}
			seen[s] = true
			if strings.TrimSpace(s) == "" || strings.ContainsAny(s, "\n\r") || len(s) > 600 {
				t.Errorf("not a line of plain text: %q", s)
			}
		}
		// What was carried in full is not in the list.
		for _, notWanted := range [][]string{{"mode:"}, {"rule_groups.xss"}, {"rule_groups.lfi"}, {"rule_groups.sqli"}, {"outbound.inspect"}, {"exclusions[1]"}, {"exclusions[2]"}} {
			if skippedHas(skipped, notWanted...) {
				t.Errorf("a setting that was carried is in the list: %v", notWanted)
			}
		}
	})

	t.Run("the result compiles, and what it says survives a round trip", func(t *testing.T) {
		if _, err := Compile(p); err != nil {
			t.Fatal(err)
		}
		enc, err := Encode(p)
		wantValid(t, err)
		back, err := Decode(enc)
		wantValid(t, err)
		if !reflect.DeepEqual(back, p) {
			t.Fatal("the converted policy changes when it is encoded and decoded")
		}
	})
}

func TestConsolePolicyFile(t *testing.T) {
	p, skipped, err := FromConsoleExport(readFixture(t, "console_policy_bare.json"))
	wantValid(t, err)
	if p.Mode != ModeMonitor || p.Sensitivity != SensitivityStrict || !reflect.DeepEqual(p.AllowIPs, []string{"203.0.113.0/24"}) {
		t.Fatalf("%+v", p)
	}
	if !skippedHas(skipped, "sensitivity:", "strict") || len(skipped) != 1 {
		t.Fatalf("skipped %v", skipped)
	}
}

func TestConsoleExportRows(t *testing.T) {
	wrap := func(inner string) string {
		return `{"site_firewall_policy":1,"exported":"2026-10-05T00:00:00Z","site":"S","engine":"1.0.0","rev":3,"policy":` + inner + `}`
	}
	rows := []struct {
		name    string
		in      string
		errPath string // "" means it must convert
		check   func(t *testing.T, p Policy)
		skipped [][]string // each must be in the list
		clean   bool       // the list must be empty
	}{
		{name: "not JSON", in: `nope`, errPath: "$"},
		{name: "empty", in: ``, errPath: "$"},
		{name: "white space", in: "  \n", errPath: "$"},
		{name: "an array", in: `[]`, errPath: "$"},
		{name: "an object that is not an export", in: `{"hello":1}`, errPath: "$"},
		{name: "another export format", in: `{"site_firewall_policy":2,"policy":{}}`, errPath: "site_firewall_policy"},
		{name: "the format as text", in: `{"site_firewall_policy":"1","policy":{}}`, errPath: "site_firewall_policy"},
		{name: "an export with no policy", in: `{"site_firewall_policy":1}`, errPath: "policy"},
		{name: "a policy that is a list", in: `{"site_firewall_policy":1,"policy":[1,2]}`, errPath: "policy"},
		{name: "a policy file of another schema", in: `{"schema":2,"mode":"block"}`, errPath: "$"},
		{name: "a repeated field", in: wrap(`{"mode":"block","mode":"off"}`), errPath: "$"},
		{name: "deeply nested nonsense", in: wrap(`{"rules":` + strings.Repeat("[", 40) + strings.Repeat("]", 40) + `}`), errPath: "$"},
		{name: "mode off", in: wrap(`{"mode":"off","sensitivity":"standard"}`), check: func(t *testing.T, p Policy) {
			if p.Mode != ModeOff || p.Sensitivity != SensitivityNormal {
				t.Fatalf("%+v", p)
			}
		}, clean: true},
		{name: "mode block, standard, no threshold", in: wrap(`{"mode":"block","sensitivity":"standard","threshold":null}`), clean: true, check: func(t *testing.T, p Policy) {
			if p.Mode != ModeBlock || p.Threshold != nil {
				t.Fatalf("%+v", p)
			}
		}},
		{name: "a mode that is not one", in: wrap(`{"mode":"detect"}`), skipped: [][]string{{"mode:", "detect", "monitor was used"}}, check: func(t *testing.T, p Policy) {
			if p.Mode != ModeMonitor {
				t.Fatal(p.Mode)
			}
		}},
		{name: "a threshold with standard sensitivity is exact", in: wrap(`{"mode":"block","threshold":8}`), clean: true, check: func(t *testing.T, p Policy) {
			if p.Threshold == nil || *p.Threshold != 8 {
				t.Fatalf("%v", p.Threshold)
			}
		}},
		{name: "a threshold with strict sensitivity is scaled", in: wrap(`{"mode":"block","sensitivity":"strict","threshold":10}`), skipped: [][]string{{"threshold:", "10", "6"}, {"sensitivity:", "strict"}}, check: func(t *testing.T, p Policy) {
			if p.Threshold == nil || *p.Threshold != 6 {
				t.Fatalf("%v", p.Threshold)
			}
		}},
		{name: "a threshold out of range", in: wrap(`{"mode":"block","threshold":5000}`), skipped: [][]string{{"threshold:", "1 to 1000"}}, check: func(t *testing.T, p Policy) {
			if p.Threshold != nil {
				t.Fatal("a threshold out of range was carried")
			}
		}},
		{name: "rule groups written as a PHP empty array", in: wrap(`{"mode":"block","rule_groups":[]}`), clean: true},
		{name: "a rule group with a state that is not one", in: wrap(`{"mode":"block","rule_groups":{"sqli":"maybe"}}`), skipped: [][]string{{"rule_groups.sqli", "maybe"}}},
		{name: "a rule group this program does not know", in: wrap(`{"mode":"block","rule_groups":{"xyz":"off"}}`), skipped: [][]string{{"rule_groups.xyz", "not a rule group"}}},
		{name: "every group the PHP console has", in: wrap(`{"mode":"block","rule_groups":{"sqli":"off","xss":"off","lfi":"off","rfi":"off","rce":"off","php":"off","java":"off","ssrf":"off","ssti":"off","xxe":"off","upload":"off","scanner":"off","protocol":"off","cve":"off","wordpress":"off","probe":"off","other":"off"}}`),
			skipped: [][]string{{"rule_groups.ssti"}, {"rule_groups.xxe"}, {"rule_groups.upload"}, {"rule_groups.cve"}, {"rule_groups.wordpress"}, {"rule_groups.probe"}, {"rule_groups.other"}},
			check: func(t *testing.T, p Policy) {
				if len(p.RuleGroups) != 10 {
					t.Fatalf("%d groups carried, want the ten that have a counterpart: %v", len(p.RuleGroups), p.RuleGroups)
				}
			}},
		{name: "an exclusion with no targets stays the whole request", in: wrap(`{"mode":"block","exclusions":[{"path":"/a/","categories":["xss"],"targets":null}]}`), clean: true, check: func(t *testing.T, p Policy) {
			if len(p.Exclusions) != 1 || len(p.Exclusions[0].Targets) != 0 {
				t.Fatalf("%+v", p.Exclusions)
			}
		}},
		{name: "an exclusion whose only target cannot be carried is dropped, not widened", in: wrap(`{"mode":"block","exclusions":[{"path":"/a/","categories":["xss"],"targets":["uploads"]}]}`),
			skipped: [][]string{{"exclusions[1]", "widen"}}, check: func(t *testing.T, p Policy) {
				if len(p.Exclusions) != 0 {
					t.Fatalf("an exclusion whose target cannot be carried was carried (widened): %+v", p.Exclusions)
				}
			}},
		{name: "an exclusion with a category that has no group and one that has", in: wrap(`{"mode":"block","exclusions":[{"path":"/a/","categories":["upload","sqli"],"targets":["args"]}]}`),
			skipped: [][]string{{"exclusions[1]", "upload"}}, check: func(t *testing.T, p Policy) {
				if len(p.Exclusions) != 1 || !reflect.DeepEqual(p.Exclusions[0].Categories, []string{"sqli"}) {
					t.Fatalf("%+v", p.Exclusions)
				}
			}},
		{name: "an allow list address that is too wide", in: wrap(`{"mode":"block","allow_ips":["10.0.0.0/8","203.0.113.9"]}`), skipped: [][]string{{"allow_ips:", "10.0.0.0/8"}}, check: func(t *testing.T, p Policy) {
			if !reflect.DeepEqual(p.AllowIPs, []string{"203.0.113.9/32"}) {
				t.Fatalf("%v", p.AllowIPs)
			}
		}},
		{name: "a rule that blocks with no score", in: wrap(`{"mode":"block","rules":[{"id":"SITE-0001","action":"block","targets":["path"],"operator":"contains","pattern":"x","transforms":["urldecode"]}]}`),
			clean: true, check: func(t *testing.T, p Policy) {
				if len(p.CustomRules) != 1 || p.CustomRules[0].Action != ActionBlock || !p.CustomRules[0].CaseSensitive {
					t.Fatalf("%+v", p.CustomRules)
				}
			}},
		{name: "a rule with an operator that has no equivalent", in: wrap(`{"mode":"block","rules":[{"id":"SITE-0001","action":"block","score":9,"targets":["path"],"operator":"fuzzy","pattern":"x"}]}`),
			skipped: [][]string{{"SITE-0001", "fuzzy"}}, check: func(t *testing.T, p Policy) {
				if len(p.CustomRules) != 0 {
					t.Fatal("a rule that cannot be carried was carried")
				}
			}},
		{name: "a rule with an action that is not one", in: wrap(`{"mode":"block","rules":[{"id":"SITE-0001","action":"allow","score":9,"targets":["path"],"operator":"contains","pattern":"x"}]}`),
			skipped: [][]string{{"SITE-0001", "allow"}}},
		{name: "a rule that looks only at uploaded content", in: wrap(`{"mode":"block","rules":[{"id":"SITE-0001","action":"block","score":9,"targets":["uploads"],"operator":"contains","pattern":"x"}]}`),
			skipped: [][]string{{"SITE-0001", "uploads"}}, check: func(t *testing.T, p Policy) {
				if len(p.CustomRules) != 0 {
					t.Fatal("a rule with no usable target was carried")
				}
			}},
		{name: "a rule that needs a minimum length", in: wrap(`{"mode":"block","rules":[{"id":"SITE-0001","action":"block","score":9,"targets":["args"],"operator":"contains","pattern":"x","min_length":20}]}`),
			skipped: [][]string{{"SITE-0001", "20"}}},
		{name: "rules numbered by the converter keep clear of the numbers in use", in: wrap(`{"mode":"block","rules":[
			{"id":"SITE-0002","action":"log","targets":["path","query","args"],"operator":"contains","pattern":"x"}]}`),
			skipped: [][]string{{"SITE-0002", "several parts"}}, check: func(t *testing.T, p Policy) {
				ids := []int{}
				for _, r := range p.CustomRules {
					ids = append(ids, r.ID)
				}
				sort.Ints(ids)
				if !reflect.DeepEqual(ids, []int{1, 2, 3}) {
					t.Fatalf("rule numbers %v", ids)
				}
			}},
		{name: "a setting this program does not know", in: wrap(`{"mode":"block","telepathy":true}`), skipped: [][]string{{"telepathy:", "not a setting"}}},
		{name: "a part of the export this program does not know", in: `{"site_firewall_policy":1,"policy":{"mode":"block"},"extra":1}`, skipped: [][]string{{"extra:"}}},
		{name: "bookkeeping is ignored", in: wrap(`{"mode":"block","schema":1,"rev":9,"updated":"x","by":"y","compiled":null}`), clean: true},
		{name: "an export from a console whose empty settings are objects", in: wrap(`{"mode":"block","reputation":{},"ips":{},"outbound":{},"stats":{},"log":{},"overrides":{},"disabled":[]}`), clean: true},
	}
	if len(rows) < 15 {
		t.Fatal("the table lost rows")
	}
	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			p, skipped, err := FromConsoleExport([]byte(r.in))
			if r.errPath != "" {
				wantInvalid(t, err, r.errPath)
				if !reflect.DeepEqual(p, Policy{}) || len(skipped) != 0 {
					t.Fatalf("a refused export returned something: %+v %v", p, skipped)
				}
				return
			}
			wantValid(t, err)
			if err := p.Validate(); err != nil {
				t.Fatalf("the result is not valid: %v", err)
			}
			if r.check != nil {
				r.check(t, p)
			}
			for _, want := range r.skipped {
				if !skippedHas(skipped, want...) {
					t.Errorf("no line has %q in\n%s", want, strings.Join(skipped, "\n"))
				}
			}
			if r.clean && len(skipped) != 0 {
				t.Errorf("the list should be empty: %v", skipped)
			}
		})
	}
}

func TestConsoleExportLimits(t *testing.T) {
	t.Run("an export over the size limit", func(t *testing.T) {
		_, _, err := FromConsoleExport([]byte(`{"site_firewall_policy":1,"policy":{"contact":"` + strings.Repeat("a", MaxConsoleExportBytes) + `"}}`))
		wantInvalid(t, err, "$")
	})
	t.Run("a hundred and one rules", func(t *testing.T) {
		var rules []string
		for i := 1; i <= MaxCustomRules+1; i++ {
			rules = append(rules, fmt.Sprintf(`{"id":"SITE-%04d","action":"log","targets":["path"],"operator":"contains","pattern":"x%d"}`, i, i))
		}
		p, skipped, err := FromConsoleExport([]byte(`{"site_firewall_policy":1,"policy":{"mode":"block","rules":[` + strings.Join(rules, ",") + `]}}`))
		wantValid(t, err)
		if len(p.CustomRules) != MaxCustomRules || !skippedHas(skipped, "more than 100 custom rules") {
			t.Fatalf("%d rules carried; skipped %v", len(p.CustomRules), skipped)
		}
	})
	t.Run("more allow list entries than there is room for", func(t *testing.T) {
		var ips []string
		for i := 0; i < MaxAllowIPs+5; i++ {
			ips = append(ips, fmt.Sprintf(`"203.0.%d.%d"`, i/250, i%250))
		}
		p, skipped, err := FromConsoleExport([]byte(`{"site_firewall_policy":1,"policy":{"mode":"block","allow_ips":[` + strings.Join(ips, ",") + `]}}`))
		wantValid(t, err)
		if len(p.AllowIPs) != MaxAllowIPs || len(skipped) != 5 {
			t.Fatalf("%d carried, %d skipped", len(p.AllowIPs), len(skipped))
		}
	})
	t.Run("the list of skipped settings is bounded", func(t *testing.T) {
		var ids []string
		for i := 0; i < 2000; i++ {
			ids = append(ids, fmt.Sprintf(`"not an address %d"`, i))
		}
		_, skipped, err := FromConsoleExport([]byte(`{"site_firewall_policy":1,"policy":{"mode":"block","block_ips":[` + strings.Join(ids, ",") + `]}}`))
		wantValid(t, err)
		if len(skipped) > 500 {
			t.Fatalf("%d lines", len(skipped))
		}
	})
	t.Run("what is said never repeats a long value in full", func(t *testing.T) {
		long := strings.Repeat("L", 500)
		_, skipped, err := FromConsoleExport([]byte(`{"site_firewall_policy":1,"policy":{"mode":"block","allow_paths":["` + long + `"],"telepathy":1,"rule_groups":{"` + long + `":"off"}}}`))
		wantValid(t, err)
		for _, s := range skipped {
			if strings.Contains(s, long) || len(s) > 400 {
				t.Errorf("a line holds the whole of a long value: %.80s...", s)
			}
		}
	})
}
