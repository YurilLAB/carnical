// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"fmt"
	"math/rand"
	"os"
	"strings"
	"testing"
)

func readFixture(t testing.TB, name string) []byte {
	t.Helper()
	b, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// compiledPolicyZoo is a set of policies that between them use every feature, every limit and every kind of setting, plus
// policies converted from the PHP console's real exports and randomly made ones.
func compiledPolicyZoo(t testing.TB) map[string]Policy {
	t.Helper()
	zoo := map[string]Policy{
		"default":     Default(),
		"relaxed":     mut(func(p *Policy) { p.Sensitivity = SensitivityRelaxed }),
		"strict":      mut(func(p *Policy) { p.Sensitivity = SensitivityStrict }),
		"threshold 1": mut(func(p *Policy) { p.Threshold = intp(1) }),
		"monitor":     mut(func(p *Policy) { p.Mode = ModeMonitor }),
		"off":         mut(func(p *Policy) { p.Mode = ModeOff }),
		"every group at log but sqli": mut(func(p *Policy) {
			for _, g := range Groups() {
				if g.Name != "sqli" {
					p.RuleGroups[g.Name] = GroupLog
				}
			}
		}),
		"every group off but sqli": mut(func(p *Policy) {
			for _, g := range Groups() {
				if g.Name != "sqli" {
					p.RuleGroups[g.Name] = GroupOff
				}
			}
		}),
		"sqli at log": mut(func(p *Policy) { p.RuleGroups["sqli"] = GroupLog }),
		"exclusions": mut(func(p *Policy) {
			p.Exclusions = []Exclusion{
				{Path: "/editor/", Categories: []string{"xss", "sqli"}, Targets: []string{"arg:content", "cookie:session", "header:x-note", "args", "body", "query", "cookies", "headers"}},
				{Path: "/api/", Categories: []string{"rce", "lfi", "rfi", "php", "ssrf", "java", "scanner", "protocol"}},
			}
		}),
		"custom rules": mut(func(p *Policy) {
			p.CustomRules = []CustomRule{
				{ID: 1, Field: "path", Operator: OpBeginsWith, Value: "/old-admin/", Action: ActionBlock},
				{ID: 2, Field: "args", Operator: OpPM, Values: []string{"viagra", "cialis"}, Action: ActionLog},
				{ID: 3, Field: "header:referer", Operator: OpRX, Value: `casino|poker`, Action: ActionBlock},
				{ID: 4, Field: "uri", Operator: OpContains, Value: `%{tx.x}"` + "\n", Action: ActionLog},
			}
		}),
		"address lists": mut(func(p *Policy) {
			p.AllowIPs = []string{"192.0.2.9", "2001:db8::/32"}
			p.BlockIPs = []string{"198.51.100.0/24", "10.0.0.0/8", "2001:db8:bad::/48"}
			p.AllowPaths = []string{"/webhook/", "/health"}
		}),
		"hosts": mut(func(p *Policy) { p.AllowedHosts = []string{"shop.example.test", "www.example.test"} }),
		"rest api": mut(func(p *Policy) {
			p.AllowedMethods = []string{"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"}
		}),
		"wordpress":   mut(func(p *Policy) { p.WordPress = WordPressOptions{Enabled: true, AllowXMLRPC: true, LoginPerMinute: 3} }),
		"lax uploads": mut(func(p *Policy) { p.Uploads = UploadOptions{AllowScriptNames: true, AllowScriptContent: true} }),
		"lax paths":   mut(func(p *Policy) { p.Paths = PathOptions{AllowEncodedSlash: true, AllowPathParams: true} }),
		"responses":   mut(func(p *Policy) { p.Responses = ResponseOptions{KeepBanners: true, KeepCaching: true, Inspect: true} }),
		"next action": mut(func(p *Policy) {
			p.Framework.DenyNextAction = true
			p.DenyHeaders = []string{"x-original-url", "x_rewrite_url"}
		}),
		"body limits": mut(func(p *Policy) {
			p.Body = BodyLimits{MaxUploadBytes: MaxUploadBytesLimit, MaxFormBytes: MaxFormBytesLimit}
		}),
		"small body limits": mut(func(p *Policy) { p.Body = BodyLimits{MaxUploadBytes: MinBodyBytes, MaxFormBytes: MinBodyBytes} }),
		"other sections": mut(func(p *Policy) {
			p.VPatch = VPatchOptions{Tiers: []string{"verified", "community", "experimental"}, Software: []string{"wordpress", "woocommerce@9.3"}}
			p.APIMode = APIEnforce
			p.API = []byte(`{"endpoints":{"/v1/users/{id}":{"methods":["GET"]}}}`)
			p.BodyFormats = []byte(`{"allowed_types":["application/json"]}`)
			p.Note = "a note\nover two lines"
		}),
	}
	for name, file := range map[string]string{"console export of the defaults": "console_export_defaults.json", "console export of a tuned site": "console_export_tuned.json",
		"console policy file": "console_policy_bare.json"} {
		p, _, err := FromConsoleExport(readFixture(t, file))
		if err != nil {
			t.Fatalf("%s: %v", file, err)
		}
		// A site in monitor mode (the PHP default) lets the attack through, which the check below allows for.
		zoo[name] = p
	}
	zoo["the largest policy"] = largestPolicy()
	rng := rand.New(rand.NewSource(20261005))
	for i := 0; i < 24; i++ {
		zoo[fmt.Sprintf("random %02d", i)] = randomPolicy(rng)
	}
	for name, p := range zoo {
		if err := p.Validate(); err != nil {
			t.Fatalf("the zoo's %q is not valid: %v", name, err)
		}
	}
	return zoo
}

// largestPolicy uses every list to its limit.
func largestPolicy() Policy {
	p := Default()
	for i := 1; i <= MaxCustomRules; i++ {
		r := CustomRule{ID: i, Field: "args", Operator: OpContains, Value: fmt.Sprintf("zz-no-match-%d", i), Action: ActionLog}
		switch i % 5 {
		case 1:
			r = CustomRule{ID: i, Field: "header:x-test", Operator: OpPM, Values: []string{fmt.Sprintf("zz-a-%d", i), fmt.Sprintf("zz-b-%d", i)}, Action: ActionBlock}
		case 2:
			r = CustomRule{ID: i, Field: "path", Operator: OpRX, Value: fmt.Sprintf(`^/zz-(no|match)-%d/`, i), Action: ActionBlock}
		}
		p.CustomRules = append(p.CustomRules, r)
	}
	cats := []string{}
	for _, g := range Groups() {
		cats = append(cats, g.Name)
	}
	for i := 0; i < MaxExclusions; i++ {
		p.Exclusions = append(p.Exclusions, Exclusion{Path: fmt.Sprintf("/zz%d/", i), Categories: cats, Targets: []string{"arg:a", "arg:b", "cookie:c", "header:x-d", "query"}})
	}
	for i := 0; i < MaxAllowIPs; i++ {
		p.AllowIPs = append(p.AllowIPs, fmt.Sprintf("192.0.%d.%d/32", 2+i/200, i%200))
	}
	for i := 0; i < MaxBlockIPs; i++ {
		p.BlockIPs = append(p.BlockIPs, fmt.Sprintf("10.%d.%d.0/24", i>>8&255, i&255))
	}
	for i := 0; i < MaxAllowPaths; i++ {
		p.AllowPaths = append(p.AllowPaths, fmt.Sprintf("/zz-hook-%d/", i))
	}
	for i := 0; i < MaxHosts-1; i++ {
		p.AllowedHosts = append(p.AllowedHosts, fmt.Sprintf("h%d.example.test", i))
	}
	p.AllowedHosts = append(p.AllowedHosts, "shop.example.test")
	for i := 0; i < MaxDenyHeaders; i++ {
		p.DenyHeaders = append(p.DenyHeaders, fmt.Sprintf("x-zz-%d", i))
	}
	for i := 0; i < MaxSoftware; i++ {
		p.VPatch.Software = append(p.VPatch.Software, fmt.Sprintf("app%d@1.%d", i, i))
	}
	p.AllowedMethods = []string{"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "PROPFIND", "MKCOL", "COPY", "MOVE", "LOCK", "UNLOCK"}
	return p
}

// randomPolicy makes a valid policy of random choices. It keeps the properties the zoo's check depends on: block mode with sqli on
// (so the attack is stopped), the test client's address (203.0.113.77) on no list, the test host allowed, nothing excluded or
// allowed on the pages the checks use, and no custom rule that matches them.
func randomPolicy(rng *rand.Rand) Policy {
	p := Default()
	pick := func(n int) int { return rng.Intn(n) }
	coin := func() bool { return rng.Intn(2) == 0 }
	p.Sensitivity = []Sensitivity{SensitivityRelaxed, SensitivityNormal, SensitivityStrict}[pick(3)]
	if p.Sensitivity != SensitivityRelaxed && coin() {
		p.Threshold = intp(1 + pick(5))
	}
	p.Body.MaxUploadBytes = int64(MinBodyBytes + pick(MaxUploadBytesLimit-MinBodyBytes))
	p.Body.MaxFormBytes = int64(MinBodyBytes + pick(int(min(p.Body.MaxUploadBytes, MaxFormBytesLimit))-MinBodyBytes))
	for _, m := range []string{"PUT", "PATCH", "DELETE", "PROPFIND"} {
		if coin() {
			p.AllowedMethods = append(p.AllowedMethods, m)
		}
	}
	if coin() {
		p.AllowedHosts = []string{"shop.example.test", fmt.Sprintf("h%d.example.test", pick(100))}
	}
	for _, g := range Groups() {
		if g.Name != "sqli" && g.Name != "protocol" {
			p.RuleGroups[g.Name] = []GroupState{GroupOn, GroupLog, GroupOff}[pick(3)]
		}
	}
	paths := []string{"/zz/", "/zz/a/", "/zz/b.php", "/zz-c/"}
	for i, n := 0, pick(5); i < n; i++ {
		var cats, targets []string
		for _, g := range Groups() {
			if coin() {
				cats = append(cats, g.Name)
			}
		}
		if len(cats) == 0 {
			cats = []string{"xss"}
		}
		for _, tg := range []string{"args", "argnames", "cookies", "headers", "body", "query", "arg:q", "cookie:s", "header:x-r"} {
			if pick(4) == 0 {
				targets = append(targets, tg)
			}
		}
		p.Exclusions = append(p.Exclusions, Exclusion{Path: paths[pick(len(paths))], Categories: cats, Targets: targets})
	}
	ops := []Operator{OpContains, OpEquals, OpBeginsWith, OpEndsWith, OpRX}
	fields := []string{"args", "path", "uri", "query", "header:x-q", "cookie:k", "useragent", "headers", "body", "method"}
	for i, n := 1, pick(8); i <= n; i++ {
		for try := 0; try < 10; try++ {
			v := hostile[pick(len(hostile))]
			if len(v) > 100 {
				continue
			}
			r := CustomRule{ID: i, Field: fields[pick(len(fields))], Operator: ops[pick(len(ops))], Value: "zz-nomatch-" + v, CaseSensitive: coin(), Action: []Action{ActionBlock, ActionLog}[pick(2)]}
			if r.Operator == OpRX {
				r.Value = "zz-nomatch-" + strings.ReplaceAll(strings.ReplaceAll(v, `\`, ""), "(", "")
			}
			if r.Operator == OpPM || pick(5) == 0 {
				r.Operator, r.Value, r.Values = OpPM, "", []string{"zz-nomatch-" + v, "zz-other"}
			}
			cand := p
			cand.CustomRules = append(append([]CustomRule(nil), p.CustomRules...), r)
			if cand.Validate() == nil {
				p = cand
				break
			}
		}
	}
	for i, n := 0, pick(20); i < n; i++ {
		p.AllowIPs = append(p.AllowIPs, fmt.Sprintf("192.0.2.%d", i))
	}
	for i, n := 0, pick(300); i < n; i++ {
		p.BlockIPs = append(p.BlockIPs, fmt.Sprintf("10.%d.%d.0/24", i>>8&255, i&255))
	}
	for i, n := 0, pick(5); i < n; i++ {
		p.AllowPaths = append(p.AllowPaths, fmt.Sprintf("/zz-hook-%d/", i))
	}
	p.Paths = PathOptions{AllowEncodedSlash: coin(), AllowPathParams: coin()}
	p.Uploads = UploadOptions{AllowScriptNames: coin(), AllowScriptContent: coin()}
	p.WordPress = WordPressOptions{Enabled: coin(), AllowXMLRPC: coin(), LoginPerMinute: 1 + pick(600)}
	p.Responses = ResponseOptions{KeepBanners: coin(), KeepCaching: coin(), Inspect: coin()}
	p.Framework.DenyNextAction = coin()
	for i, n := 0, pick(4); i < n; i++ {
		p.DenyHeaders = append(p.DenyHeaders, fmt.Sprintf("x_zz_%d", i))
	}
	p.VPatch.Tiers = [][]string{{"verified"}, {"verified", "community"}, {}, {"experimental"}}[pick(4)]
	p.APIMode = []APIMode{APIOff, APILearn, APIMonitor, APIEnforce}[pick(4)]
	p.Note = fmt.Sprintf("random policy %d", pick(1000))
	return p
}
