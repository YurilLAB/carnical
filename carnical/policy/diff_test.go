// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"encoding/json"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// richBase is a policy that uses every setting, so that a change to any of them is a change from something.
func richBase() Policy {
	p := Default()
	p.Threshold = nil
	p.AllowedMethods = []string{"GET", "HEAD", "OPTIONS", "POST", "PUT"}
	p.AllowedHosts = []string{"example.test", "www.example.test"}
	p.RuleGroups = map[string]GroupState{"xss": GroupLog, "lfi": GroupOff}
	p.Exclusions = []Exclusion{{Path: "/editor/", Categories: []string{"xss"}, Targets: []string{"arg:content"}}, {Path: "/api/", Categories: []string{"rce", "lfi"}}}
	p.CustomRules = []CustomRule{
		{ID: 1, Field: "path", Operator: OpBeginsWith, Value: "/old-admin/", Action: ActionBlock},
		{ID: 2, Field: "args", Operator: OpPM, Values: []string{"viagra", "cialis"}, Action: ActionLog},
	}
	p.AllowIPs = []string{"203.0.113.9", "198.51.100.0/24"}
	p.BlockIPs = []string{"192.0.2.0/24", "10.0.0.0/8"}
	p.AllowPaths = []string{"/webhook/stripe", "/hooks/"}
	p.WordPress = WordPressOptions{Enabled: true, LoginPerMinute: 10}
	p.Responses = ResponseOptions{Inspect: true}
	p.DenyHeaders = []string{"x-original-url"}
	p.Framework.DenyNextAction = true
	p.VPatch = VPatchOptions{Tiers: []string{"verified", "community"}, Software: []string{"wordpress", "woocommerce"}}
	p.APIMode = APIMonitor
	p.API = json.RawMessage(`{"limit":10}`)
	p.BodyFormats = json.RawMessage(`{"allowed_types":["application/json"]}`)
	return p.Normalize()
}

func codes(cs []Change) []string {
	seen := map[string]bool{}
	var out []string
	for _, c := range cs {
		if !seen[c.Code] {
			seen[c.Code] = true
			out = append(out, c.Code)
		}
	}
	sort.Strings(out)
	return out
}

func TestWeakensReportsEachKindOfWeakeningAndOnlyThose(t *testing.T) {
	th := func(n int) func(*Policy) { return func(p *Policy) { p.Threshold = &n } }
	rows := []struct {
		name    string
		change  func(*Policy)
		weakens []string // the codes Weakens must return, exactly
		diff    []string // codes that must be among Diff's (a weakening is also in Diff)
	}{
		// ---- weakening
		{"block to monitor", func(p *Policy) { p.Mode = ModeMonitor }, []string{"mode.lowered"}, nil},
		{"block to off", func(p *Policy) { p.Mode = ModeOff }, []string{"mode.lowered"}, nil},
		{"normal to relaxed (a higher blocking score)", func(p *Policy) { p.Sensitivity = SensitivityRelaxed }, []string{"threshold.raised"}, nil},
		{"a threshold of 5 replaced by 8", func(p *Policy) { p.Threshold = intp(8) }, []string{"threshold.raised"}, nil},
		{"no threshold to a threshold of 10", th(10), []string{"threshold.raised"}, nil},
		{"a rule group on to log only", func(p *Policy) { p.RuleGroups["sqli"] = GroupLog }, []string{"rule_group.log"}, nil},
		{"a rule group on to off", func(p *Policy) { p.RuleGroups["php"] = GroupOff }, []string{"rule_group.off"}, nil},
		{"a rule group log only to off", func(p *Policy) { p.RuleGroups["xss"] = GroupOff }, []string{"rule_group.off"}, nil},
		{"two groups lowered", func(p *Policy) { p.RuleGroups["sqli"], p.RuleGroups["rce"] = GroupOff, GroupLog }, []string{"rule_group.log", "rule_group.off"}, nil},
		{"an exclusion added", func(p *Policy) {
			p.Exclusions = append(p.Exclusions, Exclusion{Path: "/shop/", Categories: []string{"sqli"}, Targets: []string{"arg:q"}})
		}, []string{"exclusion.added"}, nil},
		{"an exclusion widened to the whole request", func(p *Policy) { p.Exclusions[1].Targets = nil }, []string{"exclusion.added"}, nil},
		{"an exclusion moved to a shorter path", func(p *Policy) { p.Exclusions[0].Path = "/" }, []string{"exclusion.added"}, nil},
		{"a category added to an exclusion", func(p *Policy) { p.Exclusions[0].Categories = []string{"sqli", "xss"} }, []string{"exclusion.added"}, nil},
		{"a target added to an exclusion that named one", func(p *Policy) { p.Exclusions[1].Targets = []string{"arg:content", "cookies"} }, []string{"exclusion.added"}, nil},
		{"a blocking custom rule removed", func(p *Policy) { p.CustomRules = p.CustomRules[1:] }, []string{"custom_rule.removed"}, nil},
		{"a blocking custom rule changed to log", func(p *Policy) { p.CustomRules[0].Action = ActionLog }, []string{"custom_rule.relaxed"}, nil},
		{"a blocking custom rule changed to match something else", func(p *Policy) { p.CustomRules[0].Value = "/new-admin/" }, []string{"custom_rule.changed"}, nil},
		{"a blocking custom rule's field changed", func(p *Policy) { p.CustomRules[0].Field = "uri" }, []string{"custom_rule.changed"}, nil},
		{"an address added to the allow list", func(p *Policy) { p.AllowIPs = append(p.AllowIPs, "192.0.2.77") }, []string{"allow_ip.added"}, nil},
		{"the allow list range widened", func(p *Policy) { p.AllowIPs = []string{"203.0.113.9", "198.51.0.0/16"} }, []string{"allow_ip.added"}, nil},
		{"an IPv6 range added to the allow list", func(p *Policy) { p.AllowIPs = append(p.AllowIPs, "2001:db8::/32") }, []string{"allow_ip.added"}, nil},
		{"an address taken off the block list", func(p *Policy) { p.BlockIPs = p.BlockIPs[:1] }, []string{"block_ip.removed"}, nil},
		{"a block list range narrowed", func(p *Policy) { p.BlockIPs = []string{"192.0.2.0/25", "10.0.0.0/8"} }, []string{"block_ip.removed"}, nil},
		{"a page added to those never inspected", func(p *Policy) { p.AllowPaths = append(p.AllowPaths, "/pay/") }, []string{"allow_path.added"}, nil},
		{"a page widened to its folder", func(p *Policy) { p.AllowPaths = []string{"/webhook/", "/hooks/"} }, []string{"allow_path.added"}, nil},
		{"the upload limit raised", func(p *Policy) { p.Body.MaxUploadBytes *= 2 }, []string{"body.upload_limit_raised"}, nil},
		{"the form limit raised", func(p *Policy) { p.Body.MaxFormBytes *= 2 }, []string{"body.form_limit_raised"}, nil},
		{"a method added", func(p *Policy) { p.AllowedMethods = append(p.AllowedMethods, "PATCH") }, []string{"method.added"}, nil},
		{"a host added", func(p *Policy) { p.AllowedHosts = append(p.AllowedHosts, "shop.example.test") }, []string{"host.added"}, nil},
		{"the host list emptied", func(p *Policy) { p.AllowedHosts = nil }, []string{"hosts.opened"}, nil},
		{"script names in uploads allowed", func(p *Policy) { p.Uploads.AllowScriptNames = true }, []string{"uploads.script_names_allowed"}, nil},
		{"script content in uploads allowed", func(p *Policy) { p.Uploads.AllowScriptContent = true }, []string{"uploads.script_content_allowed"}, nil},
		{"encoded slashes allowed", func(p *Policy) { p.Paths.AllowEncodedSlash = true }, []string{"paths.encoded_slash_allowed"}, nil},
		{"path parameters allowed", func(p *Policy) { p.Paths.AllowPathParams = true }, []string{"paths.path_params_allowed"}, nil},
		{"WordPress protections switched off", func(p *Policy) { p.WordPress.Enabled = false }, []string{"wordpress.disabled"}, nil},
		{"xmlrpc.php allowed", func(p *Policy) { p.WordPress.AllowXMLRPC = true }, []string{"wordpress.xmlrpc_allowed"}, nil},
		{"the login rate raised", func(p *Policy) { p.WordPress.LoginPerMinute = 60 }, []string{"wordpress.login_rate_raised"}, nil},
		{"banners kept", func(p *Policy) { p.Responses.KeepBanners = true }, []string{"responses.banners_kept"}, nil},
		{"caching headers left alone", func(p *Policy) { p.Responses.KeepCaching = true }, []string{"responses.caching_kept"}, nil},
		{"response inspection switched off", func(p *Policy) { p.Responses.Inspect = false }, []string{"responses.inspection_disabled"}, nil},
		{"a denied header allowed again", func(p *Policy) { p.DenyHeaders = nil }, []string{"deny_header.removed"}, nil},
		{"Next-Action allowed again", func(p *Policy) { p.Framework.DenyNextAction = false }, []string{"framework.next_action_allowed"}, nil},
		{"a virtual-patch tier removed", func(p *Policy) { p.VPatch.Tiers = []string{"verified"} }, []string{"vpatch.tier_removed"}, nil},
		{"all virtual-patch tiers removed", func(p *Policy) { p.VPatch.Tiers = nil }, []string{"vpatch.tier_removed"}, nil},
		{"declared software removed", func(p *Policy) { p.VPatch.Software = []string{"wordpress"} }, []string{"vpatch.software_removed"}, nil},
		{"API protection from monitor to off", func(p *Policy) { p.APIMode = APIOff }, []string{"api.mode_lowered"}, nil},
		{"API settings changed while monitored", func(p *Policy) { p.API = json.RawMessage(`{"limit":1000}`) }, []string{"api.config_changed"}, nil},
		{"body-format settings changed", func(p *Policy) { p.BodyFormats = json.RawMessage(`{"allowed_types":["*/*"]}`) }, []string{"body_formats.config_changed"}, nil},
		// ---- changes that strengthen, narrow or do nothing: none of these may be reported as weakening
		{"normal to strict", func(p *Policy) { p.Sensitivity = SensitivityStrict }, nil, []string{"paranoia.raised"}},
		{"a threshold of 5 replaced by 3", func(p *Policy) { p.Threshold = intp(3) }, nil, []string{"threshold.lowered"}},
		{"a threshold equal to the preset's", func(p *Policy) { p.Threshold = intp(5) }, nil, []string{"sensitivity.changed"}},
		{"a rule group log only to on", func(p *Policy) { p.RuleGroups["xss"] = GroupOn }, nil, []string{"rule_group.on"}},
		{"a rule group off to log only", func(p *Policy) { p.RuleGroups["lfi"] = GroupLog }, nil, []string{"rule_group.log"}},
		{"a rule group off to on", func(p *Policy) { p.RuleGroups["lfi"] = GroupOn }, nil, []string{"rule_group.on"}},
		{"an exclusion removed", func(p *Policy) { p.Exclusions = p.Exclusions[:1] }, nil, []string{"exclusion.removed"}},
		{"an exclusion narrowed to a longer path", func(p *Policy) { p.Exclusions[1].Path = "/editor/save/" }, nil, []string{"exclusion.removed"}},
		{"an exclusion narrowed to fewer categories", func(p *Policy) { p.Exclusions[0].Categories = []string{"rce"} }, nil, []string{"exclusion.removed"}},
		{"a target added to an exclusion that covered the whole request", func(p *Policy) { p.Exclusions[0].Targets = []string{"args"} }, nil, []string{"exclusion.removed"}},
		{"an exclusion that an existing one already covers", func(p *Policy) {
			p.Exclusions = append(p.Exclusions, Exclusion{Path: "/editor/save", Categories: []string{"xss"}, Targets: []string{"arg:content"}})
		}, nil, nil},
		{"an exclusion for one argument under an exclusion for all arguments", func(p *Policy) {
			p.Exclusions = append(p.Exclusions, Exclusion{Path: "/api/x", Categories: []string{"rce"}, Targets: []string{"arg:a"}})
		}, nil, nil},
		{"a blocking custom rule added", func(p *Policy) {
			p.CustomRules = append(p.CustomRules, CustomRule{ID: 3, Field: "uri", Operator: OpContains, Value: "x", Action: ActionBlock})
		}, nil, []string{"custom_rule.added"}},
		{"a logging custom rule added", func(p *Policy) {
			p.CustomRules = append(p.CustomRules, CustomRule{ID: 3, Field: "uri", Operator: OpContains, Value: "x", Action: ActionLog})
		}, nil, []string{"custom_rule.added"}},
		{"a custom rule changed from log to block", func(p *Policy) { p.CustomRules[1].Action = ActionBlock }, nil, []string{"custom_rule.raised"}},
		{"a logging custom rule removed", func(p *Policy) { p.CustomRules = p.CustomRules[:1] }, nil, []string{"custom_rule.removed"}},
		{"a logging custom rule changed to match something else", func(p *Policy) { p.CustomRules[1].Values = []string{"poker"} }, nil, []string{"custom_rule.changed"}},
		{"a custom rule's note changed", func(p *Policy) { p.CustomRules[0].Note = "now with a note" }, nil, nil},
		{"an address taken off the allow list", func(p *Policy) { p.AllowIPs = p.AllowIPs[:1] }, nil, []string{"allow_ip.removed"}},
		{"an allow list range narrowed", func(p *Policy) { p.AllowIPs = []string{"203.0.113.9", "198.51.100.0/25"} }, nil, []string{"allow_ip.removed"}},
		{"an allow list address that a range already holds", func(p *Policy) { p.AllowIPs = append(p.AllowIPs, "198.51.100.77") }, nil, nil},
		{"an address added to the block list", func(p *Policy) { p.BlockIPs = append(p.BlockIPs, "192.0.2.0/24", "203.0.113.200") }, nil, []string{"block_ip.added"}},
		{"a block list range widened", func(p *Policy) { p.BlockIPs = []string{"192.0.0.0/16", "10.0.0.0/8"} }, nil, []string{"block_ip.added"}},
		{"a block list address that a range already holds", func(p *Policy) { p.BlockIPs = append(p.BlockIPs, "10.1.2.3") }, nil, nil},
		{"a block list address replaced by one the range holds", func(p *Policy) { p.BlockIPs = []string{"192.0.2.0/24", "10.0.0.0/8", "10.9.9.9"} }, nil, nil},
		{"a page taken off those never inspected", func(p *Policy) { p.AllowPaths = p.AllowPaths[:1] }, nil, []string{"allow_path.removed"}},
		{"a page narrowed", func(p *Policy) { p.AllowPaths = []string{"/webhook/stripe", "/hooks/a"} }, nil, []string{"allow_path.removed"}},
		{"a page that an allowed folder already holds", func(p *Policy) { p.AllowPaths = append(p.AllowPaths, "/hooks/github") }, nil, nil},
		{"the upload limit lowered", func(p *Policy) { p.Body.MaxUploadBytes /= 2 }, nil, []string{"body.upload_limit_lowered"}},
		{"the form limit lowered", func(p *Policy) { p.Body.MaxFormBytes /= 2 }, nil, []string{"body.form_limit_lowered"}},
		{"a method removed", func(p *Policy) { p.AllowedMethods = []string{"GET", "HEAD", "OPTIONS", "POST"} }, nil, []string{"method.removed"}},
		{"a host removed", func(p *Policy) { p.AllowedHosts = []string{"example.test"} }, nil, []string{"host.removed"}},
		{"WordPress protections switched on", func(p *Policy) { p.WordPress.Enabled = true }, nil, nil},
		{"xmlrpc.php refused", func(p *Policy) { p.WordPress.AllowXMLRPC = false }, nil, nil},
		{"the login rate lowered", func(p *Policy) { p.WordPress.LoginPerMinute = 3 }, nil, []string{"wordpress.login_rate_lowered"}},
		{"banners hidden", func(p *Policy) { p.Responses.KeepBanners = false }, nil, nil},
		{"response inspection kept on", func(p *Policy) { p.Responses.Inspect = true }, nil, nil},
		{"a header denied", func(p *Policy) { p.DenyHeaders = append(p.DenyHeaders, "x-rewrite-url") }, nil, []string{"deny_header.added"}},
		{"Next-Action denied", func(p *Policy) { p.Framework.DenyNextAction = true }, nil, nil},
		{"a virtual-patch tier added", func(p *Policy) { p.VPatch.Tiers = append(p.VPatch.Tiers, "experimental") }, nil, []string{"vpatch.tier_added"}},
		{"software declared", func(p *Policy) { p.VPatch.Software = append(p.VPatch.Software, "elementor") }, nil, []string{"vpatch.software_added"}},
		{"API protection from monitor to enforce", func(p *Policy) { p.APIMode = APIEnforce }, nil, []string{"api.mode_raised"}},
		{"the note changed", func(p *Policy) { p.Note = "new note" }, nil, []string{"note.changed"}},
		{"the revision changed", func(p *Policy) { p.Revision += 5 }, nil, nil},
		{"the lists written in another order and case", func(p *Policy) {
			p.AllowedHosts = []string{"WWW.EXAMPLE.TEST", "example.test"}
			p.AllowedMethods = []string{"put", "post", "options", "head", "get"}
			p.AllowIPs = []string{"198.51.100.0/24", "203.0.113.9/32"}
		}, nil, nil},
	}
	count := 0
	for _, r := range rows {
		count++
		t.Run(r.name, func(t *testing.T) {
			old := richBase()
			next := deepCopy(t, old)
			r.change(&next)
			if err := next.Validate(); err != nil {
				t.Fatalf("the row's new policy is not valid: %v", err)
			}
			got := codes(Weakens(old, next))
			want := append([]string(nil), r.weakens...)
			sort.Strings(want)
			if !reflect.DeepEqual(got, want) && !(len(got) == 0 && len(want) == 0) {
				t.Fatalf("Weakens = %v, want %v\nDiff = %v", got, want, codes(Diff(old, next)))
			}
			all := codes(Diff(old, next))
			for _, c := range r.diff {
				found := false
				for _, a := range all {
					found = found || a == c
				}
				if !found {
					t.Errorf("Diff = %v, want it to include %s", all, c)
				}
			}
			for _, w := range Weakens(old, next) {
				if !w.Weakens || w.Message == "" || w.Code == "" || w.Section == "" {
					t.Errorf("a weakening without its parts: %+v", w)
				}
			}
			if len(want) == 0 {
				for _, c := range Confirm(old, next) {
					t.Errorf("Confirm asks for a password for %+v, which is not a weakening or a risk", c)
				}
			}
		})
	}
	if count < 15 {
		t.Fatalf("%d rows", count)
	}
}

func deepCopy(t testing.TB, p Policy) Policy {
	t.Helper()
	b, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	var q Policy
	if err := json.Unmarshal(b, &q); err != nil {
		t.Fatal(err)
	}
	return q.Normalize()
}

// A few comparisons need a different starting point from richBase.
func TestWeakensFromOtherStartingPoints(t *testing.T) {
	rows := []struct {
		name    string
		from    func(*Policy)
		to      func(*Policy)
		weakens []string
		diff    []string
	}{
		{"monitor to off", func(p *Policy) { p.Mode = ModeMonitor }, func(p *Policy) { p.Mode = ModeOff }, []string{"mode.lowered"}, nil},
		{"monitor to block", func(p *Policy) { p.Mode = ModeMonitor }, func(p *Policy) { p.Mode = ModeBlock }, nil, []string{"mode.raised"}},
		{"off to monitor", func(p *Policy) { p.Mode = ModeOff }, func(p *Policy) { p.Mode = ModeMonitor }, nil, []string{"mode.raised"}},
		{"strict to normal lowers the paranoia level", func(p *Policy) { p.Sensitivity = SensitivityStrict }, func(p *Policy) { p.Sensitivity = SensitivityNormal }, []string{"paranoia.lowered"}, nil},
		{"strict to relaxed lowers both", func(p *Policy) { p.Sensitivity = SensitivityStrict }, func(p *Policy) { p.Sensitivity = SensitivityRelaxed }, []string{"paranoia.lowered", "threshold.raised"}, nil},
		{"relaxed to strict lowers nothing", func(p *Policy) { p.Sensitivity = SensitivityRelaxed }, func(p *Policy) { p.Sensitivity = SensitivityStrict }, nil, []string{"paranoia.raised", "threshold.lowered"}},
		{"strict with a high threshold: a stricter level but a higher score still counts as weaker", func(p *Policy) { p.Sensitivity = SensitivityNormal },
			func(p *Policy) { p.Sensitivity, p.Threshold = SensitivityStrict, intp(20) }, []string{"threshold.raised"}, []string{"paranoia.raised"}},
		{"a site that answered to any host name is given a list", func(p *Policy) {}, func(p *Policy) { p.AllowedHosts = []string{"a.test"} }, nil, []string{"hosts.restricted"}},
		{"the first host added to an empty list is a restriction, not a weakening", func(p *Policy) {}, func(p *Policy) { p.AllowedHosts = []string{"a.test", "b.test"} }, nil, []string{"hosts.restricted"}},
		{"enforce to monitor", func(p *Policy) { p.APIMode = APIEnforce }, func(p *Policy) { p.APIMode = APIMonitor }, []string{"api.mode_lowered"}, nil},
		{"enforce to learn", func(p *Policy) { p.APIMode = APIEnforce }, func(p *Policy) { p.APIMode = APILearn }, []string{"api.mode_lowered"}, nil},
		{"learn to off", func(p *Policy) { p.APIMode = APILearn }, func(p *Policy) { p.APIMode = APIOff }, []string{"api.mode_lowered"}, nil},
		{"off to learn", func(p *Policy) {}, func(p *Policy) { p.APIMode = APILearn }, nil, []string{"api.mode_raised"}},
		{"API settings changed while the API guard is off", func(p *Policy) { p.API = json.RawMessage(`{"a":1}`) }, func(p *Policy) { p.API = json.RawMessage(`{"a":2}`) }, nil, []string{"api.config_changed"}},
		{"API settings changed while the API guard only learns", func(p *Policy) { p.APIMode, p.API = APILearn, json.RawMessage(`{"a":1}`) }, func(p *Policy) { p.APIMode, p.API = APILearn, json.RawMessage(`{"a":2}`) }, nil, []string{"api.config_changed"}},
		{"API settings changed while enforced", func(p *Policy) { p.APIMode, p.API = APIEnforce, json.RawMessage(`{"a":1}`) }, func(p *Policy) { p.APIMode, p.API = APIEnforce, json.RawMessage(`{"a":2}`) }, []string{"api.config_changed"}, nil},
		{"API settings written in another order are not a change", func(p *Policy) { p.APIMode, p.API = APIEnforce, json.RawMessage(`{"a":1,"b":2}`) }, func(p *Policy) { p.APIMode, p.API = APIEnforce, json.RawMessage(`{"b":2,"a":1}`) }, nil, nil},
		{"the first custom rule", func(p *Policy) {}, func(p *Policy) {
			p.CustomRules = []CustomRule{{ID: 1, Field: "path", Operator: OpEquals, Value: "/x", Action: ActionBlock}}
		}, nil, []string{"custom_rule.added"}},
		{"a hundred allow-list addresses added at once", func(p *Policy) {}, func(p *Policy) {
			for i := 0; i < 100; i++ {
				p.AllowIPs = append(p.AllowIPs, "192.0.2."+strconv.Itoa(i))
			}
		}, []string{"allow_ip.added"}, nil},
		{"a threshold removed for a normal sensitivity whose preset is the same", func(p *Policy) { p.Threshold = intp(5) }, func(p *Policy) { p.Threshold = nil }, nil, []string{"sensitivity.changed"}},
	}
	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			a, b := Default(), Default()
			r.from(&a)
			r.to(&b)
			got := codes(Weakens(a, b))
			want := append([]string(nil), r.weakens...)
			sort.Strings(want)
			if !reflect.DeepEqual(got, want) && !(len(got) == 0 && len(want) == 0) {
				t.Fatalf("Weakens = %v, want %v (Diff %v)", got, want, codes(Diff(a, b)))
			}
			all := codes(Diff(a, b))
			for _, c := range r.diff {
				ok := false
				for _, x := range all {
					ok = ok || x == c
				}
				if !ok {
					t.Errorf("Diff = %v, want it to include %s", all, c)
				}
			}
		})
	}
	if len(rows) < 15 {
		t.Fatal("the table lost rows")
	}
}

func TestWideBlockRangesNeedConfirmationButAreNotWeakenings(t *testing.T) {
	a := Default()
	for _, tc := range []struct {
		name string
		add  string
		risk bool
	}{
		{"a /24", "192.0.2.0/24", false},
		{"a /16, the widest that is not asked about", "192.0.0.0/16", false},
		{"a /15", "192.0.0.0/15", true},
		{"a /8", "10.0.0.0/8", true},
		{"an IPv6 /32", "2001:db8::/32", false},
		{"an IPv6 /31", "2001:db8::/31", true},
		{"an IPv6 /16", "2001::/16", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b := Default()
			b.BlockIPs = []string{tc.add}
			if w := Weakens(a, b); len(w) != 0 {
				t.Fatalf("Weakens = %v", codes(w))
			}
			conf := Confirm(a, b)
			risky := false
			for _, c := range conf {
				risky = risky || (c.Risk && c.Code == "block_ip.wide")
				if c.Weakens {
					t.Errorf("a block-list addition is a weakening: %+v", c)
				}
			}
			if risky != tc.risk {
				t.Fatalf("Confirm = %v, want a wide-range risk = %v", codes(conf), tc.risk)
			}
			// Taking it off again is a weakening (a protection removed), whatever its width.
			if got := codes(Weakens(b, a)); !reflect.DeepEqual(got, []string{"block_ip.removed"}) {
				t.Fatalf("Weakens of the removal = %v", got)
			}
		})
	}
}

func TestDiffIsDeterministicAndHasPlainSentences(t *testing.T) {
	a := richBase()
	b := deepCopy(t, a)
	b.Mode = ModeMonitor
	b.RuleGroups["sqli"] = GroupOff
	b.AllowIPs = append(b.AllowIPs, "192.0.2.5")
	b.VPatch.Tiers = nil
	b.Note = "x"
	first := Diff(a, b)
	for i := 0; i < 20; i++ {
		if !reflect.DeepEqual(first, Diff(a, b)) {
			t.Fatal("Diff is not deterministic")
		}
	}
	for _, c := range first {
		if c.Message == "" || !strings.HasSuffix(c.Message, ".") || strings.Contains(c.Message, "%!") || strings.Contains(c.Message, "{") {
			t.Errorf("not a plain sentence: %+v", c)
		}
		if c.Code == "" || strings.ToLower(c.Code) != c.Code || !strings.Contains(c.Code, ".") {
			t.Errorf("not a stable code: %+v", c)
		}
	}
	if Diff(a, a) != nil && len(Diff(a, a)) != 0 {
		t.Errorf("a policy differs from itself: %v", Diff(a, a))
	}
	if len(Diff(Default(), Default())) != 0 {
		t.Error("Default differs from itself")
	}
	// A note never leaks into a change message.
	n := deepCopy(t, a)
	n.Note = "SECRET-NOTE"
	n.Exclusions[0].Note = "SECRET-NOTE"
	n.CustomRules[0].Note = "SECRET-NOTE"
	n.Mode = ModeMonitor
	for _, c := range Diff(a, n) {
		if strings.Contains(c.Message, "SECRET-NOTE") {
			t.Errorf("a note was written into a message: %+v", c)
		}
	}
}

func TestEveryCodeThatWeakensIsStable(t *testing.T) {
	// The codes are an interface to the web UI; this is the list, so that a rename is a deliberate act.
	want := []string{
		"allow_ip.added", "allow_path.added", "api.config_changed", "api.mode_lowered", "block_ip.removed", "body.form_limit_raised", "body.upload_limit_raised",
		"body_formats.config_changed", "custom_rule.changed", "custom_rule.relaxed", "custom_rule.removed", "deny_header.removed", "exclusion.added",
		"framework.next_action_allowed", "host.added", "hosts.opened", "method.added", "mode.lowered", "paranoia.lowered", "paths.encoded_slash_allowed",
		"paths.path_params_allowed", "responses.banners_kept", "responses.caching_kept", "responses.inspection_disabled", "rule_group.log", "rule_group.off",
		"threshold.raised", "uploads.script_content_allowed", "uploads.script_names_allowed", "vpatch.software_removed", "vpatch.tier_removed",
		"wordpress.disabled", "wordpress.login_rate_raised", "wordpress.xmlrpc_allowed",
	}
	// Collect the codes the table above can produce by running a policy through every weakening it knows.
	seen := map[string]bool{}
	base := richBase()
	mutations := []func(*Policy){
		func(p *Policy) { p.Mode = ModeMonitor }, func(p *Policy) { p.Sensitivity = SensitivityRelaxed }, func(p *Policy) { p.RuleGroups["sqli"] = GroupLog },
		func(p *Policy) { p.RuleGroups["php"] = GroupOff }, func(p *Policy) {
			p.Exclusions = append(p.Exclusions, Exclusion{Path: "/s/", Categories: []string{"sqli"}})
		},
		func(p *Policy) { p.CustomRules = p.CustomRules[1:] }, func(p *Policy) { p.CustomRules[0].Action = ActionLog }, func(p *Policy) { p.CustomRules[0].Value = "x" },
		func(p *Policy) { p.AllowIPs = append(p.AllowIPs, "192.0.2.77") }, func(p *Policy) { p.BlockIPs = nil }, func(p *Policy) { p.AllowPaths = append(p.AllowPaths, "/p/") },
		func(p *Policy) { p.Body.MaxUploadBytes *= 2 }, func(p *Policy) { p.Body.MaxFormBytes *= 2 }, func(p *Policy) { p.AllowedMethods = append(p.AllowedMethods, "PATCH") },
		func(p *Policy) { p.AllowedHosts = append(p.AllowedHosts, "n.test") }, func(p *Policy) { p.AllowedHosts = nil },
		func(p *Policy) { p.Uploads.AllowScriptNames, p.Uploads.AllowScriptContent = true, true },
		func(p *Policy) { p.Paths.AllowEncodedSlash, p.Paths.AllowPathParams = true, true },
		func(p *Policy) { p.WordPress.Enabled = false }, func(p *Policy) { p.WordPress.AllowXMLRPC = true }, func(p *Policy) { p.WordPress.LoginPerMinute = 99 },
		func(p *Policy) {
			p.Responses.KeepBanners, p.Responses.KeepCaching, p.Responses.Inspect = true, true, false
		},
		func(p *Policy) { p.DenyHeaders = nil }, func(p *Policy) { p.Framework.DenyNextAction = false },
		func(p *Policy) { p.VPatch.Tiers = nil }, func(p *Policy) { p.VPatch.Software = nil }, func(p *Policy) { p.APIMode = APIOff },
		func(p *Policy) { p.API = json.RawMessage(`{"x":1}`) }, func(p *Policy) { p.BodyFormats = json.RawMessage(`{"x":1}`) },
		func(p *Policy) { p.Sensitivity = SensitivityNormal; p.Threshold = intp(9) },
	}
	for _, m := range mutations {
		n := deepCopy(t, base)
		m(&n)
		for _, c := range Weakens(base, n) {
			seen[c.Code] = true
		}
	}
	strict := Default()
	strict.Sensitivity = SensitivityStrict
	for _, c := range Weakens(strict, Default()) {
		seen[c.Code] = true
	}
	var got []string
	for c := range seen {
		got = append(got, c)
	}
	sort.Strings(got)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("the weakening codes are\n%v\nwant\n%v", got, want)
	}
}
