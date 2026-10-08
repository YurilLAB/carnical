// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
)

type vrow struct {
	name   string
	change func(*Policy)
	path   string // "" means the policy must be valid; otherwise a problem must be reported at a path starting with this
}

func runRows(t *testing.T, min int, rows []vrow) {
	t.Helper()
	if len(rows) < min {
		t.Fatalf("%d rows, want at least %d", len(rows), min)
	}
	valid, invalid := 0, 0
	for _, r := range rows {
		if r.path == "" {
			valid++
		} else {
			invalid++
		}
		t.Run(r.name, func(t *testing.T) {
			p := mut(r.change)
			err := p.Validate()
			if r.path == "" {
				wantValid(t, err)
				// A valid policy compiles, and one that compiles survives a round trip through its own encoding.
				if _, err := Compile(p); err != nil {
					t.Fatalf("Compile: %v", err)
				}
				enc, err := Encode(p)
				wantValid(t, err)
				if _, err := Decode(enc); err != nil {
					t.Fatalf("Decode(Encode(p)): %v", err)
				}
				return
			}
			wantInvalid(t, err, r.path)
			if _, err := Compile(p); err == nil || !errors.Is(err, ErrInvalid) {
				t.Fatalf("Compile accepted an invalid policy, or failed differently: %v", err)
			}
			if _, err := Encode(p); err == nil {
				t.Fatal("Encode accepted an invalid policy")
			}
		})
	}
	if valid == 0 || invalid == 0 {
		t.Fatalf("a table needs positive and negative rows: %d valid, %d invalid", valid, invalid)
	}
}

func TestValidateEnumsAndThreshold(t *testing.T) {
	th := func(n int) func(*Policy) { return func(p *Policy) { p.Threshold = &n } }
	rows := []vrow{
		{"mode block", func(p *Policy) { p.Mode = ModeBlock }, ""},
		{"mode monitor", func(p *Policy) { p.Mode = ModeMonitor }, ""},
		{"mode off", func(p *Policy) { p.Mode = ModeOff }, ""},
		{"mode empty", func(p *Policy) { p.Mode = "" }, "mode"},
		{"mode in capitals", func(p *Policy) { p.Mode = "BLOCK" }, "mode"},
		{"mode with a space", func(p *Policy) { p.Mode = "block " }, "mode"},
		{"mode detect (the engine's word, not the policy's)", func(p *Policy) { p.Mode = "detect" }, "mode"},
		{"mode on", func(p *Policy) { p.Mode = "on" }, "mode"},
		{"mode with a newline", func(p *Policy) { p.Mode = "block\nSecRuleEngine Off" }, "mode"},
		{"sensitivity relaxed", func(p *Policy) { p.Sensitivity = SensitivityRelaxed }, ""},
		{"sensitivity normal", func(p *Policy) { p.Sensitivity = SensitivityNormal }, ""},
		{"sensitivity strict", func(p *Policy) { p.Sensitivity = SensitivityStrict }, ""},
		{"sensitivity standard (the PHP console's word)", func(p *Policy) { p.Sensitivity = "standard" }, "sensitivity"},
		{"sensitivity empty", func(p *Policy) { p.Sensitivity = "" }, "sensitivity"},
		{"sensitivity paranoid", func(p *Policy) { p.Sensitivity = "paranoid" }, "sensitivity"},
		{"threshold unset", func(p *Policy) { p.Threshold = nil }, ""},
		{"threshold 1", th(1), ""},
		{"threshold 5", th(5), ""},
		{"threshold 1000", th(1000), ""},
		{"threshold 0", th(0), "threshold"},
		{"threshold -1", th(-1), "threshold"},
		{"threshold 1001", th(1001), "threshold"},
		{"threshold maximum integer", th(1<<62 - 1), "threshold"},
		{"api off", func(p *Policy) { p.APIMode = APIOff }, ""},
		{"api learn", func(p *Policy) { p.APIMode = APILearn }, ""},
		{"api monitor", func(p *Policy) { p.APIMode = APIMonitor }, ""},
		{"api enforce", func(p *Policy) { p.APIMode = APIEnforce }, ""},
		{"api empty", func(p *Policy) { p.APIMode = "" }, "api_mode"},
		{"api block", func(p *Policy) { p.APIMode = "block" }, "api_mode"},
		{"schema 1", func(p *Policy) { p.Schema = 1 }, ""},
		{"schema 0", func(p *Policy) { p.Schema = 0 }, "schema"},
		{"schema 2", func(p *Policy) { p.Schema = 2 }, "schema"},
	}
	runRows(t, 15, rows)
}

func TestValidateBodyLimits(t *testing.T) {
	body := func(up, fm int64) func(*Policy) {
		return func(p *Policy) { p.Body = BodyLimits{MaxUploadBytes: up, MaxFormBytes: fm} }
	}
	rows := []vrow{
		{"the defaults", body(DefaultUploadBytes, DefaultFormBytes), ""},
		{"the smallest both", body(MinBodyBytes, MinBodyBytes), ""},
		{"the largest upload", body(MaxUploadBytesLimit, DefaultFormBytes), ""},
		{"the largest form", body(MaxUploadBytesLimit, MaxFormBytesLimit), ""},
		{"form equal to upload", body(1<<20, 1<<20), ""},
		{"upload below the least", body(MinBodyBytes-1, MinBodyBytes), "body.max_upload_bytes"},
		{"upload zero", body(0, MinBodyBytes), "body.max_upload_bytes"},
		{"upload negative", body(-5, MinBodyBytes), "body.max_upload_bytes"},
		{"upload above the most", body(MaxUploadBytesLimit+1, MinBodyBytes), "body.max_upload_bytes"},
		{"upload a terabyte", body(1<<40, MinBodyBytes), "body.max_upload_bytes"},
		{"form below the least", body(1<<20, MinBodyBytes-1), "body.max_form_bytes"},
		{"form zero", body(1<<20, 0), "body.max_form_bytes"},
		{"form above the most", body(MaxUploadBytesLimit, MaxFormBytesLimit+1), "body.max_form_bytes"},
		{"form more than upload", body(2048, 4096), "body.max_form_bytes"},
		{"form one more than upload", body(1<<20, 1<<20+1), "body.max_form_bytes"},
		{"both wrong", body(0, 0), "body.max_upload_bytes"},
		{"upload at the engine's own limit of 1 GiB", body(1<<30, MinBodyBytes), "body.max_upload_bytes"},
	}
	runRows(t, 15, rows)
}

func TestValidateMethods(t *testing.T) {
	set := func(m ...string) func(*Policy) { return func(p *Policy) { p.AllowedMethods = m } }
	many := make([]string, MaxMethods+1)
	for i := range many {
		many[i] = fmt.Sprintf("M%c", 'A'+i)
	}
	rows := []vrow{
		{"the defaults", func(p *Policy) {}, ""},
		{"one method", set("GET"), ""},
		{"a REST API", set("GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"), ""},
		{"WebDAV methods", set("GET", "PROPFIND", "MKCOL", "COPY", "MOVE", "LOCK", "UNLOCK"), ""},
		{"a method with a hyphen", set("GET", "VERSION-CONTROL"), ""},
		{"lower case is made upper case", set("get", "post"), ""},
		{"twenty methods", set(many[:MaxMethods]...), ""},
		{"none", set(), "allowed_methods"},
		{"more than twenty", set(many...), "allowed_methods"},
		{"CONNECT", set("GET", "CONNECT"), "allowed_methods"},
		{"TRACE", set("GET", "TRACE"), "allowed_methods"},
		{"trace in lower case", set("GET", "trace"), "allowed_methods"},
		{"a method with a space", set("GET HEAD"), "allowed_methods"},
		{"a method with a quote", set(`GET"`), "allowed_methods"},
		{"a method with a digit", set("G3T"), "allowed_methods"},
		{"a method of 21 letters", set(strings.Repeat("A", 21)), "allowed_methods"},
		{"a method of 20 letters", set(strings.Repeat("A", 20)), ""},
		{"an empty method", set(""), "allowed_methods"},
		{"a method with a newline", set("GET\nSecRuleEngine Off"), "allowed_methods"},
		{"a method with a non-ASCII letter", set("GÉT"), "allowed_methods"},
		{"a method that starts with a hyphen", set("-GET"), "allowed_methods"},
	}
	runRows(t, 15, rows)
}

func TestValidateHosts(t *testing.T) {
	set := func(h ...string) func(*Policy) { return func(p *Policy) { p.AllowedHosts = h } }
	label63, label64 := strings.Repeat("a", 63), strings.Repeat("a", 64)
	many := make([]string, MaxHosts+1)
	for i := range many {
		many[i] = fmt.Sprintf("h%d.example.test", i)
	}
	long := strings.Repeat(label63+".", 4) + "com" // 4*64 + 3 > 253
	rows := []vrow{
		{"no names (any name)", set(), ""},
		{"a name", set("www.example.com"), ""},
		{"two names", set("example.com", "www.example.com"), ""},
		{"upper case is made lower case", set("WWW.Example.COM"), ""},
		{"a single label", set("localhost"), ""},
		{"a hyphen inside a label", set("my-shop.example.com"), ""},
		{"punycode", set("xn--bcher-kva.example"), ""},
		{"digits", set("123.example.com"), ""},
		{"a label of 63 characters", set(label63 + ".test"), ""},
		{"a hundred names", set(many[:MaxHosts]...), ""},
		{"more than a hundred", set(many...), "allowed_hosts"},
		{"a label of 64 characters", set(label64 + ".test"), "allowed_hosts"},
		{"a name over 253 characters", set(long), "allowed_hosts"},
		{"an empty name", set(""), "allowed_hosts"},
		{"a trailing dot", set("example.com."), "allowed_hosts"},
		{"a leading dot", set(".example.com"), "allowed_hosts"},
		{"two dots", set("a..example.com"), "allowed_hosts"},
		{"a port", set("example.com:8443"), "allowed_hosts"},
		{"a wildcard", set("*.example.com"), "allowed_hosts"},
		{"a leading hyphen", set("-a.example.com"), "allowed_hosts"},
		{"a trailing hyphen", set("a-.example.com"), "allowed_hosts"},
		{"an underscore", set("a_b.example.com"), "allowed_hosts"},
		{"a space", set("a b.example.com"), "allowed_hosts"},
		{"a slash", set("example.com/path"), "allowed_hosts"},
		{"user information", set("user@example.com"), "allowed_hosts"},
		{"an IPv6 literal", set("[::1]"), "allowed_hosts"},
		{"a non-ASCII name (it must be written in punycode)", set("bücher.example"), "allowed_hosts"},
		{"a newline", set("example.com\nSecRuleEngine Off"), "allowed_hosts"},
	}
	runRows(t, 15, rows)
}

func TestValidateRuleGroups(t *testing.T) {
	set := func(m map[string]GroupState) func(*Policy) { return func(p *Policy) { p.RuleGroups = m } }
	all := map[string]GroupState{}
	for _, g := range Groups() {
		all[g.Name] = GroupLog
	}
	rows := []vrow{
		{"none", set(nil), ""},
		{"empty", set(map[string]GroupState{}), ""},
		{"sqli off", set(map[string]GroupState{"sqli": GroupOff}), ""},
		{"xss log", set(map[string]GroupState{"xss": GroupLog}), ""},
		{"lfi on", set(map[string]GroupState{"lfi": GroupOn}), ""},
		{"every group at log", set(all), ""},
		{"rfi rce php", set(map[string]GroupState{"rfi": GroupOff, "rce": GroupLog, "php": GroupOff}), ""},
		{"ssrf java scanner protocol", set(map[string]GroupState{"ssrf": GroupLog, "java": GroupOff, "scanner": GroupOff, "protocol": GroupLog}), ""},
		{"a name in capitals is made lower case", set(map[string]GroupState{"SQLI": GroupOff}), ""},
		{"conflicting group case aliases", set(map[string]GroupState{"sqli": GroupOff, "SQLI": GroupLog}), "rule_groups"},
		{"default and disabled group case aliases", set(map[string]GroupState{"sqli": GroupOn, "SQLI": GroupOff}), "rule_groups"},
		{"matching group case aliases", set(map[string]GroupState{"sqli": GroupOn, "SQLI": GroupOn}), "rule_groups"},
		{"a known default group in capitals", set(map[string]GroupState{"SQLI": GroupOn}), ""},
		{"an unknown group at its default", set(map[string]GroupState{"ssti": GroupOn}), "rule_groups"},
		{"an unknown group", set(map[string]GroupState{"ssti": GroupOff}), "rule_groups"},
		{"the PHP console's wordpress group", set(map[string]GroupState{"wordpress": GroupOff}), "rule_groups"},
		{"an empty name", set(map[string]GroupState{"": GroupOff}), "rule_groups"},
		{"a name with a space", set(map[string]GroupState{"sqli ": GroupOff}), "rule_groups"},
		{"a state in capitals", set(map[string]GroupState{"sqli": "OFF"}), "rule_groups.sqli"},
		{"a state that is not one", set(map[string]GroupState{"sqli": "block"}), "rule_groups.sqli"},
		{"an empty state", set(map[string]GroupState{"sqli": ""}), "rule_groups.sqli"},
		{"a name that is a range", set(map[string]GroupState{"942000-942999": GroupOff}), "rule_groups"},
		{"a name with a newline", set(map[string]GroupState{"sqli\nSecRuleEngine Off": GroupOff}), "rule_groups"},
	}
	runRows(t, 15, rows)
}

func TestValidateExclusions(t *testing.T) {
	ex := func(path string, cats []string, targets ...string) func(*Policy) {
		return func(p *Policy) { p.Exclusions = []Exclusion{{Path: path, Categories: cats, Targets: targets}} }
	}
	xss := []string{"xss"}
	manyTargets := []string{"args", "argnames", "cookies", "cookienames", "headers", "body", "query", "path", "uri"}
	hundred := func(p *Policy) {
		for i := 0; i < MaxExclusions+1; i++ {
			p.Exclusions = append(p.Exclusions, Exclusion{Path: fmt.Sprintf("/p%d/", i), Categories: xss})
		}
	}
	rows := []vrow{
		{"a folder, a group, the whole request", ex("/editor/", xss), ""},
		{"a file", ex("/wp-admin/admin-ajax.php", xss), ""},
		{"the root", ex("/", xss), ""},
		{"two groups", ex("/a/", []string{"xss", "sqli"}), ""},
		{"every group", ex("/a/", []string{"sqli", "xss", "lfi", "rfi", "rce", "php", "ssrf", "java", "scanner", "protocol"}), ""},
		{"one argument", ex("/a/", xss, "arg:content"), ""},
		{"one cookie and one header", ex("/a/", xss, "cookie:session", "header:x-api-key"), ""},
		{"each fixed target", ex("/a/", xss, "args", "argnames", "cookies", "cookienames", "headers", "body", "query", "path"), ""},
		{"targets in capitals are made lower case", ex("/a/", xss, "ARG:Content"), ""},
		{"an argument written as a PHP array", ex("/a/", xss, "arg:items[0]"), ""},
		{"a path with allowed punctuation", ex("/a-b_c.d~e@f:g=h+i,j/", xss), ""},
		{"an empty path", ex("", xss), "exclusions[0].path"},
		{"a path that does not start with a slash", ex("editor/", xss), "exclusions[0].path"},
		{"a path with a space", ex("/a b/", xss), "exclusions[0].path"},
		{"a path with a quote", ex(`/a"b/`, xss), "exclusions[0].path"},
		{"a path with an apostrophe", ex("/a'b/", xss), "exclusions[0].path"},
		{"a path with a backslash", ex(`/a\b/`, xss), "exclusions[0].path"},
		{"a path with a percent sign", ex("/a%2fb/", xss), "exclusions[0].path"},
		{"a path with a macro", ex("/%{tx.x}/", xss), "exclusions[0].path"},
		{"a path with a semicolon", ex("/a;b/", xss), "exclusions[0].path"},
		{"a path with a pipe", ex("/a|b/", xss), "exclusions[0].path"},
		{"a path with a newline", ex("/a\nSecRuleEngine Off\n/", xss), "exclusions[0].path"},
		{"a path with a NUL", ex("/a\x00b/", xss), "exclusions[0].path"},
		{"a path with a hash", ex("/a#b/", xss), "exclusions[0].path"},
		{"a path with a question mark", ex("/a?b=c", xss), "exclusions[0].path"},
		{"a path with a dot segment", ex("/a/../b/", xss), "exclusions[0].path"},
		{"a path with a double slash", ex("/a//b/", xss), "exclusions[0].path"},
		{"a path with a non-ASCII letter", ex("/café/", xss), "exclusions[0].path"},
		{"a path with a brace", ex("/a{b}/", xss), "exclusions[0].path"},
		{"a path of 200 characters", ex("/"+strings.Repeat("a", 199), xss), ""},
		{"a path of 201 characters", ex("/"+strings.Repeat("a", 200), xss), "exclusions[0].path"},
		{"no groups", ex("/a/", nil), "exclusions[0].categories"},
		{"an unknown group", ex("/a/", []string{"ssti"}), "exclusions[0].categories"},
		{"a group that is a range", ex("/a/", []string{"942000-942999"}), "exclusions[0].categories"},
		{"all as a group", ex("/a/", []string{"all"}), "exclusions[0].categories"},
		{"uploads as a target (not supported)", ex("/a/", xss, "uploads"), "exclusions[0].targets"},
		{"an empty argument name", ex("/a/", xss, "arg:"), "exclusions[0].targets"},
		{"an argument name with a space", ex("/a/", xss, "arg:a b"), "exclusions[0].targets"},
		{"an argument name with a semicolon", ex("/a/", xss, "arg:a;ctl:ruleEngine=Off"), "exclusions[0].targets"},
		{"an argument name with a comma", ex("/a/", xss, "arg:a,b"), "exclusions[0].targets"},
		{"an argument name with only a semicolon in it", ex("/a/", xss, "arg:a;b"), "exclusions[0].targets"},
		{"a cookie name with only a semicolon in it", ex("/a/", xss, "cookie:a;b"), "exclusions[0].targets"},
		{"an argument name with a pipe", ex("/a/", xss, "arg:a|b"), "exclusions[0].targets"},
		{"an argument name with a slash (a regular expression)", ex("/a/", xss, "arg:/x/"), "exclusions[0].targets"},
		{"an argument name of 65 characters", ex("/a/", xss, "arg:"+strings.Repeat("a", 65)), "exclusions[0].targets"},
		{"a header with an underscore", ex("/a/", xss, "header:x_api_key"), "exclusions[0].targets"},
		{"an unknown kind of name", ex("/a/", xss, "file:a"), "exclusions[0].targets"},
		{"nine targets", ex("/a/", xss, manyTargets...), "exclusions[0].targets"},
		{"a note with a control character", func(p *Policy) {
			p.Exclusions = []Exclusion{{Path: "/a/", Categories: xss, Note: "x\x07y"}}
		}, "exclusions[0].note"},
		{"a note with a line break (not allowed on an exclusion)", func(p *Policy) {
			p.Exclusions = []Exclusion{{Path: "/a/", Categories: xss, Note: "x\ny"}}
		}, "exclusions[0].note"},
		{"a note of 201 bytes", func(p *Policy) {
			p.Exclusions = []Exclusion{{Path: "/a/", Categories: xss, Note: strings.Repeat("n", 201)}}
		}, "exclusions[0].note"},
		{"a hundred exclusions", func(p *Policy) {
			hundred(p)
			p.Exclusions = p.Exclusions[:MaxExclusions]
		}, ""},
		{"a hundred and one exclusions", hundred, "exclusions"},
	}
	runRows(t, 15, rows)
}

func TestValidateIPLists(t *testing.T) {
	allow := func(e ...string) func(*Policy) { return func(p *Policy) { p.AllowIPs = e } }
	block := func(e ...string) func(*Policy) { return func(p *Policy) { p.BlockIPs = e } }
	gen := func(n int) []string {
		out := make([]string, n)
		for i := range out {
			out[i] = fmt.Sprintf("10.%d.%d.%d", i>>16&255, i>>8&255, i&255)
		}
		return out
	}
	rows := []vrow{
		{"an address", allow("203.0.113.9"), ""},
		{"a range", allow("198.51.100.0/24"), ""},
		{"an IPv6 address", allow("2001:db8::1"), ""},
		{"an IPv6 range", allow("2001:db8::/32"), ""},
		{"an IPv4-mapped address", allow("::ffff:192.0.2.1"), ""},
		{"host bits are cleared", allow("198.51.100.77/24"), ""},
		{"the widest allow range for IPv4", allow("10.0.0.0/16"), ""},
		{"the widest allow range for IPv6", allow("2001:db8::/32"), ""},
		{"an allow range wider than /16", allow("10.0.0.0/15"), "allow_ips"},
		{"an allow range of /8", allow("10.0.0.0/8"), "allow_ips"},
		{"everyone, IPv4, in the allow list", allow("0.0.0.0/0"), "allow_ips"},
		{"everyone, IPv6, in the allow list", allow("::/0"), "allow_ips"},
		{"an IPv6 allow range wider than /32", allow("2001::/31"), "allow_ips"},
		{"the widest block range for IPv4", block("10.0.0.0/8"), ""},
		{"the widest block range for IPv6", block("2001::/16"), ""},
		{"a block range wider than /8", block("10.0.0.0/7"), "block_ips"},
		{"everyone in the block list", block("0.0.0.0/0"), "block_ips"},
		{"everyone, IPv6, in the block list", block("::/0"), "block_ips"},
		{"an IPv6 block range wider than /16", block("2000::/15"), "block_ips"},
		{"not an address", allow("not.an.address"), "allow_ips"},
		{"an empty entry", allow(""), "allow_ips"},
		{"an address with white space", allow(" 203.0.113.9"), "allow_ips"},
		{"an address with a trailing space", block("203.0.113.9 "), "block_ips"},
		{"two addresses in one entry", allow("203.0.113.9,203.0.113.10"), "allow_ips"},
		{"a range with a length too big", allow("198.51.100.0/33"), "allow_ips"},
		{"a range with a negative length", allow("198.51.100.0/-1"), "allow_ips"},
		{"a range with a hostname", allow("example.com/24"), "allow_ips"},
		{"an IPv6 zone", allow("fe80::1%eth0"), "allow_ips"},
		{"an octal-looking address", allow("010.0.0.1"), "allow_ips"},
		{"a hexadecimal address", allow("0x7f.0.0.1"), "allow_ips"},
		{"an IPv4-mapped range shorter than the mapping", allow("::ffff:0.0.0.0/64"), "allow_ips"},
		{"an entry with a newline", block("203.0.113.9\nSecRuleEngine Off"), "block_ips"},
		{"an entry with a quote", block(`203.0.113.9"`), "block_ips"},
		{"five hundred allow entries", allow(gen(MaxAllowIPs)...), ""},
		{"more than five hundred allow entries", allow(gen(MaxAllowIPs + 1)...), "allow_ips"},
		{"five thousand block entries", block(gen(MaxBlockIPs)...), ""},
		{"more than five thousand block entries", block(gen(MaxBlockIPs + 1)...), "block_ips"},
		{"duplicates count once", allow(append(gen(MaxAllowIPs), gen(MaxAllowIPs)...)...), ""},
	}
	runRows(t, 15, rows)
}

func TestValidatePathsHeadersAndOptions(t *testing.T) {
	paths := func(s ...string) func(*Policy) { return func(p *Policy) { p.AllowPaths = s } }
	headers := func(s ...string) func(*Policy) { return func(p *Policy) { p.DenyHeaders = s } }
	rate := func(n int) func(*Policy) { return func(p *Policy) { p.WordPress.LoginPerMinute = n } }
	tiers := func(s ...string) func(*Policy) { return func(p *Policy) { p.VPatch.Tiers = s } }
	software := func(s ...string) func(*Policy) { return func(p *Policy) { p.VPatch.Software = s } }
	genPaths := func(n int) []string {
		out := make([]string, n)
		for i := range out {
			out[i] = fmt.Sprintf("/hook%d/", i)
		}
		return out
	}
	genHeaders := func(n int) []string {
		out := make([]string, n)
		for i := range out {
			out[i] = fmt.Sprintf("x-h%d", i)
		}
		return out
	}
	genSoftware := func(n int) []string {
		out := make([]string, n)
		for i := range out {
			out[i] = fmt.Sprintf("app%d", i)
		}
		return out
	}
	rows := []vrow{
		{"a webhook path", paths("/webhook/stripe"), ""},
		{"a folder", paths("/hooks/"), ""},
		{"two hundred paths", paths(genPaths(MaxAllowPaths)...), ""},
		{"more than two hundred paths", paths(genPaths(MaxAllowPaths + 1)...), "allow_paths"},
		{"a path with a space", paths("/pay ment/"), "allow_paths"},
		{"a path with a query", paths("/a?b=c"), "allow_paths"},
		{"a path with a quote", paths(`/a"b`), "allow_paths"},
		{"a relative path", paths("hooks/"), "allow_paths"},
		{"a path with a dot segment", paths("/a/./b"), "allow_paths"},
		{"an empty path", paths(""), "allow_paths"},
		{"a header", headers("x-forwarded-host"), ""},
		{"a header with underscores is written with hyphens", headers("X_Forwarded_Host"), ""},
		{"fifty headers", headers(genHeaders(MaxDenyHeaders)...), ""},
		{"more than fifty headers", headers(genHeaders(MaxDenyHeaders + 1)...), "deny_headers"},
		{"a header with a space", headers("x a"), "deny_headers"},
		{"a header with a colon", headers("x:a"), "deny_headers"},
		{"an empty header", headers(""), "deny_headers"},
		{"a header of 65 characters", headers(strings.Repeat("a", 65)), "deny_headers"},
		{"a header with a newline", headers("x\nSecRuleEngine Off"), "deny_headers"},
		{"login attempts 1", rate(1), ""},
		{"login attempts 600", rate(600), ""},
		{"login attempts 0", rate(0), "wordpress.login_per_minute"},
		{"login attempts 601", rate(601), "wordpress.login_per_minute"},
		{"login attempts negative", rate(-3), "wordpress.login_per_minute"},
		{"all three tiers", tiers("verified", "community", "experimental"), ""},
		{"no tiers", tiers(), ""},
		{"an unknown tier", tiers("beta"), "vpatch.tiers"},
		{"a tier in capitals is made lower case", tiers("Verified"), ""},
		{"software", software("wordpress", "woocommerce@9.3", "elementor@3.21.1"), ""},
		{"software with a plus and a dot", software("php-fpm", "c++.runtime@1.2+b3"), ""},
		{"two hundred software entries", software(genSoftware(MaxSoftware)...), ""},
		{"more than two hundred", software(genSoftware(MaxSoftware + 1)...), "vpatch.software"},
		{"software with a space", software("word press"), "vpatch.software"},
		{"software with two versions", software("a@1@2"), "vpatch.software"},
		{"software with a slash", software("a/b"), "vpatch.software"},
		{"software with an empty version", software("a@"), "vpatch.software"},
		{"a note of 1000 bytes", func(p *Policy) { p.Note = strings.Repeat("n", MaxNoteBytes) }, ""},
		{"a note of 1001 bytes", func(p *Policy) { p.Note = strings.Repeat("n", MaxNoteBytes+1) }, "note"},
		{"a note with a tab", func(p *Policy) { p.Note = "a\tb" }, "note"},
		{"a note with a zero-width space", func(p *Policy) { p.Note = "a\u200bb" }, "note"},
		{"a note with a right-to-left override", func(p *Policy) { p.Note = "a\u202eb" }, "note"},
		{"a note with a line separator", func(p *Policy) { p.Note = "a\u2028b" }, "note"},
		{"a note with a non-breaking space", func(p *Policy) { p.Note = "a\u00a0b" }, "note"},
		{"a note with letters of another script, an emoji and a line break", func(p *Policy) { p.Note = "日本語 café 😀\nok" }, ""},
		{"a note that is not UTF-8", func(p *Policy) { p.Note = "a\xffb" }, "note"},
	}
	runRows(t, 15, rows)
}

func TestValidateCustomRules(t *testing.T) {
	rule := func(r CustomRule) func(*Policy) {
		return func(p *Policy) {
			if r.ID == 0 {
				r.ID = 1
			}
			p.CustomRules = []CustomRule{r}
		}
	}
	base := func(op Operator, value string) CustomRule {
		return CustomRule{ID: 1, Field: "args", Operator: op, Value: value, Action: ActionBlock}
	}
	pm := func(words ...string) CustomRule {
		return CustomRule{ID: 1, Field: "args", Operator: OpPM, Values: words, Action: ActionLog}
	}
	manyWords := make([]string, MaxPMValues+1)
	for i := range manyWords {
		manyWords[i] = fmt.Sprintf("word%d", i)
	}
	with := func(c CustomRule, f func(*CustomRule)) CustomRule { f(&c); return c }
	rows := []vrow{
		{"contains", rule(base(OpContains, "casino")), ""},
		{"equals", rule(base(OpEquals, "/status?debug=1")), ""},
		{"beginsWith", rule(base(OpBeginsWith, "/old-admin/")), ""},
		{"endsWith", rule(base(OpEndsWith, ".php")), ""},
		{"rx", rule(base(OpRX, `^/old-(admin|panel)/`)), ""},
		{"pm", rule(pm("viagra", "cialis")), ""},
		{"case sensitive", rule(with(base(OpContains, "Casino"), func(r *CustomRule) { r.CaseSensitive = true })), ""},
		{"a value with a double quote", rule(base(OpContains, `a"b`)), ""},
		{"a value with an apostrophe", rule(base(OpContains, `it's`)), ""},
		{"a value with a backslash", rule(base(OpContains, `a\b`)), ""},
		{"a value that ends in a backslash", rule(base(OpEndsWith, `a\`)), ""},
		{"a value with a percent sign and a macro", rule(base(OpContains, `%{tx.score}`)), ""},
		{"a value with a newline", rule(base(OpContains, "a\nb")), ""},
		{"a value with a NUL", rule(base(OpContains, "a\x00b")), ""},
		{"a value with SecLang in it", rule(base(OpContains, `" "id:1,pass"`+"\nSecRuleEngine Off")), ""},
		{"a value with letters of another script and an emoji", rule(base(OpContains, "日本語 café 😀")), ""},
		{"a field that is one header", rule(with(base(OpContains, "x"), func(r *CustomRule) { r.Field = "header:x-api-key" })), ""},
		{"a field that is one argument", rule(with(base(OpContains, "x"), func(r *CustomRule) { r.Field = "arg:id" })), ""},
		{"a field that is one cookie", rule(with(base(OpContains, "x"), func(r *CustomRule) { r.Field = "cookie:session" })), ""},
		{"the host and the user agent", rule(with(base(OpContains, "x"), func(r *CustomRule) { r.Field = "useragent" })), ""},
		{"an id of 9999", rule(with(base(OpContains, "x"), func(r *CustomRule) { r.ID = 9999 })), ""},
		{"a value of 256 bytes", rule(base(OpContains, strings.Repeat("a", MaxValueBytes))), ""},
		{"fifty words of 64 bytes", rule(pm(func() []string {
			w := make([]string, MaxPMValues)
			for i := range w {
				w[i] = fmt.Sprintf("%063d", i) + "x"
			}
			return w
		}()...)), ""},
		{"an empty value", rule(base(OpContains, "")), "custom_rules[1].value"},
		{"a value of 257 bytes", rule(base(OpContains, strings.Repeat("a", MaxValueBytes+1))), "custom_rules[1].value"},
		{"a value with a line separator", rule(base(OpContains, "a\u2028b")), "custom_rules[1].value"},
		{"a value with a next-line character", rule(base(OpContains, "a\u0085b")), "custom_rules[1].value"},
		{"a value with a zero-width space", rule(base(OpContains, "a\u200bb")), "custom_rules[1].value"},
		{"a value with a right-to-left override", rule(base(OpContains, "a\u202eb")), "custom_rules[1].value"},
		{"a value with a non-breaking space", rule(base(OpContains, "a\u00a0b")), "custom_rules[1].value"},
		{"a value that is not UTF-8", rule(base(OpContains, "a\xffb")), "custom_rules[1].value"},
		{"an rx that does not parse", rule(base(OpRX, `(`)), "custom_rules[1].value"},
		{"an rx with a possessive quantifier", rule(base(OpRX, `a++b`)), "custom_rules[1].value"},
		{"an rx with a lookahead", rule(base(OpRX, `(?=a)b`)), "custom_rules[1].value"},
		{"an rx with a back-reference", rule(base(OpRX, `(a)\1`)), "custom_rules[1].value"},
		{"an rx with an atomic group", rule(base(OpRX, `(?>a+)b`)), "custom_rules[1].value"},
		{"an rx that repeats too much", rule(base(OpRX, `(a{1000}){1000}`)), "custom_rules[1].value"},
		{"an rx that repeats too much, nested deeper", rule(base(OpRX, `((a{100}){100}){100}`)), "custom_rules[1].value"},
		{"an rx with a hex escape above 0x7f, which RE2 reads as that character and is written out as itself", rule(base(OpRX, `\xff`)), ""},
		{"an rx with a braced escape", rule(base(OpRX, `\x{1F600}|\x{85}`)), "custom_rules[1].value"},
		{"an rx that is empty", rule(base(OpRX, ``)), "custom_rules[1].value"},
		{"an rx with a unicode class", rule(base(OpRX, `\p{Han}+`)), ""},
		{"an rx with a negated ASCII class, which is a range above 0x7f that the engine would read as bytes", rule(base(OpRX, `[^\x00-\x7f]`)), "custom_rules[1].value"},
		{"an rx with a quote and a space", rule(base(OpRX, `a" b'c%d`)), ""},
		{"an rx that ends in an escaped backslash", rule(base(OpRX, `a\\`)), ""},
		{"an rx that ends in a lone backslash", rule(base(OpRX, `a\`)), "custom_rules[1].value"},
		{"an rx with a flag group", rule(base(OpRX, `(?i)admin`)), ""},
		{"an rx with an unsupported flag", rule(base(OpRX, `(?x) a b`)), "custom_rules[1].value"},
		{"pm with no words", rule(pm()), "custom_rules[1].values"},
		{"pm with an empty word", rule(pm("a", "")), "custom_rules[1].values"},
		{"pm with a word of 65 bytes", rule(pm(strings.Repeat("a", MaxPMValueBytes+1))), "custom_rules[1].values"},
		{"pm with 51 words", rule(pm(manyWords...)), "custom_rules[1].values"},
		{"pm with a value as well", rule(with(pm("a"), func(r *CustomRule) { r.Value = "b" })), "custom_rules[1].value"},
		{"contains with words", rule(with(base(OpContains, "a"), func(r *CustomRule) { r.Values = []string{"b"} })), "custom_rules[1].values"},
		{"a word with a line separator", rule(pm("a\u2028b")), "custom_rules[1].values"},
		{"an id of 0", func(p *Policy) {
			r := base(OpContains, "x")
			r.ID = 0
			p.CustomRules = []CustomRule{r}
		}, "custom_rules[#1].id"},
		{"a negative id", rule(with(base(OpContains, "x"), func(r *CustomRule) { r.ID = -4 })), "custom_rules[#1].id"},
		{"an id of 10000", rule(with(base(OpContains, "x"), func(r *CustomRule) { r.ID = 10000 })), "custom_rules[#1].id"},
		{"an operator that is not one", rule(with(base(OpContains, "x"), func(r *CustomRule) { r.Operator = "regex" })), "custom_rules[1].operator"},
		{"an operator in the wrong case", rule(with(base(OpContains, "x"), func(r *CustomRule) { r.Operator = "BeginsWith" })), "custom_rules[1].operator"},
		{"an empty operator", rule(with(base(OpContains, "x"), func(r *CustomRule) { r.Operator = "" })), "custom_rules[1].operator"},
		{"an action that is not one", rule(with(base(OpContains, "x"), func(r *CustomRule) { r.Action = "allow" })), "custom_rules[1].action"},
		{"an empty action", rule(with(base(OpContains, "x"), func(r *CustomRule) { r.Action = "" })), "custom_rules[1].action"},
		{"a field that is not one", rule(with(base(OpContains, "x"), func(r *CustomRule) { r.Field = "ARGS_POST" })), "custom_rules[1].field"},
		{"uploads as a field", rule(with(base(OpContains, "x"), func(r *CustomRule) { r.Field = "uploads" })), "custom_rules[1].field"},
		{"a header field with a space", rule(with(base(OpContains, "x"), func(r *CustomRule) { r.Field = "header:a b" })), "custom_rules[1].field"},
		{"an argument field with only a semicolon", rule(with(base(OpContains, "x"), func(r *CustomRule) { r.Field = "arg:a;b" })), "custom_rules[1].field"},
		{"an argument field with a pipe", rule(with(base(OpContains, "x"), func(r *CustomRule) { r.Field = "arg:a|REQUEST_BODY" })), "custom_rules[1].field"},
		{"a field that is two variables", rule(with(base(OpContains, "x"), func(r *CustomRule) { r.Field = "args|body" })), "custom_rules[1].field"},
		{"a field that is a regular expression key", rule(with(base(OpContains, "x"), func(r *CustomRule) { r.Field = "arg:/.*/" })), "custom_rules[1].field"},
		{"an empty field", rule(with(base(OpContains, "x"), func(r *CustomRule) { r.Field = "" })), "custom_rules[1].field"},
		{"a note with a control character", rule(with(base(OpContains, "x"), func(r *CustomRule) { r.Note = "a\x01" })), "custom_rules[1].note"},
		{"a note of 201 bytes", rule(with(base(OpContains, "x"), func(r *CustomRule) { r.Note = strings.Repeat("n", 201) })), "custom_rules[1].note"},
		{"two rules with one id", func(p *Policy) {
			p.CustomRules = []CustomRule{base(OpContains, "a"), base(OpContains, "b")}
		}, "custom_rules[1].id"},
		{"a hundred rules", func(p *Policy) {
			for i := 1; i <= MaxCustomRules; i++ {
				r := base(OpContains, "x")
				r.ID = i
				p.CustomRules = append(p.CustomRules, r)
			}
		}, ""},
		{"a hundred and one rules", func(p *Policy) {
			for i := 1; i <= MaxCustomRules+1; i++ {
				r := base(OpContains, "x")
				r.ID = i
				p.CustomRules = append(p.CustomRules, r)
			}
		}, "custom_rules"},
	}
	runRows(t, 15, rows)
}

func TestValidateReportsEveryProblemAndLimitsHowMany(t *testing.T) {
	bad := func(n int) Policy {
		p := Default()
		p.Mode, p.Sensitivity, p.APIMode = "x", "y", "z"
		for i := 0; i < n; i++ {
			p.AllowedHosts = append(p.AllowedHosts, fmt.Sprintf("bad host %d", i))
		}
		return p
	}
	var e *Error
	if err := bad(30).Validate(); !errors.As(err, &e) {
		t.Fatalf("not an *Error: %v", err)
	}
	seen := map[string]bool{}
	for _, pr := range e.Problems {
		seen[strings.SplitN(pr.Path, "[", 2)[0]] = true
	}
	for _, want := range []string{"mode", "sensitivity", "api_mode", "allowed_hosts"} {
		if !seen[want] {
			t.Errorf("no problem reported for %s: %v", want, e.Problems[:4])
		}
	}
	if len(e.Problems) != 33 {
		t.Errorf("%d problems, want every one of the 33", len(e.Problems))
	}
	err := bad(80).Validate()
	if !errors.As(err, &e) {
		t.Fatalf("not an *Error: %v", err)
	}
	if len(e.Problems) != maxProblems {
		t.Fatalf("%d problems, want exactly the cap of %d", len(e.Problems), maxProblems)
	}
	if !strings.Contains(e.Problems[len(e.Problems)-1].Message, "more problems") {
		t.Errorf("the last problem does not say there were more: %q", e.Problems[len(e.Problems)-1].Message)
	}
	if e.Error() == "" || !errors.Is(e, ErrInvalid) {
		t.Error("the error has no text or is not ErrInvalid")
	}
	if (&Error{}).Error() == "" {
		t.Error("an empty Error has no text")
	}
}

func TestProblemsNeverRepeatWhatTheCustomerSent(t *testing.T) {
	secret := "SENTINEL-" + strings.Repeat("s", 80)
	p := Default()
	p.Mode = Mode(secret)
	p.AllowedHosts = []string{secret}
	p.AllowedMethods = []string{secret}
	p.RuleGroups = map[string]GroupState{secret: GroupOff}
	p.AllowIPs = []string{secret}
	p.DenyHeaders = []string{secret}
	p.Exclusions = []Exclusion{{Path: secret, Categories: []string{secret}, Targets: []string{secret}}}
	p.CustomRules = []CustomRule{{ID: 1, Field: secret, Operator: Operator(secret), Value: secret, Action: Action(secret)}}
	err := p.Validate()
	if err == nil {
		t.Fatal("accepted")
	}
	var e *Error
	errors.As(err, &e)
	for _, pr := range e.Problems {
		if strings.Contains(pr.Message, secret) || strings.Contains(pr.Path, secret) {
			t.Errorf("a problem repeats the whole of what was sent: %+v", pr)
		}
	}
	raw, _ := json.Marshal(e.Problems)
	if len(raw) > 20000 {
		t.Errorf("the problems are %d bytes for one policy", len(raw))
	}
}
