// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"fmt"
	"net/url"
	"regexp"
	"runtime"
	"strings"
	"testing"
	"time"
	"unicode"
	"unicode/utf8"
)

// hostile is text chosen to end a directive, start another, open a macro, escape a quote, hide in a line, or confuse the engine's
// reading of an escape. Every operator is tried with every one of them.
var hostile = []string{
	"a\nb", "a\r\nb", "\n", "\r", "a\"b", `"`, `""`, `\`, `\\`, `a\`, `\"`, `\\"`, `a\"b`, `a'b`, `'`, `%`, `%{tx.score}`, `%{REQUEST_URI}`, `%%`, `a%b`,
	"SecRule", "SecRuleEngine Off", `" "id:1" "x`, "\nSecRule ARGS \"x\" \"id:2,pass\"", `"` + "\nSecRuleEngine Off\n" + `"`, "Include /etc/passwd", "#", "# comment",
	"ctl:ruleEngine=Off", `",ctl:ruleEngine=Off,"`, `',ctl:ruleEngine=Off,'`, "a b", " a", "a ", "\ta", "\x00", "a\x00b", "\x7f", "\x1b[31m",
	"\u2028", "\u2029", "\u0085", "a\u2028b", "\u200b", "\u200d", "\u202e", "\u2066", "\u00a0", "\u3000", "\ufeff", "\ufffd", "é", "É", "日本語", "😀", "ǅ",
	"\xff", "\xc0\xaf", "\xed\xa0\x80",
	strings.Repeat("a", 256), strings.Repeat(`"`, 64), strings.Repeat(`\`, 64), strings.Repeat("%{", 40), strings.Repeat("\n", 20),
	"`", "a`", "`\n", "|", ",", ":", ";", "[", "]", "{", "}", "(", ")", "*", "+", "?", ".", "^", "$", "x|y", "(?i)", "(?s:.)", `\x41`, `\x{41}`, `\Q`, `\E`, `\Qa\E`,
	"\\\n", "a\\\nb", "\\", "a\\", `phase:1,deny`, `id:1`, "\"\\", "\\\"", "\\\\\"",
}

// rejectedForText says a value that Validate may refuse, because it holds a character that cannot be shown or written safely,
// is empty, or is not text.
func rejectedForText(s string) bool {
	if s == "" || !utf8.ValidString(s) {
		return true
	}
	for _, r := range s {
		if r >= 0x80 && !unicode.IsPrint(r) {
			return true
		}
	}
	return false
}

func oneRule(op Operator, value string, words []string, cs bool) Policy {
	return mut(func(p *Policy) {
		p.CustomRules = []CustomRule{{ID: 7, Field: "args", Operator: op, Value: value, Values: words, CaseSensitive: cs, Action: ActionBlock}}
	})
}

// query makes a request whose argument "a" holds exactly v after the engine has decoded it.
func query(v string) string { return "/?a=" + url.QueryEscape(v) }

// Every operator, every hostile value: the policy is either refused for a documented reason or compiles to exactly one rule, on one
// line, that the engine reads as exactly one rule, and that matches what the operator means.
func TestHostileValuesCompileToOneRuleOrNone(t *testing.T) {
	type op struct {
		name   Operator
		oracle func(value string, cs bool) *regexp.Regexp
	}
	ci := func(cs bool) string {
		if cs {
			return ""
		}
		return "(?i)"
	}
	ops := []op{
		{OpContains, func(v string, cs bool) *regexp.Regexp { return regexp.MustCompile(ci(cs) + regexp.QuoteMeta(v)) }},
		{OpEquals, func(v string, cs bool) *regexp.Regexp {
			return regexp.MustCompile(ci(cs) + `\A` + regexp.QuoteMeta(v) + `\z`)
		}},
		{OpBeginsWith, func(v string, cs bool) *regexp.Regexp { return regexp.MustCompile(ci(cs) + `\A` + regexp.QuoteMeta(v)) }},
		{OpEndsWith, func(v string, cs bool) *regexp.Regexp { return regexp.MustCompile(ci(cs) + regexp.QuoteMeta(v) + `\z`) }},
	}
	accepted, refused := 0, 0
	for _, o := range ops {
		for _, cs := range []bool{false, true} {
			for _, v := range hostile {
				name := fmt.Sprintf("%s/cs=%v/%q", o.name, cs, v)
				if len(name) > 90 {
					name = name[:90]
				}
				t.Run(name, func(t *testing.T) {
					p := oneRule(o.name, v, nil, cs)
					err := p.Validate()
					if err != nil {
						refused++
						if !rejectedForText(v) && len(v) <= MaxValueBytes {
							t.Fatalf("refused for no documented reason: %v", err)
						}
						if _, cerr := Compile(p); cerr == nil {
							t.Fatal("Compile accepted what Validate refused")
						}
						return
					}
					accepted++
					if rejectedForText(v) {
						t.Fatalf("a value that is empty or has a character that cannot be written safely was accepted: %q", v)
					}
					q := p.Normalize()
					text, n, err := renderBefore(q)
					if err != nil || n != 1 {
						t.Fatalf("renderBefore: %d rules, %v", n, err)
					}
					if strings.Count(text, "\n") != 0 || strings.Count(text, `"`) != 4 {
						t.Fatalf("not one line of four quotation marks: %q", text)
					}
					waf, rules, err := wafWith(t, text)
					if err != nil {
						t.Fatalf("the engine refused the rule: %v\n%s", err, text)
					}
					if rules != 1 {
						t.Fatalf("the engine read %d rules from one: %s", rules, text)
					}
					oracle := o.oracle(v, cs)
					probes := []string{v, "pre" + v + "post", v + "post", "pre" + v, strings.ToUpper(v), strings.ToLower(v), "", "x", "pre", "post", strings.TrimSuffix(v, v[len(v)-1:]),
						"%{tx.score}", `"`, `\`, "a\nb", "É"}
					for _, probe := range probes {
						if !utf8.ValidString(probe) {
							continue
						}
						ids, status := matched(t, waf, "GET", query(probe), nil, "")
						want := oracle.MatchString(probe)
						if got := has(ids, idCustom+7); got != want {
							t.Fatalf("probe %q: the engine says %v, the operator means %v\n%s", probe, got, want, text)
						}
						if want && status != 403 {
							t.Fatalf("probe %q matched but the status is %d, not 403", probe, status)
						}
						if !want && status != 0 {
							t.Fatalf("probe %q did not match but was interrupted (%d)", probe, status)
						}
					}
				})
			}
		}
	}
	if accepted < 100 || refused < 20 {
		t.Fatalf("the table is not exercising both outcomes: %d accepted, %d refused", accepted, refused)
	}
}

func TestHostilePMWordsCompileToOneRule(t *testing.T) {
	good := 0
	for _, v := range hostile {
		for _, cs := range []bool{false, true} {
			p := oneRule(OpPM, "", []string{v, "other word"}, cs)
			if err := p.Validate(); err != nil {
				if !rejectedForText(v) && len(v) <= MaxPMValueBytes {
					t.Errorf("%q: refused for no documented reason: %v", v, err)
				}
				continue
			}
			text, n, err := renderBefore(p.Normalize())
			if err != nil || n != 1 || strings.Count(text, "\n") != 0 {
				t.Errorf("%q: %d rules, %v", v, n, err)
				continue
			}
			waf, rules, err := wafWith(t, text)
			if err != nil || rules != 1 {
				t.Errorf("%q: the engine read %d rules (%v) from %s", v, rules, err, text)
				continue
			}
			for _, probe := range []string{v, "xx" + v + "yy", "OTHER WORD here", "neither", ""} {
				if !utf8.ValidString(probe) {
					continue
				}
				want := false
				for _, w := range []string{v, "other word"} {
					if cs {
						want = want || strings.Contains(probe, w)
					} else {
						want = want || regexp.MustCompile("(?i)"+regexp.QuoteMeta(w)).MatchString(probe)
					}
				}
				ids, _ := matched(t, waf, "GET", query(probe), nil, "")
				if got := has(ids, idCustom+7); got != want {
					t.Errorf("pm %q probe %q: engine %v, want %v", v, probe, got, want)
				}
			}
			good++
		}
	}
	if good < 60 {
		t.Fatalf("only %d cases ran", good)
	}
}

// rx values are regular expressions, so they are not all "plain text"; what has to hold is that the rule means what RE2 says the
// expression means, in one line.
func TestRegexValuesMeanWhatRE2SaysAndStayOnOneLine(t *testing.T) {
	tests := []struct {
		pattern string
		valid   bool
	}{
		{`admin`, true}, {`^/old-(admin|panel)/`, true}, {`a.c`, true}, {`a.*c`, true}, {`a\.c`, true}, {`\d{3}-\d{4}`, true}, {`(?i)select\s+from`, true},
		{`[a-z]+@[a-z]+\.com`, true}, {`\bword\b`, true}, {`^$`, true}, {`a|b|c`, true}, {`(foo|bar)baz`, true}, {`\p{L}+`, true}, {`\p{Han}`, true},
		{`"`, true}, {`'`, true}, {`%`, true}, {`%{tx.score}`, true}, {`a b`, true}, {` a`, true}, {`a `, true}, {`\"`, true}, {`\\`, true}, {`\\"`, true}, {`a\\`, true},
		{`\x41`, true}, {`\x00`, true}, {`\x7f`, true}, {`\n`, true}, {`\r\n`, true}, {`\t`, true}, {`é`, true}, {`日本語`, true}, {`\Qa.b\E`, true}, {`\Q"%{x}\E`, true},
		{`(?s:.)`, true}, {`(?m:^a$)`, true}, {`^a$`, true}, {`a$`, true}, {`[^"]`, true}, {`["']`, true}, {`[ %]`, true}, {`[\s"]`, true}, {`[\x22-\x27]`, true},
		{"a\nb", true}, {"a\x00b", true}, {"\u2028", false}, {"\u0085", false},
		{`(`, false}, {`)`, false}, {`[`, false}, {`a**`, false}, {`a++`, false}, {`(?=a)`, false}, {`(?!a)`, false}, {`(?<=a)b`, false}, {`(a)\1`, false}, {`\`, false},
		{`a\`, false}, {`(?P<n`, false}, {`\x{85}`, false}, {`[\x{80}-\x{10ffff}]`, false}, {`[^\x00-\x7f]`, false}, {`\p{NoSuchScript}`, false},
		{strings.Repeat("a", 257), false}, {`(a{1000}){1000}`, false}, {`(((a{50}){50}){50}){50}`, false}, {"", false},
	}
	probes := []string{"", "a", "abc", "admin", "ADMIN", "/old-admin/x", "a.c", "abc.c", "123-4567", "SELECT  FROM", "x@y.com", "word", "a word b", `"`, `'`, "%", "%{tx.score}", "a b", " a",
		"a ", `\`, `\"`, `a\`, "A", "\n", "\r\n", "\t", "é", "É", "日本語", "a.b", "a\nb", "foo", "foobaz", "barbaz", "\u2028", "\u0085", "\x00", "a\x00b"}
	for _, tc := range tests {
		for _, cs := range []bool{false, true} {
			name := fmt.Sprintf("%q/cs=%v", tc.pattern, cs)
			if len(name) > 80 {
				name = name[:80]
			}
			t.Run(name, func(t *testing.T) {
				p := oneRule(OpRX, tc.pattern, nil, cs)
				err := p.Validate()
				if !tc.valid {
					if err == nil {
						t.Fatalf("accepted")
					}
					wantInvalid(t, err, "custom_rules[7].value")
					return
				}
				wantValid(t, err)
				text, n, err := renderBefore(p.Normalize())
				if err != nil || n != 1 {
					t.Fatalf("%d rules, %v", n, err)
				}
				if strings.Contains(text, "\n") {
					t.Fatalf("more than one line: %q", text)
				}
				waf, rules, err := wafWith(t, text)
				if err != nil || rules != 1 {
					t.Fatalf("the engine read %d rules (%v) from: %s", rules, err, text)
				}
				flags := "(?sm)"
				if !cs {
					flags += "(?i)"
				}
				oracle := regexp.MustCompile(flags + tc.pattern)
				for _, probe := range probes {
					ids, _ := matched(t, waf, "GET", query(probe), nil, "")
					if got, want := has(ids, idCustom+7), oracle.MatchString(probe); got != want {
						t.Fatalf("probe %q: engine %v, RE2 says %v\n%s", probe, got, want, text)
					}
				}
			})
		}
	}
}

// What a careless escaper would do, to show that the checks above would have noticed it.
func TestANaiveEscaperIsCaughtByTheSameChecks(t *testing.T) {
	naive := func(value string) string {
		return fmt.Sprintf(`SecRule ARGS "@contains %s" "id:1050007,phase:2,deny,status:403,log,t:none,msg:'Custom rule 7'"`, value)
	}
	caught := 0
	for _, v := range hostile {
		line := naive(v)
		lineOK := checkRuleLine(line, 1050007) == nil
		_, rules, err := wafWith(t, line)
		engineOK := err == nil && rules == 1
		if !lineOK || !engineOK {
			caught++
		}
	}
	// A value with a newline or a quotation mark, written in as it is, is not one rule.
	for _, v := range []string{"a\nb", `a"b`, "\nSecRuleEngine Off", `x" "id:2,pass`, "a`", "a\u2028b", `\"`} {
		if checkRuleLine(naive(v), 1050007) == nil {
			t.Errorf("checkRuleLine passed the naive rule for %q", v)
		}
	}
	if caught < 20 {
		t.Fatalf("only %d of %d hostile values break a naive rule; the checks are not strong enough to tell the two escapers apart", caught, len(hostile))
	}
	// One of them really is two rules: the engine reads the newline as the end of the first directive.
	if _, rules, err := wafWith(t, naive("x\" \"id:1,pass\"\nSecRule ARGS \"y")); err == nil && rules == 1 {
		t.Log("the naive rule with an injected directive was read as one rule by the engine (it should not have been)")
	}
	text, _, _ := renderBefore(oneRule(OpContains, "a\"\nSecRuleEngine Off\n\"b", nil, false).Normalize())
	if _, rules, err := wafWith(t, text); err != nil || rules != 1 {
		t.Fatalf("the real escaper: %d rules, %v", rules, err)
	}
}

func TestCheckRuleLineRefusesWhatCouldNotBeOneRule(t *testing.T) {
	good := `SecRule ARGS "@rx abc" "id:1050001,phase:2,pass"`
	tests := []struct {
		name string
		line string
		ok   bool
	}{
		{"a good line", good, true},
		{"a newline", good + "\nSecRuleEngine Off", false},
		{"a carriage return", good[:10] + "\r" + good[10:], false},
		{"a NUL", good[:10] + "\x00" + good[10:], false},
		{"a fifth quotation mark", `SecRule ARGS "@rx a"b" "id:1050001,phase:2,pass"`, false},
		{"only three quotation marks", `SecRule ARGS "@rx abc "id:1050001,phase:2,pass"`, false},
		{"an escaped quotation mark", `SecRule ARGS "@rx a\" "id:1050001,phase:2,pass"`, false},
		{"another id", `SecRule ARGS "@rx abc" "id:1050002,phase:2,pass"`, false},
		{"not a SecRule", `SecAction "id:1050001,phase:2,pass"`, false},
		{"a backtick", `SecRule ARGS "@rx a` + "`" + `" "id:1050001,phase:2,pass"`, false},
		{"a line separator", `SecRule ARGS "@rx a` + "\u2028" + `" "id:1050001,phase:2,pass"`, false},
		{"a paragraph separator", `SecRule ARGS "@rx a` + "\u2029" + `" "id:1050001,phase:2,pass"`, false},
		{"a next-line character", `SecRule ARGS "@rx a` + "\u0085" + `" "id:1050001,phase:2,pass"`, false},
		{"invalid UTF-8", `SecRule ARGS "@rx a` + "\xff" + `" "id:1050001,phase:2,pass"`, false},
		{"a line over the limit", `SecRule ARGS "@rx ` + strings.Repeat("a", MaxLineBytes) + `" "id:1050001,phase:2,pass"`, false},
		{"not ending in a quotation mark", good + " ", false},
		{"a DEL", good[:10] + "\x7f" + good[10:], false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := checkRuleLine(tc.line, 1050001)
			if (err == nil) != tc.ok {
				t.Fatalf("got %v, want ok = %v", err, tc.ok)
			}
		})
	}
}

func TestLiteralRxIsMadeOnlyOfPlainCharacters(t *testing.T) {
	for _, v := range hostile {
		lit, err := literalRx(v)
		if err != nil {
			if !rejectedForText(v) {
				t.Errorf("%q: %v", v, err)
			}
			continue
		}
		if err := checkEmittable(lit); err != nil {
			t.Errorf("%q gave %q, which fails the check: %v", v, lit, err)
		}
		for _, r := range lit {
			if r < 0x21 || r == '"' || r == '\'' || r == '%' || r == 0x7f {
				t.Errorf("%q gave %q, which holds %q", v, lit, r)
			}
		}
	}
	if lit, _ := literalRx("a.b"); lit != `a\x2eb` {
		t.Errorf("a.b gave %q", lit)
	}
	if lit, _ := literalRx("é"); lit != "é" {
		t.Errorf("é gave %q: a printable character outside ASCII is written as itself", lit)
	}
}

func TestIPListsCompileToRulesThatMatchTheRightAddresses(t *testing.T) {
	gen := func(n int) []string {
		out := make([]string, n)
		for i := range out {
			out[i] = fmt.Sprintf("10.%d.%d.0/24", i>>8&255, i&255)
		}
		return out
	}
	p := mut(func(p *Policy) {
		p.AllowIPs = []string{"203.0.113.5", "198.51.100.0/24", "2001:db8::/32"}
		p.BlockIPs = append(gen(250), "192.0.2.0/24", "2001:db8:bad::/48")
	}).Normalize()
	text, n, err := renderBefore(p)
	if err != nil {
		t.Fatal(err)
	}
	// 1 allow rule; 252 block entries in chunks of 100 = 3 rules.
	if n != 4 {
		t.Fatalf("%d rules, want 4 (one allow, three block)", n)
	}
	waf, rules, err := wafWith(t, text)
	if err != nil || rules != 4 {
		t.Fatalf("the engine read %d rules (%v)", rules, err)
	}
	probe := func(ip string) (blocked bool, allowed bool) {
		tx := waf.NewTransaction()
		defer tx.Close()
		tx.ProcessConnection(ip, 1234, "", 0)
		tx.ProcessURI("/", "GET", "HTTP/1.1")
		it := tx.ProcessRequestHeaders()
		return it != nil && it.Status == 403, false
	}
	for _, tc := range []struct {
		ip      string
		blocked bool
	}{
		{"192.0.2.77", true}, {"192.0.3.1", false}, {"10.0.0.9", true}, {"10.0.249.200", true}, {"10.1.0.1", false}, {"10.0.250.1", false},
		{"2001:db8:bad::1", false}, // inside the allow range 2001:db8::/32, which wins
		{"2001:db9::1", false}, {"203.0.113.5", false}, {"8.8.8.8", false},
	} {
		if got, _ := probe(tc.ip); got != tc.blocked {
			t.Errorf("%s: blocked = %v, want %v", tc.ip, got, tc.blocked)
		}
	}
	// the allow list wins over the block list, even for an address that is in both
	both := mut(func(p *Policy) {
		p.AllowIPs = []string{"192.0.2.0/24"}
		p.BlockIPs = []string{"192.0.2.0/24"}
	}).Normalize()
	text, _, _ = renderBefore(both)
	waf, _, _ = wafWith(t, text)
	if blocked, _ := probe("192.0.2.9"); blocked {
		t.Error("an address on both lists was blocked: the allow list must win")
	}
	// an address list with an allow rule means the CRS never runs; checked end to end in the proxy tests
}

// A regular expression that expands to a huge program must be refused before it is expanded: the size is worked out from the
// parsed tree, so refusing it costs next to nothing, where compiling it would cost memory and seconds of the control host's time.
func TestAHugeRegularExpressionIsRefusedCheaply(t *testing.T) {
	for _, pattern := range []string{`((a{100}){100}){100}`, `(a{1000}){1000}`, `((((a{30}){30}){30}){30}){30}`, `(\pL{500}){500}`, "(" + strings.Repeat(`(a|b)`, 40) + "){200}"} {
		start := time.Now()
		var before, after runtime.MemStats
		runtime.ReadMemStats(&before)
		_, err := canonRx(pattern)
		runtime.ReadMemStats(&after)
		if err == nil {
			t.Fatalf("%q was accepted", pattern)
		}
		if d := time.Since(start); d > 200*time.Millisecond {
			t.Errorf("%q took %s to refuse", pattern, d)
		}
		if grown := after.TotalAlloc - before.TotalAlloc; grown > 8<<20 {
			t.Errorf("%q allocated %d bytes to refuse", pattern, grown)
		}
	}
}
