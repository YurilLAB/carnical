// SPDX-License-Identifier: Apache-2.0

package vpatch

import (
	"fmt"
	"math"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/YurilLAB/coraza/carnical/inspect"
)

// mkReq builds a request the way the proxy would hand it over: the URI is split at the first '?'.
func mkReq(method, uri string, headers map[string]string, body string) *inspect.Request {
	r, _ := sampleRequest{Method: method, URI: uri, Headers: headers, Body: body}.build()
	return r
}

func sig(id string, c Condition, also ...Condition) Signature {
	return Signature{ID: id, Category: "other", Severity: "high", Description: "test " + id, Condition: c, Also: also}
}

func cond(op, pattern string, targets []string, transforms ...string) Condition {
	return Condition{Operator: op, Pattern: pattern, Targets: targets, Transforms: transforms}
}

func tg(t ...string) []string { return t }

func hasHit(hits []Hit, id string) bool {
	for _, h := range hits {
		if h.ID == id {
			return true
		}
	}
	return false
}

func loadOne(t *testing.T, opts Options, s ...Signature) *Engine {
	t.Helper()
	e := New(opts)
	rep := e.Load(s)
	if len(rep.Rejected) > 0 {
		t.Fatalf("rejected: %+v", rep.Rejected)
	}
	return e
}

// TestConditionSemantics is the table of what a condition means: every operator, every target, the transforms in context, Negate,
// Also, and the named targets, each with rows that match and rows that must not.
func TestConditionSemantics(t *testing.T) {
	t.Run("transform class masks span words", func(t *testing.T) {
		names := []string{"lowercase", "normpath", "urldecode1"}
		var signatures []Signature
		for i := 0; i < 81; i++ {
			code := i
			var transforms []string
			for step := 0; step < 4; step++ {
				transforms = append(transforms, names[code%3])
				code /= 3
			}
			signatures = append(signatures, sig(fmt.Sprintf("MASK-%03d", i), cond("contains", "/danger", tg("path"), transforms...)))
		}
		e := loadOne(t, Options{}, signatures...)
		ki := &e.cur.Load().kinds[kPath]
		if len(ki.classes) != 81 || ki.words != 2 {
			t.Fatalf("class mask dimensions: %d classes, %d words", len(ki.classes), ki.words)
		}
		for _, tc := range []struct {
			path string
			want int
		}{{"/danger/attack", 81}, {"/ordinary", 0}} {
			t.Run(tc.path, func(t *testing.T) {
				request := mkReq("GET", tc.path, nil, "")
				for _, hits := range [][]Hit{e.Match(request), e.MatchBruteForce(request)} {
					if len(hits) != tc.want {
						t.Fatalf("%s: %d matches, want %d", tc.path, len(hits), tc.want)
					}
				}
			})
		}
	})
	form := map[string]string{"content-type": "application/x-www-form-urlencoded"}
	jsonH := map[string]string{"content-type": "application/json"}
	tests := []struct {
		name string
		sig  Signature
		req  *inspect.Request
		want bool
	}{
		// operators
		{"rx matches", sig("T", cond("rx", `^/wp-admin/.*\.php$`, tg("path"))), mkReq("GET", "/wp-admin/x.php", nil, ""), true},
		{"rx does not match", sig("T", cond("rx", `^/wp-admin/.*\.php$`, tg("path"))), mkReq("GET", "/wp-admin/x.txt", nil, ""), false},
		{"rx dollar accepts a final newline", sig("T", cond("rx", `x\.php$`, tg("path"), "urldecode1")), mkReq("GET", "/x.php%0a", nil, ""), true},
		{"rx dollar still needs the end", sig("T", cond("rx", `x\.php$`, tg("path"), "urldecode1")), mkReq("GET", "/x.php%0aq", nil, ""), false},
		{"rx flag i", sig("T", Condition{Operator: "rx", Pattern: "admin", Flags: "i", Targets: tg("path")}), mkReq("GET", "/ADMIN", nil, ""), true},
		{"rx without flag is case sensitive", sig("T", cond("rx", "admin", tg("path"))), mkReq("GET", "/ADMIN", nil, ""), false},
		{"contains", sig("T", cond("contains", "plugins/foo", tg("path"))), mkReq("GET", "/wp-content/plugins/foo/x.php", nil, ""), true},
		{"contains no", sig("T", cond("contains", "plugins/foo", tg("path"))), mkReq("GET", "/wp-content/plugins/bar/x.php", nil, ""), false},
		{"contains is case sensitive", sig("T", cond("contains", "Foo", tg("path"))), mkReq("GET", "/foo", nil, ""), false},
		{"contains flag i", sig("T", Condition{Operator: "contains", Pattern: "Foo", Flags: "i", Targets: tg("path")}), mkReq("GET", "/xFOOx", nil, ""), true},
		{"equals", sig("T", cond("equals", "/a", tg("path"))), mkReq("GET", "/a", nil, ""), true},
		{"equals no", sig("T", cond("equals", "/a", tg("path"))), mkReq("GET", "/a/", nil, ""), false},
		{"prefix", sig("T", cond("prefix", "/api/", tg("path"))), mkReq("GET", "/api/x", nil, ""), true},
		{"prefix no", sig("T", cond("prefix", "/api/", tg("path"))), mkReq("GET", "/x/api/", nil, ""), false},
		{"suffix", sig("T", cond("suffix", ".php", tg("path"))), mkReq("GET", "/a.php", nil, ""), true},
		{"suffix no", sig("T", cond("suffix", ".php", tg("path"))), mkReq("GET", "/a.php/b", nil, ""), false},
		{"pm words in Pattern", sig("T", cond("pm", "sqlmap nikto", tg("header:user-agent"))), mkReq("GET", "/", map[string]string{"user-agent": "xx nikto/2"}, ""), true},
		{"pm words no", sig("T", cond("pm", "sqlmap nikto", tg("header:user-agent"))), mkReq("GET", "/", map[string]string{"user-agent": "Mozilla"}, ""), false},
		{"pm list", sig("T", Condition{Operator: "pm", Patterns: []string{"a b", "zz"}, Targets: tg("path")}), mkReq("GET", "/xa bx", nil, ""), true},
		{"pm list no", sig("T", Condition{Operator: "pm", Patterns: []string{"a b", "zz"}, Targets: tg("path")}), mkReq("GET", "/ab", nil, ""), false},
		// targets
		{"uri has the query", sig("T", cond("contains", "?x=1", tg("uri"))), mkReq("GET", "/a?x=1", nil, ""), true},
		{"path has no query", sig("T", cond("contains", "x=1", tg("path"))), mkReq("GET", "/a?x=1", nil, ""), false},
		{"query only", sig("T", cond("equals", "x=1&y=2", tg("query"))), mkReq("GET", "/a?x=1&y=2", nil, ""), true},
		{"path is as received", sig("T", cond("contains", "%2e", tg("path"))), mkReq("GET", "/a%2e", nil, ""), true},
		{"method", sig("T", cond("equals", "PUT", tg("method"))), mkReq("PUT", "/", nil, ""), true},
		{"method no", sig("T", cond("equals", "PUT", tg("method"))), mkReq("GET", "/", nil, ""), false},
		{"method override header", sig("T", cond("equals", "DELETE", tg("method"))), mkReq("POST", "/", map[string]string{"x-http-method-override": "DELETE"}, ""), true},
		{"method override argument", sig("T", cond("equals", "DELETE", tg("method"))), mkReq("POST", "/?_method=DELETE", nil, ""), true},
		{"args from the query", sig("T", cond("contains", "<script", tg("args"), "lowercase")), mkReq("GET", "/?q=%3CScript%3E", nil, ""), true},
		{"args are form decoded", sig("T", cond("equals", "a b", tg("args"))), mkReq("GET", "/?q=a+b", nil, ""), true},
		{"args from a form body", sig("T", cond("equals", "evil", tg("args"))), mkReq("POST", "/", form, "a=1&b=evil"), true},
		{"args are not the body", sig("T", cond("contains", "a=1&b", tg("args"))), mkReq("POST", "/", form, "a=1&b=evil"), false},
		{"args from JSON", sig("T", cond("equals", "evil", tg("args"))), mkReq("POST", "/", jsonH, `{"a":{"b":["x","evil"]}}`), true},
		{"args from JSON sniffed from the body", sig("T", cond("equals", "evil", tg("args"))), mkReq("POST", "/", nil, `{"a":"evil"}`), true},
		{"a semicolon is part of the value", sig("T", cond("equals", "1;cat /etc/passwd", tg("arg:x"))), mkReq("GET", "/?x=1;cat%20/etc/passwd", nil, ""), true},
		{"argnames", sig("T", cond("equals", "__proto__", tg("argnames"))), mkReq("GET", "/?__proto__=1", nil, ""), true},
		{"argnames no", sig("T", cond("equals", "__proto__", tg("argnames"))), mkReq("GET", "/?a=__proto__", nil, ""), false},
		{"argnames from JSON paths", sig("T", cond("equals", "json.a.b", tg("argnames"))), mkReq("POST", "/", jsonH, `{"a":{"b":1}}`), true},
		{"cookies", sig("T", cond("equals", "x", tg("cookies"))), mkReq("GET", "/", map[string]string{"cookie": "a=1; b=x"}, ""), true},
		{"cookies are decoded once", sig("T", cond("equals", "a b", tg("cookies"))), mkReq("GET", "/", map[string]string{"cookie": "a=a%20b"}, ""), true},
		{"cookienames", sig("T", cond("equals", "PHPSESSID", tg("cookienames"))), mkReq("GET", "/", map[string]string{"cookie": "PHPSESSID=1"}, ""), true},
		{"cookienames no", sig("T", cond("equals", "PHPSESSID", tg("cookienames"))), mkReq("GET", "/", map[string]string{"cookie": "a=PHPSESSID"}, ""), false},
		{"headers includes every value", sig("T", cond("contains", "evil", tg("headers"))), mkReq("GET", "/", map[string]string{"x-a": "evil"}, ""), true},
		{"headers includes Host", sig("T", cond("equals", "victim.test", tg("headers"))), mkReq("GET", "/", map[string]string{"host": "victim.test"}, ""), true},
		{"headers are not names", sig("T", cond("contains", "x-a", tg("headers"))), mkReq("GET", "/", map[string]string{"x-a": "1"}, ""), false},
		{"body", sig("T", cond("contains", "<?xml", tg("body"))), mkReq("POST", "/", map[string]string{"content-type": "text/xml"}, "<?xml version='1.0'?>"), true},
		{"body no", sig("T", cond("contains", "<?xml", tg("body"))), mkReq("POST", "/", nil, "hello"), false},
		// named targets
		{"header:NAME any case", sig("T", cond("equals", "x", tg("header:X-Custom"))), mkReq("GET", "/", map[string]string{"x-custom": "x"}, ""), true},
		{"header:NAME picks only that header", sig("T", cond("equals", "x", tg("header:X-Custom"))), mkReq("GET", "/", map[string]string{"x-other": "x"}, ""), false},
		{"header:NAME with underscore on the wire", sig("T", cond("equals", "x", tg("header:x-custom"))), mkReq("GET", "/", map[string]string{"x_custom": "x"}, ""), true},
		{"arg:NAME any case", sig("T", cond("equals", "evil", tg("arg:Action"))), mkReq("GET", "/?ACTION=evil", nil, ""), true},
		{"arg:NAME picks only that argument", sig("T", cond("equals", "evil", tg("arg:action"))), mkReq("GET", "/?other=evil", nil, ""), false},
		{"arg:NAME as PHP names it (dots)", sig("T", cond("equals", "evil", tg("arg:a_b"))), mkReq("GET", "/?a.b=evil", nil, ""), true},
		{"arg:NAME as PHP names it (brackets)", sig("T", cond("equals", "evil", tg("arg:a"))), mkReq("GET", "/?a[]=evil", nil, ""), true},
		{"arg:NAME for JSON by path", sig("T", cond("equals", "evil", tg("arg:json.p.q"))), mkReq("POST", "/", jsonH, `{"p":{"q":"evil"}}`), true},
		{"arg:NAME for JSON by key", sig("T", cond("equals", "evil", tg("arg:q"))), mkReq("POST", "/", jsonH, `{"p":{"q":"evil"}}`), true},
		{"repeated parameters are also offered joined with a space", sig("T", cond("contains", "union/**/ select", tg("arg:id"))), mkReq("GET", "/?id=1%20union/**/&id=select", nil, ""), true},
		{"repeated parameters are not joined with nothing", sig("T", cond("contains", "union/**/select", tg("arg:id"))), mkReq("GET", "/?id=1%20union/**/&id=select", nil, ""), false},
		{"arg:NAME of repeated parameters, joined with a comma", sig("T", cond("equals", "a,b", tg("arg:id"))), mkReq("GET", "/?id=a&id=b", nil, ""), true},
		{"cookie:NAME", sig("T", cond("equals", "evil", tg("cookie:sid"))), mkReq("GET", "/", map[string]string{"cookie": "SID=evil"}, ""), true},
		{"cookie:NAME no", sig("T", cond("equals", "evil", tg("cookie:sid"))), mkReq("GET", "/", map[string]string{"cookie": "other=evil"}, ""), false},
		// several targets: any of them
		{"any target", sig("T", cond("equals", "x", tg("path", "arg:q"))), mkReq("GET", "/p?q=x", nil, ""), true},
		{"any target, none", sig("T", cond("equals", "x", tg("path", "arg:q"))), mkReq("GET", "/p?q=y", nil, ""), false},
		// negation
		{"negate holds when nothing matches", sig("T", Condition{Operator: "contains", Pattern: "ok", Targets: tg("path"), Negate: true}), mkReq("GET", "/bad", nil, ""), true},
		{"negate fails when a value matches", sig("T", Condition{Operator: "contains", Pattern: "ok", Targets: tg("path"), Negate: true}), mkReq("GET", "/ok", nil, ""), false},
		{"negate holds when the target is absent", sig("T", Condition{Operator: "contains", Pattern: "ok", Targets: tg("cookies"), Negate: true}), mkReq("GET", "/ok", nil, ""), true},
		{"a missing target fails a plain condition", sig("T", cond("contains", "ok", tg("cookies"))), mkReq("GET", "/ok", nil, ""), false},
		// Also
		{"also all hold", sig("T", cond("contains", "/a", tg("path")), cond("contains", "x=1", tg("query")), cond("equals", "POST", tg("method"))), mkReq("POST", "/a?x=1", nil, ""), true},
		{"also one fails", sig("T", cond("contains", "/a", tg("path")), cond("contains", "x=1", tg("query")), cond("equals", "POST", tg("method"))), mkReq("GET", "/a?x=1", nil, ""), false},
		{"also with a negation", sig("T", cond("contains", "/a", tg("path")), Condition{Operator: "contains", Pattern: "ok", Targets: tg("query"), Negate: true}), mkReq("GET", "/a?q=ok", nil, ""), false},
		// transforms in context
		{"urldecode sees through double encoding", sig("T", cond("contains", "../", tg("uri"), "urldecode")), mkReq("GET", "/a/%252e%252e/b", nil, ""), true},
		{"urldecode1 does not", sig("T", cond("contains", "../", tg("uri"), "urldecode1")), mkReq("GET", "/a/%252e%252e/b", nil, ""), false},
		{"lowercase then contains", sig("T", cond("contains", "wp-admin", tg("path"), "lowercase")), mkReq("GET", "/WP-Admin/", nil, ""), true},
		{"normpath resolves dot segments", sig("T", cond("equals", "/etc/passwd", tg("path"), "normpath")), mkReq("GET", "/a/../etc//passwd", nil, ""), true},
		{"large and small values are both seen", sig("T", cond("contains", "EVIL", tg("body"))), mkReq("POST", "/", nil, strings.Repeat("a", 200000)+"EVIL"), true},
		{"a payload in the middle of an oversize value is not seen (documented)", sig("T", cond("contains", "EVIL", tg("body"))), mkReq("POST", "/", nil, strings.Repeat("a", 100000)+"EVIL"+strings.Repeat("a", 200000)), false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			for _, brute := range []bool{false, true} {
				e := loadOne(t, Options{}, tc.sig)
				var hits []Hit
				if brute {
					hits = e.MatchBruteForce(tc.req)
				} else {
					hits = e.Match(tc.req)
				}
				if got := hasHit(hits, "T"); got != tc.want {
					t.Fatalf("brute=%v: matched=%v, want %v", brute, got, tc.want)
				}
			}
		})
	}
}

func TestOptionsTiersScopeSeverityExpiry(t *testing.T) {
	// Constructor capacity is a Go options contract, independent of request/rule profiles.
	t.Run("result cache capacity", func(t *testing.T) {
		cases := []struct {
			name            string
			requested, want int
			warn            bool
		}{
			{"default", 0, 32768, false},
			{"disabled", -1, 0, false},
			{"minimum integer", math.MinInt, 0, false},
			{"single entry", 1, 1, false},
			{"power of two", 2, 2, false},
			{"round upward", 3, 4, false},
			{"below default", 32767, 32768, false},
			{"above default", 32769, 65536, false},
			{"below cap", 1048575, 1048576, false},
			{"at cap", 1048576, 1048576, false},
			{"above cap", 1048577, 1048576, true},
			{"large power of two", 1 << 30, 1048576, true},
			{"maximum integer", math.MaxInt, 1048576, true},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				e := New(Options{ResultCache: tc.requested, Mode: ModeBlock})
				if got := len(e.cache); got != tc.want {
					t.Fatalf("cache entries = %d, want %d", got, tc.want)
				}
				if tc.want > 0 && e.cacheMask != uint64(tc.want-1) {
					t.Fatalf("cache mask = %d, want %d", e.cacheMask, tc.want-1)
				}
				for load := 0; load < 2; load++ {
					rep := e.Load([]Signature{sig("CACHE", cond("rx", "^/danger/[0-9]+$", tg("path")))})
					if rep.LoadedTotal != 1 || len(rep.Rejected) != 0 || (len(rep.Warnings) != 0) != tc.warn {
						t.Fatalf("load report = %+v", rep)
					}
					for repeat := 0; repeat < 2; repeat++ {
						for _, req := range []struct {
							path  string
							block bool
						}{{"/danger/42", true}, {"/danger/43", true}, {"/safe/42", false}, {"/danger/x", false}} {
							result := e.Inspect(mkReq("GET", req.path, nil, ""))
							blocked := false
							for _, verdict := range result.Verdicts {
								blocked = blocked || verdict.Block
							}
							if blocked != req.block {
								t.Fatalf("%s: blocked=%v, want %v", req.path, blocked, req.block)
							}
						}
					}
				}
			})
		}
	})
	base := func(id, tier string, scope []string, sev, expires string) Signature {
		s := sig(id, cond("contains", "/x", tg("path")))
		s.Tier, s.Scope, s.Severity, s.Expires = tier, scope, sev, expires
		return s
	}
	sigs := []Signature{
		base("V", "", nil, "high", ""),
		base("V2", TierVerified, nil, "low", ""),
		base("C", TierCommunity, nil, "high", ""),
		base("E", TierExperimental, nil, "high", ""),
		base("WP", "", []string{"wordpress:plugin:x"}, "high", ""),
		base("WPC", "", []string{"wordpress"}, "high", ""),
		base("NEXT", "", []string{"nextjs"}, "high", ""),
		base("OLD", "", nil, "high", "2020-01-01"),
		base("NEW", "", nil, "high", "2999-01-01"),
	}
	now := func() time.Time { return time.Date(2026, 10, 5, 0, 0, 0, 0, time.UTC) }
	tests := []struct {
		name string
		opts Options
		want []string
	}{
		{"default is verified only, unscoped, unexpired", Options{Now: now}, []string{"V", "V2", "NEW"}},
		{"community added", Options{Tiers: []string{"verified", "community"}, Now: now}, []string{"V", "V2", "C", "NEW"}},
		{"all tiers", Options{Tiers: allTiers, Now: now}, []string{"V", "V2", "C", "E", "NEW"}},
		{"a site that declares wordpress gets its plugins", Options{Scope: []string{"WordPress"}, Now: now}, []string{"V", "V2", "WP", "WPC", "NEW"}},
		{"a site that declares one plugin gets that plugin and not the whole of wordpress", Options{Scope: []string{"wordpress:plugin:x"}, Now: now}, []string{"V", "V2", "WP", "NEW"}},
		{"a different plugin does not match", Options{Scope: []string{"wordpress:plugin:y"}, Now: now}, []string{"V", "V2", "NEW"}},
		{"a prefix of the tag's name is not a tag", Options{Scope: []string{"word"}, Now: now}, []string{"V", "V2", "NEW"}},
		{"nextjs", Options{Scope: []string{"nextjs"}, Now: now}, []string{"V", "V2", "NEXT", "NEW"}},
		{"minimum severity", Options{MinSeverity: "medium", Now: now}, []string{"V", "NEW"}},
		{"expired signatures load if the clock is earlier", Options{Now: func() time.Time { return time.Date(2019, 1, 1, 0, 0, 0, 0, time.UTC) }}, []string{"V", "V2", "OLD", "NEW"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			e := New(tc.opts)
			rep := e.Load(sigs)
			if len(rep.Rejected) != 0 {
				t.Fatalf("rejected %+v", rep.Rejected)
			}
			var got []string
			for _, h := range e.Match(mkReq("GET", "/x", nil, "")) {
				got = append(got, h.ID)
			}
			if fmt.Sprint(got) != fmt.Sprint(tc.want) {
				t.Fatalf("loaded %v, want %v (report %+v)", got, tc.want, rep)
			}
		})
	}
}

func TestInspectVerdicts(t *testing.T) {
	mk := func(id, tier, action string) Signature {
		s := sig(id, cond("contains", "/boom", tg("path")))
		s.Tier, s.Action, s.CVEs = tier, action, []string{"CVE-2024-0001", "CVE-2024-0002"}
		s.Description = "A vulnerable plugin endpoint"
		return s
	}
	sigs := []Signature{mk("B", "", ""), mk("LOG", "", "log"), mk("COM", TierCommunity, ""), mk("EXP", TierExperimental, "")}
	tests := []struct {
		name      string
		opts      Options
		wantBlock map[string]bool
	}{
		{"monitor never blocks", Options{Tiers: allTiers}, map[string]bool{"B": false, "LOG": false, "COM": false, "EXP": false}},
		{"block mode blocks block-action signatures, the experimental tier only records", Options{Tiers: allTiers, Mode: ModeBlock}, map[string]bool{"B": true, "LOG": false, "COM": true, "EXP": false}},
		{"experimental may block when asked", Options{Tiers: allTiers, Mode: ModeBlock, ExperimentalMayBlock: true}, map[string]bool{"B": true, "LOG": false, "COM": true, "EXP": true}},
		{"verified only", Options{Mode: ModeBlock}, map[string]bool{"B": true, "LOG": false}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			e := loadOne(t, tc.opts, sigs...)
			res := e.Inspect(mkReq("GET", "/boom?secret=hunter2", map[string]string{"cookie": "session=topsecret"}, "password=hunter2"))
			if len(res.Verdicts) != len(tc.wantBlock) {
				t.Fatalf("got %d verdicts %+v", len(res.Verdicts), res.Verdicts)
			}
			seen := map[int]string{}
			for _, v := range res.Verdicts {
				if v.ID < 5100000 || v.ID > 5199999 {
					t.Errorf("verdict ID %d outside 5100000..5199999", v.ID)
				}
				var id string
				for k := range tc.wantBlock {
					if strings.Contains(v.Message, "virtual patch "+k+" ") {
						id = k
					}
				}
				if id == "" {
					t.Fatalf("the message names no signature: %q", v.Message)
				}
				if v.Block != tc.wantBlock[id] {
					t.Errorf("%s: Block=%v, want %v", id, v.Block, tc.wantBlock[id])
				}
				if v.Block && v.Status != 403 {
					t.Errorf("%s: status %d", id, v.Status)
				}
				if v.Severity != "high" {
					t.Errorf("%s: severity %q", id, v.Severity)
				}
				for _, want := range []string{"CVE-2024-0001", "CVE-2024-0002", "A vulnerable plugin endpoint"} {
					if !strings.Contains(v.Message, want) {
						t.Errorf("%s: message %q lacks %q", id, v.Message, want)
					}
				}
				for _, leak := range []string{"hunter2", "topsecret", "password", "/boom"} {
					if strings.Contains(v.Message, leak) {
						t.Errorf("%s: the message holds request content %q: %q", id, leak, v.Message)
					}
				}
				if prev, dup := seen[v.ID]; dup && prev != id {
					t.Logf("note: %s and %s share the verdict number %d (a hash collision, listed for the owner)", prev, id, v.ID)
				}
				seen[v.ID] = id
			}
		})
	}
}

func TestVerdictNumberIsStableAndInRange(t *testing.T) {
	for _, id := range []string{"A", "CS-CVE-2024-4577-1", "ET-2012345", strings.Repeat("z", 128)} {
		n := verdictNumber(id)
		if n < 5101000 || n > 5199999 || n != verdictNumber(id) {
			t.Errorf("%s: %d", id, n)
		}
	}
	if verdictNumber("A") == verdictNumber("B") {
		t.Error("distinct IDs gave one number")
	}
}

func TestInspectCapsTheVerdicts(t *testing.T) {
	var sigs []Signature
	for i := 0; i < 40; i++ {
		sigs = append(sigs, sig(fmt.Sprintf("S%02d", i), cond("contains", "/x", tg("path"))))
	}
	e := loadOne(t, Options{MaxVerdicts: 5}, sigs...)
	res := e.Inspect(mkReq("GET", "/x", nil, ""))
	if len(res.Verdicts) != 6 || res.Verdicts[5].ID != IDMoreMatches {
		t.Fatalf("verdicts %d: %+v", len(res.Verdicts), res.Verdicts)
	}
	if got := len(e.Match(mkReq("GET", "/x", nil, ""))); got != 40 {
		t.Fatalf("Match returns every hit: %d", got)
	}
}

func TestLoadReportAndRejections(t *testing.T) {
	t.Run("index representation boundaries", func(t *testing.T) {
		for _, tc := range []struct {
			total, count int
			want         int32
			valid        bool
		}{
			{0, 0, 0, true},
			{math.MaxInt32 - 1, 1, math.MaxInt32, true},
			{math.MaxInt32, 1, 0, false},
			{-1, 1, 0, false},
			{1, -1, 0, false},
			{math.MaxInt, math.MaxInt, 0, false},
		} {
			t.Run(fmt.Sprintf("endpoint-%d-plus-%d", tc.total, tc.count), func(t *testing.T) {
				got, err := addIndex32(tc.total, tc.count)
				if (err == nil) != tc.valid || got != tc.want {
					t.Fatalf("index endpoint for %d + %d: %d (%v)", tc.total, tc.count, got, err)
				}
			})
		}
		for _, tc := range []struct {
			n     int
			valid bool
		}{{-1, false}, {0, true}, {math.MaxInt32, true}, {math.MaxInt, math.MaxInt == math.MaxInt32}} {
			t.Run(fmt.Sprintf("index-%d", tc.n), func(t *testing.T) {
				got, err := index32(tc.n)
				if (err == nil) != tc.valid || (tc.valid && int(got) != tc.n) {
					t.Fatalf("index %d became %d (%v)", tc.n, got, err)
				}
			})
		}
	})
	t.Run("class mask representation boundaries", func(t *testing.T) {
		for _, tc := range []struct {
			classes, words   int64
			valid32, valid64 bool
		}{
			{-1, 0, false, false},
			{0, 0, true, true},
			{1, 1, true, true},
			{63, 1, true, true},
			{64, 1, true, true},
			{65, 2, true, true},
			{131071, 2048, true, true},
			{131072, 2048, false, true},
			{185364, 2897, false, true},
			{370728, 5793, false, true},
			{8589934591, 134217728, false, true},
			{8589934592, 134217728, false, false},
			{int64(math.MaxInt), 0, false, false},
		} {
			t.Run(fmt.Sprintf("classes-%d", tc.classes), func(t *testing.T) {
				if tc.classes > int64(math.MaxInt) {
					t.Skip("class count exceeds native int")
				}
				valid := tc.valid64
				if math.MaxInt == math.MaxInt32 {
					valid = tc.valid32
				}
				got, err := classMaskWords(int(tc.classes))
				if (err == nil) != valid || (valid && int64(got) != tc.words) {
					t.Fatalf("mask for %d classes: %d words (%v)", tc.classes, got, err)
				}
			})
		}
	})
	good := sig("GOOD", cond("contains", "/x", tg("path")))
	bad := []Signature{
		sig("", cond("contains", "/x", tg("path"))),
		sig("BAD ID", cond("contains", "/x", tg("path"))),
		sig("OP", cond("startswith", "/x", tg("path"))),
		sig("TARGET", cond("contains", "/x", tg("pathh"))),
		sig("TARGET2", cond("contains", "/x", tg("arg:"))),
		sig("TRANSFORM", cond("contains", "/x", tg("path"), "rot13")),
		sig("EMPTY", cond("contains", "", tg("path"))),
		sig("RXEMPTY", cond("rx", "", tg("path"))),
		sig("LOOKAHEAD", cond("rx", `a(?!b)`, tg("path"))),
		sig("BACKREF", cond("rx", `(a)\1`, tg("path"))),
		sig("BADRX", cond("rx", `(`, tg("path"))),
		sig("FLAG", Condition{Operator: "rx", Pattern: "a", Flags: "z", Targets: tg("path")}),
		sig("ALSO", cond("contains", "/x", tg("path")), cond("rx", `a(?<!b)`, tg("path"))),
		{ID: "SEV", Severity: "huge", Condition: cond("contains", "/x", tg("path"))},
		{ID: "TIER", Severity: "high", Tier: "gold", Condition: cond("contains", "/x", tg("path"))},
		{ID: "DATE", Severity: "high", Expires: "tomorrow", Condition: cond("contains", "/x", tg("path"))},
		{ID: "PMBOTH", Severity: "high", Condition: Condition{Operator: "pm", Pattern: "a", Patterns: []string{"b"}, Targets: tg("path")}},
		good,
		good, // a duplicate
	}
	e := New(Options{})
	rep := e.Load(append([]Signature{good}, bad[:len(bad)-2]...))
	if rep.LoadedTotal != 1 || rep.Loaded[TierVerified] != 1 || len(rep.Rejected) != len(bad)-2 {
		t.Fatalf("loaded %d, rejected %d: %+v", rep.LoadedTotal, len(rep.Rejected), rep.Rejected)
	}
	for _, r := range rep.Rejected {
		if r.Reason == "" || len(r.Reason) > 300 {
			t.Errorf("%s: reason %q", r.ID, r.Reason)
		}
	}
	rep = e.Load([]Signature{good, good})
	if rep.LoadedTotal != 1 || len(rep.Rejected) != 1 || !strings.Contains(rep.Rejected[0].Reason, "earlier") {
		t.Fatalf("duplicate: %+v", rep)
	}
}

// TestLoadReplacesTheSetWhileRequestsAreMatched runs requests during repeated Loads: every answer must be the answer of one of the two
// sets, never a mixture, and nothing may panic or race (run with -race).
func TestLoadReplacesTheSetWhileRequestsAreMatched(t *testing.T) {
	// Shared anchors reach both regexes; their true/false positions exchange on reload.
	setA := []Signature{sig("A1", cond("rx", "^/x$", tg("path"))), sig("A2", cond("rx", "^/x[0-9]+$", tg("path")))}
	setB := []Signature{sig("B1", cond("rx", "^/x[0-9]+$", tg("path"))), sig("B2", cond("rx", "^/x$", tg("path"))), sig("B3", cond("rx", "^/x$", tg("path")))}
	e := New(Options{})
	e.Load(setA)
	var stop atomic.Bool
	var wg sync.WaitGroup
	var bad atomic.Int64
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r := mkReq("GET", "/x?a=1", map[string]string{"user-agent": "t"}, "")
			for !stop.Load() {
				hits := e.Match(r)
				ok := len(hits) == 1 && hits[0].ID == "A1"
				ok = ok || (len(hits) == 2 && hits[0].ID == "B2" && hits[1].ID == "B3")
				if !ok {
					bad.Add(1)
				}
			}
		}()
	}
	for i := 0; i < 200; i++ {
		if i%2 == 0 {
			e.Load(setB)
		} else {
			e.Load(setA)
		}
	}
	stop.Store(true)
	wg.Wait()
	if bad.Load() != 0 {
		t.Fatalf("%d requests saw a mixture of the two sets", bad.Load())
	}
}

func TestWorkAllowance(t *testing.T) {
	// A signature with a literal that the body holds and an expression that costs about a byte of allowance per byte of body.
	s := sig("W", cond("rx", `needle.*\d{4}$`, tg("body", "uri")))
	body := strings.Repeat("needle", 5000)
	tests := []struct {
		name        string
		opts        Options
		wantLimited bool
		wantBlock   bool
	}{
		{"within the allowance", Options{MaxWork: 1 << 20}, false, false},
		{"over the allowance", Options{MaxWork: 1000}, true, false},
		{"over the allowance, blocking when asked", Options{MaxWork: 1000, Mode: ModeBlock, BlockOnWorkLimit: true}, true, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tc.opts.ResultCache = -1
			e := loadOne(t, tc.opts, s)
			// two values, each a regex run, so the second goes over a 1000 byte allowance
			r := mkReq("POST", "/?a="+strings.Repeat("x", 100), nil, body)
			res := e.Inspect(r)
			limited, block := false, false
			for _, v := range res.Verdicts {
				if v.ID == IDWorkLimit {
					limited = true
					block = v.Block
				}
			}
			if limited != tc.wantLimited || block != tc.wantBlock {
				t.Fatalf("limited=%v block=%v, want %v %v: %+v", limited, block, tc.wantLimited, tc.wantBlock, res.Verdicts)
			}
			if st := e.Stats(); (st.WorkLimited == 1) != tc.wantLimited {
				t.Fatalf("stats %+v", st)
			}
		})
	}
}

func TestStatsCount(t *testing.T) {
	e := loadOne(t, Options{Mode: ModeBlock}, sig("S", cond("contains", "/x", tg("path"))))
	e.Inspect(mkReq("GET", "/x", nil, ""))
	e.Inspect(mkReq("GET", "/y", nil, ""))
	st := e.Stats()
	if st.Requests != 2 || st.Matches != 1 || st.Blocked != 1 || st.Signatures != 1 || st.ByTier[TierVerified] != 1 || st.Indexed != 1 {
		t.Fatalf("%+v", st)
	}
}

func TestInspectorContract(t *testing.T) {
	var _ inspect.Inspector = (*Engine)(nil)
	e := New(Options{})
	if e.Name() != "vpatch" {
		t.Fatal(e.Name())
	}
	// no signatures, no request, an empty request: nothing to say and no panic
	if res := e.Inspect(&inspect.Request{}); len(res.Verdicts) != 0 {
		t.Fatal(res)
	}
	if res := e.Inspect(nil); len(res.Verdicts) != 0 {
		t.Fatal(res)
	}
	e.Load([]Signature{sig("S", cond("contains", "/x", tg("path")))})
	if hits := e.Match(&inspect.Request{Header: http.Header{}}); len(hits) != 0 {
		t.Fatal(hits)
	}
	if hits := e.Match(&inspect.Request{}); len(hits) != 0 { // a nil header map
		t.Fatal(hits)
	}
}
