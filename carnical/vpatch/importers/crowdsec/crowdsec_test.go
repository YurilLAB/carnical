// SPDX-License-Identifier: Apache-2.0

package crowdsec

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/YurilLAB/coraza/carnical/vpatch"
	"github.com/YurilLAB/coraza/carnical/vpatch/importers"
)

var testOpts = importers.Options{Revision: "t1"}

// rule wraps rule entries in a complete rule file.
func rule(name, entries string) string {
	return "name: crowdsecurity/" + name + "\ndescription: 'A test rule'\nrules:\n" + entries +
		"labels:\n  type: exploit\n  confidence: 3\n  classification:\n    - cve.CVE-2024-0001\n    - cwe.CWE-79\n"
}

func convert(t *testing.T, name, yamlText string) importers.Result {
	t.Helper()
	return ConvertBytes(name+".yaml", []byte(yamlText), testOpts)
}

func cond(op, pattern string, targets []string, transforms ...string) vpatch.Condition {
	return vpatch.Condition{Operator: op, Pattern: pattern, Targets: targets, Transforms: transforms}
}

func TestLeafMapping(t *testing.T) {
	tests := []struct {
		name  string
		entry string // the entries under "rules:"
		// want is the expected signatures as (main, also) pairs, in order; nil with wantSkip set means nothing is produced.
		want     [][]vpatch.Condition
		wantSkip string
	}{
		{name: "uri is the decoded path",
			entry: "  - zones: [URI]\n    transform: [lowercase]\n    match: {type: endsWith, value: /x.php}\n",
			want:  [][]vpatch.Condition{{cond("suffix", "/x.php", []string{"path"}, "urldecode1", "lowercase")}}},
		{name: "uri_full is raw",
			entry: "  - zones: [URI_FULL]\n    transform: [lowercase]\n    match: {type: contains, value: '?%ad'}\n",
			want:  [][]vpatch.Condition{{cond("contains", "?%ad", []string{"uri"}, "lowercase")}}},
		{name: "args with variables become named arguments, lower-cased",
			entry: "  - zones: [ARGS, BODY_ARGS]\n    variables: [Action, json.Foo]\n    match: {type: equals, value: go}\n",
			want:  [][]vpatch.Condition{{cond("equals", "go", []string{"arg:action", "arg:json.foo"})}}},
		{name: "args without variables",
			entry: "  - zones: [ARGS]\n    transform: [urldecode, lowercase]\n    match: {type: contains, value: '<'}\n",
			want:  [][]vpatch.Condition{{cond("contains", "<", []string{"args"}, "urldecode", "lowercase")}}},
		{name: "header variable is a named header",
			entry: "  - zones: [HEADERS]\n    variables: [User-Agent]\n    match: {type: contains, value: Mozilla}\n",
			want:  [][]vpatch.Condition{{cond("contains", "Mozilla", []string{"header:user-agent"})}}},
		{name: "cookie variable",
			entry: "  - zones: [COOKIES]\n    variables: [sid]\n    match: {type: startsWith, value: x}\n",
			want:  [][]vpatch.Condition{{cond("prefix", "x", []string{"cookie:sid"})}}},
		{name: "method body filenames uploads",
			entry: "  - and:\n    - {zones: [METHOD], match: {type: equals, value: POST}}\n    - {zones: [RAW_BODY], match: {type: contains, value: abc}}\n    - {zones: [FILENAMES], match: {type: endsWith, value: .php}}\n    - {zones: [FILES], match: {type: contains, value: '<?php'}}\n",
			want: [][]vpatch.Condition{{
				cond("contains", "abc", []string{"body"}),
				cond("equals", "POST", []string{"method"}),
				cond("suffix", ".php", []string{"filenames"}),
				cond("contains", "<?php", []string{"uploads"}),
			}}},
		{name: "every supported transform",
			entry: "  - zones: [RAW_BODY]\n    transform: [lowercase, urldecode, b64decode, trim, normalizepath, normalize_path_win, htmlentitydecode, js_decode, css_decode, cmdline, remove_whitespaces, compress_whitespaces, remove_nulls, remove_comments, replace_comments]\n    match: {type: contains, value: abc}\n",
			want: [][]vpatch.Condition{{cond("contains", "abc", []string{"body"}, "lowercase", "urldecode", "base64decode", "trim", "normpath", "normpathwin",
				"htmldecode", "jsdecode", "cssdecode", "cmdline", "removespace", "compressspace", "nulls", "comments", "replacecomments")}}},
		{name: "regex is kept as written", entry: "  - zones: [ARGS]\n    variables: [f]\n    match: {type: regex, value: '[^a-z]+'}\n",
			want: [][]vpatch.Condition{{cond("rx", "[^a-z]+", []string{"arg:f"})}}},
		{name: "number as value", entry: "  - zones: [ARGS]\n    variables: [n]\n    match: {type: equals, value: 5}\n",
			want: [][]vpatch.Condition{{cond("equals", "5", []string{"arg:n"})}}},
		{name: "count equals zero is absence", entry: "  - zones: [HEADERS]\n    variables: [X-A]\n    transform: [count]\n    match: {type: equals, value: '0'}\n",
			want: [][]vpatch.Condition{{{Operator: "rx", Pattern: "^", Targets: []string{"header:x-a"}, Negate: true}}}},
		{name: "count at least one is presence", entry: "  - zones: [HEADERS]\n    variables: [X-A]\n    transform: [count]\n    match: {type: gte, value: 1}\n",
			want: [][]vpatch.Condition{{cond("rx", "^", []string{"header:x-a"})}}},
		{name: "length greater than", entry: "  - zones: [ARGS]\n    variables: [t]\n    transform: [length]\n    match: {type: gt, value: 99}\n",
			want: [][]vpatch.Condition{{cond("rx", "(?s)^.{100,}$", []string{"arg:t"})}}},
		{name: "length equals", entry: "  - zones: [ARGS]\n    variables: [t]\n    transform: [length]\n    match: {type: equals, value: 8}\n",
			want: [][]vpatch.Condition{{cond("rx", "(?s)^.{8}$", []string{"arg:t"})}}},
		{name: "header names, equals", entry: "  - zones: [HEADERS_NAMES]\n    transform: [lowercase]\n    match: {type: equals, value: x-a}\n",
			want: [][]vpatch.Condition{{cond("rx", "^", []string{"header:x-a"})}}},
		{name: "header names, regex of names",
			entry: "  - zones: [HEADERS_NAMES]\n    transform: [lowercase]\n    match: {type: regex, value: 'x-m-(one|two)'}\n",
			want:  [][]vpatch.Condition{{cond("rx", "^", []string{"header:x-m-one"})}, {cond("rx", "^", []string{"header:x-m-two"})}}},

		// An or becomes several signatures; an and of ors multiplies; zones that need different transforms split.
		{name: "or", entry: "  - or:\n    - {zones: [URI], match: {type: contains, value: /a}}\n    - {zones: [URI], match: {type: contains, value: /b}}\n",
			want: [][]vpatch.Condition{{cond("contains", "/a", []string{"path"}, "urldecode1")}, {cond("contains", "/b", []string{"path"}, "urldecode1")}}},
		{name: "entries of rules are alternatives",
			entry: "  - zones: [METHOD]\n    match: {type: equals, value: PUT}\n  - zones: [METHOD]\n    match: {type: equals, value: DELETE}\n",
			want:  [][]vpatch.Condition{{cond("equals", "PUT", []string{"method"})}, {cond("equals", "DELETE", []string{"method"})}}},
		{name: "and of or",
			entry: "  - and:\n    - {zones: [URI], match: {type: equals, value: /x}}\n    - or:\n      - {zones: [METHOD], match: {type: equals, value: POST}}\n      - {zones: [METHOD], match: {type: equals, value: PUT}}\n",
			want: [][]vpatch.Condition{
				{cond("equals", "/x", []string{"path"}, "urldecode1"), cond("equals", "POST", []string{"method"})},
				{cond("equals", "/x", []string{"path"}, "urldecode1"), cond("equals", "PUT", []string{"method"})},
			}},
		{name: "zones that need different transforms split",
			entry: "  - zones: [URI, HEADERS]\n    match: {type: contains, value: x}\n",
			want:  [][]vpatch.Condition{{cond("contains", "x", []string{"path"}, "urldecode1")}, {cond("contains", "x", []string{"headers"})}}},
		{name: "an or branch that cannot be converted is dropped, the rest stays",
			entry: "  - or:\n    - {zones: [URI], match: {type: contains, value: /a}}\n    - {zones: [ARGS], match: {type: libinjectionSQL}}\n",
			want:  [][]vpatch.Condition{{cond("contains", "/a", []string{"path"}, "urldecode1")}}},

		// What is refused, and why.
		{name: "an and with an unconvertible leaf is refused whole",
			entry:    "  - and:\n    - {zones: [URI], match: {type: contains, value: /a}}\n    - {zones: [ARGS], match: {type: libinjectionXSS}}\n",
			wantSkip: "libinjection"},
		{name: "count of two", entry: "  - zones: [ARGS]\n    variables: [u]\n    transform: [count]\n    match: {type: gte, value: 2}\n", wantSkip: "count-comparison-unsupported"},
		{name: "numeric comparison of the value", entry: "  - zones: [ARGS]\n    variables: [u]\n    match: {type: gt, value: 2}\n", wantSkip: "numeric-comparison-unsupported"},
		{name: "length too big", entry: "  - zones: [ARGS]\n    variables: [u]\n    transform: [length]\n    match: {type: gte, value: 5000}\n", wantSkip: "length-comparison-unsupported"},
		{name: "uppercase transform", entry: "  - zones: [ARGS]\n    transform: [uppercase]\n    match: {type: contains, value: A}\n", wantSkip: "transform-unsupported:uppercase"},
		{name: "count not last", entry: "  - zones: [ARGS]\n    variables: [a]\n    transform: [count, lowercase]\n    match: {type: equals, value: 0}\n", wantSkip: "transform-after-count"},
		{name: "files names zone", entry: "  - zones: [FILES_NAMES]\n    match: {type: contains, value: a}\n", wantSkip: "zone-unsupported:FILES_NAMES"},
		{name: "protocol zone", entry: "  - zones: [PROTOCOL]\n    match: {type: equals, value: HTTP/1.0}\n", wantSkip: "zone-unsupported:PROTOCOL"},
		{name: "header names with a quantifier", entry: "  - zones: [HEADERS_NAMES]\n    transform: [lowercase]\n    match: {type: regex, value: '.+x-a'}\n", wantSkip: "zone-unsupported:HEADERS_NAMES"},
		{name: "regex variable", entry: "  - zones: [BODY_ARGS]\n    variables: ['/a[0-9]+/']\n    match: {type: equals, value: x}\n", wantSkip: "variable-regex"},
		{name: "variables on a zone with no names", entry: "  - zones: [URI]\n    variables: [a]\n    match: {type: equals, value: x}\n", wantSkip: "variables-on-unkeyed-zone"},
		{name: "regex that does not compile in Go", entry: "  - zones: [ARGS]\n    variables: [a]\n    match: {type: regex, value: 'a(?=b)'}\n", wantSkip: "regex:lookaround"},
		{name: "capital letter under lowercase can never match", entry: "  - zones: [URI]\n    transform: [lowercase]\n    match: {type: endsWith, value: /Admin}\n", wantSkip: "unmatchable-literal"},
		{name: "capital letter without lowercase is fine", entry: "  - zones: [METHOD]\n    match: {type: equals, value: POST}\n",
			want: [][]vpatch.Condition{{cond("equals", "POST", []string{"method"})}}},
		{name: "empty value", entry: "  - zones: [URI]\n    match: {type: contains, value: ''}\n", wantSkip: "empty-value"},
		{name: "unknown match type", entry: "  - zones: [URI]\n    match: {type: fuzzy, value: a}\n", wantSkip: "match-type-unsupported:fuzzy"},
		{name: "no zones", entry: "  - match: {type: equals, value: a}\n", wantSkip: "no-zones"},
		{name: "empty and", entry: "  - and: []\n", wantSkip: "empty-and-or"},
		{name: "and and or together", entry: "  - and:\n    - {zones: [METHOD], match: {type: equals, value: a}}\n    or:\n    - {zones: [METHOD], match: {type: equals, value: b}}\n", wantSkip: "and-and-or-together"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res := convert(t, "vpatch-CVE-2024-0001", rule("vpatch-CVE-2024-0001", tt.entry))
			if tt.wantSkip != "" {
				if len(res.Signatures) != 0 || res.Report.Skipped[tt.wantSkip] != 1 {
					t.Fatalf("got %d signatures, skipped %v, errors %v; want skip %q", len(res.Signatures), res.Report.Skipped, res.Report.Errors, tt.wantSkip)
				}
				return
			}
			var got [][]vpatch.Condition
			for _, s := range res.Signatures {
				got = append(got, append([]vpatch.Condition{s.Condition}, s.Also...))
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("got\n  %+v\nwant\n  %+v\nreport %+v", got, tt.want, res.Report)
			}
		})
	}
}

func TestExpansionBound(t *testing.T) {
	var b strings.Builder
	b.WriteString("  - or:\n")
	for i := 0; i < 70; i++ {
		b.WriteString("    - {zones: [URI], match: {type: contains, value: /p" + string(rune('a'+i%26)) + string(rune('a'+i/26)) + "}}\n")
	}
	res := convert(t, "big", rule("big", b.String()))
	if len(res.Signatures) != 0 || res.Report.Skipped["or-expands-too-far"] != 1 {
		t.Fatalf("70 alternatives: got %d signatures, skipped %v", len(res.Signatures), res.Report.Skipped)
	}
	res = ConvertBytes("big.yaml", []byte(rule("big", b.String())), importers.Options{Limits: importers.Limits{MaxAlternatives: 100}})
	if len(res.Signatures) != 70 {
		t.Fatalf("with the limit raised to 100: got %d signatures, want 70", len(res.Signatures))
	}
}

func TestMetadata(t *testing.T) {
	entry := "  - zones: [URI]\n    match: {type: contains, value: /wp-content/plugins/my-plugin/a.php}\n"
	tests := []struct {
		name     string
		file     string
		check    func(s vpatch.Signature) string // returns a problem, or ""
		wantTier string
	}{
		{name: "identifiers and provenance", file: rule("vpatch-CVE-2024-0001", entry), check: func(s vpatch.Signature) string {
			switch {
			case s.ID != "CS-CVE-2024-0001-1":
				return "id " + s.ID
			case !reflect.DeepEqual(s.Sources, []string{"crowdsec:vpatch-CVE-2024-0001@t1"}):
				return "sources"
			case !reflect.DeepEqual(s.CVEs, []string{"CVE-2024-0001"}):
				return "cves"
			case s.Category != "xss":
				return "category from CWE-79: " + s.Category
			case s.Severity != "medium" || s.Confidence != "high" || s.Action != "block" || s.Rev != 1:
				return "severity/confidence/action"
			case !reflect.DeepEqual(s.Scope, []string{"wordpress:plugin:my-plugin"}):
				return "scope from the path: " + strings.Join(s.Scope, ",")
			}
			return ""
		}, wantTier: "community"},
		{name: "confidence 0 is experimental and only logs", file: strings.Replace(rule("exp", entry), "confidence: 3", "confidence: 0", 1),
			check: func(s vpatch.Signature) string {
				if s.Confidence != "low" || s.Action != "log" {
					return "confidence/action"
				}
				return ""
			}, wantTier: "experimental"},
		{name: "confidence 2 is medium", file: strings.Replace(rule("c2", entry), "confidence: 3", "confidence: 2", 1),
			check: func(s vpatch.Signature) string {
				if s.Confidence != "medium" {
					return "confidence " + s.Confidence
				}
				return ""
			}, wantTier: "community"},
		{name: "a name without vpatch- keeps its words", file: rule("generic-thing", entry), check: func(s vpatch.Signature) string {
			if s.ID != "CS-GENERIC-THING-1" {
				return "id " + s.ID
			}
			return ""
		}, wantTier: "community"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res := ConvertBytes("x.yaml", []byte(tt.file), testOpts)
			if len(res.Signatures) != 1 {
				t.Fatalf("got %d signatures; report %+v", len(res.Signatures), res.Report)
			}
			s := res.Signatures[0]
			if p := tt.check(s); p != "" {
				t.Fatalf("%s: %+v", p, s)
			}
			if s.Tier != tt.wantTier {
				t.Fatalf("tier %q, want %q", s.Tier, tt.wantTier)
			}
		})
	}
	t.Run("the requested tier is used", func(t *testing.T) {
		res := ConvertBytes("x.yaml", []byte(rule("v", entry)), importers.Options{Tier: "verified", Revision: "t1"})
		if len(res.Signatures) != 1 || res.Signatures[0].Tier != "verified" {
			t.Fatalf("%+v", res.Signatures)
		}
	})
	t.Run("without a revision the content hash is used", func(t *testing.T) {
		res := ConvertBytes("x.yaml", []byte(rule("v", entry)), importers.Options{})
		src := res.Signatures[0].Sources[0]
		if !strings.HasPrefix(src, "crowdsec:v@") || len(src) != len("crowdsec:v@")+12 {
			t.Fatalf("sources %q", src)
		}
	})
}

func TestFileLevelSkips(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{name: "test rule", in: "name: a/t\nrules:\n  - zones: [URI]\n    match: {type: equals, value: /x}\nlabels:\n  type: test\n", want: "test-rule"},
		{name: "seclang rules", in: "name: a/c\nseclang_rules:\n  - SecRuleEngine On\n", want: "seclang-embedded"},
		{name: "seclang files", in: "name: a/c\nseclang_files_rules:\n  - x.conf\n", want: "seclang-embedded"},
		{name: "no rules", in: "name: a/c\ndata:\n  - source_url: x\n", want: "no-rules"},
		{name: "empty rules list", in: "name: a/c\nrules: []\n", want: "no-rules"},
		{name: "not a mapping", in: "- a\n- b\n", want: "not-a-rule-file"},
		{name: "broken yaml", in: "name: [\n", want: "yaml-invalid"},
		{name: "anchors", in: "name: a/c\nx: &a 1\ny: *a\n", want: "yaml-unsafe"},
		{name: "empty", in: "", want: "yaml-empty"},
		{name: "rule entry that is not a mapping", in: "name: a/c\nrules:\n  - 5\n", want: "rule-not-a-mapping"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res := ConvertBytes("x.yaml", []byte(tt.in), testOpts)
			if len(res.Signatures) != 0 || res.Report.Skipped[tt.want] != 1 || res.Report.UnitsRead != 1 {
				t.Fatalf("signatures %d skipped %v", len(res.Signatures), res.Report.Skipped)
			}
		})
	}
}

// TestFixtures converts the real rules in testdata (copies from the CrowdSec hub, MIT licence, see LICENSE-NOTICE.txt) and checks the
// parts of each result that matter.
func TestFixtures(t *testing.T) {
	tests := []struct {
		file     string
		wantSigs int
		wantSkip string
		check    func(t *testing.T, sigs []vpatch.Signature)
	}{
		{file: "vpatch-CVE-2002-1131.yaml", wantSigs: 4, check: func(t *testing.T, s []vpatch.Signature) {
			if s[0].Pattern != "/src/addressbook.php" || !reflect.DeepEqual(s[0].Targets, []string{"path"}) ||
				!reflect.DeepEqual(s[0].Also[0].Targets, []string{"argnames"}) || !reflect.DeepEqual(s[1].Also[0].Targets, []string{"arg:optpage"}) ||
				!reflect.DeepEqual(s[2].Also[0].Targets, []string{"arg:mailbox", "arg:where"}) {
				t.Fatalf("%+v", s)
			}
		}},
		{file: "vpatch-CVE-2021-26086.yaml", wantSigs: 2},
		{file: "vpatch-CVE-2023-7028.yaml", wantSkip: "count-comparison-unsupported"},
		{file: "vpatch-CVE-2023-1389.yaml", wantSigs: 1, check: func(t *testing.T, s []vpatch.Signature) {
			if s[0].Operator != "suffix" || len(s[0].Also) != 3 || s[0].Also[2].Operator != "rx" || s[0].Category != "rce" || s[0].Severity != "critical" {
				t.Fatalf("%+v", s[0])
			}
		}},
		{file: "vpatch-CVE-2024-4577.yaml", wantSigs: 1, check: func(t *testing.T, s []vpatch.Signature) {
			// The pattern holds an encoded byte, so the URI must not be decoded before it is compared.
			if !reflect.DeepEqual(s[0].Targets, []string{"uri"}) || !reflect.DeepEqual(s[0].Transforms, []string{"lowercase"}) {
				t.Fatalf("%+v", s[0])
			}
		}},
		{file: "experimental-no-user-agent.yaml", wantSigs: 1, check: func(t *testing.T, s []vpatch.Signature) {
			if s[0].Tier != "experimental" || s[0].Action != "log" || len(s[0].Also) != 1 || !s[0].Also[0].Negate {
				t.Fatalf("%+v", s[0])
			}
		}},
		{file: "generic-wordpress-uploads-php.yaml", wantSigs: 1, check: func(t *testing.T, s []vpatch.Signature) {
			if !reflect.DeepEqual(s[0].Scope, []string{"wordpress"}) || s[0].Category != "wordpress" {
				t.Fatalf("%+v", s[0])
			}
		}},
		{file: "vpatch-CVE-2023-3519.yaml", wantSigs: 1, check: func(t *testing.T, s []vpatch.Signature) {
			if s[0].Also[1].Pattern != "(?s)^.{100,}$" || !reflect.DeepEqual(s[0].Also[1].Targets, []string{"arg:target"}) {
				t.Fatalf("%+v", s[0])
			}
		}},
		{file: "vpatch-CVE-2019-12989.yaml", wantSkip: "libinjection"},
		{file: "base-config.yaml", wantSkip: "seclang-embedded"},
		{file: "appsec-generic-test.yaml", wantSkip: "test-rule"},
		{file: "vpatch-CVE-2020-17496.yaml", wantSkip: "variable-regex"},
		{file: "vpatch-CVE-2019-18952.yaml", wantSigs: 1, check: func(t *testing.T, s []vpatch.Signature) {
			if !reflect.DeepEqual(s[0].Also[0].Targets, []string{"filenames"}) || s[0].Also[0].Operator != "suffix" || s[0].Category != "upload" {
				t.Fatalf("%+v", s[0])
			}
		}},
		{file: "vpatch-CVE-2025-2611.yaml", wantSigs: 1, check: func(t *testing.T, s []vpatch.Signature) {
			if !reflect.DeepEqual(s[0].Also[0].Targets, []string{"cookie:broadcast"}) {
				t.Fatalf("%+v", s[0])
			}
		}},
		{file: "vpatch-CVE-2023-40044.yaml", wantSigs: 1, check: func(t *testing.T, s []vpatch.Signature) {
			if !reflect.DeepEqual(s[0].Also[1].Transforms, []string{"base64decode", "lowercase"}) {
				t.Fatalf("%+v", s[0])
			}
		}},
	}
	for _, tt := range tests {
		t.Run(tt.file, func(t *testing.T) {
			data, err := os.ReadFile(filepath.Join("testdata", tt.file))
			if err != nil {
				t.Fatal(err)
			}
			res := ConvertBytes(tt.file, data, testOpts)
			if tt.wantSkip != "" {
				if len(res.Signatures) != 0 || res.Report.Skipped[tt.wantSkip] != 1 {
					t.Fatalf("signatures %d skipped %v", len(res.Signatures), res.Report.Skipped)
				}
				return
			}
			if len(res.Signatures) != tt.wantSigs {
				t.Fatalf("signatures %d, want %d; report %+v", len(res.Signatures), tt.wantSigs, res.Report)
			}
			if tt.check != nil {
				tt.check(t, res.Signatures)
			}
		})
	}
	if n := len(tests); n > 15 {
		t.Fatalf("%d fixtures; at most 15 are allowed", n)
	}
}

// TestRunDirectory checks the whole path: a directory of files, in order, with a report.
func TestRunDirectory(t *testing.T) {
	res, err := Convert("testdata", testOpts)
	if err != nil {
		t.Fatal(err)
	}
	r := res.Report
	// 15 fixtures: 10 convert (4+2+1+1+1+1+1+1+1+1 = 14 signatures), 5 are skipped (see TestFixtures).
	if r.FilesRead != 15 || r.UnitsConverted != 10 || r.Signatures != 14 || r.SkippedTotal() != 5 {
		t.Fatalf("files %d converted %d signatures %d skipped %d; report %+v", r.FilesRead, r.UnitsConverted, r.Signatures, r.SkippedTotal(), r)
	}
	for i := 1; i < len(res.Signatures); i++ {
		if res.Signatures[i-1].ID == res.Signatures[i].ID {
			t.Fatalf("duplicate id %s", res.Signatures[i].ID)
		}
	}
}
