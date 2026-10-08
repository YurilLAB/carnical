// SPDX-License-Identifier: Apache-2.0

package importers

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/YurilLAB/coraza/carnical/vpatch"
)

func lit(target, op, pattern string) vpatch.Condition {
	return vpatch.Condition{Operator: op, Pattern: pattern, Targets: []string{target}}
}

func TestExpand(t *testing.T) {
	a, b, c, d := lit("path", "contains", "a"), lit("args", "contains", "b"), lit("body", "contains", "c"), lit("method", "equals", "POST")
	tests := []struct {
		name    string
		e       Expr
		maxAlts int
		want    [][]vpatch.Condition
		wantErr error
	}{
		{name: "leaf", e: Leaf(a), maxAlts: 8, want: [][]vpatch.Condition{{a}}},
		{name: "and", e: And(Leaf(a), Leaf(b)), maxAlts: 8, want: [][]vpatch.Condition{{a, b}}},
		{name: "or", e: Or(Leaf(a), Leaf(b)), maxAlts: 8, want: [][]vpatch.Condition{{a}, {b}}},
		{name: "and of or multiplies", e: And(Leaf(a), Or(Leaf(b), Leaf(c))), maxAlts: 8, want: [][]vpatch.Condition{{a, b}, {a, c}}},
		{name: "two ors", e: And(Or(Leaf(a), Leaf(b)), Or(Leaf(c), Leaf(d))), maxAlts: 8,
			want: [][]vpatch.Condition{{a, c}, {a, d}, {b, c}, {b, d}}},
		{name: "duplicate condition removed", e: And(Leaf(a), Leaf(a), Leaf(b)), maxAlts: 8, want: [][]vpatch.Condition{{a, b}}},
		{name: "duplicate alternative removed", e: Or(Leaf(a), Leaf(a)), maxAlts: 8, want: [][]vpatch.Condition{{a}}},
		{name: "too many alternatives", e: And(Or(Leaf(a), Leaf(b)), Or(Leaf(c), Leaf(d))), maxAlts: 3, wantErr: ErrTooManyAlternatives},
		{name: "empty or", e: Or(), maxAlts: 8, wantErr: ErrEmptyExpr},
		{name: "empty and", e: And(), maxAlts: 8, wantErr: ErrEmptyExpr},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.e.Expand(tt.maxAlts, 8)
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("error = %v, want %v", err, tt.wantErr)
			}
			if tt.wantErr == nil && !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("got %v, want %v", got, tt.want)
			}
		})
	}
	t.Run("deep nesting is refused, not recursed into", func(t *testing.T) {
		e := Leaf(a)
		for i := 0; i < 1000; i++ {
			e = And(e)
		}
		if _, err := e.Expand(8, 8); !errors.Is(err, ErrExprTooDeep) {
			t.Fatalf("error = %v, want %v", err, ErrExprTooDeep)
		}
	})
}

func TestAssemble(t *testing.T) {
	path := lit("path", "suffix", "/x.php")
	rxPath := lit("path", "rx", `/x\d\.php`)
	uri := lit("uri", "contains", "x")
	arg := lit("arg:a", "equals", "1")
	method := lit("method", "equals", "POST")
	neg := lit("path", "contains", "z")
	neg.Negate = true
	tests := []struct {
		name     string
		in       []vpatch.Condition
		wantMain vpatch.Condition
		wantAlso []vpatch.Condition
	}{
		{name: "literal path wins over everything", in: []vpatch.Condition{arg, method, path}, wantMain: path, wantAlso: []vpatch.Condition{arg, method}},
		{name: "literal path beats regex path", in: []vpatch.Condition{rxPath, path}, wantMain: path, wantAlso: []vpatch.Condition{rxPath}},
		{name: "path beats uri", in: []vpatch.Condition{uri, rxPath}, wantMain: rxPath, wantAlso: []vpatch.Condition{uri}},
		{name: "method is a poor main", in: []vpatch.Condition{method, arg}, wantMain: arg, wantAlso: []vpatch.Condition{method}},
		{name: "negated is last", in: []vpatch.Condition{neg, method}, wantMain: method, wantAlso: []vpatch.Condition{neg}},
		{name: "ties keep the first", in: []vpatch.Condition{arg, uri, lit("arg:b", "equals", "2")}, wantMain: uri, wantAlso: []vpatch.Condition{arg, lit("arg:b", "equals", "2")}},
		{name: "single", in: []vpatch.Condition{arg}, wantMain: arg, wantAlso: nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m, also := Assemble(tt.in)
			if !reflect.DeepEqual(m, tt.wantMain) || !reflect.DeepEqual(also, tt.wantAlso) {
				t.Fatalf("got main %v also %v; want main %v also %v", m, also, tt.wantMain, tt.wantAlso)
			}
		})
	}
}

func TestCVEs(t *testing.T) {
	tests := []struct {
		name string
		in   []string
		want []string
	}{
		{name: "plain", in: []string{"fixes CVE-2024-4577 in PHP"}, want: []string{"CVE-2024-4577"}},
		{name: "underscore and case", in: []string{"cve_2020_0688"}, want: []string{"CVE-2020-0688"}},
		{name: "several texts, deduplicated and sorted", in: []string{"CVE-2023-1389", "x CVE-2021-26086 and cve-2023-1389"}, want: []string{"CVE-2021-26086", "CVE-2023-1389"}},
		{name: "seven digit sequence", in: []string{"CVE-2024-1234567"}, want: []string{"CVE-2024-1234567"}},
		{name: "not a cve", in: []string{"CVE-24-1", "ACVE-2024-1234", "CVE-2024-123"}, want: nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := CVEs(tt.in...); !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("CVEs(%q) = %v, want %v", tt.in, got, tt.want)
			}
		})
	}
}

func TestIDPart(t *testing.T) {
	tests := []struct{ in, want string }{
		{"vpatch-CVE-2024-4577", "VPATCH-CVE-2024-4577"},
		{"env access!", "ENV-ACCESS"},
		{"  --a__b--  ", "A-B"},
		{"", ""},
		{"../../etc/passwd", "ETC-PASSWD"},
		{strings.Repeat("a", 200), strings.Repeat("A", 80)},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			if got := IDPart(tt.in); got != tt.want {
				t.Fatalf("IDPart(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestInferScope(t *testing.T) {
	tests := []struct {
		name  string
		paths []string
		texts []string
		tags  []string
		want  []string
	}{
		{name: "wordpress plugin from the path", paths: []string{"/wp-content/plugins/contact-form-7/includes/x.php"}, want: []string{"wordpress:plugin:contact-form-7"}},
		{name: "wordpress theme", paths: []string{"/wp-content/themes/twentyten/x.php?a=1"}, want: []string{"wordpress:theme:twentyten"}},
		{name: "wordpress core path", paths: []string{"/wp-admin/admin-ajax.php"}, want: []string{"wordpress"}},
		{name: "plain php", paths: []string{"/src/help.php"}, want: []string{"php"}},
		{name: "java extension", paths: []string{"/x/y.jsp"}, want: []string{"java"}},
		{name: "joomla option", paths: []string{"/index.php?option=com_foo"}, want: []string{"joomla"}},
		{name: "nextjs", paths: []string{"/_next/data/x"}, want: []string{"nextjs"}},
		{name: "words fill in when paths say nothing", texts: []string{"Jira Server path traversal"}, want: []string{"jira"}},
		{name: "tag", tags: []string{"cve", "wordpress", "wp-plugin"}, want: []string{"wordpress"}},
		{name: "specific plugin hides the generic words", paths: []string{"/wp-content/plugins/foo/a.php"}, texts: []string{"WordPress plugin foo"}, want: []string{"wordpress:plugin:foo"}},
		{name: "a framework hides php", paths: []string{"/index.php"}, texts: []string{"Drupal core"}, want: []string{"drupal"}},
		{name: "names no software", paths: []string{"/cgi-bin/luci/;stok=/locale"}, texts: []string{"router RCE"}, want: nil},
		{name: "a variable is not a plugin slug", paths: []string{"/wp-content/plugins/{{x}}/a"}, want: []string{"wordpress"}},
		{name: "javascript is not java", texts: []string{"JavaScript library"}, want: nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := InferScope(tt.paths, tt.texts, tt.tags)
			if len(got) == 0 && len(tt.want) == 0 {
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("InferScope = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestClassifyAndCWE(t *testing.T) {
	text := []struct{ in, want string }{
		{"WordPress Plugin X - SQL Injection", "sqli"},
		{"Cross-Site Scripting in help.php", "xss"},
		{"Unauthenticated Remote Code Execution", "rce"},
		{"Path Traversal in downloader", "lfi"},
		{"Arbitrary File Upload", "upload"},
		{"Server-Side Request Forgery", "ssrf"},
		{"Log4Shell JNDI", "java"},
		{"Weather widget settings page", ""},
	}
	for _, tt := range text {
		t.Run("text:"+tt.in, func(t *testing.T) {
			if got := ClassifyText(tt.in); got != tt.want {
				t.Fatalf("ClassifyText(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
	cwe := []struct{ in, want string }{{"CWE-79", "xss"}, {"cwe.CWE-89", "sqli"}, {"89", "sqli"}, {"CWE.22", "lfi"}, {"CWE-918", "ssrf"}, {"CWE-1", ""}, {"", ""}}
	for _, tt := range cwe {
		t.Run("cwe:"+tt.in, func(t *testing.T) {
			if got := CategoryFromCWE(tt.in); got != tt.want {
				t.Fatalf("CategoryFromCWE(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func goodSig() vpatch.Signature {
	return vpatch.Signature{
		ID: "T-1", Category: "xss", Severity: "high", Confidence: "high",
		Condition: vpatch.Condition{Operator: "contains", Pattern: "/x.php", Targets: []string{"path"}, Transforms: []string{"urldecode1", "lowercase"}},
		Also:      []vpatch.Condition{{Operator: "rx", Pattern: `<\s*script`, Flags: "i", Targets: []string{"arg:q", "header:user-agent"}}},
	}
}

func TestValidate(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(s *vpatch.Signature)
		bad    bool
	}{
		{name: "good", mutate: func(s *vpatch.Signature) {}},
		{name: "empty id", mutate: func(s *vpatch.Signature) { s.ID = "" }, bad: true},
		{name: "id with space", mutate: func(s *vpatch.Signature) { s.ID = "A B" }, bad: true},
		{name: "unknown category", mutate: func(s *vpatch.Signature) { s.Category = "nope" }, bad: true},
		{name: "unknown severity", mutate: func(s *vpatch.Signature) { s.Severity = "urgent" }, bad: true},
		{name: "unknown operator", mutate: func(s *vpatch.Signature) { s.Operator = "within" }, bad: true},
		{name: "no targets", mutate: func(s *vpatch.Signature) { s.Targets = nil }, bad: true},
		{name: "unknown target", mutate: func(s *vpatch.Signature) { s.Targets = []string{"request"} }, bad: true},
		{name: "named target without a name", mutate: func(s *vpatch.Signature) { s.Targets = []string{"arg:"} }, bad: true},
		{name: "unknown transform", mutate: func(s *vpatch.Signature) { s.Transforms = []string{"rot13"} }, bad: true},
		{name: "regex that does not compile", mutate: func(s *vpatch.Signature) { s.Also[0].Pattern = `a*+` }, bad: true},
		{name: "empty literal", mutate: func(s *vpatch.Signature) { s.Pattern = "" }, bad: true},
		{name: "bad flag", mutate: func(s *vpatch.Signature) { s.Also[0].Flags = "z" }, bad: true},
		{name: "score out of range", mutate: func(s *vpatch.Signature) { s.Score = 11 }, bad: true},
		{name: "bad tier", mutate: func(s *vpatch.Signature) { s.Tier = "gold" }, bad: true},
		{name: "bad cve", mutate: func(s *vpatch.Signature) { s.CVEs = []string{"CVE-1"} }, bad: true},
		{name: "pm with words", mutate: func(s *vpatch.Signature) {
			s.Also[0] = vpatch.Condition{Operator: "pm", Patterns: []string{"a", "b"}, Targets: []string{"headers"}}
		}},
		{name: "pm without words", mutate: func(s *vpatch.Signature) {
			s.Also[0] = vpatch.Condition{Operator: "pm", Targets: []string{"headers"}}
		}, bad: true},
		{name: "invalid utf8 pattern", mutate: func(s *vpatch.Signature) { s.Pattern = "a\xff" }, bad: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := goodSig()
			tt.mutate(&s)
			err := Validate(s, 0, 0)
			if (err != nil) != tt.bad {
				t.Fatalf("Validate error = %v, want bad=%v", err, tt.bad)
			}
		})
	}
}

func TestJSONLRoundTrip(t *testing.T) {
	s := goodSig()
	s.Also[0].Pattern = `<\s*script>&`
	var buf bytes.Buffer
	if err := WriteJSONL(&buf, []vpatch.Signature{s, s}); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(buf.String(), "u003c") { // how encoding/json writes "<" when it escapes HTML
		t.Fatalf("HTML characters were escaped: %s", buf.String())
	}
	if n := strings.Count(buf.String(), "\n"); n != 2 {
		t.Fatalf("lines = %d, want 2", n)
	}
	got, err := ReadJSONL(&buf, 0)
	if err != nil || len(got) != 2 || !reflect.DeepEqual(got[0], s) {
		t.Fatalf("round trip: %v, %v", got, err)
	}
	if _, err := ReadJSONL(strings.NewReader(`{"id": 5}`+"\n"), 0); err == nil {
		t.Fatal("a line of the wrong type was accepted")
	}
	if _, err := ReadJSONL(strings.NewReader(strings.Repeat("x", 5000)), 1000); err == nil {
		t.Fatal("a line over the limit was accepted")
	}
}

func fakeFormat() Format {
	return Format{Name: "fake", Extensions: []string{".r"}, Convert: func(name string, data []byte, opts Options, rep *Report) []vpatch.Signature {
		rep.UnitsRead++
		switch strings.TrimSpace(string(data)) {
		case "panic":
			panic("boom")
		case "bad":
			rep.UnitsConverted++
			return []vpatch.Signature{{ID: "bad id", Category: "xss", Severity: "low", Condition: vpatch.Condition{Operator: "contains", Pattern: "x", Targets: []string{"uri"}}}}
		}
		rep.UnitsConverted++
		s := goodSig()
		s.ID = "F-" + IDPart(strings.TrimSuffix(strings.ToLower(name), ".r"))
		s.Tier = opts.StartTier()
		return []vpatch.Signature{s}
	}}
}

func TestRun(t *testing.T) {
	t.Run("in-memory input obeys the file limit before conversion", func(t *testing.T) {
		for _, size := range []int{15, 16, 17} {
			t.Run(fmt.Sprint(size), func(t *testing.T) {
				calls := 0
				f := fakeFormat()
				convert := f.Convert
				f.Convert = func(name string, data []byte, opts Options, rep *Report) []vpatch.Signature {
					calls++
					return convert(name, data, opts, rep)
				}
				res := ConvertBytes(f, "memory.r", []byte(strings.Repeat("x", size)), Options{Limits: Limits{MaxFileBytes: 16}})
				if size <= 16 {
					if calls != 1 || len(res.Signatures) != 1 || res.Report.FilesRead != 1 || res.Report.FilesSkipped != 0 {
						t.Fatalf("input within the limit: calls=%d report=%+v", calls, res.Report)
					}
					return
				}
				if calls != 0 || len(res.Signatures) != 0 || res.Report.FilesRead != 0 || res.Report.FilesSkipped != 1 || res.Report.UnitsRead != 0 || len(res.Report.Errors) != 1 {
					t.Fatalf("oversized input reached conversion or was not reported: calls=%d report=%+v", calls, res.Report)
				}
			})
		}
	})
	dir := t.TempDir()
	write := func(rel, content string) {
		p := filepath.Join(dir, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("b.r", "ok")
	write("a.r", "ok")
	write("sub/c.R", "ok") // upper-case extension is picked up
	write("sub/skip.txt", "ok")
	write(".hidden/d.r", "ok")
	write("e.r", "panic")
	write("f.r", "bad")
	write("big.r", strings.Repeat("x", 5000))
	write("dup/a.r", "ok") // same ID as a.r

	res, err := Run(fakeFormat(), dir, Options{Limits: Limits{MaxFileBytes: 1000}})
	if err != nil {
		t.Fatal(err)
	}
	var ids []string
	for _, s := range res.Signatures {
		ids = append(ids, s.ID)
	}
	// Order is by sorted path: a.r, b.r, big.r (skipped), dup/a.r (duplicate), e.r (panics), f.r (invalid), sub/c.R.
	want := []string{"F-A", "F-B", "F-C"}
	if !reflect.DeepEqual(ids, want) {
		t.Fatalf("ids = %v, want %v", ids, want)
	}
	r := res.Report
	if r.FilesRead != 6 || r.FilesSkipped != 1 {
		t.Errorf("files read/skipped = %d/%d, want 6/1", r.FilesRead, r.FilesSkipped)
	}
	if r.Skipped["internal-error"] != 1 {
		t.Errorf("a panic in a converter was not reported: %+v", r.Skipped)
	}
	if r.Partial["invalid-output"] != 1 || r.Partial["duplicate-id"] != 1 {
		t.Errorf("partial = %+v, want one invalid-output and one duplicate-id", r.Partial)
	}
	if r.Signatures != 3 || r.Tiers["community"] != 3 {
		t.Errorf("signatures %d tiers %v, want 3 community", r.Signatures, r.Tiers)
	}

	t.Run("a single file", func(t *testing.T) {
		res, err := Run(fakeFormat(), filepath.Join(dir, "a.r"), Options{Tier: "experimental"})
		if err != nil || len(res.Signatures) != 1 || res.Signatures[0].Tier != "experimental" {
			t.Fatalf("got %v, %v", res.Signatures, err)
		}
	})
	t.Run("missing input", func(t *testing.T) {
		if _, err := Run(fakeFormat(), filepath.Join(dir, "nope"), Options{}); err == nil {
			t.Fatal("no error for a missing input")
		}
	})
	t.Run("deterministic", func(t *testing.T) {
		res2, _ := Run(fakeFormat(), dir, Options{Limits: Limits{MaxFileBytes: 1000}})
		if !reflect.DeepEqual(res.Signatures, res2.Signatures) {
			t.Fatal("two runs differ")
		}
	})
}

func TestReportMergeAndTop(t *testing.T) {
	a, b := NewReport("x"), NewReport("x")
	a.Skip("one", "u1")
	a.Skip("one", "u2")
	b.Skip("one", "u3")
	b.Skip("one", "u4")
	b.Skip("one", "u5")
	b.Skip("two", "u6")
	b.Skip("three", "u7")
	b.Skip("three", "u8")
	a.Merge(b)
	top := a.TopSkips(2)
	if len(top) != 2 || top[0] != (ReasonCount{"one", 5}) || top[1] != (ReasonCount{"three", 2}) {
		t.Fatalf("top = %v", top)
	}
	if got := len(a.Examples["one"]); got != maxExamples {
		t.Fatalf("examples kept = %d, want %d", got, maxExamples)
	}
	if a.SkippedTotal() != 8 {
		t.Fatalf("SkippedTotal = %d, want 8", a.SkippedTotal())
	}
}

func TestLowerTier(t *testing.T) {
	for in, want := range map[string]string{"verified": "community", "": "community", "community": "experimental", "experimental": "experimental"} {
		if got := LowerTier(in); got != want {
			t.Errorf("LowerTier(%q) = %q, want %q", in, got, want)
		}
	}
}
