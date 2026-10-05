// SPDX-License-Identifier: Apache-2.0

package legacy

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"testing"

	"github.com/YurilLAB/coraza/carnical/vpatch"
	"github.com/YurilLAB/coraza/carnical/vpatch/importers"
	"github.com/YurilLAB/coraza/carnical/vpatch/importers/crowdsec"
	"github.com/YurilLAB/coraza/carnical/vpatch/importers/nuclei"
	"github.com/YurilLAB/coraza/carnical/vpatch/importers/suricata"
)

func c(op, pattern string, targets []string, transforms ...string) vpatch.Condition {
	return vpatch.Condition{Operator: op, Pattern: pattern, Targets: targets, Transforms: transforms}
}

func TestEvaluator(t *testing.T) {
	req := sampleRequest{
		Method: "POST",
		URI:    "/Wp-Admin//admin-ajax.php?action=Foo&q=%3Cscript%3E&x=a+b",
		Headers: map[string]string{
			"host": "example.test", "user-agent": "Mozilla/5.0 Zollard", "cookie": "sid=abc; Uid=Admin", "content-type": "application/x-www-form-urlencoded",
		},
		Body: "p=1&Name=%2e%2e%2fetc",
	}
	x := newCtx(req)
	tests := []struct {
		name string
		cond vpatch.Condition
		want bool
	}{
		{"path suffix", c("suffix", "admin-ajax.php", []string{"path"}), true},
		{"path is without the query", c("contains", "action=", []string{"path"}), false},
		{"uri has the query", c("contains", "action=Foo", []string{"uri"}), true},
		{"query alone", c("prefix", "action=", []string{"query"}), true},
		{"method", c("equals", "POST", []string{"method"}), true},
		{"method case matters", c("equals", "post", []string{"method"}), false},
		{"lowercase transform", c("contains", "/wp-admin/", []string{"path"}, "normpath", "lowercase"), true},
		{"normpath collapses //", c("contains", "/wp-admin//", []string{"path"}, "normpath", "lowercase"), false},
		{"named arg is lower-cased and decoded", c("equals", "Foo", []string{"arg:action"}), true},
		{"named arg missing", c("equals", "Foo", []string{"arg:nope"}), false},
		{"arg value decoded once by the parser", c("contains", "<script>", []string{"args"}), true},
		{"plus is a space in a form value", c("equals", "a b", []string{"arg:x"}), true},
		{"body argument", c("equals", "1", []string{"arg:p"}), true},
		{"argnames", c("equals", "name", []string{"argnames"}), true},
		{"urldecode1 once", c("contains", "../etc", []string{"body"}, "urldecode1"), true},
		{"urldecode1 once is not twice", c("contains", "%2e", []string{"body"}, "urldecode1"), false},
		{"header", c("contains", "Zollard", []string{"header:user-agent"}), true},
		{"header name is case-insensitive", c("contains", "Zollard", []string{"header:User-Agent"}), true},
		{"any header value", c("equals", "example.test", []string{"headers"}), true},
		{"cookie", c("equals", "Admin", []string{"cookie:uid"}), true},
		{"cookie names", c("equals", "sid", []string{"cookienames"}), true},
		{"regex", c("rx", `^/wp-admin`, []string{"path"}, "lowercase"), true},
		{"regex flag i", vpatch.Condition{Operator: "rx", Pattern: "^/WP-ADMIN", Flags: "i", Targets: []string{"path"}}, true},
		{"regex without the flag", c("rx", "^/WP-ADMIN", []string{"path"}), false},
		{"negate holds when nothing matches", vpatch.Condition{Operator: "contains", Pattern: "zzz", Targets: []string{"path"}, Negate: true}, true},
		{"negate fails when something matches", vpatch.Condition{Operator: "contains", Pattern: "admin", Targets: []string{"path"}, Negate: true}, false},
		{"negate on a missing value holds, which is why converters add an existence guard", vpatch.Condition{Operator: "contains", Pattern: "x", Targets: []string{"header:referer"}, Negate: true}, true},
		{"pm", vpatch.Condition{Operator: "pm", Patterns: []string{"nope", "zollard"}, Flags: "i", Targets: []string{"header:user-agent"}}, true},
		{"base64", c("equals", "hello", []string{"arg:x"}, "base64decode"), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := evalCond(tt.cond, x)
			if !ok || got != tt.want {
				t.Fatalf("evalCond = %v, %v; want %v", got, ok, tt.want)
			}
		})
	}
	t.Run("a pattern Go cannot compile is not evaluable", func(t *testing.T) {
		if _, ok := evalCond(c("rx", `a(?=b)`, []string{"path"}), x); ok {
			t.Fatal("evaluated a lookahead")
		}
	})
	t.Run("the library's lookahead conjunction is read as a conjunction", func(t *testing.T) {
		p := `^(?=[\s\S]{0,4096}?(?i:\/ADMIN\-ajax))(?=[\s\S]{0,4096}?(?i:\.php))`
		if got, ok := evalCond(c("rx", p, []string{"path"}), x); !ok || !got {
			t.Fatalf("got %v, %v", got, ok)
		}
		q := `^(?=[\s\S]{0,4096}?(?i:\/ADMIN\-ajax))(?=[\s\S]{0,4096}?(?i:\.asp))`
		if got, ok := evalCond(c("rx", q, []string{"path"}), x); !ok || got {
			t.Fatalf("one literal missing must fail: %v, %v", got, ok)
		}
	})
}

func TestCanon(t *testing.T) {
	tests := []struct {
		name string
		a, b vpatch.Condition
		same bool
	}{
		{"regex that is a suffix literal vs suffix", c("rx", `\/src\/help\.php\z`, []string{"path"}), c("suffix", "/src/help.php", []string{"path"}), true},
		{"anchored regex vs equals", c("rx", `^country\z`, []string{"arg:form"}), c("equals", "country", []string{"arg:form"}), true},
		{"unanchored literal regex vs contains", c("rx", `\.env`, []string{"path"}), c("contains", ".env", []string{"path"}), true},
		{"prefix", c("rx", `\A/ecp/`, []string{"uri"}), c("prefix", "/ecp/", []string{"uri"}), true},
		{"case folding through a flag", vpatch.Condition{Operator: "rx", Pattern: "Select", Flags: "i", Targets: []string{"uri"}}, c("contains", "select", []string{"uri"}, "lowercase"), true},
		{"case folding through a group", c("rx", `(?i:SELECT)`, []string{"uri"}), c("contains", "select", []string{"uri"}, "lowercase"), true},
		{"a method is a token", c("rx", "GET", []string{"method"}), c("equals", "GET", []string{"method"}), true},
		{"size written two ways", c("rx", `\A[\s\S]{601}`, []string{"uri"}), c("rx", `(?s)\A.{601,}\z`, []string{"uri"}), true},
		{"exact size", c("rx", `(?s)\A.{14}\z`, []string{"uri"}), c("rx", `\A[\s\S]{14}$`, []string{"uri"}), true},
		{"gap written two ways", c("rx", `a[\s\S]*?b`, []string{"uri"}), c("rx", `a(?s:.)*b`, []string{"uri"}), true},
		{"target order does not matter", c("contains", "x", []string{"uri", "body"}), c("contains", "x", []string{"body", "uri"}), true},
		{"different literal", c("contains", "a", []string{"uri"}), c("contains", "b", []string{"uri"}), false},
		{"different target", c("contains", "a", []string{"uri"}), c("contains", "a", []string{"path"}), false},
		{"different case sensitivity", c("contains", "A", []string{"uri"}), c("contains", "a", []string{"uri"}), false},
		{"prefix is not contains", c("prefix", "a", []string{"uri"}), c("contains", "a", []string{"uri"}), false},
		{"regex that is not a literal", c("rx", `a+b`, []string{"uri"}), c("contains", "a+b", []string{"uri"}), false},
		{"negation matters", vpatch.Condition{Operator: "contains", Pattern: "a", Targets: []string{"uri"}, Negate: true}, c("contains", "a", []string{"uri"}), false},
		{"different size", c("rx", `\A[\s\S]{601}`, []string{"uri"}), c("rx", `(?s)\A.{602,}\z`, []string{"uri"}), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ka, kb := canon(tt.a).key, canon(tt.b).key
			if (ka == kb) != tt.same {
				t.Fatalf("keys %q and %q; same = %v, want %v", ka, kb, ka == kb, tt.same)
			}
		})
	}
}

func sigOf(main vpatch.Condition, also ...vpatch.Condition) vpatch.Signature {
	return vpatch.Signature{ID: "X", Condition: main, Also: also}
}

func TestDiffVerdicts(t *testing.T) {
	path := c("suffix", "/a.php", []string{"path"}, "urldecode1", "lowercase")
	arg := c("rx", "<", []string{"arg:q"}, "urldecode")
	tests := []struct {
		name         string
		legacy, mine vpatch.Signature
		want         string
	}{
		{"identical", sigOf(path, arg), sigOf(arg, path), Identical},
		{"literal written as a regex", sigOf(c("rx", `\/a\.php\z`, []string{"path"}, "urldecode1", "lowercase"), arg), sigOf(path, arg), Identical},
		{"same conditions, different transforms", sigOf(path, arg), sigOf(c("suffix", "/a.php", []string{"path"}, "lowercase"), arg), TransformsDiffer},
		{"mine has an extra condition", sigOf(path), sigOf(path, arg), MineNarrower},
		{"the library has an extra condition", sigOf(path, arg), sigOf(path), MineBroader},
		{"each lacks one", sigOf(path, arg), sigOf(path, c("rx", ">", []string{"arg:q"}, "urldecode")), Equivalent},
		{"a different target is a different condition", sigOf(path, arg), sigOf(path, c("rx", "<", []string{"arg:z"}, "urldecode")), Different},
		{"nothing in common", sigOf(path), sigOf(c("contains", "zzz", []string{"body"})), Different},
		{"a redundant prefilter is ignored", sigOf(c("rx", `(?i:output=\w)`, []string{"uri"})), sigOf(c("contains", "output=", []string{"uri"}, "lowercase"), vpatch.Condition{Operator: "rx", Pattern: `output=\w`, Flags: "i", Targets: []string{"uri"}}), Identical},
		{"a lookahead conjunction is separate contents", sigOf(c("rx", `^(?=[\s\S]{0,4096}?(?i:\/a\.php\?))(?=[\s\S]{0,4096}?(?i:id\=))`, []string{"uri"})), sigOf(c("contains", "/a.php?", []string{"uri"}, "lowercase"), c("contains", "id=", []string{"uri"}, "lowercase")), Identical},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Diff(tt.legacy, tt.mine).Verdict; got != tt.want {
				t.Fatalf("verdict %q, want %q", got, tt.want)
			}
		})
	}
}

func TestPairUp(t *testing.T) {
	lib := []Record{
		{Signature: vpatch.Signature{ID: "CS-CVE-2002-1131-2"}, Origin: "crowdsec:vpatch-CVE-2002-1131@abc"},
		{Signature: vpatch.Signature{ID: "CS-CVE-2023-1389"}, Origin: "crowdsec:vpatch-CVE-2023-1389@abc"},
		{Signature: vpatch.Signature{ID: "CS-ENV-ACCESS"}, Origin: "crowdsec:vpatch-env-access@abc"},
		{Signature: vpatch.Signature{ID: "CS-GONE-1"}, Origin: "crowdsec:vpatch-gone@abc"},
		{Signature: vpatch.Signature{ID: "ET-1"}, Origin: "et-open:1@1"},
	}
	mine := []vpatch.Signature{{ID: "CS-CVE-2002-1131-1"}, {ID: "CS-CVE-2002-1131-2"}, {ID: "CS-CVE-2023-1389-1"}, {ID: "CS-ENV-ACCESS-1"}, {ID: "CS-NEW-1"}}
	p := PairUp("crowdsec", mine, lib)
	var keys []string
	for _, pr := range p.Pairs {
		keys = append(keys, pr.Key)
	}
	if !reflect.DeepEqual(keys, []string{"CS-CVE-2002-1131-2", "CS-CVE-2023-1389-1", "CS-ENV-ACCESS-1"}) {
		t.Fatalf("pairs %v", keys)
	}
	if !reflect.DeepEqual(p.OnlyMine, []string{"CS-CVE-2002-1131-1", "CS-NEW-1"}) || len(p.OnlyLegacy) != 1 || p.OnlyLegacy[0].ID != "CS-GONE-1" {
		t.Fatalf("only mine %v only legacy %v", p.OnlyMine, p.OnlyLegacy)
	}
	t.Run("suricata pairs by sid", func(t *testing.T) {
		p := PairUp("suricata", []vpatch.Signature{{ID: "ET-1"}, {ID: "ET-2"}}, lib)
		if len(p.Pairs) != 1 || p.Pairs[0].Key != "ET-1" || !reflect.DeepEqual(p.OnlyMine, []string{"ET-2"}) {
			t.Fatalf("%+v", p)
		}
	})
}

func TestReadLibrary(t *testing.T) {
	in := `{"id":"A","operator":"pm","pattern":["x","y"],"targets":["headers"],"_status":"verified","_origin":"crs:1@4"}` + "\n" +
		`{"id":"B","operator":"rx","pattern":"a+","targets":["uri"],"also":[{"operator":"pm","pattern":["z"],"targets":["body"]}],"_status":"held","_origin":"crowdsec:x@1"}` + "\n"
	recs, err := ReadLibrary(strings.NewReader(in))
	if err != nil || len(recs) != 2 {
		t.Fatalf("%v %v", recs, err)
	}
	if !reflect.DeepEqual(recs[0].Patterns, []string{"x", "y"}) || recs[0].Pattern != "" || recs[0].Status != "verified" || recs[0].Origin != "crs:1@4" {
		t.Fatalf("%+v", recs[0])
	}
	if recs[1].Pattern != "a+" || !reflect.DeepEqual(recs[1].Also[0].Patterns, []string{"z"}) {
		t.Fatalf("%+v", recs[1])
	}
	if _, err := ReadLibrary(strings.NewReader("{broken\n")); err == nil {
		t.Fatal("a broken line was accepted")
	}
}

// ---- behaviour against the library's sample requests -------------------------------------------------------------------------

const (
	upstreamRoot = "../../../../.attack/upstream"
	libraryPath  = "../../../../.attack/sigs/legacy.jsonl"
	samplesPath  = "../../../../.attack/sigs/samples.jsonl"
)

type behaviour struct {
	Format string `json:"format"`
	Pairs  int    `json:"pairs"`
	// LibraryNotEvaluable counts pairs whose library signature holds a regular expression Go cannot compile.
	LibraryNotEvaluable int `json:"library_pairs_not_evaluable_in_go"`
	// LibraryUncompilable counts every library row of this format with such a pattern, paired or not.
	LibraryUncompilable int `json:"library_rows_with_a_pattern_go_cannot_compile"`
	// The regular expressions of the library rows of this format: how many Go compiles as written, how many only after the exact
	// translation of possessive quantifiers and atomic groups, and how many not at all (lookahead is the usual reason).
	LibRegexTotal      int `json:"library_regex_conditions"`
	LibRegexCompiled   int `json:"library_regex_compile_as_written"`
	LibRegexTranslated int `json:"library_regex_compile_after_translation"`
	LibRegexFailed     int `json:"library_regex_fail"`
	LibRegexLookaround int `json:"library_regex_fail_with_lookahead"`
	LibraryRows        int `json:"library_rows"`
	AttackSamples      int `json:"attack_samples_compared"`
	AttackBoth         int `json:"attack_both_match"`
	AttackLegacyOnly   int `json:"attack_only_library_matches"`
	AttackMineOnly     int `json:"attack_only_converted_matches"`
	AttackNeither      int `json:"attack_neither_matches"`
	BenignSamples      int `json:"benign_samples_compared"`
	BenignLegacyHits   int `json:"benign_library_matches"`
	BenignMineHits     int `json:"benign_converted_matches"`
	// VerifiedCalibration: of the library rows marked verified, the share this evaluator also finds matching at least one of its own
	// attack samples. It says how far this evaluator agrees with the one that set the status.
	VerifiedRows        int      `json:"verified_rows_evaluated"`
	VerifiedMatching    int      `json:"verified_rows_matching_an_attack_sample"`
	ExamplesLegacyOnly  []string `json:"examples_only_library_matches"`
	ExamplesMineOnly    []string `json:"examples_only_converted_matches"`
	ExamplesBenignMine  []string `json:"examples_benign_matched_by_converted"`
	ExamplesBenignLib   []string `json:"examples_benign_matched_by_library"`
	PairsLegacyMatchesN int      `json:"pairs_where_library_matches_some_attack"`
	PairsMineMatchesN   int      `json:"pairs_where_converted_matches_some_attack"`
}

func loadSamples(t *testing.T) map[string][]sampleRow {
	t.Helper()
	fh, err := os.Open(samplesPath)
	if err != nil {
		t.Skip("no samples at " + samplesPath)
	}
	defer fh.Close()
	out := map[string][]sampleRow{}
	sc := bufio.NewScanner(fh)
	sc.Buffer(make([]byte, 0, 64<<10), 4<<20)
	for sc.Scan() {
		var r sampleRow
		if err := json.Unmarshal(sc.Bytes(), &r); err != nil {
			t.Fatal(err)
		}
		out[r.Sig] = append(out[r.Sig], r)
	}
	return out
}

func loadLibrary(t *testing.T) []Record {
	t.Helper()
	fh, err := os.Open(libraryPath)
	if err != nil {
		t.Skip("no library at " + libraryPath)
	}
	defer fh.Close()
	recs, err := ReadLibrary(fh)
	if err != nil {
		t.Fatal(err)
	}
	return recs
}

func uncompilable(s vpatch.Signature) bool {
	for _, cnd := range append([]vpatch.Condition{s.Condition}, s.Also...) {
		if cnd.Operator == vpatch.OpRegex && rx(cnd) == nil {
			return true
		}
	}
	return false
}

// runBehaviour pairs the converted signatures with the library's and runs both against the library's sample requests.
func runBehaviour(t *testing.T, format string, mine []vpatch.Signature, lib []Record, samples map[string][]sampleRow) behaviour {
	t.Helper()
	b := behaviour{Format: format}
	for _, r := range lib {
		if !isFormat(r.Origin, format) {
			continue
		}
		b.LibraryRows++
		if uncompilable(r.Signature) {
			b.LibraryUncompilable++
		}
		for _, cnd := range append([]vpatch.Condition{r.Condition}, r.Also...) {
			if cnd.Operator != vpatch.OpRegex {
				continue
			}
			b.LibRegexTotal++
			pre := flagPrefix(cnd.Flags)
			if _, err := regexp.Compile(pre + cnd.Pattern); err == nil {
				b.LibRegexCompiled++
			} else if compileRx(cnd.Pattern, cnd.Flags) != nil {
				b.LibRegexTranslated++
			} else {
				b.LibRegexFailed++
				if strings.Contains(cnd.Pattern, "(?=") || strings.Contains(cnd.Pattern, "(?!") {
					b.LibRegexLookaround++
				}
			}
		}
	}
	p := PairUp(format, mine, lib)
	// For nuclei the library has one signature per template and the importer one per request: a sample is matched by the converted side if
	// any signature of the template matches it.
	byTemplate := map[string][]vpatch.Signature{}
	if format == "nuclei" {
		for _, s := range mine {
			id := strings.TrimPrefix(s.ID, "NU-")
			if i := strings.LastIndexByte(id, '-'); i > 0 {
				id = id[:i]
			}
			byTemplate[id] = append(byTemplate[id], s)
		}
	}
	for _, pr := range p.Pairs {
		b.Pairs++
		mineSigs := []vpatch.Signature{pr.Mine}
		if format == "nuclei" {
			id := strings.TrimPrefix(pr.Mine.ID, "NU-")
			id = id[:strings.LastIndexByte(id, '-')]
			mineSigs = byTemplate[id]
		}
		rows := samples[pr.Legacy.ID]
		evaluable := true
		legacyHit, mineHit := false, false
		for _, row := range rows {
			x := newCtx(row.Request)
			l, lok := evalSig(pr.Legacy.Signature, x)
			if !lok {
				evaluable = false
				break
			}
			m := false
			for _, s := range mineSigs {
				if h, ok := evalSig(s, x); ok && h {
					m = true
				}
			}
			switch row.Kind {
			case "attack":
				b.AttackSamples++
				switch {
				case l && m:
					b.AttackBoth++
				case l:
					b.AttackLegacyOnly++
					if len(b.ExamplesLegacyOnly) < 12 {
						b.ExamplesLegacyOnly = append(b.ExamplesLegacyOnly, pr.Key+" "+row.Request.Method+" "+clip(row.Request.URI))
					}
				case m:
					b.AttackMineOnly++
					if len(b.ExamplesMineOnly) < 12 {
						b.ExamplesMineOnly = append(b.ExamplesMineOnly, pr.Key+" "+row.Request.Method+" "+clip(row.Request.URI))
					}
				default:
					b.AttackNeither++
				}
				legacyHit = legacyHit || l
				mineHit = mineHit || m
			case "benign":
				b.BenignSamples++
				if l {
					b.BenignLegacyHits++
					if len(b.ExamplesBenignLib) < 6 {
						b.ExamplesBenignLib = append(b.ExamplesBenignLib, pr.Key+" "+clip(row.Request.URI))
					}
				}
				if m {
					b.BenignMineHits++
					if len(b.ExamplesBenignMine) < 6 {
						b.ExamplesBenignMine = append(b.ExamplesBenignMine, pr.Key+" "+clip(row.Request.URI))
					}
				}
			}
		}
		if !evaluable {
			b.LibraryNotEvaluable++
			continue
		}
		if legacyHit {
			b.PairsLegacyMatchesN++
		}
		if mineHit {
			b.PairsMineMatchesN++
		}
		if pr.Legacy.Status == "verified" {
			b.VerifiedRows++
			if legacyHit {
				b.VerifiedMatching++
			}
		}
	}
	return b
}

func clip(s string) string {
	if len(s) > 110 {
		return s[:110] + "..."
	}
	return s
}

func TestBehaviourAgainstLibrary(t *testing.T) {
	if testing.Short() {
		t.Skip("slow: converts the upstream rule sets")
	}
	if _, err := os.Stat(upstreamRoot); err != nil {
		t.Skip("no upstream checkout at " + upstreamRoot)
	}
	lib := loadLibrary(t)
	samples := loadSamples(t)
	jobs := []struct {
		format string
		run    func() (importers.Result, error)
	}{
		{"crowdsec", func() (importers.Result, error) {
			return crowdsec.Convert(filepath.Join(upstreamRoot, "crowdsec-hub/appsec-rules"), importers.Options{})
		}},
		{"suricata", func() (importers.Result, error) {
			return suricata.Convert(filepath.Join(upstreamRoot, "et-open"), importers.Options{})
		}},
		{"nuclei", func() (importers.Result, error) {
			return nuclei.Convert(filepath.Join(upstreamRoot, "nuclei-templates/http"), importers.Options{})
		}},
	}
	for _, job := range jobs {
		t.Run(job.format, func(t *testing.T) {
			res, err := job.run()
			if err != nil {
				t.Fatal(err)
			}
			b := runBehaviour(t, job.format, res.Signatures, lib, samples)
			out, _ := json.MarshalIndent(b, "", "  ")
			t.Logf("%s", out)
			if dir := os.Getenv("CARNICAL_REPORT_DIR"); dir != "" {
				_ = os.WriteFile(filepath.Join(dir, "behaviour-"+job.format+".json"), out, 0o644)
				cmp := Compare(job.format, res.Signatures, lib)
				cb, _ := json.MarshalIndent(cmp, "", "  ")
				_ = os.WriteFile(filepath.Join(dir, "comparison-"+job.format+".json"), cb, 0o644)
			}
			if b.Pairs == 0 || b.AttackSamples == 0 {
				t.Fatalf("nothing was compared: %+v", b)
			}
		})
	}
}

// TestExplain prints, for the ids in CARNICAL_EXPLAIN (comma separated library ids) and format CARNICAL_FORMAT, the library's signature,
// the converted one and what each condition says about each sample. It is a debugging aid and does nothing unless the variables are set.
func TestExplain(t *testing.T) {
	ids := os.Getenv("CARNICAL_EXPLAIN")
	format := os.Getenv("CARNICAL_FORMAT")
	if ids == "" || format == "" {
		t.Skip("set CARNICAL_EXPLAIN and CARNICAL_FORMAT")
	}
	lib := loadLibrary(t)
	samples := loadSamples(t)
	var res importers.Result
	var err error
	switch format {
	case "crowdsec":
		res, err = crowdsec.Convert(filepath.Join(upstreamRoot, "crowdsec-hub/appsec-rules"), importers.Options{})
	case "suricata":
		res, err = suricata.Convert(filepath.Join(upstreamRoot, "et-open"), importers.Options{})
	case "nuclei":
		res, err = nuclei.Convert(filepath.Join(upstreamRoot, "nuclei-templates/http"), importers.Options{})
	}
	if err != nil {
		t.Fatal(err)
	}
	p := PairUp(format, res.Signatures, lib)
	for _, id := range strings.Split(ids, ",") {
		for _, pr := range p.Pairs {
			if pr.Legacy.ID != id {
				continue
			}
			lj, _ := json.Marshal(pr.Legacy.Signature)
			mj, _ := json.Marshal(pr.Mine)
			t.Logf("LIBRARY  %s (%s)\n%s\nCONVERTED %s\n%s", pr.Legacy.ID, pr.Legacy.Status, lj, pr.Mine.ID, mj)
			for _, row := range samples[id] {
				x := newCtx(row.Request)
				t.Logf("  sample %s %s %s", row.Kind, row.Request.Method, clip(row.Request.URI))
				for name, s := range map[string]vpatch.Signature{"library": pr.Legacy.Signature, "converted": pr.Mine} {
					for i, cnd := range append([]vpatch.Condition{s.Condition}, s.Also...) {
						h, ok := evalCond(cnd, x)
						t.Logf("    %-9s cond %d %v/%v  %s %s %v %q", name, i, h, ok, cnd.Operator, cnd.Targets, cnd.Transforms, clip(cnd.Pattern))
					}
				}
			}
		}
	}
}
