// SPDX-License-Identifier: Apache-2.0

// Package legacy compares signatures converted by the importers with the signature library that was built from the same sources
// earlier (JSON lines in the shape of vpatch.Signature, with "_origin" and "_status" added), rule by rule.
//
// The comparison is structural: for each rule that exists on both sides it asks whether the two have the same targets, the same kind
// of test, and an equivalent pattern, and says what differs where they do not. The tests of this package add a behavioural check
// (see legacy_test.go): both signatures are run against the library's sample requests, and the answer on each request is compared.
package legacy

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/YurilLAB/coraza/carnical/vpatch"
	"github.com/YurilLAB/coraza/carnical/vpatch/importers"
)

// Record is one line of the library.
type Record struct {
	vpatch.Signature
	Status string // "verified", "candidate", "held" or "rejected"
	Origin string // such as "crowdsec:vpatch-CVE-2002-1131@b29724e642ab", "nuclei:CVE-2002-1131@10.4.9", "et-open:2013002@11303"
}

// rawCond is a condition as the library writes it: for the "pm" operator the pattern is a list of words, not a string.
type rawCond struct {
	Operator   string          `json:"operator"`
	Pattern    json.RawMessage `json:"pattern"`
	Patterns   []string        `json:"patterns"`
	Flags      string          `json:"flags"`
	Targets    []string        `json:"targets"`
	Transforms []string        `json:"transforms"`
	Negate     bool            `json:"negate"`
}

func (r rawCond) cond() vpatch.Condition {
	c := vpatch.Condition{Operator: r.Operator, Patterns: r.Patterns, Flags: r.Flags, Targets: r.Targets, Transforms: r.Transforms, Negate: r.Negate}
	if len(r.Pattern) > 0 && r.Pattern[0] == '[' {
		var list []string
		if json.Unmarshal(r.Pattern, &list) == nil {
			c.Patterns = list
		}
	} else if len(r.Pattern) > 0 {
		var s string
		if json.Unmarshal(r.Pattern, &s) == nil {
			c.Pattern = s
		}
	}
	return c
}

type rawRecord struct {
	rawCond
	ID          string    `json:"id"`
	Rev         int       `json:"rev"`
	Description string    `json:"description"`
	Category    string    `json:"category"`
	Severity    string    `json:"severity"`
	Confidence  string    `json:"confidence"`
	Action      string    `json:"action"`
	Score       int       `json:"score"`
	CVEs        []string  `json:"cves"`
	Sources     []string  `json:"sources"`
	Scope       []string  `json:"scope"`
	Tier        string    `json:"tier"`
	Also        []rawCond `json:"also"`
	Status      string    `json:"_status"`
	Origin      string    `json:"_origin"`
}

// ReadLibrary reads the library file.
func ReadLibrary(r io.Reader) ([]Record, error) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64<<10), 4<<20)
	var out []Record
	line := 0
	for sc.Scan() {
		line++
		b := bytes.TrimSpace(sc.Bytes())
		if len(b) == 0 {
			continue
		}
		var rr rawRecord
		if err := json.Unmarshal(b, &rr); err != nil {
			return nil, fmt.Errorf("line %d: %w", line, err)
		}
		s := vpatch.Signature{
			ID: rr.ID, Rev: rr.Rev, Description: rr.Description, Category: rr.Category, Severity: rr.Severity, Confidence: rr.Confidence,
			Action: rr.Action, Score: rr.Score, CVEs: rr.CVEs, Sources: rr.Sources, Scope: rr.Scope, Tier: rr.Tier, Condition: rr.cond(),
		}
		for _, a := range rr.Also {
			s.Also = append(s.Also, a.cond())
		}
		out = append(out, Record{Signature: s, Status: rr.Status, Origin: rr.Origin})
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("line %d: %w", line+1, err)
	}
	return out, nil
}

// Pair is a converted signature and the library's signature for the same rule.
type Pair struct {
	Key    string
	Legacy Record
	Mine   vpatch.Signature
}

// Pairing is the result of matching the two sides.
type Pairing struct {
	Pairs      []Pair
	OnlyMine   []string // ids of converted signatures with no library twin
	OnlyLegacy []Record // library rows with no converted twin
}

func isFormat(origin, format string) bool {
	switch format {
	case "suricata":
		return strings.HasPrefix(origin, "et-open:")
	}
	return strings.HasPrefix(origin, format+":")
}

// PairUp matches converted signatures with the library's rows of the same source format. CrowdSec rows are matched on the rule's name
// and the position of the signature in it; ET rows on the sid; nuclei rows on the template id (the library holds one signature per
// template, the importer one per request, so each library row is paired with the converted signature of that template that agrees with
// it best).
func PairUp(format string, mine []vpatch.Signature, lib []Record) Pairing {
	var p Pairing
	var rows []Record
	for _, r := range lib {
		if isFormat(r.Origin, format) {
			rows = append(rows, r)
		}
	}
	used := map[string]bool{}
	switch format {
	case "crowdsec":
		byKey := map[string]vpatch.Signature{}
		for _, s := range mine {
			byKey[s.ID] = s
		}
		for _, r := range rows {
			name := strings.TrimPrefix(strings.TrimPrefix(originName(r.Origin), "vpatch-"), "VPATCH-")
			part := importers.IDPart(name)
			n := 1
			if r.ID != "CS-"+part {
				if rest, ok := strings.CutPrefix(r.ID, "CS-"+part+"-"); ok {
					if k, err := strconv.Atoi(rest); err == nil {
						n = k
					}
				}
			}
			key := "CS-" + part + "-" + strconv.Itoa(n)
			if s, ok := byKey[key]; ok {
				p.Pairs = append(p.Pairs, Pair{Key: key, Legacy: r, Mine: s})
				used[s.ID] = true
			} else {
				p.OnlyLegacy = append(p.OnlyLegacy, r)
			}
		}
	case "suricata":
		byID := map[string]vpatch.Signature{}
		for _, s := range mine {
			byID[s.ID] = s
		}
		for _, r := range rows {
			if s, ok := byID[r.ID]; ok {
				p.Pairs = append(p.Pairs, Pair{Key: r.ID, Legacy: r, Mine: s})
				used[s.ID] = true
			} else {
				p.OnlyLegacy = append(p.OnlyLegacy, r)
			}
		}
	case "nuclei":
		byTemplate := map[string][]vpatch.Signature{}
		for _, s := range mine {
			id := strings.TrimPrefix(s.ID, "NU-")
			if i := strings.LastIndexByte(id, '-'); i > 0 {
				id = id[:i]
			}
			byTemplate[id] = append(byTemplate[id], s)
		}
		for _, r := range rows {
			tid := importers.IDPart(originName(r.Origin))
			cands := byTemplate[tid]
			if len(cands) == 0 {
				p.OnlyLegacy = append(p.OnlyLegacy, r)
				continue
			}
			best := 0
			bestRank := 99
			for i, c := range cands {
				if rk := verdictRank(Diff(r.Signature, c).Verdict); rk < bestRank {
					best, bestRank = i, rk
				}
			}
			p.Pairs = append(p.Pairs, Pair{Key: r.ID, Legacy: r, Mine: cands[best]})
			used[cands[best].ID] = true
		}
	}
	for _, s := range mine {
		if !used[s.ID] {
			p.OnlyMine = append(p.OnlyMine, s.ID)
		}
	}
	return p
}

// originName is the rule's own name in an origin such as "crowdsec:vpatch-CVE-2002-1131@b29724e642ab".
func originName(origin string) string {
	_, rest, _ := strings.Cut(origin, ":")
	name, _, _ := strings.Cut(rest, "@")
	return name
}

// The verdicts of a comparison of two signatures for the same rule, best first.
const (
	// Identical: the same conditions after the two ways of writing a literal are made the same.
	Identical = "identical"
	// TransformsDiffer: the same conditions (targets and matchers) on both sides, with different transform lists.
	TransformsDiffer = "same-conditions-different-transforms"
	// Equivalent: every condition on each side has a counterpart on the other, but some are written differently (a different split of
	// one regular expression, a different transform list); the tests of this package check those behaviourally.
	Equivalent = "equivalent-targets-and-literals"
	// MineNarrower: the library's conditions are all present in the converted signature, which has more.
	MineNarrower = "mine-has-extra-conditions"
	// MineBroader: the converted signature's conditions are all present in the library's, which has more.
	MineBroader = "legacy-has-extra-conditions"
	// Different: each has a condition the other lacks.
	Different = "different"
)

func verdictRank(v string) int {
	switch v {
	case Identical:
		return 0
	case TransformsDiffer:
		return 1
	case Equivalent:
		return 1
	case MineNarrower:
		return 2
	case MineBroader:
		return 3
	}
	return 4
}

// Result is the comparison of one pair.
type Result struct {
	Verdict    string
	LegacyOnly []string // conditions only the library has
	MineOnly   []string // conditions only the converted signature has
}

// Diff compares the conditions of two signatures. It canonicalises each condition (see canon) and compares the two sets.
func Diff(legacy, mine vpatch.Signature) Result {
	lc := canonAll(legacy)
	mc := canonAll(mine)
	mc = dropRedundant(mc)
	lc = dropRedundant(lc)
	var res Result
	mset := map[string]int{}
	for _, c := range mc {
		mset[c.key]++
	}
	lset := map[string]int{}
	for _, c := range lc {
		lset[c.key]++
	}
	for _, c := range lc {
		if mset[c.key] > 0 {
			mset[c.key]--
		} else {
			res.LegacyOnly = append(res.LegacyOnly, c.show)
		}
	}
	for _, c := range mc {
		if lset[c.key] > 0 {
			lset[c.key]--
		} else {
			res.MineOnly = append(res.MineOnly, c.show)
		}
	}
	switch {
	case len(res.LegacyOnly) == 0 && len(res.MineOnly) == 0:
		res.Verdict = Identical
		if !sameFull(lc, mc) {
			res.Verdict = TransformsDiffer
		}
	case len(res.LegacyOnly) == 0:
		res.Verdict = MineNarrower
	case len(res.MineOnly) == 0:
		res.Verdict = MineBroader
	default:
		res.Verdict = Different
		// Different only on the targets-and-literal level may still be the same thing written differently: compare the targets alone.
		if sameTargetSets(lc, mc) {
			res.Verdict = Equivalent
		}
	}
	return res
}

// dropRedundant removes a plain "contains X" test that another condition on the same targets already requires, because that
// condition's pattern holds X as a literal. Emerging Threats rules carry such a content next to the pcre that repeats it (it is the
// fast pattern); the converter keeps it, the library did not, and it changes nothing about which requests match.
func dropRedundant(cs []canonCond) []canonCond {
	var out []canonCond
	for i, c := range cs {
		redundant := false
		if lit, ok := strings.CutPrefix(c.matcher, "contains:"); ok && lit != "" && !strings.HasPrefix(c.key, "!") {
			for j, o := range cs {
				if i != j && o.targets == c.targets && o.matcher != c.matcher && strings.Contains(o.matcher, lit) {
					redundant = true
					break
				}
			}
		}
		if !redundant {
			out = append(out, c)
		}
	}
	return out
}

// sameFull compares the conditions together with their transform lists.
func sameFull(a, b []canonCond) bool {
	ma := map[string]int{}
	for _, c := range a {
		ma[c.full]++
	}
	for _, c := range b {
		if ma[c.full] == 0 {
			return false
		}
		ma[c.full]--
	}
	return true
}

func sameTargetSets(a, b []canonCond) bool {
	ka, kb := map[string]int{}, map[string]int{}
	for _, c := range a {
		ka[c.targets]++
	}
	for _, c := range b {
		kb[c.targets]++
	}
	if len(ka) != len(kb) {
		return false
	}
	for k, n := range ka {
		if kb[k] != n {
			return false
		}
	}
	return true
}

type canonCond struct {
	key     string // targets + matcher
	full    string // key + the transform list
	matcher string // the matcher alone, such as "contains:abc"
	targets string
	show    string
}

func canonAll(s vpatch.Signature) []canonCond {
	var out []canonCond
	for _, c := range append([]vpatch.Condition{s.Condition}, s.Also...) {
		if parts := expandLookaheads(c); parts != nil {
			out = append(out, parts...)
			continue
		}
		out = append(out, canon(c))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].key < out[j].key })
	return out
}

var (
	anyRe     = regexp.MustCompile(`\[\\s\\S\]\*\??|\(\?s:\.\)\*\??|\(\?s:\.\*\)`)
	escapedRe = regexp.MustCompile(`\\([^A-Za-z0-9])`)
)

// canon writes a condition in a normal form: the sorted set of targets, and the matcher as "mode:text" where it is a plain string (a
// literal operator, or a regular expression that is nothing but a literal with anchors) and as the normalised pattern otherwise. Case
// is folded into the text when the condition ignores case.
func canon(c vpatch.Condition) canonCond {
	targets := append([]string(nil), c.Targets...)
	sort.Strings(targets)
	t := strings.Join(targets, ",")
	ci := strings.Contains(c.Flags, "i")
	for _, x := range c.Transforms {
		if x == "lowercase" {
			ci = true
		}
	}
	var m string
	switch c.Operator {
	case vpatch.OpContains:
		m = "contains:" + fold(c.Pattern, ci)
		if t == vpatch.TargetMethod {
			m = "exact:" + fold(c.Pattern, ci) // a method is one token, so containing it and being it are the same test
		}
	case vpatch.OpPrefix:
		m = "prefix:" + fold(c.Pattern, ci)
	case vpatch.OpSuffix:
		m = "suffix:" + fold(c.Pattern, ci)
	case vpatch.OpEquals:
		m = "exact:" + fold(c.Pattern, ci)
	case vpatch.OpPM:
		words := c.Patterns
		if len(words) == 0 {
			words = strings.Fields(c.Pattern)
		}
		ws := make([]string, len(words))
		for i, w := range words {
			ws[i] = strings.ToLower(w)
		}
		sort.Strings(ws)
		m = "pm:" + strings.Join(ws, " ")
	default:
		m = rxMatcher(c.Pattern, ci)
	}
	if t == vpatch.TargetMethod && strings.HasPrefix(m, "contains:") {
		m = "exact:" + strings.TrimPrefix(m, "contains:") // a method is one token, so containing it and being it are the same test
	}
	neg := ""
	if c.Negate {
		neg = "!"
	}
	// "lowercase" is already folded into the matcher; "urldecode1, urldecode" is one decode followed by a repeating one and is written
	// the same on both sides, so the lists are compared as they are otherwise.
	var tf []string
	for _, x := range c.Transforms {
		if x != "lowercase" {
			tf = append(tf, x)
		}
	}
	key := neg + t + "|" + m
	return canonCond{key: key, full: key + "|" + strings.Join(tf, ","), matcher: m, targets: t, show: neg + t + " " + m}
}

func fold(s string, ci bool) string {
	if ci {
		return strings.ToLower(s)
	}
	return s
}

// rxMatcher turns a regular expression that is only a literal with anchors into the literal's matcher, and normalises the rest.
func rxMatcher(p string, ci bool) string {
	s := p
	if strings.HasPrefix(s, "(?i)") {
		ci = true
		s = s[4:]
	}
	if strings.HasPrefix(s, "(?i:") && strings.HasSuffix(s, ")") && wrapsWhole(s[4:len(s)-1]) {
		ci = true
		s = s[4 : len(s)-1]
	}
	body := s // the pattern with its case flag taken out, before the anchors are
	start, end := false, false
	switch {
	case strings.HasPrefix(s, `\A`):
		start, s = true, s[2:]
	case strings.HasPrefix(s, "^"):
		start, s = true, s[1:]
	}
	switch {
	case strings.HasSuffix(s, `\z`):
		end, s = true, s[:len(s)-2]
	case strings.HasSuffix(s, "$") && !strings.HasSuffix(s, `\$`):
		end, s = true, s[:len(s)-1]
	}
	if l, ok := lengthMatcher(p); ok {
		return l
	}
	if lit, ok := unescapeLiteral(s); ok {
		mode := "contains"
		switch {
		case start && end:
			mode = "exact"
		case start:
			mode = "prefix"
		case end:
			mode = "suffix"
		}
		return mode + ":" + fold(lit, ci)
	}
	n := anyRe.ReplaceAllString(body, `.*`)
	n = strings.ReplaceAll(n, `\A`, "^")
	n = strings.ReplaceAll(n, `\z`, "$")
	n = escapedRe.ReplaceAllString(n, "$1")
	return "rx:" + fold(n, ci)
}

// wrapsWhole says whether s, taken as the inside of a group, has balanced parentheses that never close the group early: so that
// "(?i:" + s + ")" really is one group around all of s.
func wrapsWhole(s string) bool {
	depth := 0
	inClass := false
	for i := 0; i < len(s); i++ {
		switch c := s[i]; {
		case c == '\\':
			i++
		case inClass:
			if c == ']' {
				inClass = false
			}
		case c == '[':
			inClass = true
		case c == '(':
			depth++
		case c == ')':
			depth--
			if depth < 0 {
				return false
			}
		}
	}
	return depth == 0
}

var lenRe = regexp.MustCompile(`^(?:\(\?s\))?(?:\^|\\A)(?:\.|\[\\s\\S\])\{(\d+)(,(\d*))?\}(\$|\\z)?$`)

// lengthMatcher recognises "at least n characters" and friends written as a regular expression, which both sides use for bsize and
// urilen: the library writes \A[\s\S]{601} for "more than 600", the importer (?s)\A.{601,}\z. A count with no end anchor means "at
// least"; {n} with an end anchor means exactly n; {n,m} with an end anchor is a range.
func lengthMatcher(p string) (string, bool) {
	m := lenRe.FindStringSubmatch(p)
	if m == nil {
		return "", false
	}
	n, _ := strconv.Atoi(m[1])
	hasComma, maxDigits, anchoredEnd := m[2] != "", m[3], m[4] != ""
	hi := "inf"
	if anchoredEnd {
		switch {
		case !hasComma:
			hi = m[1]
		case maxDigits != "":
			hi = maxDigits
		}
	}
	return "len:" + strconv.Itoa(n) + "-" + hi, true
}

// lookRe matches one "(?=[\s\S]{0,N}?" opening of the library's way of writing "all of these appear".
var lookRe = regexp.MustCompile(`^\(\?=\[\\s\\S\]\{0,\d+\}\?`)

// expandLookaheads reads the library's pattern ^(?=[\s\S]{0,4096}?(?i:A))(?=[\s\S]{0,4096}?(?i:B)) as the separate conditions "contains A" and
// "contains B" that it is, or returns nil when the pattern is not of that shape. (Go's regular-expression engine has no lookahead, so
// such a pattern cannot be used as it is written.)
func expandLookaheads(c vpatch.Condition) []canonCond {
	lits := lookaheadLits(c)
	if lits == nil {
		return nil
	}
	var out []canonCond
	for _, l := range lits {
		cc := vpatch.Condition{Operator: vpatch.OpContains, Pattern: l.text, Targets: c.Targets, Transforms: c.Transforms, Negate: c.Negate}
		if l.ci {
			cc.Flags = "i"
		}
		out = append(out, canon(cc))
	}
	return out
}

// lit is one literal of a lookahead conjunction, and whether it is matched without regard to case.
type lit struct {
	text string
	ci   bool
}

// lookaheadLits returns the literals of a pattern of the library's lookahead shape, or nil when it is not of that shape.
func lookaheadLits(c vpatch.Condition) []lit {
	if c.Operator != vpatch.OpRegex {
		return nil
	}
	var s string
	switch {
	case strings.HasPrefix(c.Pattern, `^(?=`):
		s = c.Pattern[1:]
	case strings.HasPrefix(c.Pattern, `\A(?=`):
		s = c.Pattern[2:]
	default:
		return nil
	}
	var out []lit
	for len(s) > 0 {
		loc := lookRe.FindString(s)
		if loc == "" {
			return nil
		}
		s = s[len(loc):]
		ci := strings.Contains(c.Flags, "i")
		inGroup := false // the literal is inside a (?i: ... ) group, which closes before the lookahead does
		if strings.HasPrefix(s, "(?i:") {
			ci, inGroup = true, true
			s = s[4:]
		}
		// the literal runs to the first unescaped ")"
		i := 0
		for i < len(s) && s[i] != ')' {
			if s[i] == '\\' {
				i++
			}
			i++
		}
		if i >= len(s) {
			return nil
		}
		text, ok := unescapeLiteral(s[:i])
		if !ok {
			return nil
		}
		s = s[i+1:]
		if inGroup {
			if !strings.HasPrefix(s, ")") {
				return nil // the lookahead's own ")" must follow the closing of the (?i: group
			}
			s = s[1:]
		}
		out = append(out, lit{text: text, ci: ci})
	}
	return out
}

// unescapeLiteral returns the text of a pattern that has no regular-expression operators once its escapes are removed.
func unescapeLiteral(s string) (string, bool) {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '\\' {
			if i+1 >= len(s) {
				return "", false
			}
			n := s[i+1]
			if n >= '0' && n <= '9' || n >= 'A' && n <= 'Z' || n >= 'a' && n <= 'z' {
				return "", false // \d, \s, \b ...: a class, not a literal
			}
			b.WriteByte(n)
			i++
			continue
		}
		if strings.IndexByte(".*+?()[]{}|^$", c) >= 0 {
			return "", false
		}
		b.WriteByte(c)
	}
	return b.String(), true
}

// Comparison is the report of PairUp and Diff over a whole format.
type Comparison struct {
	Format     string                    `json:"format"`
	Mine       int                       `json:"converted_signatures"`
	LegacyRows int                       `json:"library_rows_of_this_format"`
	Paired     int                       `json:"paired"`
	OnlyMine   int                       `json:"only_converted"`
	OnlyLegacy int                       `json:"only_in_library"`
	Verdicts   map[string]int            `json:"verdicts"`
	ByStatus   map[string]map[string]int `json:"verdicts_by_library_status"`
	Examples   map[string][]Example      `json:"examples"`
	// OnlyLegacyExamples are library rows the importer did not produce, with the library's status.
	OnlyLegacyExamples []string `json:"only_in_library_examples,omitempty"`
	OnlyMineExamples   []string `json:"only_converted_examples,omitempty"`
}

// Example is one compared pair, for reading.
type Example struct {
	Key        string   `json:"key"`
	LegacyOnly []string `json:"library_only,omitempty"`
	MineOnly   []string `json:"converted_only,omitempty"`
}

// Compare pairs and compares everything in one go.
func Compare(format string, mine []vpatch.Signature, lib []Record) Comparison {
	p := PairUp(format, mine, lib)
	cmp := Comparison{
		Format: format, Mine: len(mine), Paired: len(p.Pairs), OnlyMine: len(p.OnlyMine), OnlyLegacy: len(p.OnlyLegacy),
		Verdicts: map[string]int{}, ByStatus: map[string]map[string]int{}, Examples: map[string][]Example{},
	}
	for _, r := range lib {
		if isFormat(r.Origin, format) {
			cmp.LegacyRows++
		}
	}
	for _, pr := range p.Pairs {
		d := Diff(pr.Legacy.Signature, pr.Mine)
		cmp.Verdicts[d.Verdict]++
		if cmp.ByStatus[pr.Legacy.Status] == nil {
			cmp.ByStatus[pr.Legacy.Status] = map[string]int{}
		}
		cmp.ByStatus[pr.Legacy.Status][d.Verdict]++
		if d.Verdict != Identical && len(cmp.Examples[d.Verdict]) < 8 {
			cmp.Examples[d.Verdict] = append(cmp.Examples[d.Verdict], Example{Key: pr.Key, LegacyOnly: trim(d.LegacyOnly), MineOnly: trim(d.MineOnly)})
		}
	}
	for i, r := range p.OnlyLegacy {
		if i >= 10 {
			break
		}
		cmp.OnlyLegacyExamples = append(cmp.OnlyLegacyExamples, r.ID+" ("+r.Status+")")
	}
	for i, id := range p.OnlyMine {
		if i >= 10 {
			break
		}
		cmp.OnlyMineExamples = append(cmp.OnlyMineExamples, id)
	}
	return cmp
}

func trim(ss []string) []string {
	out := make([]string, 0, len(ss))
	for _, s := range ss {
		if len(s) > 160 {
			s = s[:160] + "..."
		}
		out = append(out, s)
	}
	if len(out) > 6 {
		out = out[:6]
	}
	return out
}

// WriteSummary prints the counts of a comparison.
func (c Comparison) WriteSummary(w io.Writer) {
	fmt.Fprintf(w, "%s: %d converted, %d library rows, %d paired, %d only converted, %d only in the library\n",
		c.Format, c.Mine, c.LegacyRows, c.Paired, c.OnlyMine, c.OnlyLegacy)
	keys := importers.SortedKeys(c.Verdicts)
	for _, k := range keys {
		fmt.Fprintf(w, "  %-34s %d\n", k, c.Verdicts[k])
	}
}
