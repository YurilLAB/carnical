// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
)

// MaxConsoleExportBytes is the largest export FromConsoleExport reads (the PHP console's own limit).
const MaxConsoleExportBytes = 2 << 20

// FromConsoleExport reads the export of the PHP site console (firewall/engine/src/PolicyTransfer.php:
// {"site_firewall_policy":1,"exported":...,"site":...,"engine":...,"rev":...,"policy":{...}}), or a policy.json copied as it is
// (schema 1), and returns the policy that says the same thing here, with a list of what could not be carried over and why.
//
// Nothing is approximated without being named. A setting the Core Rule Set cannot honour exactly (a score for one signature,
// a rule that adds to the score without blocking alone, a rule with several conditions, a pattern that PCRE accepts and RE2
// does not, a rule group that has no counterpart here) is left out, or carried in the nearest form that does not loosen
// anything, and each such case has a line in the list. An entry that cannot be carried is never carried wider than it was:
// an exclusion that loses a part is dropped whole, not widened to the whole request.
//
// A setting the export leaves unset (null) means "whatever config.php says" in the PHP console, which this package cannot see;
// the PHP firewall's own built-in value is used, and the mode is named in the list because it differs from Default (monitor
// there, block here). The result has passed Validate. It returns an error only for a document that is not an export at all.
func FromConsoleExport(data []byte) (Policy, []string, error) {
	if len(data) > MaxConsoleExportBytes {
		return Policy{}, nil, invalid("$", "the export is larger than %d MiB", MaxConsoleExportBytes>>20)
	}
	if len(bytes.TrimSpace(data)) == 0 {
		return Policy{}, nil, invalid("$", "there is nothing to import")
	}
	if err := scanJSON(data, scanLimits{maxDepth: 32, maxTokens: 2_000_000, maxString: 1 << 16, nullOK: func([]string) bool { return true }}); err != nil {
		return Policy{}, nil, invalid("$", "%s", err.Error())
	}
	doc, err := decodeObject(data)
	if err != nil {
		return Policy{}, nil, invalid("$", "an export is a JSON object")
	}
	c := &converter{p: Default(), nextRule: 1, usedIDs: map[int]bool{}}
	pol := doc
	if v, ok := doc["site_firewall_policy"]; ok {
		if n, isNum := v.(json.Number); !isNum || n.String() != "1" {
			return Policy{}, nil, invalid("site_firewall_policy", "an export of another format, which this program does not read")
		}
		for k := range doc {
			switch k {
			case "site_firewall_policy", "exported", "site", "engine", "rev", "policy":
			default:
				c.skip("%s: a part of the export this program does not know, left out", safeName(k))
			}
		}
		inner, ok := doc["policy"].(map[string]any)
		if !ok {
			return Policy{}, nil, invalid("policy", "the export holds no policy")
		}
		pol = inner
	} else if n, ok := doc["schema"].(json.Number); !ok || n.String() != "1" {
		return Policy{}, nil, invalid("$", "this is not an exported site policy")
	}
	c.convert(pol)
	p := c.p.Normalize()
	if err := p.Validate(); err != nil {
		return Policy{}, nil, fmt.Errorf("the converted policy is not valid (a fault in the converter, not in the export): %w", err)
	}
	return p, c.skipped, nil
}

func decodeObject(data []byte) (map[string]any, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, err
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, errors.New("more than one value")
	}
	m, ok := v.(map[string]any)
	if !ok {
		return nil, errors.New("not an object")
	}
	return m, nil
}

type converter struct {
	p        Policy
	skipped  []string
	sens     string // the PHP sensitivity name
	base     int    // the PHP threshold (5 if unset)
	nextRule int
	usedIDs  map[int]bool
}

func (c *converter) skip(format string, args ...any) {
	if len(c.skipped) < 500 {
		c.skipped = append(c.skipped, fmt.Sprintf(format, args...))
	}
}

// asMap reads a value that PHP wrote as an object: an empty one is written [] by PHP's json_encode.
func asMap(v any) (map[string]any, bool) {
	switch x := v.(type) {
	case map[string]any:
		return x, true
	case []any:
		if len(x) == 0 {
			return map[string]any{}, true
		}
	case nil:
		return map[string]any{}, true
	}
	return nil, false
}

func asList(v any) ([]any, bool) {
	switch x := v.(type) {
	case []any:
		return x, true
	case nil:
		return nil, true
	case map[string]any:
		if len(x) == 0 {
			return nil, true
		}
	}
	return nil, false
}

func asInt(v any) (int, bool) {
	n, ok := v.(json.Number)
	if !ok {
		return 0, false
	}
	i, err := strconv.ParseInt(n.String(), 10, 32)
	return int(i), err == nil
}

// phpStop is the score at which the PHP firewall stops a request: its threshold, scaled by the sensitivity (Engine::sensitiveThreshold).
func phpStop(base int, sensitivity string) int {
	num, den := 1, 1
	switch sensitivity {
	case "relaxed":
		num, den = 3, 2
	case "strict":
		num, den = 3, 5
	}
	if base < 1 {
		base = 1
	}
	if v := (base*num + den - 1) / den; v > 1 {
		return v
	}
	return 1
}

// phpKeys are the settings of the PHP policy (Policy::blank()), and the bookkeeping it carries.
var phpBookkeeping = map[string]bool{"schema": true, "rev": true, "updated": true, "by": true, "compiled": true}

func (c *converter) convert(pol map[string]any) {
	c.sens = "standard"
	c.base = 5
	c.mode(pol)
	c.sensitivity(pol)
	c.threshold(pol)
	c.simple(pol)
	c.ruleGroups(pol)
	c.signatures(pol)
	c.exclusions(pol)
	c.lists(pol)
	c.groupsOfSettings(pol)
	c.rules(pol)
	known := map[string]bool{"mode": true, "threshold": true, "sensitivity": true, "rule_groups": true, "block_oversize": true, "contact": true, "timezone": true,
		"disabled": true, "overrides": true, "exclusions": true, "allow_ips": true, "block_ips": true, "allow_paths": true, "reputation": true, "ips": true,
		"outbound": true, "stats": true, "log": true, "rules": true}
	var unknown []string
	for k := range pol {
		if !known[k] && !phpBookkeeping[k] {
			unknown = append(unknown, safeName(k))
		}
	}
	sort.Strings(unknown)
	for _, k := range unknown {
		c.skip("%s: not a setting this program knows, left out", k)
	}
}

func (c *converter) mode(pol map[string]any) {
	switch v := pol["mode"].(type) {
	case string:
		switch v {
		case "block":
			c.p.Mode = ModeBlock
		case "monitor":
			c.p.Mode = ModeMonitor
		case "off":
			c.p.Mode = ModeOff
		default:
			c.p.Mode = ModeMonitor
			c.skip("mode: %q is not a mode; monitor was used", safeName(v))
		}
	default:
		c.p.Mode = ModeMonitor
		c.skip("mode: the export does not set one (the PHP console takes it from config.php, built-in default monitor), so monitor was used; a new site here starts in block")
	}
}

func (c *converter) sensitivity(pol map[string]any) {
	v, _ := pol["sensitivity"].(string)
	switch v {
	case "", "standard":
		c.p.Sensitivity = SensitivityNormal
	case "relaxed":
		c.p.Sensitivity, c.sens = SensitivityRelaxed, "relaxed"
		c.skip("sensitivity: relaxed also ignores low and medium confidence signatures in the PHP firewall; here it means paranoia level 1 and a blocking score of 8, which is similar and not the same")
	case "strict":
		c.p.Sensitivity, c.sens = SensitivityStrict, "strict"
		c.skip("sensitivity: strict stops at three fifths of the threshold in the PHP firewall; here it means paranoia level 2 and a blocking score of 5, which is similar and not the same")
	default:
		c.p.Sensitivity = SensitivityNormal
		c.skip("sensitivity: %q is not one of relaxed, standard or strict; normal was used", safeName(v))
	}
}

func (c *converter) threshold(pol map[string]any) {
	v, set := pol["threshold"]
	if !set || v == nil {
		return
	}
	n, ok := asInt(v)
	if !ok || n < 1 || n > 1000 {
		c.skip("threshold: not a whole number from 1 to 1000, so the sensitivity's own was used")
		return
	}
	c.base = n
	stop := phpStop(n, c.sens)
	c.p.Threshold = &stop
	if stop != n {
		c.skip("threshold: %d, scaled by the %s sensitivity as the PHP firewall scales it, is %d here", n, c.sens, stop)
	}
}

// simple carries the settings that are a single value.
func (c *converter) simple(pol map[string]any) {
	if v, ok := pol["block_oversize"].(bool); ok && !v {
		c.skip("block_oversize: it is off in the export; here a request too big to inspect is always refused, which is stricter")
	}
	if v, ok := pol["contact"].(string); ok && v != "" {
		c.skip("contact: the line shown on the refusal page is not carried; the refusal page is not customisable yet")
	}
	if v, ok := pol["timezone"].(string); ok && v != "" {
		c.skip("timezone: it belongs to the site's records, not to the policy the edge runs, and was left out")
	}
}

func (c *converter) ruleGroups(pol map[string]any) {
	m, ok := asMap(pol["rule_groups"])
	if !ok {
		c.skip("rule_groups: not an object, left out")
		return
	}
	names := make([]string, 0, len(m))
	for k := range m {
		names = append(names, k)
	}
	sort.Strings(names)
	noCounterpart := map[string]string{
		"upload":    "its checks are in the uploads section here (allow_script_names and allow_script_content), not a rule group",
		"wordpress": "its checks are in the wordpress section here, not a rule group",
		"cve":       "known-vulnerability signatures are the virtual patches here (vpatch.tiers), not a rule group",
		"ssti":      "the Core Rule Set has no template-injection group of its own (934 carries a few rules, in the ssrf group)",
		"xxe":       "the Core Rule Set has no rule for XML external entities",
		"probe":     "the Core Rule Set has no group for probes for files",
		"other":     "there is no group of the rules the PHP firewall left uncategorised",
	}
	for _, name := range names {
		state, _ := m[name].(string)
		if !validStates[GroupState(state)] {
			c.skip("rule_groups.%s: %q is not on, log or off, left out", safeName(name), safeName(state))
			continue
		}
		if _, ok := groupByName[name]; ok {
			if GroupState(state) != GroupOn {
				c.p.RuleGroups[name] = GroupState(state)
			}
			continue
		}
		if why, known := noCounterpart[name]; known {
			if state != "on" {
				c.skip("rule_groups.%s: set to %s in the export; it was not carried: %s", name, state, why)
			}
			continue
		}
		c.skip("rule_groups.%s: not a rule group this program knows, left out", safeName(name))
	}
}

func (c *converter) signatures(pol map[string]any) {
	if list, ok := asList(pol["disabled"]); ok && len(list) > 0 {
		var ids []string
		for _, v := range list {
			if s, isStr := v.(string); isStr {
				ids = append(ids, safeName(s))
			}
		}
		c.skip("disabled: %d signature(s) switched off in the export (%s) were not carried: single rules cannot be switched off here, so they stay on; an exclusion or a rule group set to off is the equivalent",
			len(list), joinIDs(ids))
	}
	if m, ok := asMap(pol["overrides"]); ok && len(m) > 0 {
		var ids []string
		for k := range m {
			ids = append(ids, safeName(k))
		}
		sort.Strings(ids)
		c.skip("overrides: the score or log-only tuning of %d signature(s) (%s) was not carried: the rule set scores a rule by its severity (5, 4, 3 or 2), so a score between cannot be set exactly; a rule group set to log, or an exclusion, is the nearest",
			len(m), joinIDs(ids))
	}
}

func joinIDs(ids []string) string {
	sort.Strings(ids)
	if len(ids) > 8 {
		return strings.Join(ids[:8], ", ") + fmt.Sprintf(" and %d more", len(ids)-8)
	}
	return strings.Join(ids, ", ")
}

func (c *converter) exclusions(pol map[string]any) {
	list, ok := asList(pol["exclusions"])
	if !ok {
		c.skip("exclusions: not a list, left out")
		return
	}
	for i, v := range list {
		at := fmt.Sprintf("exclusions[%d]", i+1)
		m, ok := v.(map[string]any)
		if !ok {
			c.skip("%s: not an object, left out", at)
			continue
		}
		path, _ := m["path"].(string)
		if !validPath(path) {
			c.skip("%s: the path %q cannot be used here (a path starts with / and uses only letters, digits and / _ . ~ @ : = + , -), so the exclusion was left out", at, safeName(path))
			continue
		}
		var cats []string
		var dropped []string
		cl, _ := asList(m["categories"])
		for _, cv := range cl {
			name, _ := cv.(string)
			if _, ok := groupByName[name]; ok {
				cats = append(cats, name)
			} else {
				dropped = append(dropped, safeName(name))
			}
		}
		if len(dropped) > 0 {
			c.skip("%s: the categories %s have no rule group here and were left out of the exclusion", at, strings.Join(dropped, ", "))
		}
		if len(cats) == 0 {
			c.skip("%s: none of its categories has a rule group here, so the exclusion was left out", at)
			continue
		}
		var targets []string
		tl, hasTargets := asList(m["targets"])
		unsupported := false
		for _, tv := range tl {
			name, _ := tv.(string)
			name = strings.ToLower(name)
			if _, ok := targetVariable(name, false); ok {
				targets = append(targets, name)
			} else {
				unsupported = true
				c.skip("%s: the target %q is not one this program supports and was left out of the exclusion", at, safeName(name))
			}
		}
		if hasTargets && len(tl) > 0 && len(targets) == 0 && unsupported {
			// Dropping every target would widen the exclusion to the whole request.
			c.skip("%s: none of its targets is supported, and leaving them all out would widen it to the whole request, so the exclusion was left out", at)
			continue
		}
		if len(targets) > MaxTargets {
			c.skip("%s: more than %d targets; the exclusion was left out (it would have to be split)", at, MaxTargets)
			continue
		}
		if len(c.p.Exclusions) >= MaxExclusions {
			c.skip("%s: more than %d exclusions; the rest were left out", at, MaxExclusions)
			break
		}
		c.p.Exclusions = append(c.p.Exclusions, Exclusion{Path: path, Categories: cats, Targets: targets})
	}
}

func (c *converter) lists(pol map[string]any) {
	for _, l := range []struct {
		key    string
		dst    *[]string
		max    int
		v4, v6 int
		wide   string
	}{
		{"allow_ips", &c.p.AllowIPs, MaxAllowIPs, 16, 32, "allow list"},
		{"block_ips", &c.p.BlockIPs, MaxBlockIPs, 8, 16, "block list"},
	} {
		list, ok := asList(pol[l.key])
		if !ok {
			c.skip("%s: not a list, left out", l.key)
			continue
		}
		for _, v := range list {
			s, _ := v.(string)
			p, ok := parsePrefix(s)
			switch {
			case !ok:
				c.skip("%s: %q is not an address or range, left out", l.key, safeName(s))
			case p.Bits() < map[bool]int{true: l.v4, false: l.v6}[p.Addr().Is4()]:
				c.skip("%s: %s is wider than the %s here takes (/%d for IPv4, /%d for IPv6), left out", l.key, safeName(s), l.wide, l.v4, l.v6)
			case len(*l.dst) >= l.max:
				c.skip("%s: more than %d entries; %s and the rest were left out", l.key, l.max, safeName(s))
			default:
				*l.dst = append(*l.dst, p.String())
			}
		}
	}
	list, _ := asList(pol["allow_paths"])
	for _, v := range list {
		s, _ := v.(string)
		switch {
		case !validPath(s):
			c.skip("allow_paths: %q cannot be used here (a path starts with / and uses only letters, digits and / _ . ~ @ : = + , -), left out", safeName(s))
		case len(c.p.AllowPaths) >= MaxAllowPaths:
			c.skip("allow_paths: more than %d paths; %s and the rest were left out", MaxAllowPaths, s)
		default:
			c.p.AllowPaths = append(c.p.AllowPaths, s)
		}
	}
}

// groupsOfSettings handles the settings the PHP console keeps in groups: reputation lists, bans and IDS/IPS, outbound, stats, log.
func (c *converter) groupsOfSettings(pol map[string]any) {
	if m, ok := asMap(pol["reputation"]); ok && len(m) > 0 {
		c.skip("reputation: %d reputation list setting(s) were not carried; the lists are not part of this edge yet", len(m))
	}
	if m, ok := asMap(pol["ips"]); ok {
		if keys := setKeys(m); len(keys) > 0 {
			c.skip("ips: %s were not carried; automatic bans, flood, scan, enumeration and spraying detection are not built into this edge yet", strings.Join(keys, ", "))
		}
	}
	if m, ok := asMap(pol["outbound"]); ok {
		if v, ok := m["inspect"].(bool); ok && v {
			c.p.Responses.Inspect = true
		}
		if _, ok := m["max_kb"]; ok && m["max_kb"] != nil {
			c.skip("outbound.max_kb: how much of a response is inspected is not configurable here (up to 512 KiB of text, HTML and XML), left out")
		}
	}
	for _, g := range []string{"stats", "log"} {
		if m, ok := asMap(pol[g]); ok {
			if keys := setKeys(m); len(keys) > 0 {
				c.skip("%s: %s were not carried; records and their retention belong to the site, not to the policy the edge runs", g, strings.Join(keys, ", "))
			}
		}
	}
}

func setKeys(m map[string]any) []string {
	var out []string
	for k, v := range m {
		if v != nil {
			out = append(out, safeName(k))
		}
	}
	sort.Strings(out)
	return out
}

// rules converts the custom rules. The PHP rule is a signature (id SITE-0001, targets, transforms, operator, pattern, flags, score,
// action, also, min_length); this model's rule has one field, one operator, a value and block or log.
func (c *converter) rules(pol map[string]any) {
	list, ok := asList(pol["rules"])
	if !ok {
		c.skip("rules: not a list, left out")
		return
	}
	// Numbers first, so that a rule split in two takes numbers that no other rule has.
	for _, v := range list {
		if m, ok := v.(map[string]any); ok {
			if n := ruleNumber(m); n > 0 {
				c.usedIDs[n] = true
			}
		}
	}
	for i, v := range list {
		name := fmt.Sprintf("rules[%d]", i+1)
		m, ok := v.(map[string]any)
		if !ok {
			c.skip("%s: not an object, left out", name)
			continue
		}
		if id, ok := m["id"].(string); ok {
			name = safeName(id)
		}
		c.rule(name, m)
	}
}

// ruleNumber is the number of a SITE-0001 style id, or 0.
func ruleNumber(m map[string]any) int {
	id, _ := m["id"].(string)
	if !strings.HasPrefix(id, "SITE-") {
		return 0
	}
	n, err := strconv.Atoi(strings.TrimPrefix(id, "SITE-"))
	if err != nil || n < 1 || n > 9999 {
		return 0
	}
	return n
}

func (c *converter) freeNumber() int {
	for c.nextRule <= 9999 && c.usedIDs[c.nextRule] {
		c.nextRule++
	}
	if c.nextRule > 9999 {
		return 0
	}
	n := c.nextRule
	c.usedIDs[n] = true
	c.nextRule++
	return n
}

func (c *converter) rule(name string, m map[string]any) {
	if len(c.p.CustomRules) >= MaxCustomRules {
		c.skip("%s: more than %d custom rules; this and the rest were left out", name, MaxCustomRules)
		return
	}
	if also, _ := asList(m["also"]); len(also) > 0 {
		c.skip("%s: it has %d further condition(s) that must all hold; a rule here has one condition, so it was left out", name, len(also))
		return
	}
	if n, ok := asInt(m["min_length"]); ok && n > 0 {
		c.skip("%s: it only matches values of at least %d characters; a rule here cannot say that, so it was left out", name, n)
		return
	}
	for _, t := range stringList(m["transforms"]) {
		if t != "urldecode" && t != "lowercase" && t != "none" {
			c.skip("%s: it uses the transformation %q, which a rule here cannot, so it was left out", name, safeName(t))
			return
		}
	}
	op, _ := m["operator"].(string)
	var operator Operator
	switch op {
	case "contains":
		operator = OpContains
	case "rx":
		operator = OpRX
	case "pm":
		operator = OpPM
	default:
		c.skip("%s: the operator %q is not one a rule here has (contains, equals, beginsWith, endsWith, pm, rx), so it was left out", name, safeName(op))
		return
	}
	insensitive := false
	if f, _ := m["flags"].(string); strings.Contains(f, "i") {
		insensitive = true
	}
	for _, t := range stringList(m["transforms"]) {
		if t == "lowercase" {
			insensitive = true
		}
	}
	rule := CustomRule{Operator: operator, CaseSensitive: !insensitive}
	switch operator {
	case OpPM:
		words := stringList(m["pattern"])
		if len(words) == 0 {
			if s, ok := m["pattern"].(string); ok {
				words = strings.Fields(s)
			}
		}
		rule.Values = words
	default:
		s, ok := m["pattern"].(string)
		if !ok {
			c.skip("%s: its pattern is not text, so it was left out", name)
			return
		}
		rule.Value = s
	}
	if _, err := operatorRegex(rule.Operator, rule.Value, rule.Values, rule.CaseSensitive); err != nil {
		c.skip("%s: its pattern cannot be used here (it %s), so it was left out", name, err.Error())
		return
	}
	// Action. A block rule with a score adds to the request's total in the PHP firewall; it blocks alone only if its score reaches
	// the point at which the firewall stops a request.
	act, _ := m["action"].(string)
	score, hasScore := asInt(m["score"])
	rule.Action = ActionLog
	switch {
	case act == "log":
	case act == "block" && (!hasScore || score >= phpStop(c.base, c.sens)):
		rule.Action = ActionBlock
	case act == "block":
		c.skip("%s: its score of %d is below the %d at which the PHP firewall stops a request, so there it only adds to other matches; a rule here blocks outright or only logs, so it was carried as log only", name, score, phpStop(c.base, c.sens))
	default:
		c.skip("%s: its action %q is not block or log, so it was left out", name, safeName(act))
		return
	}
	if d, ok := m["description"].(string); ok {
		rule.Note = cleanNote(d)
	}
	targets := stringList(m["targets"])
	if len(targets) == 0 {
		targets = []string{"path"}
	}
	var fields []string
	for _, t := range targets {
		t = strings.ToLower(t)
		if _, ok := targetVariable(t, true); ok {
			fields = append(fields, t)
		} else {
			c.skip("%s: it looks at %q, which a rule here cannot, so it does not look there here", name, safeName(t))
		}
	}
	if len(fields) == 0 {
		c.skip("%s: none of the parts of the request it looks at can be used here, so it was left out", name)
		return
	}
	first := true
	var made []string
	for _, f := range fields {
		r := rule
		r.Field = f
		n := ruleNumber(m)
		if !first || n == 0 {
			n = c.freeNumber()
			if n == 0 {
				c.skip("%s: there are no free rule numbers left, so part of it was left out", name)
				return
			}
		}
		first = false
		made = append(made, strconv.Itoa(n))
		r.ID = n
		if len(c.p.CustomRules) >= MaxCustomRules {
			c.skip("%s: more than %d custom rules; the rest were left out", name, MaxCustomRules)
			return
		}
		c.p.CustomRules = append(c.p.CustomRules, r)
	}
	if len(made) > 1 {
		c.skip("%s: it looks at several parts of the request, which here takes one rule for each part, so it became rules %s", name, strings.Join(made, ", "))
	}
}

func stringList(v any) []string {
	var out []string
	l, _ := asList(v)
	for _, e := range l {
		if s, ok := e.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

// cleanNote makes text from the export fit for a note: printable, one line, at most MaxItemNoteBytes.
func cleanNote(s string) string {
	var b strings.Builder
	for _, r := range s {
		if b.Len() >= MaxItemNoteBytes-4 {
			break
		}
		if r >= 0x20 && r != 0x7f && textProblem(string(r), 8, false) == "" {
			b.WriteRune(r)
		} else {
			b.WriteByte(' ')
		}
	}
	return strings.TrimSpace(b.String())
}
