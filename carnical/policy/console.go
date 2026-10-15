// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// MaxConsoleExportBytes is the largest export FromConsoleExport reads (the PHP console's own limit).
const MaxConsoleExportBytes = 2 << 20

// maxExportRules is how many of an export's rules are read, four times as many as a policy can hold.
const maxExportRules = 4 * MaxCustomRules

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
	c := &converter{p: Default(), nextRule: 1, usedIDs: map[int]bool{}, carried: map[int]bool{}}
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
	if c.unsaid > 0 {
		c.skipped = append(c.skipped, fmt.Sprintf("%d more line(s) were not listed: the list holds %d, and what they name (a setting left out, or a rule carried as log only or on fewer parts) is not shown", c.unsaid, maxSkipped-1))
	}
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
	carried  map[int]bool // the numbers of the rules carried so far
	unsaid   int          // the lines past maxSkipped, said as one last line
}

// maxSkipped is how many lines the list holds, the last of them saying how many more there were.
const maxSkipped = 500

func (c *converter) skip(format string, args ...any) {
	if len(c.skipped) < maxSkipped-1 {
		c.skipped = append(c.skipped, fmt.Sprintf(format, args...))
		return
	}
	c.unsaid++
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
	if stop > 1000 {
		// A lower threshold blocks sooner, so this loosens nothing.
		c.skip("threshold: %d, scaled by the %s sensitivity as the PHP firewall scales it, is %d, more than the 1000 a threshold here can be, so 1000 was used", n, c.sens, stop)
		stop = 1000
	} else if stop != n {
		c.skip("threshold: %d, scaled by the %s sensitivity as the PHP firewall scales it, is %d here", n, c.sens, stop)
	}
	c.p.Threshold = &stop
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
		nonText := false
		cl, _ := asList(m["categories"])
		for _, cv := range cl {
			name, isText := cv.(string)
			if !isText {
				nonText = true
			} else if _, ok := groupByName[name]; ok {
				cats = append(cats, name)
			} else {
				dropped = append(dropped, safeName(name))
			}
		}
		if nonText {
			c.skip("%s: one or more of its categories is not named in text and was left out of the exclusion", at)
		}
		if len(dropped) > 0 {
			c.skip("%s: the categories %s have no rule group here and were left out of the exclusion", at, strings.Join(dropped, ", "))
		}
		if len(cats) == 0 {
			c.skip("%s: none of its categories has a rule group here, so the exclusion was left out", at)
			continue
		}
		var targets []string
		tl, ok := asList(m["targets"])
		if !ok {
			c.skip("%s: its targets are not a list, and reading them as none would widen it to the whole request, so the exclusion was left out", at)
			continue
		}
		unsupported, nonText := false, false
		named := map[string]bool{}
		for _, tv := range tl {
			name, isText := tv.(string)
			name = strings.ToLower(name)
			if !isText {
				// Still unsupported, so that a list with no target in text is left out and not widened.
				unsupported, nonText = true, true
			} else if _, ok := targetVariable(name, false); ok {
				targets = append(targets, name)
			} else {
				unsupported = true
				if !named[name] {
					named[name] = true
					c.skip("%s: the target %q is not one this program supports and was left out of the exclusion", at, safeName(name))
				}
			}
		}
		if nonText {
			c.skip("%s: one or more of its targets is not named in text and was left out of the exclusion", at)
		}
		if len(tl) > 0 && len(targets) == 0 && unsupported {
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
		if i == maxExportRules {
			// Checking a pattern is work, and a rule left out never counts towards the custom rules' limit.
			c.skip("rules: more than %d rules in the export; the rest were left out", maxExportRules)
			break
		}
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
	// Read as none, a value that is not a list would drop a condition or a transformation, or move the rule to the path.
	for _, key := range []string{"also", "transforms", "targets"} {
		if _, ok := asList(m[key]); !ok {
			c.skip("%s: its %q field is not a list, so it was left out", name, key)
			return
		}
	}
	if also, _ := asList(m["also"]); len(also) > 0 {
		c.skip("%s: it has %d further condition(s) that must all hold; a rule here has one condition, so it was left out", name, len(also))
		return
	}
	if n, ok := asInt(m["min_length"]); ok && n > 0 {
		c.skip("%s: it only matches values of at least %d characters; a rule here cannot say that, so it was left out", name, n)
		return
	}
	// A transformation that is not text would be dropped, and the rule would then match the value it was meant to decode first.
	if tl, _ := asList(m["transforms"]); len(stringList(tl)) != len(tl) {
		c.skip("%s: one of its transformations is not named in text, so it was left out", name)
		return
	}
	decodes := false
	for _, t := range stringList(m["transforms"]) {
		if t != "urldecode" && t != "lowercase" && t != "none" {
			c.skip("%s: it uses the transformation %q, which a rule here cannot, so it was left out", name, safeName(t))
			return
		}
		decodes = decodes || t == "urldecode"
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
	flags, _ := m["flags"].(string)
	for _, f := range flags {
		switch {
		case f == 'i':
			insensitive = true
		case operator != OpRX:
			// The other operators compare text, where a pattern flag means nothing.
		case strings.ContainsRune("smuUD", f):
			// None of these can make the pattern match less here: the engine always matches with s and m and reads UTF-8, U
			// changes how much a match takes but not whether there is one, and D only stops $ matching before a final newline.
		default:
			// x above all, which lets a pattern hold white space and # comments that are not matched: RE2 has no such mode,
			// and the pattern read without it would look for them literally and match nothing.
			c.skip("%s: it uses the pattern flag %q, which a rule here cannot honour, so it was left out", name, safeName(string(f)))
			return
		}
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
		// Dropping a word that is not text would carry the rule matching less than it says.
		if pl, _ := asList(m["pattern"]); len(words) != len(pl) {
			c.skip("%s: one of its words is not text, so it was left out", name)
			return
		}
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
		if operator == OpRX {
			var differs string
			if s, differs = re2Pattern(s); differs != "" {
				c.skip("%s: its pattern uses %s, which PCRE and RE2 read differently and which cannot be written here exactly, so it was left out", name, differs)
				return
			}
		}
		rule.Value = s
	}
	// Validate's own check of the value (with the words as Normalize keeps them), so that a value it refuses, such as a long
	// contains pattern, leaves this rule out and not the whole export.
	check, vc := rule, checker{}
	check.Values = sortedUnique(rule.Values)
	if validateRuleValue(&vc, name, check) == "" {
		c.skip("%s: its pattern cannot be used here (it %s), so it was left out", name, vc.problems[0].Message)
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
	targets, _ := asList(m["targets"])
	if len(targets) == 0 {
		targets = []any{"path"}
	}
	var fields []string
	nonText := false
	named := map[string]bool{}
	for _, tv := range targets {
		t, isText := tv.(string)
		t = strings.ToLower(t)
		if !isText {
			nonText = true
		} else if _, ok := targetVariable(t, true); ok {
			fields = append(fields, t)
		} else if !named[t] {
			named[t] = true
			c.skip("%s: it looks at %q, which a rule here cannot, so it does not look there here", name, safeName(t))
		}
	}
	if nonText {
		c.skip("%s: one or more of the parts it looks at is not named in text, so it does not look there here", name)
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
		// SITE-0001 and SITE-1 are the same number, and an export may hold a number twice: the second takes a free one.
		renumbered := first && n != 0 && c.carried[n]
		if !first || n == 0 || renumbered {
			n = c.freeNumber()
			if n == 0 {
				c.skip("%s: there are no free rule numbers left, so part of it was left out", name)
				return
			}
		}
		if renumbered {
			c.skip("%s: its number is that of an earlier rule, so it became rule %d", name, n)
		}
		first = false
		made = append(made, strconv.Itoa(n))
		r.ID = n
		if len(c.p.CustomRules) >= MaxCustomRules {
			c.skip("%s: more than %d custom rules; the rest were left out", name, MaxCustomRules)
			return
		}
		c.p.CustomRules = append(c.p.CustomRules, r)
		c.carried[n] = true
		if decodes && !urlDecoded(f) {
			c.skip("%s: it URL-decodes %s before matching, which a rule here does only for the path, uri, query and arguments, so a URL-encoded value in %s may not be matched (the rule was carried as it is)", name, f, f)
		}
	}
	if len(made) > 1 {
		c.skip("%s: it looks at several parts of the request, which here takes one rule for each part, so it became rules %s", name, strings.Join(made, ", "))
	}
}

// urlDecoded says whether a rule here matches a field after URL-decoding, as a PHP rule with the urldecode transformation does:
// uri and query are decoded by the rule (t:urlDecodeUni), the path and the arguments by the engine. Headers, cookies and the
// body are matched as they are sent (a form's values apart, which are arguments too).
func urlDecoded(field string) bool {
	switch field {
	case "uri", "query", "path", "args", "argnames":
		return true
	}
	return strings.HasPrefix(field, "arg:")
}

// re2Pattern rewrites what RE2 accepts in a PCRE pattern but would match in fewer places, or says what it cannot rewrite. PCRE's
// \s matches the vertical tab (0x0b) and RE2's does not, so \s is written [\s\x0b] (\x0b\s inside a class, the tab first, so that
// a '-' after it still follows a class escape and stays the literal it is in [\s-_], not the end of a range from the tab), as the
// Core Rule Set writes it, and SQL that MySQL reads with a vertical tab between its words still matches. Two things cannot be written so: \v,
// which is any vertical white space to PCRE and only the vertical tab to RE2, and \S in a negated class, which leaves the vertical
// tab in the class to PCRE and takes it out to RE2. \S anywhere else also matches the vertical tab to RE2, which only makes the
// rule match more, and is left. Nor can \10 and up when at least that many groups were opened before it, which PCRE reads as a
// back-reference and RE2 as an octal character. The rest is copied as it is; what RE2 does not accept at all is refused when
// the pattern is parsed. It reads the pattern as PCRE does: an escape is two characters, \Q...\E is literal text, and a class
// runs to the first ] that is not its first character, an escape or the end of a POSIX class such as [:alpha:].
func re2Pattern(p string) (string, string) {
	var b strings.Builder
	inClass, negated, first := false, false, false
	groups := 0 // the groups opened so far, as PCRE numbers them
	for i := 0; i < len(p); i++ {
		c := p[i]
		if c == '\\' && i+1 < len(p) {
			next := p[i+1]
			switch {
			case next == 'Q' && !inClass:
				end := strings.Index(p[i+2:], `\E`)
				if end < 0 {
					b.WriteString(p[i:])
					return b.String(), ""
				}
				b.WriteString(p[i : i+2+end+2])
				i += 2 + end + 1
				continue
			case next == 's' && inClass:
				b.WriteString(`\x0b\s`)
			case next == 's':
				b.WriteString(`[\s\x0b]`)
			case next == 'v':
				return "", `\v`
			case next == 'S' && inClass && negated:
				return "", `\S in a negated class`
			case next >= '1' && next <= '9' && !inClass && backReference(p[i+1:], groups) > 0:
				return "", fmt.Sprintf(`a back-reference (\%d)`, backReference(p[i+1:], groups))
			default:
				b.WriteByte(c)
				b.WriteByte(next)
			}
			i++
			first = false
			continue
		}
		switch {
		case c == '[' && !inClass:
			inClass, negated, first = true, false, true
			b.WriteByte(c)
			if i+1 < len(p) && p[i+1] == '^' {
				negated = true
				b.WriteByte('^')
				i++
			}
			continue
		case c == '[' && inClass && i+1 < len(p) && p[i+1] == ':':
			if end := strings.Index(p[i+2:], ":]"); end >= 0 {
				b.WriteString(p[i : i+2+end+2])
				i += 2 + end + 1
				first = false
				continue
			}
		case c == ']' && inClass && !first:
			inClass = false
		case c == '(' && !inClass && !nonCapturing.MatchString(p[i+1:]):
			// Counted generously: any other (? is a named group or something RE2 refuses anyway.
			groups++
		}
		first = false
		b.WriteByte(c)
	}
	return b.String(), ""
}

// nonCapturing is what follows the ( of a group that PCRE does not number: (?: and flags, as (?i) and (?i:.
var nonCapturing = regexp.MustCompile(`\A\?[a-zA-Z-]*[:)]`)

// backReference reads the digits after a backslash as PCRE does, as one number, and returns it if PCRE reads it as a
// back-reference that RE2 would read as a character: 10 or more, with at least that many groups before it. Under 10, RE2 refuses
// it as PCRE's back-reference, or reads it as the same octal character.
func backReference(digits string, groups int) int {
	end := 0
	for end < len(digits) && digits[end] >= '0' && digits[end] <= '9' {
		end++
	}
	if n, err := strconv.Atoi(digits[:end]); err == nil && n >= 10 && n <= groups {
		return n
	}
	return 0
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
