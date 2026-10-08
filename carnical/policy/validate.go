// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"fmt"
	"net/netip"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Validate checks every field of the policy, on its normalised form (see Normalize), and returns an *Error that lists what is
// wrong (every problem found, up to 50) or nil. A policy that passes can be compiled: once every part has been checked, the whole
// is written out as SecLang (what Compile does) and each line has to pass the line check, so Compile never fails for a policy
// Validate accepts.
//
// Index numbers in the paths refer to the normalised, sorted lists, except for custom rules, which are named by their id.
func (p Policy) Validate() error {
	q := p.Normalize()
	var c checker

	if q.Schema != SchemaVersion {
		c.add("schema", "must be %d", SchemaVersion)
	}
	if !validModes[q.Mode] {
		c.add("mode", "must be block, monitor or off")
	}
	if !validSens[q.Sensitivity] {
		c.add("sensitivity", "must be relaxed, normal or strict")
	}
	if q.Threshold != nil && (*q.Threshold < 1 || *q.Threshold > 1000) {
		c.add("threshold", "must be a whole number from 1 to 1000, or null to use the sensitivity's")
	}

	validateBody(&c, q.Body)
	validateMethods(&c, q.AllowedMethods)
	if len(q.AllowedHosts) > MaxHosts {
		c.add("allowed_hosts", "at most %d names", MaxHosts)
	}
	for i, h := range q.AllowedHosts {
		if !validHostname(h) {
			c.add(fmt.Sprintf("allowed_hosts[%d]", i), "%q is not a host name (letters, digits, hyphens and dots, as in www.example.com)", safeName(h))
		}
	}
	groupNames := make(map[string]bool, len(q.RuleGroups))
	for name, state := range q.RuleGroups {
		canonical := strings.ToLower(name)
		if groupNames[canonical] {
			c.add("rule_groups", "a rule group is given more than once")
		}
		groupNames[canonical] = true
		if _, ok := groupByName[canonical]; !ok {
			c.add("rule_groups", "%q is not a rule group", safeName(name))
		} else if !validStates[state] {
			c.add("rule_groups."+name, "must be on, log or off")
		}
	}
	validateExclusions(&c, q.Exclusions)
	validateRules(&c, q.CustomRules)
	validateIPs(&c, "allow_ips", q.AllowIPs, MaxAllowIPs, 16, 32)
	validateIPs(&c, "block_ips", q.BlockIPs, MaxBlockIPs, 8, 16)
	if len(q.AllowPaths) > MaxAllowPaths {
		c.add("allow_paths", "at most %d paths", MaxAllowPaths)
	}
	for i, s := range q.AllowPaths {
		if !validPath(s) {
			c.add(fmt.Sprintf("allow_paths[%d]", i), "%q is not a path: it must start with / and use only letters, digits and / _ . ~ @ : = + , - (at most %d characters)", safeName(s), MaxPathBytes)
		}
	}
	if q.WordPress.LoginPerMinute < 1 || q.WordPress.LoginPerMinute > 600 {
		c.add("wordpress.login_per_minute", "must be a whole number from 1 to 600")
	}
	if len(q.DenyHeaders) > MaxDenyHeaders {
		c.add("deny_headers", "at most %d headers", MaxDenyHeaders)
	}
	for i, h := range q.DenyHeaders {
		if !headerRe.MatchString(h) {
			c.add(fmt.Sprintf("deny_headers[%d]", i), "%q is not a header name (letters, digits and hyphens)", safeName(h))
		}
	}
	if len(q.VPatch.Tiers) > len(knownTiers) {
		c.add("vpatch.tiers", "at most %d tiers", len(knownTiers))
	}
	for _, t := range q.VPatch.Tiers {
		if !knownTiers[t] {
			c.add("vpatch.tiers", "%q is not a tier (verified, community or experimental)", safeName(t))
		}
	}
	if len(q.VPatch.Software) > MaxSoftware {
		c.add("vpatch.software", "at most %d entries", MaxSoftware)
	}
	for i, s := range q.VPatch.Software {
		if !softwareRe.MatchString(s) {
			c.add(fmt.Sprintf("vpatch.software[%d]", i), "%q is not a software name such as wordpress or woocommerce@9.3", safeName(s))
		}
	}
	if !validAPIModes[q.APIMode] {
		c.add("api_mode", "must be off, learn, monitor or enforce")
	}
	if msg := runSection(SectionAPI, q.API); msg != "" {
		c.add("api", "%s", msg)
	}
	if msg := runSection(SectionBodyFormats, q.BodyFormats); msg != "" {
		c.add("body_formats", "%s", msg)
	}
	if msg := textProblem(q.Note, MaxNoteBytes, true); msg != "" {
		c.add("note", "%s", msg)
	}
	if len(c.problems) == 0 {
		// Everything above checked the parts. This writes the whole: a policy that passes can always be compiled, because
		// compiling it is what was just done, and each line written passes the line check.
		if _, _, err := renderBefore(q); err != nil {
			c.add("$", "the rules written for this policy fail their own check (%s)", err.Error())
		} else if _, _, err := renderAfter(q); err != nil {
			c.add("$", "the changes to the rule set written for this policy fail their own check (%s)", err.Error())
		}
	}
	return c.err()
}

func validateBody(c *checker, b BodyLimits) {
	if b.MaxUploadBytes < MinBodyBytes || b.MaxUploadBytes > MaxUploadBytesLimit {
		c.add("body.max_upload_bytes", "must be from %d to %d bytes", MinBodyBytes, MaxUploadBytesLimit)
	}
	if b.MaxFormBytes < MinBodyBytes || b.MaxFormBytes > MaxFormBytesLimit {
		c.add("body.max_form_bytes", "must be from %d to %d bytes", MinBodyBytes, MaxFormBytesLimit)
	}
	if b.MaxFormBytes > b.MaxUploadBytes {
		c.add("body.max_form_bytes", "cannot be more than max_upload_bytes")
	}
}

func validateMethods(c *checker, methods []string) {
	if len(methods) == 0 {
		c.add("allowed_methods", "at least one method is needed")
	}
	if len(methods) > MaxMethods {
		c.add("allowed_methods", "at most %d methods", MaxMethods)
	}
	for i, m := range methods {
		switch {
		case !methodRe.MatchString(m):
			c.add(fmt.Sprintf("allowed_methods[%d]", i), "%q is not an HTTP method (upper-case letters and hyphens)", safeName(m))
		case m == "CONNECT" || m == "TRACE":
			c.add(fmt.Sprintf("allowed_methods[%d]", i), "%s is not allowed: CONNECT is a proxy method and TRACE reflects a request back to the page that sent it", m)
		}
	}
}

func validateExclusions(c *checker, ex []Exclusion) {
	if len(ex) > MaxExclusions {
		c.add("exclusions", "at most %d exclusions", MaxExclusions)
	}
	for i, e := range ex {
		at := fmt.Sprintf("exclusions[%d]", i)
		if !validPath(e.Path) {
			c.add(at+".path", "%q is not a path: it must start with / and use only letters, digits and / _ . ~ @ : = + , - (at most %d characters)", safeName(e.Path), MaxPathBytes)
		}
		if len(e.Categories) == 0 {
			c.add(at+".categories", "at least one rule group is needed")
		}
		for _, cat := range e.Categories {
			if _, ok := groupByName[cat]; !ok {
				c.add(at+".categories", "%q is not a rule group", safeName(cat))
			}
		}
		if len(e.Targets) > MaxTargets {
			c.add(at+".targets", "at most %d targets (leave it empty to cover the whole request)", MaxTargets)
		}
		for _, t := range e.Targets {
			if _, ok := targetVariable(t, false); !ok {
				c.add(at+".targets", "%q is not a part of a request (args, argnames, cookies, cookienames, headers, body, query, path, uri, method, filenames, arg:NAME, cookie:NAME or header:NAME)", safeName(t))
			}
		}
		if msg := textProblem(e.Note, MaxItemNoteBytes, false); msg != "" {
			c.add(at+".note", "%s", msg)
		}
	}
}

func validateRules(c *checker, rules []CustomRule) {
	if len(rules) > MaxCustomRules {
		c.add("custom_rules", "at most %d rules", MaxCustomRules)
	}
	seen := map[int]bool{}
	for i, r := range rules {
		at := fmt.Sprintf("custom_rules[%d]", r.ID)
		if r.ID < 1 || r.ID > 9999 {
			at = fmt.Sprintf("custom_rules[#%d]", i+1)
			c.add(at+".id", "must be a whole number from 1 to 9999")
		} else if seen[r.ID] {
			c.add(at+".id", "is used by more than one rule")
		}
		seen[r.ID] = true
		if _, ok := targetVariable(r.Field, true); !ok {
			c.add(at+".field", "%q is not a part of a request (method, path, uri, query, args, argnames, cookies, cookienames, headers, body, filenames, host, useragent, arg:NAME, cookie:NAME or header:NAME)", safeName(r.Field))
		}
		if r.Action != ActionBlock && r.Action != ActionLog {
			c.add(at+".action", "must be block or log")
		}
		if msg := textProblem(r.Note, MaxItemNoteBytes, false); msg != "" {
			c.add(at+".note", "%s", msg)
		}
		if !validOps[r.Operator] {
			c.add(at+".operator", "must be contains, equals, beginsWith, endsWith, pm or rx")
			continue
		}
		validateRuleValue(c, at, r)
	}
}

func validateRuleValue(c *checker, at string, r CustomRule) {
	if r.Operator == OpPM {
		if r.Value != "" {
			c.add(at+".value", "pm takes a list of words in values, not a value")
		}
		if len(r.Values) == 0 || len(r.Values) > MaxPMValues {
			c.add(at+".values", "needs from 1 to %d words", MaxPMValues)
			return
		}
		for _, w := range r.Values {
			if len(w) > MaxPMValueBytes {
				c.add(at+".values", "a word is longer than %d bytes", MaxPMValueBytes)
				return
			}
		}
	} else {
		if len(r.Values) > 0 {
			c.add(at+".values", "only pm takes a list of words")
		}
		if len(r.Value) > MaxValueBytes {
			c.add(at+".value", "is longer than %d bytes", MaxValueBytes)
			return
		}
	}
	if _, err := operatorRegex(r.Operator, r.Value, r.Values, r.CaseSensitive); err != nil {
		field := ".value"
		if r.Operator == OpPM {
			field = ".values"
		}
		c.add(at+field, "%s", err.Error())
	}
}

// validateIPs checks an address list: each entry an address or a CIDR range, a range no wider than minV4 bits (IPv4) or
// minV6 bits (IPv6), and no more than max entries. The limits on width are what keep one entry from being "everyone".
func validateIPs(c *checker, name string, list []string, max, minV4, minV6 int) {
	if len(list) > max {
		c.add(name, "at most %d entries", max)
	}
	for i, s := range list {
		p, ok := parsePrefix(s)
		if !ok || p.String() != s {
			c.add(fmt.Sprintf("%s[%d]", name, i), "%q is not an IP address or a CIDR range such as 203.0.113.0/24", safeName(s))
			continue
		}
		if min := map[bool]int{true: minV4, false: minV6}[p.Addr().Is4()]; p.Bits() < min {
			c.add(fmt.Sprintf("%s[%d]", name, i), "%s is a range wider than /%d, which this list does not take", s, min)
		}
	}
}

// textProblem says what is wrong with a free-text field: it must be valid UTF-8, at most max bytes, and made only of printable
// characters and spaces (and, if allowed, line breaks). A control character, a bidirectional override, a zero-width character
// or a line or paragraph separator is how text is made to read as something it is not.
func textProblem(s string, max int, newlines bool) string {
	if len(s) > max {
		return fmt.Sprintf("is longer than %d bytes", max)
	}
	if !utf8.ValidString(s) {
		return "is not valid UTF-8 text"
	}
	for _, r := range s {
		if unicode.IsPrint(r) || r == ' ' || (newlines && r == '\n') {
			continue
		}
		return "holds a character that cannot be shown safely (a control, separator, invisible or direction-changing character)"
	}
	return ""
}

// wideBlock reports whether a prefix is wide enough that blocking it could turn away every visitor (wider than /16 for
// IPv4 or /32 for IPv6, the threshold the PHP console asks for a password at).
func wideBlock(p netip.Prefix) bool {
	if p.Addr().Is4() {
		return p.Bits() < 16
	}
	return p.Bits() < 32
}
