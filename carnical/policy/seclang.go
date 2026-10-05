// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"
)

// This file writes the SecLang that the settings of crs.Settings and proxy.Config cannot express: the address lists, the
// pages that are never inspected, the exclusions, the custom rules, and the rule groups that are switched off or set to log.
//
// The rule it writes are built from the structure of the policy, never from its text. Every value that reaches a line is one
// of: a number, a word from a fixed list, a variable name from a fixed table, an address or range written by netip, a path
// made only of the characters in pathRe (which mean nothing to SecLang), a header, argument or cookie name made only of
// letters, digits and . _ [ ] -, or the text of a regular expression made by rxcheck.go. And each line, once written, is
// checked (checkRuleLine): one line, four quotation marks, none of them escaped, no control or separator character, short
// enough for the engine to read. A rule that fails its check is an error, never emitted.

// ruleText is the SecLang of one rule, with the number of rules it is.
type generated struct {
	lines []string
}

func (g *generated) add(line string, wantID int) error {
	if err := checkRuleLine(line, wantID); err != nil {
		return err
	}
	g.lines = append(g.lines, line)
	return nil
}

func (g *generated) text() string {
	if len(g.lines) == 0 {
		return ""
	}
	return strings.Join(g.lines, "\n")
}

// checkRuleLine is the invariant every generated rule keeps. The engine reads a rule from one line (it splits the text at
// newlines, joins a line that ends in a backslash with the next, and stops without an error at a line over 64 KiB, which would
// drop every rule after it), finds the operator by its first unescaped closing quote, and reads actions by their commas and
// colons outside apostrophes. A line with exactly four quotation marks, none preceded by a backslash, with no character that
// could end or hide a line, that begins "SecRule " and carries the id it was written for, cannot be anything else.
func checkRuleLine(line string, wantID int) error {
	if len(line) > MaxLineBytes {
		return errors.New("a generated rule is too long")
	}
	if !strings.HasPrefix(line, "SecRule ") || !strings.HasSuffix(line, `"`) {
		return errors.New("a generated rule is not a SecRule line")
	}
	if !strings.Contains(line, fmt.Sprintf(` "id:%d,`, wantID)) {
		return errors.New("a generated rule does not carry its id")
	}
	if strings.Count(line, `"`) != 4 {
		return errors.New("a generated rule has the wrong number of quotation marks")
	}
	for i := 0; i < len(line); {
		r, size := utf8.DecodeRuneInString(line[i:])
		switch {
		case r == utf8.RuneError && size <= 1:
			return errors.New("a generated rule is not valid UTF-8")
		case r < 0x20 || r == 0x7f || unicode.Is(unicode.Zl, r) || unicode.Is(unicode.Zp, r) || r == 0x85:
			return errors.New("a generated rule holds a control or line separator character")
		case r == '"' && i > 0 && line[i-1] == '\\':
			return errors.New("a generated rule has an escaped quotation mark")
		case r == '`':
			return errors.New("a generated rule holds a backtick")
		}
		i += size
	}
	return nil
}

// chunk is how many addresses one @ipMatch rule holds: its line stays under 5 KiB.
const chunk = 100

// idForException is the id of the rule compiled from one category of one exclusion.
func exclusionID(position, category int) int { return idExclusions + 100*position + category }

// renderBefore writes the rules that run before the Core Rule Set, in the order they must run: the address allow list (which
// beats everything), the block list, the pages that are never inspected, the exclusions, and the custom rules. It returns the
// number of rules it wrote. The policy must be valid and normalised.
func renderBefore(p Policy) (text string, rules int, err error) {
	var g generated
	for i, part := range chunks(p.AllowIPs) {
		id := idAllowIPs + i
		if err := g.add(fmt.Sprintf(`SecRule REMOTE_ADDR "@ipMatch %s" "id:%d,phase:1,allow,nolog,t:none"`, strings.Join(part, ","), id), id); err != nil {
			return "", 0, err
		}
	}
	for i, part := range chunks(p.BlockIPs) {
		id := idBlockIPs + i
		if err := g.add(fmt.Sprintf(`SecRule REMOTE_ADDR "@ipMatch %s" "id:%d,phase:1,deny,status:403,log,t:none,msg:'Address on the block list',tag:'carnical-block-list',severity:'CRITICAL'"`,
			strings.Join(part, ","), id), id); err != nil {
			return "", 0, err
		}
	}
	for i, path := range p.AllowPaths {
		id := idAllowPaths + i
		if err := g.add(fmt.Sprintf(`SecRule REQUEST_FILENAME "@beginsWith %s" "id:%d,phase:1,allow,nolog,t:none"`, path, id), id); err != nil {
			return "", 0, err
		}
	}
	for i, e := range p.Exclusions {
		for _, cat := range e.Categories {
			id := exclusionID(i, groupIndex(cat))
			line, err := exclusionRule(id, e, groupByName[cat])
			if err != nil {
				return "", 0, err
			}
			if err := g.add(line, id); err != nil {
				return "", 0, err
			}
		}
	}
	for _, r := range p.CustomRules {
		line, err := customRule(r)
		if err != nil {
			return "", 0, fmt.Errorf("custom rule %d: %w", r.ID, err)
		}
		if err := g.add(line, idCustom+r.ID); err != nil {
			return "", 0, err
		}
	}
	return g.text(), len(g.lines), nil
}

// chunks splits a list into runs of at most `chunk` entries.
func chunks(list []string) [][]string {
	var out [][]string
	for len(list) > 0 {
		n := min(chunk, len(list))
		out = append(out, list[:n])
		list = list[n:]
	}
	return out
}

// exclusionRule keeps one category of rules away from some parts of the requests whose path begins with the exclusion's path.
// With no targets the whole category is removed for the request; with targets, only those parts are taken out of what the
// category's rules look at (ctl:ruleRemoveTargetById, which is the Core Rule Set's own way of excluding a part of a request).
func exclusionRule(id int, e Exclusion, g GroupInfo) (string, error) {
	rng := fmt.Sprintf("%d-%d", g.First, g.Last)
	var ctl []string
	if len(e.Targets) == 0 {
		ctl = append(ctl, "ctl:ruleRemoveById="+rng)
	}
	for _, t := range e.Targets {
		v, ok := targetVariable(t, false)
		if !ok {
			return "", errors.New("an exclusion names a part of a request that is not one")
		}
		ctl = append(ctl, fmt.Sprintf("ctl:ruleRemoveTargetById=%s;%s", rng, v))
	}
	return fmt.Sprintf(`SecRule REQUEST_FILENAME "@beginsWith %s" "id:%d,phase:1,pass,nolog,t:none,%s"`, e.Path, id, strings.Join(ctl, ",")), nil
}

// customRule compiles a custom rule. It is one rule, with one variable, one @rx operator and a fixed action list.
func customRule(r CustomRule) (string, error) {
	v, ok := targetVariable(r.Field, true)
	if !ok {
		return "", errors.New("the field is not a part of a request")
	}
	rx, err := operatorRegex(r.Operator, r.Value, r.Values, r.CaseSensitive)
	if err != nil {
		return "", err
	}
	action, severity := "pass,log", "NOTICE"
	if r.Action == ActionBlock {
		action, severity = "deny,status:403,log", "CRITICAL"
	} else if r.Action != ActionLog {
		return "", errors.New("the action is not block or log")
	}
	transforms := ""
	if r.Field == "uri" || r.Field == "query" {
		transforms = ",t:urlDecodeUni" // the raw target is percent-encoded; the rule means what a person reads
	}
	id := idCustom + r.ID
	return fmt.Sprintf(`SecRule %s "@rx %s" "id:%d,phase:%d,%s,t:none%s,msg:'Custom rule %d',tag:'carnical-custom',severity:'%s'"`,
		v, rx, id, fieldPhase(r.Field), action, transforms, r.ID, severity), nil
}

// renderAfter writes what changes the rules of the Core Rule Set once they are loaded: the rule groups that are off are removed
// by id range, and the rules of the groups that are set to log have their score taken back (see groups.go). It is written in group
// order. The notes say what the edge does differently from what the policy says, in words.
func renderAfter(p Policy) (text string, notes []string, err error) {
	var lines []string
	names := make([]string, 0, len(p.RuleGroups))
	for name := range p.RuleGroups {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		g, ok := groupByName[name]
		if !ok {
			return "", nil, errors.New("a rule group is not one")
		}
		switch p.RuleGroups[name] {
		case GroupOff:
			lines = append(lines, fmt.Sprintf("SecRuleRemoveById %d-%d", g.First, g.Last))
		case GroupLog:
			comp, off, err := logGroup(g)
			if err != nil {
				return "", nil, err
			}
			lines = append(lines, comp...)
			if len(off) > 0 {
				notes = append(notes, fmt.Sprintf("Rule group %s is set to log only. %d of its rules need several conditions to match, so their score cannot be taken back on its own: they are switched off in that group, and do not record a match either.", name, len(off)))
			}
			for len(off) > 0 {
				n := min(40, len(off))
				ids := make([]string, n)
				for i, id := range off[:n] {
					ids[i] = fmt.Sprint(id)
				}
				lines = append(lines, "SecRuleRemoveById "+strings.Join(ids, " "))
				off = off[n:]
			}
		}
	}
	return strings.Join(lines, "\n"), notes, nil
}

// prefixes parses a normalised address list.
func prefixes(list []string) []netip.Prefix {
	out := make([]netip.Prefix, 0, len(list))
	for _, s := range list {
		if p, ok := parsePrefix(s); ok {
			out = append(out, p)
		}
	}
	return out
}
