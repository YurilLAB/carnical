// SPDX-License-Identifier: Apache-2.0

package crowdsec

import (
	"strings"

	"github.com/YurilLAB/coraza/carnical/vpatch"
	"github.com/YurilLAB/coraza/carnical/vpatch/importers"
)

// The model has no target for header names, but a rule about them (the Next.js middleware bypass, the React Flight RCE, the F5
// iControl bypass) is nearly always about a header being present. So HEADERS_NAMES with a lower-case transform becomes "the header
// NAME has a value" (a value that matches ^, which every value does), for each name the rule's literal or simple regular
// expression lists:
//
//   - equals NAME           the header NAME is present: exact;
//   - contains NAME         a header whose name contains NAME: written as the header NAME itself, which is narrower;
//   - regex of literal names joined by |, in groups, optionally anchored: each name, narrower in the same way.
//
// Every one of these but "equals" is counted in the report as an approximation. Anything else (a regex with a quantifier or a
// class, another match type, another transform) is skipped.
const maxHeaderNames = 32

func (c *converter) headerNames(zoneNames, vars, transforms []string, match map[string]any) (importers.Expr, error) {
	unsupported := skip("zone-unsupported:HEADERS_NAMES")
	if len(zoneNames) != 1 || len(vars) != 0 || len(transforms) != 1 || strings.ToLower(strings.TrimSpace(transforms[0])) != "lowercase" {
		return importers.Expr{}, unsupported
	}
	typ, _ := importers.AsString(match["type"])
	val, _ := importers.AsString(match["value"])
	var names []string
	kind := ""
	switch strings.ToLower(strings.TrimSpace(typ)) {
	case "equals":
		if isHeaderToken(val) {
			names = []string{val}
		}
	case "contains":
		if isHeaderToken(val) {
			names = []string{val}
			kind = "header-name-match-as-presence"
		}
	case "regex":
		names = enumerateNames(val)
		kind = "header-name-match-as-presence"
	}
	if len(names) == 0 {
		return importers.Expr{}, unsupported
	}
	var leaves []importers.Expr
	for _, n := range names {
		cond := importers.NewCondition(vpatch.OpRegex, "^", []string{"header:" + n}, nil)
		if kind != "" {
			c.approx[condKey(cond)] = kind
		}
		leaves = append(leaves, importers.Leaf(cond))
	}
	if len(leaves) == 1 {
		return leaves[0], nil
	}
	return importers.Or(leaves...), nil
}

// isHeaderToken says whether s is a lower-case header name: letters, digits and "-", 1 to 64 characters.
func isHeaderToken(s string) bool {
	if s == "" || len(s) > 64 {
		return false
	}
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-') {
			return false
		}
	}
	return true
}

// enumerateNames lists the strings a regular expression made only of lower-case header-name characters, "|" and non-nested-quantifier
// groups can match, or nil when the pattern has anything else in it (or would give more than maxHeaderNames).
func enumerateNames(pattern string) []string {
	p := strings.TrimPrefix(pattern, "^")
	p = strings.TrimSuffix(p, "$")
	pos := 0
	out, ok := parseAlt(p, &pos, 0)
	if !ok || pos != len(p) || len(out) == 0 || len(out) > maxHeaderNames {
		return nil
	}
	for _, n := range out {
		if !isHeaderToken(n) {
			return nil
		}
	}
	return out
}

func parseAlt(p string, pos *int, depth int) ([]string, bool) {
	if depth > 3 {
		return nil, false
	}
	var all []string
	cur := []string{""}
	for *pos < len(p) {
		ch := p[*pos]
		switch {
		case ch == '|':
			all = append(all, cur...)
			cur = []string{""}
			*pos++
		case ch == ')':
			if depth == 0 {
				return nil, false
			}
			all = append(all, cur...)
			return all, len(all) <= maxHeaderNames
		case ch == '(':
			*pos++
			if strings.HasPrefix(p[*pos:], "?:") {
				*pos += 2
			}
			inner, ok := parseAlt(p, pos, depth+1)
			if !ok || *pos >= len(p) || p[*pos] != ')' {
				return nil, false
			}
			*pos++
			if *pos < len(p) && strings.IndexByte("*+?{", p[*pos]) >= 0 {
				return nil, false
			}
			var next []string
			for _, a := range cur {
				for _, b := range inner {
					next = append(next, a+b)
				}
			}
			if len(next) > maxHeaderNames {
				return nil, false
			}
			cur = next
		case ch >= 'a' && ch <= 'z' || ch >= '0' && ch <= '9' || ch == '-':
			if *pos+1 < len(p) && strings.IndexByte("*+?{", p[*pos+1]) >= 0 {
				return nil, false
			}
			for i := range cur {
				cur[i] += string(ch)
			}
			*pos++
		default:
			return nil, false
		}
	}
	if depth > 0 {
		return nil, false
	}
	all = append(all, cur...)
	return all, len(all) <= maxHeaderNames
}
