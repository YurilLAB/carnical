// SPDX-License-Identifier: Apache-2.0

package crowdsec

import (
	"strconv"
	"strings"

	"github.com/YurilLAB/coraza/carnical/vpatch"
	"github.com/YurilLAB/coraza/carnical/vpatch/importers"
)

// zoneSpec says how one CrowdSec zone maps to the model.
type zoneSpec struct {
	target string // the plain target
	keyed  string // the prefix for a named value ("arg" gives "arg:NAME"), or "" when the zone has no named values
	// decoded: CrowdSec hands rules the path already percent-decoded once, and the model's "path" target is the path as received, so
	// the signature starts with urldecode1. Arguments are different: the model's "args" are the parsed arguments, which are decoded
	// already, so they need nothing.
	decoded bool
}

// zones is every zone the model can express. A zone that is not here (HEADERS_NAMES, FILES_NAMES, PROTOCOL, FILES_TOTAL_SIZE) has no
// target in the model, so a rule that needs it is skipped.
//
// ARGS is the query string's arguments and BODY_ARGS the form body's. The model's "args" covers both, so a rule that names one of them
// also matches the same name in the other place; the report counts those signatures as an approximation.
var zones = map[string]zoneSpec{
	"URI":             {target: vpatch.TargetPath, decoded: true},
	"URI_FULL":        {target: vpatch.TargetURI},
	"ARGS":            {target: vpatch.TargetArgs, keyed: "arg"},
	"BODY_ARGS":       {target: vpatch.TargetArgs, keyed: "arg"},
	"ARGS_NAMES":      {target: vpatch.TargetArgNames},
	"BODY_ARGS_NAMES": {target: vpatch.TargetArgNames},
	"HEADERS":         {target: vpatch.TargetHeaders, keyed: "header"},
	"COOKIES":         {target: vpatch.TargetCookies, keyed: "cookie"},
	"COOKIES_NAMES":   {target: vpatch.TargetCookieNames},
	"METHOD":          {target: vpatch.TargetMethod},
	"RAW_BODY":        {target: vpatch.TargetBody},
	"FILENAMES":       {target: vpatch.TargetFilenames},
	"FILES":           {target: vpatch.TargetUploads},
}

// transformMap maps CrowdSec transform names to the model's. count and length are handled apart (see buildCondition). Not here, so
// refused: uppercase, hexdecode, b64decode_lenient, b64encode, trim_left, trim_right, replace_nulls.
var transformMap = map[string]string{
	"lowercase":            "lowercase",
	"urldecode":            "urldecode",
	"b64decode":            "base64decode",
	"trim":                 "trim",
	"normalizepath":        "normpath",
	"normalize_path":       "normpath",
	"normalize_path_win":   "normpathwin",
	"htmlentitydecode":     "htmldecode",
	"js_decode":            "jsdecode",
	"css_decode":           "cssdecode",
	"cmdline":              "cmdline",
	"remove_whitespaces":   "removespace",
	"compress_whitespaces": "compressspace",
	"remove_nulls":         "nulls",
	"remove_comments":      "comments",
	"replace_comments":     "replacecomments",
}

// parseNode turns one entry of "rules" (or of an and/or) into an expression. A failure inside an "or" drops that branch only (the
// result is narrower); a failure inside an "and" fails the whole "and", because dropping one of its conditions would make the
// signature broader than the rule.
func (c *converter) parseNode(v any, depth int) (importers.Expr, error) {
	if depth > c.lim.MaxNesting {
		return importers.Expr{}, skip("nested-too-deep")
	}
	m, ok := importers.AsMap(v)
	if !ok {
		return importers.Expr{}, skip("rule-not-a-mapping")
	}
	andV, hasAnd := m["and"]
	orV, hasOr := m["or"]
	switch {
	case hasAnd && hasOr:
		return importers.Expr{}, skip("and-and-or-together")
	case hasAnd:
		kids, ok := importers.AsList(andV)
		if !ok || len(kids) == 0 {
			return importers.Expr{}, skip("empty-and-or")
		}
		var out []importers.Expr
		for _, k := range kids {
			e, err := c.parseNode(k, depth+1)
			if err != nil {
				return importers.Expr{}, err
			}
			out = append(out, e)
		}
		return importers.And(out...), nil
	case hasOr:
		kids, ok := importers.AsList(orV)
		if !ok || len(kids) == 0 {
			return importers.Expr{}, skip("empty-and-or")
		}
		var out []importers.Expr
		var first error
		for _, k := range kids {
			e, err := c.parseNode(k, depth+1)
			if err != nil {
				if first == nil {
					first = err
				}
				c.partial = append(c.partial, reasonOf(err))
				continue
			}
			out = append(out, e)
		}
		if len(out) == 0 {
			return importers.Expr{}, first
		}
		return importers.Or(out...), nil
	}
	return c.parseLeaf(m)
}

func (c *converter) parseLeaf(m map[string]any) (importers.Expr, error) {
	zoneNames, bad := importers.AsStrings(m["zones"])
	if len(zoneNames) == 0 || bad > 0 {
		return importers.Expr{}, skip("no-zones")
	}
	vars, bad := importers.AsStrings(m["variables"])
	if bad > 0 {
		return importers.Expr{}, skip("variables-not-text")
	}
	for i, v := range vars {
		v = strings.TrimSpace(v)
		if v == "" {
			return importers.Expr{}, skip("variable-empty")
		}
		if len(v) >= 2 && strings.HasPrefix(v, "/") && strings.HasSuffix(v, "/") {
			return importers.Expr{}, skip("variable-regex") // the model names one value, not a pattern of names
		}
		vars[i] = v
	}
	transforms, bad := importers.AsStrings(m["transform"])
	if bad > 0 {
		return importers.Expr{}, skip("transform-not-text")
	}
	match, ok := importers.AsMap(m["match"])
	if !ok {
		return importers.Expr{}, skip("no-match")
	}

	for _, z := range zoneNames {
		if strings.EqualFold(strings.TrimSpace(z), "HEADERS_NAMES") {
			return c.headerNames(zoneNames, vars, transforms, match)
		}
	}

	// Group the zones by whether the engine decodes them first: one condition has one list of transforms.
	var decodedTargets, rawTargets []string
	for _, z := range zoneNames {
		spec, ok := zones[strings.ToUpper(strings.TrimSpace(z))]
		if !ok {
			return importers.Expr{}, skip("zone-unsupported:%s", importers.SafeName(strings.ToUpper(strings.TrimSpace(z))))
		}
		var targets []string
		switch {
		case len(vars) == 0:
			targets = []string{spec.target}
		case spec.keyed == "":
			return importers.Expr{}, skip("variables-on-unkeyed-zone")
		default:
			for _, v := range vars {
				t := spec.keyed + ":" + strings.ToLower(v)
				if !importers.ValidTarget(t) {
					return importers.Expr{}, skip("variable-name-invalid")
				}
				targets = append(targets, t)
			}
		}
		if spec.decoded {
			decodedTargets = append(decodedTargets, targets...)
		} else {
			rawTargets = append(rawTargets, targets...)
		}
	}

	var leaves []importers.Expr
	if len(decodedTargets) > 0 {
		cond, err := c.buildCondition(match, transforms, []string{"urldecode1"}, decodedTargets)
		if err != nil {
			return importers.Expr{}, err
		}
		leaves = append(leaves, importers.Leaf(cond))
	}
	if len(rawTargets) > 0 {
		cond, err := c.buildCondition(match, transforms, nil, rawTargets)
		if err != nil {
			return importers.Expr{}, err
		}
		leaves = append(leaves, importers.Leaf(cond))
	}
	if len(leaves) == 1 {
		return leaves[0], nil
	}
	return importers.Or(leaves...), nil
}

// buildCondition makes the condition for one match over targets. pre are the transforms the engine has already applied that the
// model's raw targets need to repeat.
func (c *converter) buildCondition(match map[string]any, rawTransforms, pre, targets []string) (vpatch.Condition, error) {
	typ, _ := importers.AsString(match["type"])
	typ = strings.ToLower(strings.TrimSpace(typ))

	// Transforms, in order. count and length turn the value into a number and so must come last.
	var mapped []string
	special := ""
	for i, t := range rawTransforms {
		name := strings.ToLower(strings.TrimSpace(t))
		switch name {
		case "count", "length":
			if i != len(rawTransforms)-1 {
				return vpatch.Condition{}, skip("transform-after-%s", name)
			}
			special = name
			continue
		}
		m, ok := transformMap[name]
		if !ok {
			return vpatch.Condition{}, skip("transform-unsupported:%s", importers.SafeName(name))
		}
		mapped = append(mapped, m)
	}
	all := append(append([]string(nil), pre...), mapped...)
	all = dedupeAdjacent(all)

	value, hasValue := match["value"]
	valStr, _ := importers.AsString(value)

	switch typ {
	case "libinjectionsql", "libinjectionxss":
		return vpatch.Condition{}, skip("libinjection")
	case "gt", "gte", "lt", "lte":
		if special == "" {
			return vpatch.Condition{}, skip("numeric-comparison-unsupported")
		}
	}

	switch special {
	case "count":
		n, err := strconv.Atoi(strings.TrimSpace(valStr))
		if err != nil || !hasValue {
			return vpatch.Condition{}, skip("count-comparison-unsupported")
		}
		// The count of values a target has: only "none" and "at least one" can be said as "a value matches anything".
		var exists bool
		switch {
		case typ == "equals" && n == 0, typ == "lte" && n == 0, typ == "lt" && n == 1:
			exists = false
		case typ == "gt" && n == 0, typ == "gte" && n == 1:
			exists = true
		default:
			return vpatch.Condition{}, skip("count-comparison-unsupported")
		}
		cond := importers.NewCondition(vpatch.OpRegex, "^", targets, nil)
		cond.Negate = !exists
		return cond, nil
	case "length":
		n, err := strconv.Atoi(strings.TrimSpace(valStr))
		if err != nil || n < 0 || n > 1000 || !hasValue {
			return vpatch.Condition{}, skip("length-comparison-unsupported")
		}
		var pat string
		switch typ {
		case "equals":
			pat = "(?s)^.{" + strconv.Itoa(n) + "}$"
		case "gt":
			pat = "(?s)^.{" + strconv.Itoa(n+1) + ",}$"
			if n+1 > 1000 {
				return vpatch.Condition{}, skip("length-comparison-unsupported")
			}
		case "gte":
			pat = "(?s)^.{" + strconv.Itoa(n) + ",}$"
		case "lt":
			if n == 0 {
				return vpatch.Condition{}, skip("length-comparison-unsupported")
			}
			pat = "(?s)^.{0," + strconv.Itoa(n-1) + "}$"
		case "lte":
			pat = "(?s)^.{0," + strconv.Itoa(n) + "}$"
		default:
			return vpatch.Condition{}, skip("length-comparison-unsupported")
		}
		return importers.NewCondition(vpatch.OpRegex, pat, targets, all), nil
	}

	if !hasValue || valStr == "" {
		return vpatch.Condition{}, skip("empty-value")
	}
	if len(valStr) > c.lim.MaxPatternBytes {
		return vpatch.Condition{}, skip("pattern-too-long")
	}
	var op string
	switch typ {
	case "equals":
		op = vpatch.OpEquals
	case "contains":
		op = vpatch.OpContains
	case "startswith":
		op = vpatch.OpPrefix
	case "endswith":
		op = vpatch.OpSuffix
	case "regex":
		op = vpatch.OpRegex
	default:
		return vpatch.Condition{}, skip("match-type-unsupported:%s", importers.SafeName(typ))
	}
	if op != vpatch.OpRegex && hasLowercase(all) && strings.ContainsAny(valStr, "ABCDEFGHIJKLMNOPQRSTUVWXYZ") {
		// The value is compared after lower-casing, so a value with a capital letter can never match. CrowdSec would never match it
		// either; say so rather than write a signature that does nothing.
		return vpatch.Condition{}, skip("unmatchable-literal")
	}
	pattern := valStr
	if op == vpatch.OpRegex {
		p, err := c.rep.CheckRegex(pattern, "", c.lim.MaxPatternBytes)
		if err != nil {
			return vpatch.Condition{}, err
		}
		pattern = p
	}
	return importers.NewCondition(op, pattern, targets, all), nil
}

func hasLowercase(ts []string) bool {
	for _, t := range ts {
		if t == "lowercase" {
			return true
		}
	}
	return false
}

func dedupeAdjacent(ts []string) []string {
	var out []string
	for _, t := range ts {
		if len(out) > 0 && out[len(out)-1] == t {
			continue
		}
		out = append(out, t)
	}
	return out
}
