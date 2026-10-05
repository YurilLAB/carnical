// SPDX-License-Identifier: Apache-2.0

package seclang

import (
	"regexp"
	"strings"

	"github.com/YurilLAB/coraza/carnical/vpatch"
	"github.com/YurilLAB/coraza/carnical/vpatch/importers"
)

// varSpec says how a SecLang variable maps to the model.
type varSpec struct {
	target string
	keyed  string // the prefix when the variable is given a selector (ARGS:foo -> arg:foo), or "" if it takes none
	// decoded: SecLang's REQUEST_FILENAME is already percent-decoded, and the model's "path" is the path as received, so the signature
	// starts with urldecode1. ARGS and the like are parsed arguments, which are decoded in both.
	decoded bool
	// many: the variable has any number of values.
	many bool
}

var vars = map[string]varSpec{
	"REQUEST_URI":           {target: vpatch.TargetURI},
	"REQUEST_URI_RAW":       {target: vpatch.TargetURI},
	"REQUEST_FILENAME":      {target: vpatch.TargetPath, decoded: true},
	"QUERY_STRING":          {target: vpatch.TargetQuery},
	"ARGS":                  {target: vpatch.TargetArgs, keyed: "arg", many: true},
	"ARGS_GET":              {target: vpatch.TargetArgs, keyed: "arg", many: true},
	"ARGS_POST":             {target: vpatch.TargetArgs, keyed: "arg", many: true},
	"ARGS_NAMES":            {target: vpatch.TargetArgNames, many: true},
	"ARGS_GET_NAMES":        {target: vpatch.TargetArgNames, many: true},
	"ARGS_POST_NAMES":       {target: vpatch.TargetArgNames, many: true},
	"REQUEST_HEADERS":       {target: vpatch.TargetHeaders, keyed: "header", many: true},
	"REQUEST_COOKIES":       {target: vpatch.TargetCookies, keyed: "cookie", many: true},
	"REQUEST_COOKIES_NAMES": {target: vpatch.TargetCookieNames, many: true},
	"REQUEST_BODY":          {target: vpatch.TargetBody},
	"REQUEST_METHOD":        {target: vpatch.TargetMethod},
	"FILES":                 {target: vpatch.TargetFilenames, many: true},
	"FILES_TMP_CONTENT":     {target: vpatch.TargetUploads, many: true},
}

// transforms maps SecLang's t: names (lower case) to the model's.
var transforms = map[string]string{
	"lowercase": "lowercase", "urldecode": "urldecode1", "urldecodeuni": "urldecode1", "htmlentitydecode": "htmldecode",
	"jsdecode": "jsdecode", "cssdecode": "cssdecode", "normalizepath": "normpath", "normalisepath": "normpath",
	"normalizepathwin": "normpathwin", "normalisepathwin": "normpathwin", "removenulls": "nulls", "compresswhitespace": "compressspace",
	"removewhitespace": "removespace", "trim": "trim", "base64decode": "base64decode", "removecomments": "comments",
	"replacecomments": "replacecomments", "cmdline": "cmdline", "utf8tounicode": "utf8unicode",
}

// ruleExpr turns one SecRule line into an expression: an "or" over its variables (SecLang looks at each), split further where the
// variables need different transforms.
func (c *converter) ruleExpr(r secRule) (importers.Expr, error) {
	if err := c.checkActionsOfLink(r); err != nil {
		return importers.Expr{}, err
	}
	var decodedTargets, rawTargets []string
	negatedMany := false
	for _, v := range r.vars {
		switch {
		case v.negated:
			return importers.Expr{}, skip("variable-exclusion")
		case v.count:
			return importers.Expr{}, skip("variable-count")
		}
		spec, ok := vars[v.name]
		if !ok {
			return importers.Expr{}, skip("variable-unsupported:%s", importers.SafeName(v.name))
		}
		target := spec.target
		if v.selector != "" {
			if spec.keyed == "" {
				return importers.Expr{}, skip("selector-unsupported:%s", importers.SafeName(v.name))
			}
			if strings.HasPrefix(v.selector, "/") {
				return importers.Expr{}, skip("variable-regex-selector")
			}
			target = spec.keyed + ":" + strings.ToLower(v.selector)
			if !importers.ValidTarget(target) {
				return importers.Expr{}, skip("selector-invalid")
			}
		} else if spec.many {
			negatedMany = true
		}
		if spec.decoded {
			decodedTargets = append(decodedTargets, target)
		} else {
			rawTargets = append(rawTargets, target)
		}
	}
	if r.op.negated && negatedMany {
		// "!@rx" on a variable with many values: SecLang fires when some value fails to match; the model's Negate holds when no
		// value matches. They are not the same, so the rule is refused.
		return importers.Expr{}, skip("negated-on-many-values")
	}

	// transformations, in order; t:none starts again
	var tf []string
	for _, a := range r.actions {
		if a.key != "t" {
			continue
		}
		name := strings.ToLower(strings.TrimSpace(a.val))
		if name == "none" {
			tf = nil
			continue
		}
		m, ok := transforms[name]
		if !ok {
			return importers.Expr{}, skip("transform-unsupported:%s", importers.SafeName(name))
		}
		if name == "urldecode" || name == "urldecodeuni" {
			c.approx["urldecode-plus-and-uni"] = true
		}
		tf = append(tf, m)
	}

	var leaves []importers.Expr
	for _, g := range []struct {
		tf      []string
		targets []string
	}{{append([]string{"urldecode1"}, tf...), decodedTargets}, {tf, rawTargets}} {
		if len(g.targets) == 0 {
			continue
		}
		cond, err := c.condition(r.op, g.tf, g.targets)
		if err != nil {
			return importers.Expr{}, err
		}
		if cond.Negate {
			// SecLang does not fire a negated test on a value the request does not have; see ExistsGuard.
			if guard, ok := importers.ExistsGuard(g.targets); ok {
				leaves = append(leaves, importers.And(importers.Leaf(guard), importers.Leaf(cond)))
				continue
			}
		}
		leaves = append(leaves, importers.Leaf(cond))
	}
	if len(leaves) == 1 {
		return leaves[0], nil
	}
	return importers.Or(leaves...), nil
}

// checkActionsOfLink checks the actions of a chained rule: they are not required to have an id, but the ones that change meaning
// are still refused.
func (c *converter) checkActionsOfLink(r secRule) error {
	if r.has("id") {
		return nil // the head: checked with its own id
	}
	return c.checkActions(r)
}

func dedupe(ts []string) []string {
	var out []string
	for _, t := range ts {
		if len(out) > 0 && out[len(out)-1] == t {
			continue
		}
		out = append(out, t)
	}
	return out
}

func (c *converter) condition(op operator, tf, targets []string) (vpatch.Condition, error) {
	tf = dedupe(tf)
	arg := op.arg
	if strings.Contains(arg, "%{") {
		return vpatch.Condition{}, skip("macro-in-operator")
	}
	if len(arg) > c.lim.MaxPatternBytes {
		return vpatch.Condition{}, skip("pattern-too-long")
	}
	hasLower := false
	for _, t := range tf {
		if t == "lowercase" {
			hasLower = true
		}
	}
	var cond vpatch.Condition
	switch op.name {
	case "rx":
		if arg == "" {
			return vpatch.Condition{}, skip("empty-value")
		}
		p, err := c.rep.CheckRegex(arg, "", c.lim.MaxPatternBytes)
		if err != nil {
			return vpatch.Condition{}, err
		}
		cond = importers.NewCondition(vpatch.OpRegex, p, targets, tf)
	case "contains", "beginswith", "endswith", "streq":
		if arg == "" {
			return vpatch.Condition{}, skip("empty-value")
		}
		if hasLower && strings.ContainsAny(arg, "ABCDEFGHIJKLMNOPQRSTUVWXYZ") {
			return vpatch.Condition{}, skip("unmatchable-literal")
		}
		o := map[string]string{"contains": vpatch.OpContains, "beginswith": vpatch.OpPrefix, "endswith": vpatch.OpSuffix, "streq": vpatch.OpEquals}[op.name]
		cond = importers.NewCondition(o, arg, targets, tf)
	case "pm":
		words := strings.Fields(arg)
		if len(words) == 0 {
			return vpatch.Condition{}, skip("empty-value")
		}
		if len(words) > 4096 {
			return vpatch.Condition{}, skip("pattern-too-long")
		}
		// @pm ignores case; the model's pm does not say, so both sides are lower-cased.
		lw := make([]string, len(words))
		for i, w := range words {
			lw[i] = strings.ToLower(w)
		}
		cond = importers.NewCondition(vpatch.OpPM, "", targets, append(append([]string(nil), tf...), "lowercase"))
		cond.Patterns = lw
	case "within":
		words := strings.FieldsFunc(arg, func(r rune) bool { return r == ' ' || r == ',' || r == '\t' })
		if len(words) == 0 {
			return vpatch.Condition{}, skip("empty-value")
		}
		// SecLang's @within is true when the value is a substring of the argument. The signature says the value is one of the words,
		// which is the way the operator is used (a list of allowed methods, a list of allowed types); the report counts it.
		quoted := make([]string, len(words))
		for i, w := range words {
			quoted[i] = regexp.QuoteMeta(w)
		}
		p, err := c.rep.CheckRegex("^(?:"+strings.Join(quoted, "|")+")$", "", c.lim.MaxPatternBytes)
		if err != nil {
			return vpatch.Condition{}, err
		}
		cond = importers.NewCondition(vpatch.OpRegex, p, targets, tf)
		c.approx["within-as-word-list"] = true
	default:
		return vpatch.Condition{}, skip("operator-unsupported:%s", importers.SafeName(op.name))
	}
	cond.Negate = op.negated
	return cond, nil
}
