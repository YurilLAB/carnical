// SPDX-License-Identifier: Apache-2.0

// Package crowdsec converts CrowdSec AppSec rules (the "vpatch" rules of the CrowdSec hub, MIT licence) to vpatch signatures.
//
// A rule file has a name, a description, a list of rules and labels. Each entry of "rules" is an alternative (the entries are ORed);
// an entry is a condition or an "and" / "or" of conditions, nested. A condition says which request zones to look at (URI, ARGS,
// BODY_ARGS, HEADERS, METHOD, RAW_BODY, FILENAMES, COOKIES ...), optionally which named variables inside the zone, which
// transforms to apply, and what to match (equals, contains, startsWith, endsWith, regex, a numeric comparison, libinjection).
//
// The mapping, in short: an "or" becomes several signatures (at most importers.Limits.MaxAlternatives), an "and" becomes the main
// condition plus Also, with the condition that names the path as the main one. Zones become targets, transforms become transforms,
// match types become operators. What the model cannot say is skipped with a reason, never approximated silently. docs/signature-formats.md
// has the whole table.
package crowdsec

import (
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/YurilLAB/coraza/carnical/vpatch"
	"github.com/YurilLAB/coraza/carnical/vpatch/importers"
)

// Format is the CrowdSec AppSec rule format, for importers.Run.
var Format = importers.Format{Name: "crowdsec", Extensions: []string{".yaml", ".yml"}, Convert: convertFile}

// Convert converts a rule file, or every rule file under a directory.
func Convert(root string, opts importers.Options) (importers.Result, error) {
	return importers.Run(Format, root, opts)
}

// ConvertBytes converts the contents of one rule file.
func ConvertBytes(name string, data []byte, opts importers.Options) importers.Result {
	return importers.ConvertBytes(Format, name, data, opts)
}

// skipError is a reason a rule, or a part of one, cannot be converted.
type skipError struct{ reason string }

func (e *skipError) Error() string { return e.reason }

func skip(format string, args ...any) error {
	return &skipError{reason: fmt.Sprintf(format, args...)}
}

func reasonOf(err error) string {
	var se *skipError
	if errors.As(err, &se) {
		return se.reason
	}
	var re *importers.RegexError
	if errors.As(err, &re) {
		return "regex:" + re.Reason
	}
	switch {
	case errors.Is(err, importers.ErrTooManyAlternatives):
		return "or-expands-too-far"
	case errors.Is(err, importers.ErrTooManyConditions):
		return "too-many-conditions"
	case errors.Is(err, importers.ErrEmptyExpr):
		return "empty-and-or"
	case errors.Is(err, importers.ErrExprTooDeep):
		return "nested-too-deep"
	}
	return "invalid-rule"
}

func yamlReason(err error) string {
	switch {
	case errors.Is(err, importers.ErrYAMLTooLarge):
		return "yaml-too-large"
	case errors.Is(err, importers.ErrYAMLUnsafe):
		return "yaml-unsafe"
	case errors.Is(err, importers.ErrYAMLSlow):
		return "yaml-too-slow"
	case errors.Is(err, importers.ErrYAMLEmpty):
		return "yaml-empty"
	case errors.Is(err, importers.ErrYAMLMultiple):
		return "yaml-multiple-documents"
	case errors.Is(err, importers.ErrYAMLNotUTF8):
		return "yaml-not-utf8"
	case errors.Is(err, importers.ErrYAMLInternal):
		return "internal-error"
	}
	return "yaml-invalid"
}

// converter holds what is needed while one file is converted.
type converter struct {
	opts importers.Options
	lim  importers.Limits
	rep  *importers.Report
	// partial holds the reasons parts of the rule were left out; they are reported only if the rule yields signatures.
	partial []string
	// approx names the approximation a condition stands for, keyed by the condition's JSON, so that it is counted only for the
	// signatures that contain it.
	approx map[string]string
}

func convertFile(name string, data []byte, opts importers.Options, rep *importers.Report) []vpatch.Signature {
	rep.UnitsRead++
	lim := opts.Limits.Normalize()
	doc, err := importers.DecodeYAML(data, lim)
	if err != nil {
		rep.Skip(yamlReason(err), name)
		return nil
	}
	root, ok := importers.AsMap(doc)
	if !ok {
		rep.Skip("not-a-rule-file", name)
		return nil
	}
	ruleName := strings.TrimSuffix(strings.TrimSuffix(name, ".yaml"), ".yml")
	if s, ok := importers.AsString(root["name"]); ok && strings.TrimSpace(s) != "" {
		ruleName = s
	}
	// "crowdsecurity/vpatch-CVE-2024-4577": the organisation prefix is not part of the name.
	base := ruleName
	if i := strings.LastIndexByte(base, '/'); i >= 0 {
		base = base[i+1:]
	}
	base = importers.SafeToken(base, 80)
	if base == "" {
		rep.Skip("no-name", name)
		return nil
	}
	rulesV, hasRules := root["rules"]
	rules, ok := importers.AsList(rulesV)
	if !hasRules || !ok || len(rules) == 0 {
		if _, ok := root["seclang_rules"]; ok {
			rep.Skip("seclang-embedded", base)
		} else if _, ok := root["seclang_files_rules"]; ok {
			rep.Skip("seclang-embedded", base)
		} else {
			rep.Skip("no-rules", base)
		}
		return nil
	}
	labels, _ := importers.AsMap(root["labels"])
	if t, _ := importers.AsString(labels["type"]); strings.EqualFold(t, "test") {
		rep.Skip("test-rule", base)
		return nil
	}

	c := &converter{opts: opts, lim: lim, rep: rep, approx: map[string]string{}}
	var alts [][]vpatch.Condition
	var firstReason string
	for _, item := range rules {
		expr, err := c.parseNode(item, 0)
		if err != nil {
			if firstReason == "" {
				firstReason = reasonOf(err)
			}
			c.partial = append(c.partial, reasonOf(err))
			continue
		}
		a, err := expr.Expand(lim.MaxAlternatives, lim.MaxConditions)
		if err != nil {
			if firstReason == "" {
				firstReason = reasonOf(err)
			}
			c.partial = append(c.partial, reasonOf(err))
			continue
		}
		alts = append(alts, a...)
		if len(alts) > lim.MaxAlternatives {
			rep.Skip("or-expands-too-far", base)
			return nil
		}
	}
	if len(alts) == 0 {
		rep.Skip(firstReason, base)
		return nil
	}
	// Whatever the rule entries that failed were, they are not in the output: the result is narrower than the rule, never wider.

	meta := c.metadata(base, root, labels, alts, data)
	var out []vpatch.Signature
	for i, conds := range alts {
		main, also := importers.Assemble(conds)
		s := meta
		s.ID = "CS-" + importers.IDPart(strings.TrimPrefix(strings.ToLower(base), "vpatch-")) + "-" + strconv.Itoa(i+1)
		s.Condition = main
		s.Also = also
		s.Scope = importers.InferScope(pathsOf(conds), []string{ruleName, s.Description}, nil)
		out = append(out, s)
	}
	for _, r := range c.partial {
		rep.PartialSkip(r)
	}
	for _, s := range out {
		noteApproximations(rep, s, c.approx)
	}
	rep.UnitsConverted++
	return out
}

// noteApproximations counts the places where a signature's mapping is broader than CrowdSec's meaning: the model's "args" reads
// query and form arguments alike (CrowdSec's ARGS and BODY_ARGS read one each), and the model's "urldecode" repeats until the value
// stops changing (CrowdSec's decodes once more).
func noteApproximations(rep *importers.Report, s vpatch.Signature, named map[string]string) {
	args, repeated := false, false
	extra := map[string]bool{}
	for _, c := range append([]vpatch.Condition{s.Condition}, s.Also...) {
		if kind, ok := named[condKey(c)]; ok {
			extra[kind] = true
		}
		for _, t := range c.Targets {
			if t == vpatch.TargetArgs || strings.HasPrefix(t, "arg:") {
				args = true
			}
		}
		for _, t := range c.Transforms {
			if t == "urldecode" {
				repeated = true
			}
		}
	}
	if args {
		rep.Approximate("args-cover-query-and-form")
	}
	if repeated {
		rep.Approximate("urldecode-repeats-until-stable")
	}
	for _, k := range importers.SortedKeys(extra) {
		rep.Approximate(k)
	}
}

func condKey(c vpatch.Condition) string {
	b, _ := json.Marshal(c)
	return string(b)
}

// pathsOf returns the literal and regular-expression text that conditions on the path or URI carry, for scope inference.
func pathsOf(alts []vpatch.Condition) []string {
	var out []string
	for _, c := range alts {
		for _, t := range c.Targets {
			if t == vpatch.TargetPath || t == vpatch.TargetURI {
				out = append(out, c.Pattern)
			}
		}
	}
	return out
}

func (c *converter) metadata(base string, root, labels map[string]any, alts [][]vpatch.Condition, data []byte) vpatch.Signature {
	desc, _ := importers.AsString(root["description"])
	label, _ := importers.AsString(labels["label"])
	if strings.TrimSpace(desc) == "" {
		desc = label
	}
	class, _ := importers.AsStrings(labels["classification"])
	// The CVEs the rule's own name and classification give; a reference URL may name another product's CVE, so references are
	// not used. Only when those give none are the description and label read.
	cves := importers.CVEs(append([]string{base}, class...)...)
	if len(cves) == 0 {
		cves = importers.CVEs(desc, label)
	}
	category := ""
	for _, cl := range class {
		if strings.HasPrefix(strings.ToLower(cl), "cwe") {
			if cat := importers.CategoryFromCWE(cl); cat != "" {
				category = cat
				break
			}
		}
	}
	if category == "" {
		category = importers.ClassifyText(label, desc)
	}
	if category == "" {
		switch {
		case strings.Contains(strings.ToLower(base), "wordpress"):
			category = "wordpress"
		case len(cves) > 0:
			category = "cve"
		default:
			category = "other"
		}
	}
	conf := "medium"
	tier := c.opts.StartTier()
	if v, ok := labels["confidence"]; ok {
		n, _ := strconv.Atoi(strings.TrimSpace(fmt.Sprint(v)))
		switch {
		case n >= 3:
			conf = "high"
		case n == 2:
			conf = "medium"
		default:
			conf = "low"
		}
		if n <= 0 {
			tier = vpatch.TierExperimental // the source itself says it has no confidence in the rule
		}
	}
	return vpatch.Signature{
		Rev:         1,
		Description: importers.Describe(desc, 300),
		Category:    category,
		Severity:    importers.SeverityFor(category),
		Confidence:  conf,
		Action:      importers.ActionFor(conf),
		Score:       importers.ScoreFor(conf),
		CVEs:        cves,
		Sources:     []string{"crowdsec:" + base + "@" + c.opts.RevisionOr(data)},
		Tier:        tier,
	}
}
