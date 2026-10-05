// SPDX-License-Identifier: Apache-2.0

package vpatch

import (
	"fmt"
	"strings"
	"time"
	"unicode/utf8"
)

// The kinds of value a target can name. The request is parsed into these views, lazily, and every condition reads one or more.
const (
	kURI = iota
	kPath
	kQuery
	kArgs
	kArgNames
	kCookies
	kCookieNames
	kHeaders
	kBody
	kMethod
	kFilenames
	kUploads
	numKinds
)

var kindByName = map[string]uint8{
	TargetURI:         kURI,
	TargetPath:        kPath,
	TargetQuery:       kQuery,
	TargetArgs:        kArgs,
	TargetArgNames:    kArgNames,
	TargetCookies:     kCookies,
	TargetCookieNames: kCookieNames,
	TargetBody:        kBody,
	TargetMethod:      kMethod,
	TargetHeaders:     kHeaders,
	TargetFilenames:   kFilenames,
	TargetUploads:     kUploads,
}

const (
	opRx = iota
	opContains
	opPM
	opEquals
	opPrefix
	opSuffix
)

var opByName = map[string]uint8{
	OpRegex: opRx, OpContains: opContains, OpPM: opPM, OpEquals: opEquals, OpPrefix: opPrefix, OpSuffix: opSuffix,
}

// Limits on the shape of one signature, so that a malformed feed cannot make the loader allocate without bound.
const (
	maxConditions  = 16
	maxTargets     = 16
	maxTransforms  = 16
	maxIDLen       = 128
	maxDescLen     = 1024
	maxNameLen     = 128
	maxPMWords     = 20000
	maxPMWordLen   = 1024
	maxPMTotal     = 1 << 20
	maxStringPat   = 8 << 10
	maxCVEs        = 32
	maxScopeTags   = 32
	maxVerdictDesc = 160
)

// targetC is one place a condition looks: a kind of value, and for "header:NAME", "arg:NAME" and "cookie:NAME" the name that
// picks one value from it.
type targetC struct {
	kind uint8
	name string
}

// condC is a compiled condition.
type condC struct {
	sig  int32
	op   uint8
	neg  bool
	fold bool // case-insensitive comparison for the string operators

	str  string   // contains, equals, prefix, suffix (lower-cased if fold)
	strs []string // pm (lower-cased if fold)
	prog *rxProg

	rxPattern string
	rxFlags   string

	targets  []targetC
	tnames   []string // the transforms, in order
	fns      []transformFn
	chain    int32 // interned by the snapshot
	anchors  []string
	cost     int
	anchored bool
}

// sigC is a compiled signature, holding what a verdict needs and its conditions in the order they are evaluated.
type sigC struct {
	id       string
	desc     string
	category string
	severity string
	action   string
	tier     string
	cves     []string
	idNum    int
	conds    []int32 // indices into the snapshot's conditions, cheapest first
	gates    []int32 // the conditions that have required literals: if the index did not find one, the signature cannot match
	driver   int32   // the condition whose literals nominate this signature as a candidate, or -1
}

// prepared is a signature that passed the checks that need no regular expression, with its conditions in source order (main
// first).
type prepared struct {
	sig   Signature
	tier  string
	conds []condC
}

var severityRank = map[string]int{"low": 1, "medium": 2, "high": 3, "critical": 4}

// reject is the reason a signature was not loaded.
type reject struct{ reason string }

func (r reject) Error() string { return r.reason }

func rejectf(format string, a ...any) error { return reject{fmt.Sprintf(format, a...)} }

func validText(s string) bool {
	if !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	return true
}

func validIDChar(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '.' || c == '_' || c == ':' || c == '-' || c == '@' || c == '/' || c == '+'
}

// validateSignature checks everything about a signature that does not need a compiled regular expression, and returns its
// conditions ready for that step.
func validateSignature(sig *Signature) (*prepared, error) {
	if sig.ID == "" || len(sig.ID) > maxIDLen {
		return nil, rejectf("the ID must be 1 to %d characters", maxIDLen)
	}
	for i := 0; i < len(sig.ID); i++ {
		if !validIDChar(sig.ID[i]) {
			return nil, rejectf("the ID has a character outside A-Z a-z 0-9 . _ : - @ / +")
		}
	}
	if _, ok := severityRank[sig.Severity]; !ok {
		return nil, rejectf("the severity must be critical, high, medium or low")
	}
	switch sig.Action {
	case "", "block", "log":
	default:
		return nil, rejectf("the action must be block or log")
	}
	switch sig.Confidence {
	case "", "high", "medium", "low":
	default:
		return nil, rejectf("the confidence must be high, medium or low")
	}
	tier := sig.Tier
	if tier == "" {
		tier = TierVerified
	}
	switch tier {
	case TierVerified, TierCommunity, TierExperimental:
	default:
		return nil, rejectf("unknown tier %q", clip(sig.Tier, 32))
	}
	if sig.Score < 0 || sig.Score > 10 {
		return nil, rejectf("the score must be 0 to 10")
	}
	if len(sig.Description) > maxDescLen || !utf8.ValidString(sig.Description) {
		return nil, rejectf("the description is too long or not valid text")
	}
	if len(sig.CVEs) > maxCVEs {
		return nil, rejectf("more than %d CVEs", maxCVEs)
	}
	for _, c := range sig.CVEs {
		if len(c) == 0 || len(c) > 40 || !validText(c) {
			return nil, rejectf("a CVE identifier is empty, too long or not plain text")
		}
	}
	if len(sig.Scope) > maxScopeTags {
		return nil, rejectf("more than %d scope tags", maxScopeTags)
	}
	for _, s := range sig.Scope {
		if s == "" || len(s) > maxNameLen || !validText(s) {
			return nil, rejectf("a scope tag is empty, too long or not plain text")
		}
	}
	if sig.Expires != "" {
		if _, err := time.Parse("2006-01-02", sig.Expires); err != nil {
			return nil, rejectf("expires must be a date such as 2026-12-31")
		}
	}
	if 1+len(sig.Also) > maxConditions {
		return nil, rejectf("more than %d conditions", maxConditions)
	}
	p := &prepared{sig: *sig, tier: tier}
	all := make([]*Condition, 0, 1+len(sig.Also))
	all = append(all, &p.sig.Condition)
	for i := range p.sig.Also {
		all = append(all, &p.sig.Also[i])
	}
	for i, c := range all {
		cc, err := validateCondition(c)
		if err != nil {
			where := "the main condition"
			if i > 0 {
				where = fmt.Sprintf("condition %d of Also", i)
			}
			return nil, rejectf("%s: %s", where, err.Error())
		}
		p.conds = append(p.conds, *cc)
	}
	return p, nil
}

func clip(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

func validateCondition(c *Condition) (*condC, error) {
	op, ok := opByName[c.Operator]
	if !ok {
		return nil, fmt.Errorf("unknown operator %q", clip(c.Operator, 32))
	}
	cc := &condC{op: op, neg: c.Negate}
	if op != opRx {
		for _, f := range c.Flags {
			if f != 'i' {
				return nil, fmt.Errorf("the flag %q does not apply to the %s operator", string(f), c.Operator)
			}
		}
		cc.fold = strings.Contains(c.Flags, "i")
	}
	switch op {
	case opRx:
		if c.Pattern == "" {
			return nil, fmt.Errorf("an rx condition needs a Pattern")
		}
		if len(c.Patterns) > 0 {
			return nil, fmt.Errorf("Patterns is for the pm operator")
		}
		cc.rxPattern, cc.rxFlags = c.Pattern, c.Flags
	case opPM:
		words := c.Patterns
		switch {
		case len(words) > 0 && c.Pattern != "":
			return nil, fmt.Errorf("give pm either Pattern or Patterns, not both")
		case len(words) == 0:
			words = strings.Fields(c.Pattern)
		}
		if len(words) == 0 {
			return nil, fmt.Errorf("a pm condition needs at least one word")
		}
		if len(words) > maxPMWords {
			return nil, fmt.Errorf("a pm condition has more than %d words", maxPMWords)
		}
		total := 0
		cc.strs = make([]string, 0, len(words))
		for _, w := range words {
			if w == "" {
				return nil, fmt.Errorf("a pm word is empty (it would match every value)")
			}
			if len(w) > maxPMWordLen {
				return nil, fmt.Errorf("a pm word is longer than %d bytes", maxPMWordLen)
			}
			total += len(w)
			if cc.fold {
				w = lowerASCII(w)
			}
			cc.strs = append(cc.strs, w)
		}
		if total > maxPMTotal {
			return nil, fmt.Errorf("the pm words total more than %d bytes", maxPMTotal)
		}
	default:
		if c.Pattern == "" {
			return nil, fmt.Errorf("the %s operator needs a Pattern (an empty one would match every value)", c.Operator)
		}
		if len(c.Patterns) > 0 {
			return nil, fmt.Errorf("Patterns is for the pm operator")
		}
		if len(c.Pattern) > maxStringPat {
			return nil, fmt.Errorf("the Pattern is longer than %d bytes", maxStringPat)
		}
		cc.str = c.Pattern
		if cc.fold {
			cc.str = lowerASCII(cc.str)
		}
	}
	if len(c.Targets) == 0 || len(c.Targets) > maxTargets {
		return nil, fmt.Errorf("a condition needs 1 to %d targets", maxTargets)
	}
	for _, t := range c.Targets {
		tg, err := parseTarget(t)
		if err != nil {
			return nil, err
		}
		cc.targets = append(cc.targets, tg)
	}
	if len(c.Transforms) > maxTransforms {
		return nil, fmt.Errorf("more than %d transforms", maxTransforms)
	}
	for _, name := range c.Transforms {
		fn, ok := transforms[name]
		if !ok {
			return nil, fmt.Errorf("unknown transform %q", clip(name, 32))
		}
		cc.tnames = append(cc.tnames, name)
		cc.fns = append(cc.fns, fn)
	}
	cc.cost = condCost(cc)
	return cc, nil
}

func parseTarget(t string) (targetC, error) {
	if k, ok := kindByName[t]; ok {
		return targetC{kind: k}, nil
	}
	i := strings.IndexByte(t, ':')
	if i < 0 {
		return targetC{}, fmt.Errorf("unknown target %q", clip(t, 40))
	}
	prefix, name := t[:i], t[i+1:]
	if name == "" || len(name) > maxNameLen || !validText(name) {
		return targetC{}, fmt.Errorf("the target %q has an empty or invalid name", clip(t, 40))
	}
	switch prefix {
	case "header":
		return targetC{kind: kHeaders, name: name}, nil
	case "arg":
		return targetC{kind: kArgs, name: name}, nil
	case "cookie":
		return targetC{kind: kCookies, name: name}, nil
	}
	return targetC{}, fmt.Errorf("unknown target %q", clip(t, 40))
}

// condCost orders a signature's conditions so that the cheapest to evaluate, and the most likely to fail, run first.
func condCost(c *condC) int {
	switch c.op {
	case opEquals, opPrefix, opSuffix:
		return 1
	case opContains:
		return 2
	case opPM:
		return 3 + len(c.strs)/32
	}
	return 10
}

// stringAnchors are the literals a string-operator condition requires: the pattern itself (or any word, for pm).
func stringAnchors(c *condC) []string {
	if c.neg {
		return nil
	}
	switch c.op {
	case opPM:
		lits := make([]string, len(c.strs))
		for i, w := range c.strs {
			lits[i] = lowerASCII(w)
		}
		return finalizeLits(lits)
	case opRx:
		return nil
	}
	return finalizeLits([]string{lowerASCII(c.str)})
}
