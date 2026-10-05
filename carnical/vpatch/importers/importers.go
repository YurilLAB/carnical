// SPDX-License-Identifier: Apache-2.0

// Package importers is the shared kit for turning rules published in other formats (CrowdSec AppSec vpatch rules, Suricata and
// Snort HTTP rules, nuclei templates, a subset of SecLang) into []vpatch.Signature, with a report of what was skipped and why.
//
// Each format lives in its own sub-package (crowdsec, suricata, nuclei, seclang). They share the pieces here: the report, the
// limits that bound untrusted input, the translation of PCRE-only regular expression syntax to RE2 where that is exact, the
// expansion of "or" into several signatures, the choice of a main condition, and the inference of CVEs, scope and category.
//
// The rules a converter reads are untrusted input. A feed can be wrong, hostile or just huge, so everything here is bounded by the
// size of the input (see Limits), nothing panics on any input, and a rule the converter does not fully understand is skipped with a
// reason; it is never approximated without the report saying so.
package importers

import (
	"github.com/YurilLAB/coraza/carnical/vpatch"
)

// Options controls one conversion.
type Options struct {
	// Tier is the tier given to a signature that was converted without loss. Empty means vpatch.TierCommunity: a converted rule
	// has come from one source and has not been checked against ordinary traffic. A signature that lost a constraint on the way
	// (an ordering the model cannot express, a rate limit) is given the next tier down.
	Tier string
	// Revision is written after the "@" in Sources. Empty means the importer uses what the format carries (a rule's own rev) or,
	// failing that, the first 12 hex characters of the SHA-256 of the file the rule came from.
	Revision string
	// Limits bound untrusted input. The zero value means DefaultLimits.
	Limits Limits
	// AllowCopyleft lets the Suricata importer convert rules whose licence is not permissive. The Emerging Threats files say that rules
	// with sids 1 to 3464 and 100000000 to 100000908 are GPLv2 and only 2000000 to 2799999 are BSD; converting a GPL rule into a
	// signature may make the signature a derived work, so those rules are skipped unless this is set.
	AllowCopyleft bool
}

// Limits bound what one conversion may spend, as a function of the input size, so that a feed cannot use unbounded time or memory.
type Limits struct {
	// MaxFileBytes is the largest rule file that is read. Larger files are skipped and reported.
	MaxFileBytes int64
	// MaxDocBytes is the largest single YAML document or SecLang rule that is parsed. YAML parsers recurse and expand aliases, and
	// the one used here costs more than linear time on hostile input, so this is much smaller than MaxFileBytes. The largest of the
	// 5,556 real rule files this was checked against is 207 KB.
	MaxDocBytes int
	// MaxFiles is the most files a directory walk reads.
	MaxFiles int
	// MaxAlternatives is the most signatures one rule may expand to (an "or" of many branches). A rule that would exceed it is skipped.
	MaxAlternatives int
	// MaxConditions is the most conditions (main plus Also) in one signature.
	MaxConditions int
	// MaxPatternBytes is the longest regular expression, literal or word list that is kept.
	MaxPatternBytes int
	// MaxNesting is the deepest nesting of and/or, groups and YAML flow collections that is accepted.
	MaxNesting int
}

// DefaultLimits are used when Options.Limits is the zero value.
func DefaultLimits() Limits {
	return Limits{
		MaxFileBytes:    64 << 20,
		MaxDocBytes:     256 << 10,
		MaxFiles:        200000,
		MaxAlternatives: 64,
		MaxConditions:   24,
		MaxPatternBytes: 8 << 10,
		MaxNesting:      16,
	}
}

// Normalize fills the zero fields of l from DefaultLimits.
func (l Limits) Normalize() Limits {
	d := DefaultLimits()
	if l.MaxFileBytes <= 0 {
		l.MaxFileBytes = d.MaxFileBytes
	}
	if l.MaxDocBytes <= 0 {
		l.MaxDocBytes = d.MaxDocBytes
	}
	if l.MaxFiles <= 0 {
		l.MaxFiles = d.MaxFiles
	}
	if l.MaxAlternatives <= 0 {
		l.MaxAlternatives = d.MaxAlternatives
	}
	if l.MaxConditions <= 0 {
		l.MaxConditions = d.MaxConditions
	}
	if l.MaxPatternBytes <= 0 {
		l.MaxPatternBytes = d.MaxPatternBytes
	}
	if l.MaxNesting <= 0 {
		l.MaxNesting = d.MaxNesting
	}
	return l
}

// StartTier is the tier a converted signature starts with, given opts.
func (o Options) StartTier() string {
	switch o.Tier {
	case vpatch.TierVerified, vpatch.TierCommunity, vpatch.TierExperimental:
		return o.Tier
	}
	return vpatch.TierCommunity
}

// LowerTier returns the tier one step less trusted than t. Experimental stays experimental.
func LowerTier(t string) string {
	switch t {
	case vpatch.TierVerified, "":
		return vpatch.TierCommunity
	default:
		return vpatch.TierExperimental
	}
}

// Result is what a conversion produced.
type Result struct {
	Signatures []vpatch.Signature `json:"-"`
	Report     Report             `json:"report"`
}
