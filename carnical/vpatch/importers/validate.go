// SPDX-License-Identifier: Apache-2.0

package importers

import (
	"fmt"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/YurilLAB/coraza/carnical/vpatch"
)

var (
	idRe       = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
	categories = map[string]bool{"sqli": true, "xss": true, "rce": true, "lfi": true, "rfi": true, "ssrf": true, "xxe": true, "ssti": true,
		"php": true, "java": true, "upload": true, "wordpress": true, "probe": true, "cve": true, "scanner": true, "protocol": true, "other": true}
	severities  = map[string]bool{"critical": true, "high": true, "medium": true, "low": true}
	confidences = map[string]bool{"high": true, "medium": true, "low": true}
	operators   = map[string]bool{vpatch.OpRegex: true, vpatch.OpContains: true, vpatch.OpPM: true, vpatch.OpEquals: true, vpatch.OpPrefix: true, vpatch.OpSuffix: true}
	plainTarget = map[string]bool{vpatch.TargetURI: true, vpatch.TargetPath: true, vpatch.TargetQuery: true, vpatch.TargetArgs: true,
		vpatch.TargetArgNames: true, vpatch.TargetCookies: true, vpatch.TargetCookieNames: true, vpatch.TargetBody: true,
		vpatch.TargetMethod: true, vpatch.TargetHeaders: true, vpatch.TargetFilenames: true, vpatch.TargetUploads: true}
	cveIDRe     = regexp.MustCompile(`^CVE-\d{4}-\d{4,7}$`)
	namedTarget = regexp.MustCompile(`^(header|arg|cookie):[\x21-\x7e]{1,128}$`)
)

// ValidTarget reports whether t is a target the model defines: a plain one or "header:NAME", "arg:NAME", "cookie:NAME".
func ValidTarget(t string) bool {
	return plainTarget[t] || namedTarget.MatchString(t)
}

// Validate checks that a signature is well formed in the model's own terms: known category, severity, operator, targets and
// transforms; a regular expression that compiles in Go; no empty literals. It is the safety net behind every converter: a
// signature that fails it is never written. maxPattern bounds the pattern length (0 means DefaultLimits).
func Validate(s vpatch.Signature, maxPattern, maxConds int) error {
	if maxPattern <= 0 {
		maxPattern = DefaultLimits().MaxPatternBytes
	}
	if maxConds <= 0 {
		maxConds = DefaultLimits().MaxConditions
	}
	if !idRe.MatchString(s.ID) {
		return fmt.Errorf("bad id")
	}
	if !categories[s.Category] {
		return fmt.Errorf("bad category %q", s.Category)
	}
	if !severities[s.Severity] {
		return fmt.Errorf("bad severity %q", s.Severity)
	}
	if s.Confidence != "" && !confidences[s.Confidence] {
		return fmt.Errorf("bad confidence %q", s.Confidence)
	}
	if s.Action != "" && s.Action != "block" && s.Action != "log" {
		return fmt.Errorf("bad action %q", s.Action)
	}
	if s.Score < 0 || s.Score > 10 {
		return fmt.Errorf("bad score %d", s.Score)
	}
	switch s.Tier {
	case "", vpatch.TierVerified, vpatch.TierCommunity, vpatch.TierExperimental:
	default:
		return fmt.Errorf("bad tier %q", s.Tier)
	}
	if s.Expires != "" {
		if _, err := time.Parse("2006-01-02", s.Expires); err != nil {
			return fmt.Errorf("bad expires")
		}
	}
	if !utf8.ValidString(s.Description) {
		return fmt.Errorf("description is not UTF-8")
	}
	if 1+len(s.Also) > maxConds {
		return fmt.Errorf("too many conditions")
	}
	if err := validCondition(s.Condition, maxPattern); err != nil {
		return fmt.Errorf("condition: %w", err)
	}
	for i, c := range s.Also {
		if err := validCondition(c, maxPattern); err != nil {
			return fmt.Errorf("also[%d]: %w", i, err)
		}
	}
	for _, c := range s.CVEs {
		if !cveIDRe.MatchString(c) {
			return fmt.Errorf("bad cve")
		}
	}
	for _, sc := range s.Scope {
		if !scopeOK(sc) {
			return fmt.Errorf("bad scope")
		}
	}
	return nil
}

func validCondition(c vpatch.Condition, maxPattern int) error {
	if !operators[c.Operator] {
		return fmt.Errorf("bad operator %q", c.Operator)
	}
	if len(c.Targets) == 0 {
		return fmt.Errorf("no targets")
	}
	for _, t := range c.Targets {
		if !ValidTarget(t) {
			return fmt.Errorf("bad target %q", t)
		}
	}
	for _, t := range c.Transforms {
		if !KnownTransforms[t] {
			return fmt.Errorf("bad transform %q", t)
		}
	}
	for _, f := range c.Flags {
		if f != 'i' && f != 's' && f != 'm' {
			return fmt.Errorf("bad flags")
		}
	}
	if len(c.Pattern) > maxPattern {
		return fmt.Errorf("pattern too long")
	}
	if !utf8.ValidString(c.Pattern) {
		return fmt.Errorf("pattern is not UTF-8")
	}
	switch c.Operator {
	case vpatch.OpRegex:
		if _, err := regexp.Compile(flagPrefix(c.Flags) + c.Pattern); err != nil {
			return fmt.Errorf("regex does not compile")
		}
	case vpatch.OpPM:
		words := c.Patterns
		if len(words) == 0 {
			words = strings.Fields(c.Pattern)
		}
		if len(words) == 0 {
			return fmt.Errorf("pm without words")
		}
		total := 0
		for _, w := range words {
			if w == "" {
				return fmt.Errorf("pm with an empty word")
			}
			if !utf8.ValidString(w) {
				return fmt.Errorf("pm word is not UTF-8")
			}
			total += len(w)
		}
		if total > maxPattern*8 {
			return fmt.Errorf("pm list too long")
		}
	default:
		if c.Pattern == "" {
			return fmt.Errorf("empty pattern")
		}
	}
	return nil
}
