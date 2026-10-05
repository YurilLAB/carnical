// SPDX-License-Identifier: Apache-2.0

package importers

import (
	"encoding/json"
	"io"
	"sort"

	"github.com/YurilLAB/coraza/carnical/vpatch"
)

// maxExamples is how many example unit names a report keeps for each reason.
const maxExamples = 3

// maxErrors is how many file-level problems a report keeps.
const maxErrors = 50

// RegexStats counts the regular expressions a converter met in its input, before any rule was dropped for having one that does not
// compile. "Translated" means the pattern did not compile as written and did compile after an exact translation (a possessive
// quantifier or an atomic group that provably means the same without it).
type RegexStats struct {
	Seen       int            `json:"seen"`
	Compiled   int            `json:"compiled_as_written"`
	Translated int            `json:"compiled_after_translation"`
	Failed     int            `json:"failed"`
	FailReason map[string]int `json:"fail_reasons,omitempty"`
}

// Report says what a conversion did. A "unit" is the thing the format calls one rule: a CrowdSec rule file, a Suricata rule, a
// nuclei template, a SecLang rule (with its chain).
type Report struct {
	Format         string `json:"format"`
	FilesRead      int    `json:"files_read"`
	FilesSkipped   int    `json:"files_skipped"`
	UnitsRead      int    `json:"units_read"`
	UnitsConverted int    `json:"units_converted"`
	Signatures     int    `json:"signatures"`
	// Skipped counts units that produced no signature, by reason.
	Skipped map[string]int `json:"skipped"`
	// Examples are up to three unit names for each skip reason, so a reason can be looked at.
	Examples map[string][]string `json:"skipped_examples,omitempty"`
	// Partial counts parts of a converted unit that were left out (an "or" branch, one request of several), by reason. The
	// signature that remains is narrower than the rule was, never broader.
	Partial map[string]int `json:"partial,omitempty"`
	// Dropped counts signatures that lost a constraint the model cannot express, by kind. They are one tier lower for it.
	Dropped map[string]int `json:"dropped_constraints,omitempty"`
	// Approximations counts signatures that use a mapping known to differ from the source's meaning in some detail, by kind.
	Approximations map[string]int `json:"approximations,omitempty"`
	// Ignored counts lines of the input that are not rules and were not looked at (SecLang configuration directives, for example), by
	// name. They are not units.
	Ignored map[string]int `json:"ignored,omitempty"`
	// Tiers counts signatures by the tier they were given.
	Tiers map[string]int `json:"tiers"`
	Regex RegexStats     `json:"regex"`
	// Errors are file-level problems (unreadable, too large, not text), capped.
	Errors []string `json:"errors,omitempty"`
}

// NewReport starts a report for a format.
func NewReport(format string) *Report {
	return &Report{
		Format:         format,
		Skipped:        map[string]int{},
		Examples:       map[string][]string{},
		Partial:        map[string]int{},
		Dropped:        map[string]int{},
		Approximations: map[string]int{},
		Ignored:        map[string]int{},
		Tiers:          map[string]int{},
		Regex:          RegexStats{FailReason: map[string]int{}},
	}
}

// Skip records that a unit produced no signature, and why. The name is kept as an example for the first few of each reason.
func (r *Report) Skip(reason, unit string) {
	r.Skipped[reason]++
	if ex := r.Examples[reason]; len(ex) < maxExamples {
		r.Examples[reason] = append(ex, unit)
	}
}

// PartialSkip records that part of a unit that did convert was left out.
func (r *Report) PartialSkip(reason string) { r.Partial[reason]++ }

// Ignore records a line that is not a rule and was not looked at.
func (r *Report) Ignore(what string) { r.Ignored[what]++ }

// Drop records that a signature lost a constraint of the given kind.
func (r *Report) Drop(kind string) { r.Dropped[kind]++ }

// Approximate records that a signature uses a mapping that differs from the source in some detail.
func (r *Report) Approximate(kind string) { r.Approximations[kind]++ }

// Error records a file-level problem. Only the first few are kept; the text must not hold rule contents.
func (r *Report) Error(msg string) {
	if len(r.Errors) < maxErrors {
		r.Errors = append(r.Errors, msg)
	}
}

// AddSignatures counts signatures by tier. An empty tier means verified, as in the model.
func (r *Report) AddSignatures(sigs []vpatch.Signature) {
	for _, s := range sigs {
		r.Signatures++
		t := s.Tier
		if t == "" {
			t = vpatch.TierVerified
		}
		r.Tiers[t]++
	}
}

// Merge adds the counts of o into r.
func (r *Report) Merge(o *Report) {
	r.FilesRead += o.FilesRead
	r.FilesSkipped += o.FilesSkipped
	r.UnitsRead += o.UnitsRead
	r.UnitsConverted += o.UnitsConverted
	r.Signatures += o.Signatures
	for k, v := range o.Skipped {
		r.Skipped[k] += v
	}
	for k, ex := range o.Examples {
		for _, e := range ex {
			if len(r.Examples[k]) < maxExamples {
				r.Examples[k] = append(r.Examples[k], e)
			}
		}
	}
	for k, v := range o.Partial {
		r.Partial[k] += v
	}
	for k, v := range o.Dropped {
		r.Dropped[k] += v
	}
	for k, v := range o.Approximations {
		r.Approximations[k] += v
	}
	for k, v := range o.Ignored {
		r.Ignored[k] += v
	}
	for k, v := range o.Tiers {
		r.Tiers[k] += v
	}
	r.Regex.Seen += o.Regex.Seen
	r.Regex.Compiled += o.Regex.Compiled
	r.Regex.Translated += o.Regex.Translated
	r.Regex.Failed += o.Regex.Failed
	for k, v := range o.Regex.FailReason {
		r.Regex.FailReason[k] += v
	}
	for _, e := range o.Errors {
		r.Error(e)
	}
}

// SkippedTotal is the number of units that produced no signature.
func (r *Report) SkippedTotal() int {
	n := 0
	for _, v := range r.Skipped {
		n += v
	}
	return n
}

// TopSkips returns the n most common skip reasons, most common first, ties by name.
func (r *Report) TopSkips(n int) []ReasonCount {
	return topCounts(r.Skipped, n)
}

// ReasonCount is a reason and how many times it happened.
type ReasonCount struct {
	Reason string `json:"reason"`
	Count  int    `json:"count"`
}

func topCounts(m map[string]int, n int) []ReasonCount {
	out := make([]ReasonCount, 0, len(m))
	for k, v := range m {
		out = append(out, ReasonCount{k, v})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].Reason < out[j].Reason
	})
	if n > 0 && len(out) > n {
		out = out[:n]
	}
	return out
}

// WriteJSON writes the report as indented JSON.
func (r *Report) WriteJSON(w io.Writer) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	return enc.Encode(r)
}
