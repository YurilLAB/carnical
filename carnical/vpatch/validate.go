// SPDX-License-Identifier: Apache-2.0

package vpatch

import (
	"sort"

	"github.com/YurilLAB/coraza/carnical/inspect"
)

// SampleResult is how one signature fared against the samples written for it.
type SampleResult struct {
	ID   string
	Tier string
	// Loaded is false if the engine did not load the signature (its tier is off, or it was rejected).
	Loaded bool
	// Attacks is the number of attack samples written for it and AttacksCaught how many of them it matches. Benign is the number
	// of benign samples written for it and BenignTripped how many of those it wrongly matches.
	Attacks, AttacksCaught int
	Benign, BenignTripped  int
}

// Passes is true if the signature catches every one of its attack samples and none of its benign ones.
func (r SampleResult) Passes() bool {
	return r.Loaded && r.AttacksCaught == r.Attacks && r.BenignTripped == 0
}

// ValidateSamples runs each sample against the engine and reports, per signature in sigs, whether its own attack samples match it
// and its own benign samples do not. Samples named for a signature that is not in sigs are ignored. The results are in ID order.
func ValidateSamples(e *Engine, sigs []Signature, samples []Sample) []SampleResult {
	byID := make(map[string]*SampleResult, len(sigs))
	for i := range sigs {
		s := &sigs[i]
		tier := s.Tier
		if tier == "" {
			tier = TierVerified
		}
		byID[s.ID] = &SampleResult{ID: s.ID, Tier: tier, Loaded: e.Loaded(s.ID)}
	}
	for _, sm := range samples {
		r := byID[sm.Sig]
		if r == nil {
			continue
		}
		matched := false
		if r.Loaded {
			matched = sm.matches(e, sm.Sig)
		}
		switch sm.Kind {
		case "attack":
			r.Attacks++
			if matched {
				r.AttacksCaught++
			}
		case "benign":
			r.Benign++
			if matched {
				r.BenignTripped++
			}
		}
	}
	out := make([]SampleResult, 0, len(byID))
	for _, r := range byID {
		out = append(out, *r)
	}
	sort.Slice(out, func(a, b int) bool { return out[a].ID < out[b].ID })
	return out
}

// matches reports whether the signature with this ID matches the sample, reading it both ways if it can be read two ways.
func (sm Sample) matches(e *Engine, id string) bool {
	for _, req := range [2]*inspect.Request{sm.Request, sm.Alt} {
		if req == nil {
			continue
		}
		for _, h := range e.Match(req) {
			if h.ID == id {
				return true
			}
		}
	}
	return false
}

// MatchAny returns the signatures that match the sample, reading it both ways if it can be read two ways.
func (sm Sample) MatchAny(e *Engine) []Hit {
	hits := e.Match(sm.Request)
	if sm.Alt == nil {
		return hits
	}
	have := map[string]bool{}
	for _, h := range hits {
		have[h.ID] = true
	}
	for _, h := range e.Match(sm.Alt) {
		if !have[h.ID] {
			hits = append(hits, h)
		}
	}
	return hits
}
