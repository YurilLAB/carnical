// SPDX-License-Identifier: Apache-2.0

package policy

// Preset is what a sensitivity means to the Core Rule Set.
type Preset struct {
	// ParanoiaLevel is the paranoia level whose rules can block (1 to 4). Each level up adds rules that catch more and
	// wrongly flag more ordinary traffic.
	ParanoiaLevel int
	// InboundThreshold is the anomaly score at which a request is blocked. The rules score 5 (critical), 4 (error), 3
	// (warning) or 2 (notice) each, so 5 is one critical rule and 8 is a critical rule and a warning.
	InboundThreshold int
	// OutboundThreshold is the same for a response, and matters only when responses are inspected.
	OutboundThreshold int
}

// presets are the three sensitivities. The figures come from the paranoia-level measurements in the README (715 requests, 468
// of them deliberately tricky ordinary ones and 247 attacks): level 1 wrongly blocks 2.4% of the ordinary ones and finds
// 82.6% of the attacks, level 2 wrongly blocks 8.3% and finds 86.2%, and levels 3 and 4 block more than a site can use without
// weeks of tuning, so no sensitivity uses them. A site that needs them can still be given them: set the threshold, or ask the
// operator.
//
//	relaxed   level 1, blocks at 8    a lone critical rule (5) is not enough; it takes a second rule with it. Fewer wrongly
//	                                  refused requests, and the attacks that trip only one rule get through.
//	normal    level 1, blocks at 5    the Core Rule Set as published. One critical rule is enough.
//	strict    level 2, blocks at 5    the rules of level 2 as well, which find more and flag more. Use it once the site's
//	                                  exclusions have been tuned at normal.
//
// The detection paranoia level is left equal to the blocking one: asking the engine to also run the next level up only to log
// it would double the log with matches nobody blocked on, and cost the rules' time for it.
var presets = map[Sensitivity]Preset{
	SensitivityRelaxed: {ParanoiaLevel: 1, InboundThreshold: 8, OutboundThreshold: 8},
	SensitivityNormal:  {ParanoiaLevel: 1, InboundThreshold: 5, OutboundThreshold: 4},
	SensitivityStrict:  {ParanoiaLevel: 2, InboundThreshold: 5, OutboundThreshold: 4},
}

// PresetFor returns what a sensitivity means, and false for a name that is not one.
func PresetFor(s Sensitivity) (Preset, bool) {
	p, ok := presets[s]
	return p, ok
}

// effective is the paranoia level and threshold a policy really runs with: the preset's, with the threshold replaced if the
// policy sets one.
func (p Policy) effective() (paranoia, inbound int) {
	pre := presets[p.Sensitivity]
	inbound = pre.InboundThreshold
	if p.Threshold != nil {
		inbound = *p.Threshold
	}
	return pre.ParanoiaLevel, inbound
}
