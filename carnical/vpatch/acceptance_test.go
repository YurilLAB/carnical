// SPDX-License-Identifier: Apache-2.0

package vpatch

import (
	"sort"
	"strings"
	"testing"

	"github.com/YurilLAB/coraza/carnical/inspect"
)

// TestAcceptance measures what the library does with the engine: how much loads, how the signatures fare against their own
// samples, what each tier costs in false positives on the benign corpus and buys in detection on the attack corpus. It logs the
// numbers that docs/vpatch.md quotes, and fails if they get worse than the guards below, which sit a little under what was
// measured. It needs the data described in data_test.go and is skipped without it.
func TestAcceptance(t *testing.T) {
	sigs := library(t)
	allSamples := readSamplesFile(t, samplesPath(t), "")
	benign := readSamplesFile(t, corpusPath(t, "benign.jsonl"), "benign")
	attack := readSamplesFile(t, corpusPath(t, "attack.jsonl"), "attack")
	var benignSamples, attackSamples []Sample
	for _, s := range allSamples {
		if s.Kind == "benign" {
			benignSamples = append(benignSamples, s)
		} else {
			attackSamples = append(attackSamples, s)
		}
	}
	byID := map[string]Signature{}
	for _, s := range sigs {
		byID[s.ID] = s
	}
	t.Logf("library: %d signatures read (the file has 8,052 lines; the 25 marked rejected are not read)", len(sigs))

	tierSets := []struct {
		name  string
		tiers []string
	}{
		{"verified", []string{TierVerified}},
		{"community", []string{TierCommunity}},
		{"experimental", []string{TierExperimental}},
		{"verified+community", []string{TierVerified, TierCommunity}},
		{"all three", allTiers},
	}
	for _, ts := range tierSets {
		e := New(Options{Tiers: ts.tiers})
		rep := e.Load(sigs)
		tripped := func(set []Sample) (n int, sigsHit map[string]int) {
			sigsHit = map[string]int{}
			for _, s := range set {
				h := s.MatchAny(e)
				if len(h) > 0 {
					n++
				}
				for _, x := range h {
					sigsHit[x.ID]++
				}
			}
			return
		}
		fpCorpus, fpSigs := tripped(benign)
		fpSamples, _ := tripped(benignSamples)
		caught, _ := tripped(attack)
		t.Logf("%-19s loaded %4d (%d rejected as invalid, %d unindexed) | benign corpus: %d of %d wrongly matched (%v) | benign samples: %d of %d | attack corpus: %d of %d detected (%.1f%%)",
			ts.name, rep.LoadedTotal, len(rep.Rejected), rep.Unindexed, fpCorpus, len(benign), topKeys(fpSigs, 3), fpSamples, len(benignSamples), caught, len(attack), 100*float64(caught)/float64(len(attack)))
		if ts.name == "verified" {
			if fpCorpus != 0 {
				t.Errorf("the verified tier wrongly matched %d of the benign corpus", fpCorpus)
			}
			if caught < 200 {
				t.Errorf("the verified tier detects only %d of %d attacks", caught, len(attack))
			}
		}
	}

	// every signature against its own samples, per tier
	for _, ts := range tierSets[:3] {
		e := New(Options{Tiers: ts.tiers})
		e.Load(sigs)
		res := ValidateSamples(e, sigs, allSamples)
		var loaded, strict, most, gate, tripBenign, noAttack int
		var fail []string
		for _, r := range res {
			if !r.Loaded {
				continue
			}
			loaded++
			rate := 1.0
			if r.Attacks > 0 {
				rate = float64(r.AttacksCaught) / float64(r.Attacks)
			} else {
				noAttack++
			}
			if r.Passes() {
				strict++
			}
			if rate >= 0.8 {
				most++
			}
			need := 0.8
			if srcOf(byID[r.ID]) == "first-party" {
				need = 1.0
			}
			if rate >= need && r.BenignTripped == 0 {
				gate++
			} else {
				fail = append(fail, r.ID)
			}
			if r.BenignTripped > 0 {
				tripBenign++
			}
		}
		t.Logf("%-12s own samples: %d loaded; all attack samples caught and no benign tripped: %d; at least 80%% of attack samples: %d; the library's own gate (first-party 100%%, others 80%%, no benign): %d; trip a benign sample: %d; no attack samples: %d",
			ts.name, loaded, strict, most, gate, tripBenign, noAttack)
		if ts.name == "verified" {
			explainFailures(t, e, sigs, byID, allSamples, fail)
			if strict < 1380 {
				t.Errorf("only %d verified signatures pass their own samples completely", strict)
			}
		}
	}
	_ = attackSamples
}

func srcOf(s Signature) string {
	if len(s.Sources) == 0 {
		return "?"
	}
	src := s.Sources[0]
	if i := strings.IndexAny(src, ":@"); i > 0 {
		src = src[:i]
	}
	return src
}

func topKeys(m map[string]int, n int) string {
	var keys []string
	for k := range m {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(a, b int) bool {
		if m[keys[a]] != m[keys[b]] {
			return m[keys[a]] > m[keys[b]]
		}
		return keys[a] < keys[b]
	})
	if len(keys) > n {
		keys = keys[:n]
	}
	return strings.Join(keys, ",")
}

// explainFailures says, for the verified signatures that fail the library's own gate, whether the engine or the signature is at
// fault, as far as that can be decided without a second engine: a sample that is another signature's attack (the samples are
// attached to a CVE, and a CVE can have several signatures), a sample the signature cannot match under any decoding because a
// literal it requires is not in the request, a benign sample that is really an attack, and the rest, which are listed.
func explainFailures(t *testing.T, e *Engine, sigs []Signature, byID map[string]Signature, samples []Sample, failing []string) {
	all := New(Options{Tiers: allTiers})
	all.Load(sigs)
	cves := func(id string) map[string]bool {
		m := map[string]bool{}
		for _, c := range byID[id].CVEs {
			m[c] = true
		}
		return m
	}
	sibling, absent, benignAttack, other := 0, 0, 0, 0
	var rest []string
	for _, id := range failing {
		mine := cves(id)
		allSibling, anyAbsent, hasBenign := true, false, false
		for _, s := range samples {
			if s.Sig != id {
				continue
			}
			if s.Kind == "benign" && s.matches(e, id) {
				hasBenign = true
			}
			if s.Kind != "attack" || s.matches(e, id) {
				continue
			}
			caughtBySibling := false
			for _, h := range s.MatchAny(all) {
				for _, c := range h.CVEs {
					if h.ID != id && mine[c] {
						caughtBySibling = true
					}
				}
			}
			if !caughtBySibling {
				allSibling = false
				if literalAbsent(e, id, s.Request) {
					anyAbsent = true
				}
			}
		}
		switch {
		case hasBenign:
			benignAttack++
		case allSibling:
			sibling++
		case anyAbsent:
			absent++
		default:
			other++
			rest = append(rest, id)
		}
	}
	t.Logf("verified signatures failing the library's gate: %d. Of them: %d trip a benign sample; %d miss only samples that another signature of the same CVE catches; %d miss a sample that lacks a literal the signature requires, in any decoding (a sample the signature cannot match); %d other: %v",
		len(failing), benignAttack, sibling, absent, other, rest)
}

// literalAbsent reports whether some condition of the signature requires a literal that appears nowhere in the request, in any
// decoding I can think of: no reading of the transforms could make the signature match it.
func literalAbsent(e *Engine, id string, req *inspect.Request) bool {
	snap := e.cur.Load()
	si, ok := snap.byID[id]
	if !ok {
		return false
	}
	var sb strings.Builder
	sb.WriteString(req.Method + " " + req.Path + "?" + req.RawQuery + " " + string(req.Body) + " " + req.Host)
	for k, vs := range req.Header {
		for _, v := range vs {
			sb.WriteString(" " + k + ":" + v)
		}
	}
	raw := sb.String()
	d := urlDecode(raw)
	hay := strings.ToLower(raw + " " + d + " " + htmlDecode(d) + " " + jsDecode(d) + " " + cssDecode(d))
	for _, ci := range snap.sigs[si].conds {
		c := snap.conds[ci]
		if c.neg {
			continue
		}
		if c.anchors != nil {
			found := false
			for _, l := range c.anchors {
				if strings.Contains(hay, l) {
					found = true
				}
			}
			if !found {
				return true
			}
		}
		// a condition on a named argument, header or cookie needs the name in the request (the segments of a JSON path are each a key)
		named, present := 0, 0
		for _, tg := range c.targets {
			if tg.name == "" {
				continue
			}
			named++
			ok := true
			for _, seg := range strings.Split(strings.TrimPrefix(strings.ToLower(tg.name), "json."), ".") {
				if !strings.Contains(hay, strings.ReplaceAll(seg, "_", "")) && !strings.Contains(strings.ReplaceAll(hay, "-", ""), strings.ReplaceAll(seg, "_", "")) && !strings.Contains(hay, seg) {
					ok = false
				}
			}
			if ok {
				present++
			}
		}
		if named == len(c.targets) && named > 0 && present == 0 {
			return true
		}
	}
	return false
}
