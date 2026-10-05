// SPDX-License-Identifier: Apache-2.0

package vpatch

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
)

// Limits on reading a signature file. A file is read once, at start-up or when it is replaced, but it comes from a feed, so it
// is bounded before it is trusted.
const (
	maxLegacyLine  = 1 << 20
	maxLegacyBytes = 256 << 20
	maxLegacySigs  = 500000
)

// legacyCond is a condition as the signature library writes it. The one difference from Condition is that the pattern of a pm
// condition may be a list of words, which Condition keeps in Patterns.
type legacyCond struct {
	Operator   string          `json:"operator"`
	Pattern    json.RawMessage `json:"pattern"`
	Patterns   []string        `json:"patterns"`
	Flags      string          `json:"flags"`
	Targets    []string        `json:"targets"`
	Transforms []string        `json:"transforms"`
	Negate     bool            `json:"negate"`
}

func (c legacyCond) condition() (Condition, error) {
	out := Condition{Operator: c.Operator, Patterns: c.Patterns, Flags: c.Flags, Targets: c.Targets, Transforms: c.Transforms, Negate: c.Negate}
	p := bytes.TrimSpace(c.Pattern)
	switch {
	case len(p) == 0 || bytes.Equal(p, []byte("null")):
	case p[0] == '"':
		if err := json.Unmarshal(p, &out.Pattern); err != nil {
			return out, fmt.Errorf("pattern: %w", err)
		}
	case p[0] == '[':
		var words []string
		if err := json.Unmarshal(p, &words); err != nil {
			return out, fmt.Errorf("pattern: %w", err)
		}
		if len(out.Patterns) > 0 {
			return out, fmt.Errorf("both pattern and patterns are lists")
		}
		out.Patterns = words
	default:
		return out, fmt.Errorf("pattern must be a string or a list of strings")
	}
	return out, nil
}

// legacyLine is one line of the signature library: a Signature, plus the pipeline's own verdict on it.
type legacyLine struct {
	ID          string   `json:"id"`
	Rev         int      `json:"rev"`
	Description string   `json:"description"`
	Category    string   `json:"category"`
	Severity    string   `json:"severity"`
	Confidence  string   `json:"confidence"`
	Action      string   `json:"action"`
	Score       int      `json:"score"`
	CVEs        []string `json:"cves"`
	Sources     []string `json:"sources"`
	Scope       []string `json:"scope"`
	Tier        string   `json:"tier"`
	Expires     string   `json:"expires"`
	legacyCond
	Also   []legacyCond `json:"also"`
	Status string       `json:"_status"`
	Origin string       `json:"_origin"`
}

// ReadLegacy reads a signature library written as JSON lines, one signature per line, with fields as in Signature plus an optional
// "_status" and "_origin". The status becomes the tier: verified is TierVerified, candidate is TierCommunity, held is
// TierExperimental, and rejected signatures are left out. A line with no status takes its "tier" field, or is verified. A pm
// pattern written as a JSON list becomes Patterns. The origin is kept as one more source. An unknown field, a malformed line or a
// file over the limits is an error that names the line.
func ReadLegacy(r io.Reader) ([]Signature, error) {
	lr := io.LimitReader(r, maxLegacyBytes+1)
	sc := bufio.NewScanner(lr)
	sc.Buffer(make([]byte, 0, 64<<10), maxLegacyLine)
	var out []Signature
	total := 0
	for line := 1; sc.Scan(); line++ {
		raw := bytes.TrimSpace(sc.Bytes())
		total += len(raw) + 1
		if total > maxLegacyBytes {
			return nil, fmt.Errorf("the file is larger than %d bytes", maxLegacyBytes)
		}
		if len(raw) == 0 {
			continue
		}
		var l legacyLine
		dec := json.NewDecoder(bytes.NewReader(raw))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&l); err != nil {
			return nil, fmt.Errorf("line %d: %w", line, err)
		}
		if dec.More() {
			return nil, fmt.Errorf("line %d: more than one JSON value", line)
		}
		sig, keep, err := l.signature()
		if err != nil {
			return nil, fmt.Errorf("line %d: %w", line, err)
		}
		if !keep {
			continue
		}
		if len(out) >= maxLegacySigs {
			return nil, fmt.Errorf("more than %d signatures", maxLegacySigs)
		}
		out = append(out, sig)
	}
	if err := sc.Err(); err != nil {
		if err == bufio.ErrTooLong {
			return nil, fmt.Errorf("a line is longer than %d bytes", maxLegacyLine)
		}
		return nil, err
	}
	return out, nil
}

func (l legacyLine) signature() (Signature, bool, error) {
	tier := l.Tier
	switch l.Status {
	case "verified":
		tier = TierVerified
	case "candidate":
		tier = TierCommunity
	case "held":
		tier = TierExperimental
	case "rejected":
		return Signature{}, false, nil
	case "":
	default:
		return Signature{}, false, fmt.Errorf("unknown _status %q", clip(l.Status, 32))
	}
	main, err := l.legacyCond.condition()
	if err != nil {
		return Signature{}, false, err
	}
	sig := Signature{
		ID: l.ID, Rev: l.Rev, Description: l.Description, Category: l.Category, Severity: l.Severity, Confidence: l.Confidence,
		Action: l.Action, Score: l.Score, CVEs: l.CVEs, Sources: l.Sources, Scope: l.Scope, Tier: tier, Expires: l.Expires,
		Condition: main,
	}
	for i, a := range l.Also {
		c, err := a.condition()
		if err != nil {
			return Signature{}, false, fmt.Errorf("also %d: %w", i, err)
		}
		sig.Also = append(sig.Also, c)
	}
	if l.Origin != "" {
		have := false
		for _, s := range sig.Sources {
			if s == l.Origin {
				have = true
			}
		}
		if !have {
			sig.Sources = append(append([]string(nil), sig.Sources...), l.Origin)
		}
	}
	return sig, true, nil
}
