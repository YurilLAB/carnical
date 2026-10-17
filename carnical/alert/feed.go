// SPDX-License-Identifier: Apache-2.0

package alert

import (
	"strconv"
	"strings"

	"github.com/YurilLAB/coraza/carnical/control/feed"
)

// FeedEvent turns a record into an event of the signed pull feed (control/feed), in the vocabulary the owner's console
// reads (docs/backend-compat.md section 2), for an integrator that serves the feed from its own EventSource. It
// reports false for a record that is not an event there: totals, summaries, drops, and findings counted only.
//
// control/feed imports nothing of carnical's, so this adapter adds no import cycle. The feed handler still checks and
// cuts every field to the reader's limits, and shortens the address for a key that asks for it.
func FeedEvent(r Record) (feed.Event, bool) {
	a := &r.Alert
	kind := ""
	switch r.Kind {
	case KindAlert, KindRepeated:
		switch a.Action {
		case Blocked, RateLimited, SourceBlocked:
			kind = "block"
		case WouldBlock:
			kind = "would_block"
		case Detected:
			kind = "match"
		case NotInspected:
			kind = "budget"
		}
	case KindSuspected:
		kind = "campaign"
	case KindSourceBlocked:
		kind = "ip_ban"
	case KindSourceWouldBlock:
		kind = "would_ban"
	case KindSourceBlockEnded:
		kind = "ip_unban"
	case KindAutoBlockFull:
		kind = "health"
	}
	if kind == "" {
		return feed.Event{}, false
	}
	e := feed.Event{
		Time:    a.Last,
		Kind:    kind,
		Sev:     feedSeverity(a.Risk),
		Channel: "fw",
		ID:      incidentID(a.ID),
		Mode:    a.Mode.String(),
		Method:  a.Method,
		Path:    a.Path,
		Host:    a.Host,
		Msg:     a.SigName,
		Why:     a.Note,
	}
	if e.Time.IsZero() {
		e.Time = a.First
	}
	if r.Kind == KindRepeated {
		e.ID = "" // the repeats are other requests: none of them has the first one's incident id
	}
	if a.Src.IsValid() {
		e.IP = a.Src.Unmap().String()
	}
	if a.Status != 0 {
		e.Status = &a.Status
	}
	if a.Score > 0 {
		e.Score, e.Threshold = &a.Score, &a.Threshold
	}
	if r.Kind == KindRepeated && a.Count > 0 {
		n := int(min(a.Count, uint64(1<<31-1)))
		e.N = &n
	}
	if a.Sig != "" {
		e.Sigs = append(e.Sigs, feed.SigMatch{ID: feedSigID(a.Sig), Action: a.Action.String()})
	}
	for i, id := range a.Rules {
		if i == MaxRules {
			break
		}
		if s := Signature(id); s != "" && s != a.Sig {
			e.Sigs = append(e.Sigs, feed.SigMatch{ID: feedSigID(s)})
		}
	}
	return e, true
}

// feedSigID writes a CRS signature as the console's library names it, CRS-<rule id>; the others stay as they are.
func feedSigID(sig string) string {
	if rest, ok := strings.CutPrefix(sig, "crs-"); ok {
		return "CRS-" + rest
	}
	return sig
}

func feedSeverity(r Risk) string {
	switch r {
	case RiskHigh:
		return "high"
	case RiskMedium:
		return "medium"
	case RiskLow:
		return "low"
	}
	return "info"
}

// incidentID is the console's incident id: 12 upper-case hex characters, the first twelve of the request id. Anything
// else gives "".
func incidentID(id string) string {
	if len(id) < 12 {
		return ""
	}
	if _, err := strconv.ParseUint(id[:12], 16, 64); err != nil {
		return ""
	}
	return strings.ToUpper(id[:12])
}
