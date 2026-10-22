// SPDX-License-Identifier: Apache-2.0

package alert

// Line is a record as LogSink writes it, for a sink that sends it elsewhere (the alert endpoint): the same fields under
// the same names, without the time and the level. Only the records that are alerts have one; the totals and the
// summary are reports, and stay in the log.
type Line struct {
	Msg string `json:"msg"`
	*AlertLine
	*DropLine
	// Count is an alert's requests, or the lines that were dropped. It is here rather than in both of the above, where
	// encoding/json would leave out a name the two share.
	Count uint64 `json:"count"`
}

// AlertLine holds the fields of an alert, a repeat, a suspected intrusion and a repeat-offender line.
type AlertLine struct {
	AlertID     string   `json:"alert_id,omitempty"`
	Layer       string   `json:"layer"`
	Sig         string   `json:"sig"`
	SigName     string   `json:"sig_name,omitempty"`
	Rules       []int    `json:"rules,omitempty"`
	Category    []string `json:"category,omitempty"`
	Risk        string   `json:"risk"`
	SeverityRaw string   `json:"severity_raw,omitempty"`
	Action      string   `json:"action"`
	Mode        string   `json:"mode,omitempty"`
	Status      *int     `json:"status,omitempty"` // not on a repeat, whose repeats need not have had the first one's
	Score       *int     `json:"score,omitempty"`
	Threshold   *int     `json:"threshold,omitempty"`
	Client      string   `json:"client,omitempty"`
	Src         string   `json:"src,omitempty"`
	SrcKey      string   `json:"src_key,omitempty"`
	SrcNet      string   `json:"src_net,omitempty"`
	ViaProxy    bool     `json:"via_proxy,omitempty"`
	Method      string   `json:"method,omitempty"`
	Host        string   `json:"host,omitempty"`
	Path        string   `json:"path,omitempty"`
	First       string   `json:"first,omitempty"`
	Last        string   `json:"last,omitempty"`
	Note        string   `json:"note,omitempty"`
}

// DropLine holds the fields of an "alerts dropped" line.
type DropLine struct {
	DroppedHigh      uint64            `json:"dropped_high"`
	DroppedLow       uint64            `json:"dropped_low"`
	DroppedQueue     uint64            `json:"dropped_queue"`
	RepeatsUnwritten uint64            `json:"repeats_unwritten"`
	RepeatsBySig     map[string]uint64 `json:"repeats_unwritten_by_sig,omitempty"`
}

// NewLine gives r as its log line shows it, the source as mode says, and reports false for the totals and the summary.
func NewLine(r Record, mode SourceMode) (Line, bool) {
	switch r.Kind {
	case KindTotals, KindSummary:
		return Line{}, false
	case KindDropped:
		d := &DropLine{DroppedHigh: r.Dropped.High, DroppedLow: r.Dropped.Low,
			DroppedQueue: r.Dropped.Queue, RepeatsUnwritten: r.Dropped.Repeats}
		if len(r.Unwritten) > 0 {
			d.RepeatsBySig = make(map[string]uint64, len(r.Unwritten))
			for _, u := range r.Unwritten {
				d.RepeatsBySig[u.Sig+"/"+u.Action.String()] += u.N
			}
		}
		return Line{Msg: r.Message(), DropLine: d, Count: r.Dropped.Total()}, true
	}
	a := &r.Alert
	l := &AlertLine{AlertID: a.ID, Layer: a.Layer.String(), Sig: a.Sig, SigName: a.SigName, Risk: a.Risk.String(),
		SeverityRaw: a.SeverityRaw, Action: a.Action.String(), Mode: a.Mode.String(), Method: a.Method, Host: a.Host,
		Path: a.Path, Note: a.Note, ViaProxy: a.ViaProxy && a.Src.IsValid() && mode != SourceOff}
	if len(a.Rules) > 0 {
		l.Rules = append([]int(nil), a.Rules[:min(len(a.Rules), MaxRules)]...)
	}
	if a.Categories != 0 {
		l.Category = a.Categories.Names(MaxCategories)
	}
	if r.Kind != KindRepeated {
		l.Status = &a.Status
	}
	if a.Score > 0 || a.Threshold > 0 {
		l.Score, l.Threshold = &a.Score, &a.Threshold
	}
	if a.Client != 0 {
		l.Client = a.Client.String()
	}
	if a.Src.IsValid() && mode != SourceOff {
		if mode == SourcePrefix {
			l.Src = SourceNet(a.Src).String()
		} else {
			l.Src = a.Src.Unmap().String()
		}
		switch {
		case a.Net.IsValid():
			l.SrcNet = a.Net.String()
		case mode == SourceFull:
			l.SrcKey = SourceKey(a.Src).String()
		}
	}
	if !a.First.IsZero() {
		l.First, l.Last = a.First.UTC().Format(timeFormat), a.Last.UTC().Format(timeFormat)
	}
	return Line{Msg: r.Message(), AlertLine: l, Count: a.Count}, true
}

// RiskOf is the line's risk, for a sink that keeps the riskier lines first; a line that is not an alert's is RiskInfo.
func (l *Line) RiskOf() Risk {
	if l.AlertLine == nil {
		return RiskInfo
	}
	r, _ := ParseRisk(l.Risk)
	return r
}
