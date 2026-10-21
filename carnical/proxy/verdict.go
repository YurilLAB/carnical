// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"net/http"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/YurilLAB/coraza/carnical/alert"
	"github.com/YurilLAB/coraza/carnical/bots"
	"github.com/YurilLAB/coraza/carnical/crs"
)

// A request's verdict is what happened to it in the end, for each signature that found something in it, as Suricata's
// eve verdict gives it rather than each rule's own action (ADR-0084): blocked, would_block, detected or not_inspected. The
// layers note their findings in the request's record while it runs (see Edge.note), the rule engine how its evaluation
// ended when its transaction closes (see budgetTx.Close), and once the request is done finish gives Config.OnAlert one
// alert.Alert per signature. A request with no finding allocates nothing for it.

// maxFindings is how many findings of one request its alerts are built from. Each inspector bounds its verdicts and a
// request can be refused only once, so this is reached only by a request that matches many scoring rules; past it a
// finding that refused the request takes the place of the last one that did not, and any other is left out.
const maxFindings = 16

// AlertOptions say what an alert shows of the request it is about. The zero value shows the visitor's address and the
// path as a template. A query string, a body, a header or a cookie is never in an alert.
type AlertOptions struct {
	// Source is what an alert shows of the visitor's address: all of it (the default), the same address for the
	// aggregator to cut to its /24 or /48 when it writes it, or nothing.
	Source alert.SourceMode
	// Path is the path as a template (the default: digits become 9, identifiers x, at most six segments), the path as
	// sent without its query, or nothing.
	Path alert.PathMode
}

// found is one finding of a request.
type found struct {
	id     int
	status int // the status it refused the request with; 0 when it did not
	action alert.Action
	layer  alert.Layer
	mode   alert.Mode
	risk   alert.Risk
	cats   alert.Categories
	sev    string
	// crs marks a rule set rule that only scored: it is an alert of its own only when the rule set gave no verdict.
	crs bool
}

// findings are the findings of one request, with what the rule set's verdict is built from: the rules that scored, their
// categories and the anomaly score the verdict rule gave.
type findings struct {
	list   [maxFindings]found
	n      int
	rules  [alert.MaxRules]int
	nRules int
	cats   alert.Categories
	score  int
}

var findingsPool = sync.Pool{New: func() any { return new(findings) }}

// engineEnd is how the rule engine's evaluation of a request ended.
type engineEnd struct {
	// refused is the rule that refused the request, and would the rule that would have in detection mode (0: none);
	// status is the refusal's status.
	refused, would, status int
	// cut says a phase ran out of its budget, and cutRefused that the request was refused for it. busy says a phase found
	// no evaluation slot (always refused). closed says the client went away during evaluation. noRule is any other refusal
	// the engine made without a rule.
	cut, cutRefused, busy, closed, noRule bool
}

// rank orders actions for a signature noted twice in one request: the stronger one is kept.
func rank(a alert.Action) int {
	switch {
	case a.Refused():
		return 3
	case a == alert.WouldBlock:
		return 2
	}
	return 1
}

// add notes one finding. A signature noted again keeps the stronger action.
func (f *findings) add(x found) {
	for i := range f.n {
		if f.list[i].id == x.id {
			if rank(x.action) > rank(f.list[i].action) {
				f.list[i] = x
			}
			return
		}
	}
	if f.n < maxFindings {
		f.list[f.n] = x
		f.n++
		return
	}
	if !x.action.Refused() {
		return
	}
	for i := f.n - 1; i >= 0; i-- {
		if !f.list[i].action.Refused() {
			f.list[i] = x
			return
		}
	}
}

// layerOf is the layer an id belongs to, by the ranges the layers document (see alert.Lookup).
func layerOf(id int) alert.Layer {
	switch {
	case id == idUploadName || id == idUploadScript:
		return alert.LayerUpload
	case id == idRateLimited || id == idAPIRateLimited || id == idLimitRule || id == idLimitMonitor:
		return alert.LayerRate
	case id == idCrowdSecBan || id == idCrowdSecUnavailable:
		return alert.LayerCrowdSec
	case id >= 5002000 && id <= 5002999:
		return alert.LayerFormats
	case id >= 5003000 && id <= 5003999:
		return alert.LayerAPIGuard
	case id >= 5004000 && id <= 5004999:
		return alert.LayerShield
	case id >= 5005000 && id <= 5005999:
		return alert.LayerBots
	case id >= 5100000 && id <= 5199999:
		return alert.LayerVPatch
	}
	return alert.LayerProxy
}

// note adds a finding to the request's record, for its alerts and what the flood protection is told of it. It does
// nothing without Config.OnAlert or Config.Shield, outside a request, or once the request is done. A rule set match feeds the rule set's verdict instead (see budgetTx.Close).
func (e *Edge) note(m Match, rec *record) {
	if rec == nil || !rec.alerts {
		return
	}
	risk, cats := rating(m)
	x := found{id: m.RuleID, risk: risk, cats: cats, sev: m.Severity, layer: layerOf(m.RuleID), action: alert.Detected, mode: alert.ModeMonitor}
	switch {
	case m.engine && e.cfg.CRS.OnlyDetects(m.RuleID):
		// A stricter local rule that is not switched on scores nothing, so it is an alert of its own, never the verdict's.
		x.layer, x.mode = alert.LayerCRS, alert.ModeDetect
	case m.engine:
		x.layer, x.mode, x.crs = alert.LayerCRS, crsMode(e.cfg.CRS.Mode), true
	case m.Disruptive:
		x.status, x.mode, x.action = m.status, alert.ModeBlock, alert.Blocked
		switch x.layer {
		case alert.LayerRate:
			x.action = alert.RateLimited
		case alert.LayerCrowdSec:
			if m.RuleID == idCrowdSecBan {
				x.action = alert.SourceBlocked
			}
		case alert.LayerShield:
			switch m.RuleID {
			case 5004008: // a banned address
				x.action = alert.SourceBlocked
			case 5004001, 5004002, 5004003, 5004004: // over its own, its network's or an attack's budget
				x.action = alert.RateLimited
			}
		}
	case m.would:
		x.action = alert.WouldBlock
	}
	rec.mu.Lock()
	defer rec.mu.Unlock()
	if rec.done {
		return
	}
	if rec.found == nil {
		rec.found = findingsPool.Get().(*findings)
	}
	f := rec.found
	if !x.crs {
		f.add(x)
		return
	}
	if m.verdict {
		// The anomaly verdict, a base rule or a deny rule: whether it refused the request is the engine's to say.
		if m.score > 0 {
			f.score = m.score
		}
		return
	}
	if cats == 0 && m.RuleID >= 900000 && m.RuleID <= 999999 {
		return // a CRS rule that sets up or adds up, which finds nothing itself
	}
	f.cats |= cats
	if f.nRules < len(f.rules) && !slices.Contains(f.rules[:f.nRules], m.RuleID) {
		f.rules[f.nRules] = m.RuleID
		f.nRules++
	}
	f.add(x)
}

// crsMode is the alert mode of the rule set's mode.
func crsMode(m crs.Mode) alert.Mode {
	if m == crs.ModeDetect {
		return alert.ModeDetect
	}
	return alert.ModeBlock
}

// anomalyScore reads the total score from the fixed text of the anomaly verdict 949110 or 959100, "Inbound Anomaly Score
// Exceeded (Total Score: 7)": the only place a matched rule's message is read. The macro in it expands to the score the
// rule set added up, never to request data; anything but one to six digits there gives 0.
func anomalyScore(id int, msg string) int {
	const inbound, outbound = "Inbound Anomaly Score Exceeded (Total Score: ", "Outbound Anomaly Score Exceeded (Total Score: "
	prefix := inbound
	if id == 959100 {
		prefix = outbound
	}
	rest, ok := strings.CutPrefix(msg, prefix)
	if !ok {
		return 0
	}
	digits, ok := strings.CutSuffix(rest, ")")
	if !ok || digits == "" || len(digits) > 6 {
		return 0
	}
	n := 0
	for i := 0; i < len(digits); i++ {
		c := digits[i]
		if c < '0' || c > '9' {
			return 0
		}
		n = n*10 + int(c-'0')
	}
	return n
}

// finish gives Config.OnAlert the request's alerts, once it is done: one for each signature that found something, with the
// request's final verdict for it. sent is the status the client was sent (0 when it is not known).
func (rec *record) finish(e *Edge, r *http.Request, sent int) {
	if !rec.alerts {
		return
	}
	rec.mu.Lock()
	f, end := rec.found, rec.engine
	rec.found, rec.done = nil, true
	rec.mu.Unlock()
	if f == nil && end == (engineEnd{}) {
		return
	}
	var none findings
	if f == nil {
		f = &none // the engine ended a request with no finding: a budget, a slot or the client
	} else {
		defer func() { *f = findings{}; findingsPool.Put(f) }()
	}
	base := e.alertBase(rec, r)
	if base.Client = rec.kind; base.Client == 0 {
		base.Client, _ = bots.Classify(r, e.helloOf(r))
	}
	var out outcome
	defer out.tell(e, rec.client)
	counted := false // the request's refusal, which the totals count once
	emit := func(a alert.Alert) {
		if a.Action.Refused() && !counted {
			a.Refusal, counted = true, true
		}
		out.add(&a)
		if e.cfg.OnAlert != nil {
			e.cfg.OnAlert(a)
		}
	}
	status := func(own int) int {
		if sent >= 400 {
			return sent
		}
		return own
	}
	mode := crsMode(e.cfg.CRS.Mode)
	verdict := false
	// The rule set's verdict: the rule that refused the request, or would have, with the rules that scored.
	id := end.refused
	if id == 0 {
		id = end.would
	}
	if id != 0 {
		verdict = true
		a := base
		a.Layer, a.Mode, a.RuleID, a.Sig = alert.LayerCRS, mode, id, engineSignature(id)
		entry, known := alert.Lookup(id)
		a.SigName, a.Categories, a.Risk = entry.Name, entry.Categories|f.cats, entry.Risk
		if !known {
			a.Risk = alert.RiskMedium
		}
		if f.nRules > 0 {
			a.Rules = append([]int(nil), f.rules[:f.nRules]...)
		}
		switch id {
		case 949110:
			a.Score, a.Threshold = f.score, e.cfg.CRS.InboundThreshold
		case 959100:
			a.Score, a.Threshold = f.score, e.cfg.CRS.OutboundThreshold
		}
		a.Action = alert.WouldBlock
		if end.refused != 0 {
			a.Action, a.Status = alert.Blocked, status(end.status)
		}
		emit(a)
	}
	// The ends of evaluation that no rule gave.
	switch {
	case end.busy:
		emit(engineAlert(base, idEvalBusy, alert.Blocked, mode, status(http.StatusServiceUnavailable)))
	case end.cutRefused:
		emit(engineAlert(base, idEvalBudget, alert.Blocked, mode, status(http.StatusServiceUnavailable)))
	case end.cut && end.refused == 0:
		// Detection mode let the request go on with the rest of its rules unread.
		emit(engineAlert(base, idEvalBudget, alert.NotInspected, mode, 0))
	case end.closed:
		a := base
		a.Layer, a.Mode, a.Action, a.Risk = alert.LayerCRS, mode, alert.ClientClosed, alert.RiskInfo
		emit(a)
	case end.noRule:
		emit(engineAlert(base, idEngineUnanswered, alert.Blocked, mode, status(http.StatusForbidden)))
	}
	for i := range f.n {
		x := &f.list[i]
		if x.crs && verdict {
			continue // part of the rule set's verdict
		}
		a := base
		a.Layer, a.Mode, a.Action, a.RuleID, a.Risk, a.Categories = x.layer, x.mode, x.action, x.id, x.risk, x.cats
		a.Sig, a.SigName = signature(x.id), alertName(x.id)
		a.SeverityRaw = cut(strings.ToLower(x.sev), alert.MaxSeverity)
		if x.action.Refused() {
			a.Status = status(x.status)
		}
		emit(a)
	}
}

// engineAlert is the alert of an end of evaluation that no rule gave.
func engineAlert(a alert.Alert, id int, action alert.Action, mode alert.Mode, status int) alert.Alert {
	entry, _ := alert.Lookup(id)
	a.Layer, a.Mode, a.Action, a.RuleID, a.Status = alert.LayerCRS, mode, action, id, status
	a.Sig, a.SigName, a.Risk, a.Categories = signature(id), entry.Name, entry.Risk, entry.Categories
	return a
}

// outcome is what the flood protection is told of a request once its alerts are built: whether a check in detection or
// monitor mode would have refused it, and the offence it counts toward a repeat offender's ban (see offencePoints).
type outcome struct {
	would  bool
	points int
	sig    string
}

func (o *outcome) add(a *alert.Alert) {
	if a.Action == alert.WouldBlock {
		o.would = true
	}
	if p := offencePoints(a); p > o.points {
		o.points, o.sig = p, a.Sig
	}
}

// tell gives the flood protection the request's outcome. client is the visitor's verified address, never one a forwarded
// header named without a trusted proxy: an untrusted peer that names another address is itself the client.
func (o *outcome) tell(e *Edge, client netip.Addr) {
	sh := e.cfg.Shield
	if sh == nil || !client.IsValid() {
		return
	}
	if o.would {
		sh.WouldReject(client)
	}
	if o.points > 0 {
		sh.Offend(client, o.points, o.sig)
	}
}

// offencePoints is what one alert of a request counts toward its source's ban (ADR-0085): only a refusal by a check that
// enforces and is sure of what it found. A request counts once, for its strongest alert. Rate limits, the flood
// protection's own refusals, a CrowdSec ban, a low or informational finding and anything only detected count nothing, so
// that a burst of ordinary traffic or one false positive never bans an address. Of the bot policy's refusals only a
// scanner's and a fake search engine's count (ADR-0087): a declared crawler or tool is not attacking.
func offencePoints(a *alert.Alert) int {
	if a.Action != alert.Blocked || a.Risk < alert.RiskMedium {
		return 0
	}
	switch {
	case a.RuleID == 949110 || a.RuleID == 959100:
		if a.Categories.Attacks().Len() >= 2 || a.Categories.Has(alert.CatScanner) {
			return 4
		}
		return 3
	case a.RuleID == idUploadName || a.RuleID == idUploadScript || a.RuleID == idWordPressPHP,
		a.RuleID == idPHP2ShellUpload || a.RuleID == idPHP2ShellSession:
		return 4
	case a.Layer == alert.LayerVPatch:
		return 4
	case a.RuleID == bots.RuleID(alert.ClientScanner): // a scanner refused by name, as the rule set's scanner verdict
		return 4
	case a.RuleID == bots.RuleID(alert.ClientFake): // a client lying about being a search engine
		return 3
	case (a.Layer == alert.LayerFormats || a.Layer == alert.LayerAPIGuard) && a.Risk == alert.RiskHigh:
		return 2
	case a.RuleID >= idConnect && a.RuleID <= idConnect+2: // CONNECT, an upgrade, a target that cannot be forwarded
		return 1
	}
	return 0
}

// signature is an id's signature; an id in no known range gets "rule-" and the id.
func signature(id int) string {
	if s := alert.Signature(id); s != "" {
		return s
	}
	return "rule-" + strconv.Itoa(id)
}

// engineSignature is the signature of a rule the engine ran: an id outside the known ranges (one written into
// crs.Settings.Before or After) is the rule set's.
func engineSignature(id int) string {
	if s := alert.Signature(id); s != "" {
		return s
	}
	return "crs-" + strconv.Itoa(id)
}

func alertName(id int) string {
	entry, _ := alert.Lookup(id)
	return entry.Name
}

func cut(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

// alertBase is what every alert about a request shows of it: its id, the visitor (see AlertOptions), the method, host and
// path. Nothing in it is taken from the query, a body, a header other than Host, or a cookie.
func (e *Edge) alertBase(rec *record, r *http.Request) alert.Alert {
	now := time.Now()
	a := alert.Alert{ID: rec.id, Count: 1, First: now, Last: now, Method: alertMethod(r.Method), Host: e.alertHost(r.Host)}
	if e.cfg.Alerts.Source != alert.SourceOff && rec.client.IsValid() {
		// The connection's address, when the visitor's could not be read, may be a trusted proxy's: it is never a source.
		a.Src, a.ViaProxy = rec.client, rec.via
	}
	a.MatchPath = cut(r.URL.Path, 1024)
	switch e.cfg.Alerts.Path {
	case alert.PathTemplate:
		a.Path = templatePath(r)
	case alert.PathFull:
		p, _, _ := strings.Cut(r.RequestURI, "?")
		a.Path = alert.Clean(p, alert.MaxPath)
	}
	return a
}

// alertMethod is a method as an alert gives it: a token of at most alert.MaxMethod bytes, or "other".
func alertMethod(m string) string {
	if m == "" || len(m) > alert.MaxMethod {
		return "other"
	}
	for i := 0; i < len(m); i++ {
		if !tokenByte(m[i]) {
			return "other"
		}
	}
	return m
}

// tokenByte reports a byte of a token (RFC 9110, 5.6.2).
func tokenByte(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.IndexByte("!#$%&'*+-.^_`|~", c) >= 0
}

// alertHost is the Host header as an alert gives it: the name alone, in lower case and bounded, or "(other)" for a name
// this site does not answer to, so that a visitor cannot fill the alert tables with names of its own.
func (e *Edge) alertHost(h string) string {
	n := normHost(h)
	if len(e.hosts) > 0 && !e.hosts[n] {
		return "(other)"
	}
	return alert.Clean(n, alert.MaxHost)
}

// templatePath is the path of a request as a template: each segment that is an identifier replaced (all digits by 9, a
// long token that mixes in digits, or any segment over 40 bytes, by x), at most six segments, then /*, a ? when there
// was a query, printable ASCII only and at most 96 bytes. It is the flood protection's template of a request (package
// shield), so an alert and the shield name a request's target alike.
func templatePath(r *http.Request) string {
	path := r.URL.EscapedPath()
	var b strings.Builder
	b.Grow(len(path) + 2)
	n := 0
	for seg := range strings.SplitSeq(strings.TrimPrefix(path, "/"), "/") {
		if n == 6 {
			b.WriteString("/*")
			break
		}
		b.WriteByte('/')
		b.WriteString(templateSegment(seg))
		n++
	}
	if b.Len() == 0 {
		b.WriteByte('/')
	}
	if r.URL.RawQuery != "" || r.URL.ForceQuery {
		b.WriteByte('?')
	}
	t := cut(b.String(), 96)
	for i := 0; i < len(t); i++ {
		if t[i] < 0x20 || t[i] > 0x7e {
			p := []byte(t)
			for j := i; j < len(p); j++ {
				if p[j] < 0x20 || p[j] > 0x7e {
					p[j] = '?'
				}
			}
			return string(p)
		}
	}
	return t
}

func templateSegment(s string) string {
	if s == "" {
		return ""
	}
	digits := 0
	for i := 0; i < len(s); i++ {
		if c := s[i]; c >= '0' && c <= '9' {
			digits++
		}
	}
	switch {
	case digits == len(s):
		return "9"
	case len(s) >= 16 && digits > 0, len(s) > 40:
		return "x"
	}
	return s
}
