// SPDX-License-Identifier: Apache-2.0

package feed

import (
	"encoding/json"
	"math"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode/utf8"
)

// The most of each list an answer holds, and how long a text may be before it is cut. The reader's own limits
// (brief/waf/feed.py, MOST and the per-field lengths) are the ceiling; the ones for bans and offenders are those the
// PHP console sends.
const (
	// MaxEvents is the most events in one answer.
	MaxEvents = 2000
	// MaxDays is the most days of traffic figures one request may ask for.
	MaxDays = 90

	maxBans      = 2000
	maxOffenders = 50
	maxMarks     = 2000
	maxErrors    = 50
	maxNotes     = 50
	maxSigs      = 50
	maxHours     = 24
	maxTop       = 50
	maxOutcomes  = 20
	maxStatus    = 10
	maxCounts    = 20
	maxOffSigs   = 50

	bigCount = int64(1_000_000_000_000) // no count in a feed is anywhere near this
)

// Severities, in the reader's words.
var severities = map[string]bool{"info": true, "low": true, "medium": true, "high": true, "critical": true}

var kindRE = regexp.MustCompile(`\A[a-z][a-z0-9_]{0,31}\z`)

// timeLayout is the only form of time the reader accepts: whole seconds, UTC, a literal Z.
const timeLayout = "2006-01-02T15:04:05Z"

// SiteInfo is the "site" block, apart from the id, which is always the handler's own.
type SiteInfo struct {
	Name      string
	Host      string
	Engine    string
	Bundle    string
	Mode      string
	PolicyRev int64
	Timezone  string
}

// SigMatch is one signature or rule that matched a request.
type SigMatch struct {
	ID     string // for CRS rules: CRS-<rule id>
	Score  *int
	Action string
	Target string
	Name   string // the name of the field it matched in
}

// Event is one thing that happened at a site, in the vocabulary the reports use (docs/backend-compat.md section 2).
// Zero values are left out of the answer; the fields that can legitimately be zero are pointers.
type Event struct {
	Time      time.Time
	Kind      string // [a-z][a-z0-9_]{0,31}: block, would_block, match, ip_ban, policy ...
	Sev       string // info, low, medium, high or critical
	Channel   string // "fw" or "update"; anything else is left out
	ID        string // incident id: 12 upper-case hex characters
	Mode      string
	IP        string // left out when empty or not an address
	Method    string
	Path      string
	Status    *int
	Score     *int
	Threshold *int
	Sigs      []SigMatch
	MS        *float64
	UA        string
	Msg       string
	Code      string
	Ver       string
	Detail    string
	Errs      *int
	Trunc     *bool
	Budget    *bool
	Engine    string
	Host      string
	Why       string
	N         *int
	UntilUnix *int64 // "until" is a number or a text; the number wins when both are set
	UntilText string
	User      string
	What      string
}

// Entry is an event with the cursor that stands just after it. The cursor is what lets the handler send fewer
// events than the source returned (to stay under the reader's size cap) without losing any.
type Entry struct {
	Event Event
	Next  string
}

// EventPage is what an EventSource returns for a cursor: events oldest first, at most the number asked for, the
// cursor that stands after the last of them (or the cursor that was given, when there are none), and whether more
// are waiting after that.
type EventPage struct {
	Entries []Entry
	Cursor  string
	More    bool
}

// TopEntry is one row of a top-pages list.
type TopEntry struct {
	Name string
	N    int64
}

// Hour is one hour of a day's figures.
type Hour struct{ R, A, P int64 }

// MS is the firewall's own time per request, in milliseconds.
type MS struct{ P50, P95, Max float64 }

// TrafficDay is one day's figures (the PHP Insights::rollup). The optional counts are pointers so zero can be sent.
type TrafficDay struct {
	Day            string // YYYY-MM-DD
	TZ             string
	Requests       int64
	Pages          int64
	Visitors       int64
	Attacks        int64
	Bots           *int64
	API            *int64
	Static         *int64
	Proxied        *int64
	Lines          *int64
	BadLines       *int64
	VisitorsCapped *bool
	Partial        *bool
	Outcomes       map[string]int64
	Status         map[string]int64
	Hours          []Hour
	MS             *MS
	TopPages       []TopEntry
	Top404         []TopEntry
	TopBlocked     []TopEntry
}

// Ban is one ban in the IDS/IPS snapshot.
type Ban struct {
	IP     string
	At     int64
	Until  int64
	Why    string
	By     string
	N      int64
	Active bool
}

// Offender is one address with a score that is not yet a ban.
type Offender struct {
	IP       string
	Points   int64
	Counts   map[string]int64
	Sigs     map[string]int64
	Last     int64
	BansWeek int64
}

// IPs is the "ips" section: snapshots, replaced on every read.
type IPs struct {
	Bans      []Ban
	Offenders []Offender
}

// Bundle describes the rule set in force.
type Bundle struct {
	Version    string
	Signatures int64
	Activated  *time.Time
	Verified   *bool
}

// Updates describes the update channel.
type Updates struct {
	LastCheck *time.Time
	LastOK    *time.Time
	LastError string
	NextCheck *time.Time
	Failures  int64
}

// Health is the "health" section. Every entry in Errors is a red standing alert on the owner's Desk, so only real
// problems belong there; Notes are information.
type Health struct {
	Engine     string
	Mode       string
	Inspecting *bool
	Bundle     *Bundle
	Updates    Updates
	Errors     []string
	Notes      []string
}

// MarkEvent is the part of an event a mark carries.
type MarkEvent struct {
	Time   *time.Time
	Kind   string
	Sev    string
	Path   string
	Method string
	IP     string
	ID     string
	Sigs   []SigMatch
}

// Mark is a note the firm made on an event ("this was a real visitor", "please look at this").
type Mark struct {
	ID    string // 16 hex digits
	Time  time.Time
	Kind  string
	Note  string
	User  string
	Event *MarkEvent
}

// ----------------------------------------------------------------------------------------------------- wire forms

type wireSig struct {
	ID string `json:"id"`
	S  *int   `json:"s,omitempty"`
	A  string `json:"a,omitempty"`
	T  string `json:"t,omitempty"`
	N  string `json:"n,omitempty"`
}

type wireEvent struct {
	T      string    `json:"t"`
	Ev     string    `json:"ev"`
	Sev    string    `json:"sev"`
	Ch     string    `json:"ch,omitempty"`
	ID     string    `json:"id,omitempty"`
	Mode   string    `json:"mode,omitempty"`
	IP     string    `json:"ip,omitempty"`
	Method string    `json:"method,omitempty"`
	Path   string    `json:"path,omitempty"`
	Status *int      `json:"status,omitempty"`
	Score  *int      `json:"score,omitempty"`
	Thr    *int      `json:"thr,omitempty"`
	Sigs   []wireSig `json:"sigs,omitempty"`
	MS     *float64  `json:"ms,omitempty"`
	UA     string    `json:"ua,omitempty"`
	Msg    string    `json:"msg,omitempty"`
	Code   string    `json:"code,omitempty"`
	Ver    string    `json:"ver,omitempty"`
	Detail string    `json:"detail,omitempty"`
	Errs   *int      `json:"errs,omitempty"`
	Trunc  *bool     `json:"trunc,omitempty"`
	Budget *bool     `json:"budget,omitempty"`
	Engine string    `json:"engine,omitempty"`
	Host   string    `json:"host,omitempty"`
	Why    string    `json:"why,omitempty"`
	N      *int      `json:"n,omitempty"`
	Until  any       `json:"until,omitempty"`
	User   string    `json:"user,omitempty"`
	What   string    `json:"what,omitempty"`
}

type wireHour struct {
	R int64 `json:"r"`
	A int64 `json:"a"`
	P int64 `json:"p"`
}

type wireMS struct {
	P50 float64 `json:"p50"`
	P95 float64 `json:"p95"`
	Max float64 `json:"max"`
}

type wireTraffic struct {
	Day            string           `json:"day"`
	TZ             string           `json:"tz,omitempty"`
	Requests       int64            `json:"requests"`
	Pages          int64            `json:"pages"`
	Visitors       int64            `json:"visitors"`
	Bots           *int64           `json:"bots,omitempty"`
	API            *int64           `json:"api,omitempty"`
	Static         *int64           `json:"static,omitempty"`
	Proxied        *int64           `json:"proxied,omitempty"`
	Lines          *int64           `json:"lines,omitempty"`
	BadLines       *int64           `json:"bad_lines,omitempty"`
	Attacks        int64            `json:"attacks"`
	VisitorsCapped *bool            `json:"visitors_capped,omitempty"`
	Partial        *bool            `json:"partial,omitempty"`
	Outcomes       map[string]int64 `json:"outcomes,omitempty"`
	Status         map[string]int64 `json:"status,omitempty"`
	Hours          []wireHour       `json:"hours,omitempty"`
	MS             *wireMS          `json:"ms,omitempty"`
	TopPages       [][]any          `json:"top_pages,omitempty"`
	Top404         [][]any          `json:"top_404,omitempty"`
	TopBlocked     [][]any          `json:"top_blocked,omitempty"`
}

type wireBan struct {
	IP     string `json:"ip"`
	At     int64  `json:"at"`
	Until  int64  `json:"until"`
	Why    string `json:"why,omitempty"`
	By     string `json:"by,omitempty"`
	N      int64  `json:"n"`
	Active bool   `json:"active"`
}

type wireOffender struct {
	IP       string           `json:"ip"`
	Points   int64            `json:"points"`
	Counts   map[string]int64 `json:"counts"`
	Sigs     map[string]int64 `json:"sigs"`
	Last     int64            `json:"last"`
	BansWeek int64            `json:"bans_week"`
}

type wireIPs struct {
	Bans      []wireBan      `json:"bans"`
	Offenders []wireOffender `json:"offenders"`
}

type wireBundle struct {
	Version    string `json:"version,omitempty"`
	Signatures int64  `json:"signatures"`
	Activated  string `json:"activated,omitempty"`
	Verified   *bool  `json:"verified,omitempty"`
}

type wireUpdates struct {
	LastCheck string `json:"last_check,omitempty"`
	LastOK    string `json:"last_ok,omitempty"`
	LastError string `json:"last_error,omitempty"`
	NextCheck string `json:"next_check,omitempty"`
	Failures  int64  `json:"failures"`
}

type wireHealth struct {
	Engine     string      `json:"engine,omitempty"`
	Mode       string      `json:"mode,omitempty"`
	Inspecting *bool       `json:"inspecting,omitempty"`
	Bundle     *wireBundle `json:"bundle,omitempty"`
	Updates    wireUpdates `json:"updates"`
	Errors     []string    `json:"errors"`
	Notes      []string    `json:"notes"`
}

type wireMarkEvent struct {
	T      string    `json:"t,omitempty"`
	Ev     string    `json:"ev,omitempty"`
	Sev    string    `json:"sev,omitempty"`
	Path   string    `json:"path,omitempty"`
	Method string    `json:"method,omitempty"`
	IP     string    `json:"ip,omitempty"`
	ID     string    `json:"id,omitempty"`
	Sigs   []wireSig `json:"sigs,omitempty"`
}

type wireMark struct {
	ID    string        `json:"id"`
	T     string        `json:"t"`
	Kind  string        `json:"kind"`
	Note  string        `json:"note,omitempty"`
	User  string        `json:"user,omitempty"`
	Event wireMarkEvent `json:"event"`
}

type wireSite struct {
	ID        string `json:"id"`
	Name      string `json:"name,omitempty"`
	Host      string `json:"host,omitempty"`
	Engine    string `json:"engine,omitempty"`
	Bundle    string `json:"bundle,omitempty"`
	Mode      string `json:"mode,omitempty"`
	PolicyRev int64  `json:"policy_rev"`
	Timezone  string `json:"timezone,omitempty"`
}

// ----------------------------------------------------------------------------------------------------- cleaning

// clip cuts a text to at most n characters (not bytes) and makes it valid UTF-8, as the reader does, so what is sent
// is what the reader will keep.
func clip(s string, n int) string {
	if len(s) > 4*n+4 {
		s = s[:4*n+4]
	}
	s = strings.ToValidUTF8(s, "�")
	if utf8.RuneCountInString(s) <= n {
		return s
	}
	i := 0
	for c := 0; c < n; c++ {
		_, w := utf8.DecodeRuneInString(s[i:])
		i += w
	}
	return s[:i]
}

// text clips a field and, for a customer with cut addresses, shortens any address written inside it.
func text(s string, n int, cut bool) string {
	if s == "" {
		return ""
	}
	if cut {
		s = scrubAddresses(clip(s, 4*n))
	}
	return clip(s, n)
}

func okInt(v, lo, hi int64) bool { return v >= lo && v <= hi }

func intPtr(p *int, lo, hi int) *int {
	if p == nil || *p < lo || *p > hi {
		return nil
	}
	v := *p
	return &v
}

func formatTime(t time.Time) (string, bool) {
	t = t.UTC()
	if y := t.Year(); y < 1970 || y > 9999 {
		return "", false
	}
	return t.Truncate(time.Second).Format(timeLayout), true
}

func sigs(in []SigMatch) []wireSig {
	if len(in) == 0 {
		return nil
	}
	if len(in) > maxSigs {
		in = in[:maxSigs]
	}
	out := make([]wireSig, 0, len(in))
	for _, s := range in {
		if s.ID == "" {
			continue
		}
		out = append(out, wireSig{ID: clip(s.ID, 64), S: intPtr(s.Score, -1_000_000, 1_000_000), A: clip(s.Action, 10),
			T: clip(s.Target, 40), N: clip(s.Name, 40)})
	}
	return out
}

func address(s string, cut bool) string {
	if s == "" {
		return ""
	}
	var a string
	var ok bool
	if cut {
		a, ok = CutAddress(s)
	} else {
		a, ok = WholeAddress(s)
	}
	if !ok {
		return ""
	}
	return a
}

// toWireEvent checks an event against what the reader accepts. It reports false for an event the reader would refuse
// whatever is done to it (a kind that is not a name, a severity it does not know, a time it cannot read). Everything
// else that is wrong with one field (a score out of range, a text too long) is repaired by leaving the field out or
// cutting it, so one bad field does not cost the event.
func toWireEvent(e Event, cut bool) (wireEvent, bool) {
	t, ok := formatTime(e.Time)
	if !ok || !kindRE.MatchString(e.Kind) || !severities[e.Sev] {
		return wireEvent{}, false
	}
	w := wireEvent{T: t, Ev: e.Kind, Sev: e.Sev}
	if e.Channel == "fw" || e.Channel == "update" {
		w.Ch = e.Channel
	}
	w.ID = clip(e.ID, 40)
	w.Mode = clip(e.Mode, 20)
	w.IP = address(e.IP, cut)
	w.Method = clip(e.Method, 16)
	w.Path = text(e.Path, 300, false)
	w.Status = intPtr(e.Status, 0, math.MaxInt32)
	w.Score = intPtr(e.Score, -1_000_000, 1_000_000)
	w.Thr = intPtr(e.Threshold, -1_000_000, 1_000_000)
	w.Sigs = sigs(e.Sigs)
	if e.MS != nil && !math.IsNaN(*e.MS) && *e.MS >= 0 && *e.MS < 1e9 {
		v := *e.MS
		w.MS = &v
	}
	w.UA = clip(e.UA, 200)
	w.Msg = text(e.Msg, 400, cut)
	w.Code = clip(e.Code, 64)
	w.Ver = clip(e.Ver, 40)
	w.Detail = text(e.Detail, 400, cut)
	w.Errs = intPtr(e.Errs, 0, math.MaxInt32)
	if e.Trunc != nil {
		v := *e.Trunc
		w.Trunc = &v
	}
	if e.Budget != nil {
		v := *e.Budget
		w.Budget = &v
	}
	w.Engine = clip(e.Engine, 40)
	w.Host = clip(e.Host, 255)
	w.Why = text(e.Why, 300, cut)
	w.N = intPtr(e.N, 0, math.MaxInt32)
	switch {
	case e.UntilUnix != nil && okInt(*e.UntilUnix, 0, bigCount):
		w.Until = *e.UntilUnix
	case e.UntilUnix == nil && e.UntilText != "":
		w.Until = text(e.UntilText, 60, cut)
	}
	w.User = clip(e.User, 60)
	w.What = text(e.What, 400, cut)
	return w, true
}

// MarshalEvent returns the JSON of one event as the feed sends it, with the address cut or not. It reports false for
// an event the reader would refuse. The same event always gives the same bytes, which the reader relies on to
// recognise a repeat.
func MarshalEvent(e Event, cut bool) ([]byte, bool) {
	w, ok := toWireEvent(e, cut)
	if !ok {
		return nil, false
	}
	b, err := json.Marshal(w)
	if err != nil {
		return nil, false
	}
	return b, true
}

func counts(m map[string]int64, max int) map[string]int64 {
	out := make(map[string]int64, len(m))
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if len(out) >= max {
			break
		}
		if v := m[k]; okInt(v, 0, bigCount) {
			out[clip(k, 60)] = v
		}
	}
	return out
}

func tops(in []TopEntry) [][]any {
	if len(in) == 0 {
		return nil
	}
	if len(in) > maxTop {
		in = in[:maxTop]
	}
	out := make([][]any, 0, len(in))
	for _, t := range in {
		if okInt(t.N, 0, bigCount) {
			out = append(out, []any{clip(t.Name, 300), t.N})
		}
	}
	return out
}

func optCount(p *int64) *int64 {
	if p == nil || !okInt(*p, 0, bigCount) {
		return nil
	}
	v := *p
	return &v
}

func optBool(p *bool) *bool {
	if p == nil {
		return nil
	}
	v := *p
	return &v
}

func number(v float64) bool { return !math.IsNaN(v) && v >= 0 && v < 1e9 }

// toWireTraffic checks one day's figures. A day the reader would refuse (a date that is not a real day, a required
// count out of range) is reported false.
func toWireTraffic(d TrafficDay) (wireTraffic, bool) {
	if t, err := time.Parse("2006-01-02", d.Day); err != nil || t.Format("2006-01-02") != d.Day {
		return wireTraffic{}, false
	}
	for _, v := range []int64{d.Requests, d.Pages, d.Visitors, d.Attacks} {
		if !okInt(v, 0, bigCount) {
			return wireTraffic{}, false
		}
	}
	w := wireTraffic{Day: d.Day, TZ: clip(d.TZ, 64), Requests: d.Requests, Pages: d.Pages, Visitors: d.Visitors, Attacks: d.Attacks,
		Bots: optCount(d.Bots), API: optCount(d.API), Static: optCount(d.Static), Proxied: optCount(d.Proxied),
		Lines: optCount(d.Lines), BadLines: optCount(d.BadLines), VisitorsCapped: optBool(d.VisitorsCapped), Partial: optBool(d.Partial)}
	if d.Outcomes != nil {
		w.Outcomes = counts(d.Outcomes, maxOutcomes)
	}
	if d.Status != nil {
		w.Status = counts(d.Status, maxStatus)
	}
	for i, h := range d.Hours {
		if i >= maxHours {
			break
		}
		if !okInt(h.R, 0, bigCount) || !okInt(h.A, 0, bigCount) || !okInt(h.P, 0, bigCount) {
			return wireTraffic{}, false
		}
		w.Hours = append(w.Hours, wireHour{R: h.R, A: h.A, P: h.P})
	}
	if d.MS != nil && number(d.MS.P50) && number(d.MS.P95) && number(d.MS.Max) {
		w.MS = &wireMS{P50: d.MS.P50, P95: d.MS.P95, Max: d.MS.Max}
	}
	w.TopPages, w.Top404, w.TopBlocked = tops(d.TopPages), tops(d.Top404), tops(d.TopBlocked)
	return w, true
}

// MarshalTrafficDay returns the JSON of one day's figures as the feed sends it, or false for a day the reader would
// refuse.
func MarshalTrafficDay(d TrafficDay) ([]byte, bool) {
	w, ok := toWireTraffic(d)
	if !ok {
		return nil, false
	}
	b, err := json.Marshal(w)
	if err != nil {
		return nil, false
	}
	return b, true
}

func toWireIPs(in IPs, cut bool) (w wireIPs, dropped int) {
	w.Bans = []wireBan{}
	w.Offenders = []wireOffender{}
	for _, b := range in.Bans {
		ip := address(b.IP, cut)
		if ip == "" || !okInt(b.At, 0, bigCount) || !okInt(b.Until, 0, bigCount) || !okInt(b.N, 0, bigCount) {
			dropped++
			continue
		}
		if len(w.Bans) >= maxBans {
			break
		}
		w.Bans = append(w.Bans, wireBan{IP: ip, At: b.At, Until: b.Until, Why: text(b.Why, 300, cut), By: clip(b.By, 40), N: b.N, Active: b.Active})
	}
	for _, o := range in.Offenders {
		ip := address(o.IP, cut)
		if ip == "" || !okInt(o.Points, 0, bigCount) || !okInt(o.Last, 0, bigCount) || !okInt(o.BansWeek, 0, bigCount) {
			dropped++
			continue
		}
		if len(w.Offenders) >= maxOffenders {
			break
		}
		w.Offenders = append(w.Offenders, wireOffender{IP: ip, Points: o.Points, Counts: counts(o.Counts, maxCounts),
			Sigs: counts(o.Sigs, maxOffSigs), Last: o.Last, BansWeek: o.BansWeek})
	}
	return w, dropped
}

func optTime(t *time.Time) string {
	if t == nil {
		return ""
	}
	s, ok := formatTime(*t)
	if !ok {
		return ""
	}
	return s
}

func strs(in []string, max, n int) []string {
	out := make([]string, 0, len(in))
	for _, s := range in {
		if len(out) >= max {
			break
		}
		out = append(out, clip(s, n))
	}
	return out
}

func toWireHealth(h Health, extraNotes []string) wireHealth {
	w := wireHealth{Engine: clip(h.Engine, 40), Mode: clip(h.Mode, 20), Inspecting: optBool(h.Inspecting),
		Errors: strs(h.Errors, maxErrors, 400)}
	notes := append(append([]string{}, h.Notes...), extraNotes...)
	w.Notes = strs(notes, maxNotes, 400)
	if h.Bundle != nil {
		w.Bundle = &wireBundle{Version: clip(h.Bundle.Version, 40), Signatures: clampCount(h.Bundle.Signatures),
			Activated: optTime(h.Bundle.Activated), Verified: optBool(h.Bundle.Verified)}
	}
	w.Updates = wireUpdates{LastCheck: optTime(h.Updates.LastCheck), LastOK: optTime(h.Updates.LastOK),
		LastError: clip(h.Updates.LastError, 400), NextCheck: optTime(h.Updates.NextCheck), Failures: clampCount(h.Updates.Failures)}
	return w
}

func clampCount(v int64) int64 {
	if v < 0 {
		return 0
	}
	if v > bigCount {
		return bigCount
	}
	return v
}

var markIDRE = regexp.MustCompile(`\A[0-9a-f]{16}\z`)

func toWireMark(m Mark, cut bool) (wireMark, bool) {
	t, ok := formatTime(m.Time)
	if !ok || !markIDRE.MatchString(m.ID) || !kindRE.MatchString(m.Kind) {
		return wireMark{}, false
	}
	w := wireMark{ID: m.ID, T: t, Kind: m.Kind, Note: text(m.Note, 500, cut), User: clip(m.User, 60)}
	if m.Event != nil {
		e := m.Event
		w.Event = wireMarkEvent{Path: text(e.Path, 300, false), Method: clip(e.Method, 16), IP: address(e.IP, cut),
			ID: clip(e.ID, 40), Sigs: sigs(e.Sigs)}
		if e.Time != nil {
			w.Event.T = optTime(e.Time)
		}
		if kindRE.MatchString(e.Kind) {
			w.Event.Ev = e.Kind
		}
		if severities[e.Sev] {
			w.Event.Sev = e.Sev
		}
	}
	return w, true
}
