// SPDX-License-Identifier: Apache-2.0

package feed

import (
	"encoding/json"
	"math"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

func TestCutAddress(t *testing.T) {
	rows := []struct {
		in, cut, whole string
		ok             bool
	}{
		{"198.51.100.77", "198.51.100.0", "198.51.100.77", true},
		{"198.51.100.0", "198.51.100.0", "198.51.100.0", true},
		{"0.0.0.1", "0.0.0.0", "0.0.0.1", true},
		{"255.255.255.255", "255.255.255.0", "255.255.255.255", true},
		{"2001:db8:abcd:1234::1", "2001:db8:abcd::", "2001:db8:abcd:1234::1", true},
		{"2001:0db8:abcd:1234:0000:0000:0000:0001", "2001:db8:abcd::", "2001:db8:abcd:1234::1", true},
		{"2001:DB8:ABCD:1234::1", "2001:db8:abcd::", "2001:db8:abcd:1234::1", true},
		{"::1", "::", "::1", true},
		{"::ffff:198.51.100.77", "198.51.100.0", "198.51.100.77", true},
		{"::ffff:c633:644d", "198.51.100.0", "198.51.100.77", true},
		{"fe80::1%eth0", "fe80::", "fe80::1", true},
		{"64:ff9b::198.51.100.77", "64:ff9b::", "64:ff9b::c633:644d", true},
		{"", "", "", false},
		{"not an address", "", "", false},
		{"198.51.100", "", "", false},
		{"198.51.100.256", "", "", false},
		{"198.51.100.77:80", "", "", false},
		{"198.51.100.77/24", "", "", false},
		{"[2001:db8::1]", "", "", false},
		{"2001:db8::g", "", "", false},
		{"1.2.3.4\n", "", "", false},
		{strings.Repeat("1", 70), "", "", false},
		{"٢.٣.٤.٥", "", "", false},
	}
	for _, row := range rows {
		t.Run(row.in, func(t *testing.T) {
			c, ok := CutAddress(row.in)
			if ok != row.ok || c != row.cut {
				t.Fatalf("CutAddress = %q, %v; want %q, %v", c, ok, row.cut, row.ok)
			}
			wh, ok := WholeAddress(row.in)
			if ok != row.ok || wh != row.whole {
				t.Fatalf("WholeAddress = %q, %v; want %q, %v", wh, ok, row.whole, row.ok)
			}
			if ok {
				// the reader's address pattern: [0-9A-Fa-f:.]{2,45}
				for _, s := range []string{c, wh} {
					if len(s) < 2 || len(s) > 45 || strings.Trim(s, "0123456789abcdefABCDEF:.") != "" {
						t.Fatalf("%q is not an address the reader accepts", s)
					}
				}
			}
		})
	}
}

func TestScrubAddresses(t *testing.T) {
	rows := []struct{ name, in, want string }{
		{"plain", "banned 203.0.113.7 for 15 minutes", "banned 203.0.113.0 for 15 minutes"},
		{"end of sentence", "from 203.0.113.7.", "from 203.0.113.0."},
		{"two", "203.0.113.7 and 198.51.100.200", "203.0.113.0 and 198.51.100.0"},
		{"ipv6", "from 2001:db8:abcd:1234::1 today", "from 2001:db8:abcd:: today"},
		{"ipv6 at end with full stop", "from 2001:db8:abcd:1234::1.", "from 2001:db8:abcd::."},
		{"ipv6 after a label", "addr:2001:db8:abcd:1234::1", "addr:2001:db8:abcd::"},
		{"already cut", "from 203.0.113.0", "from 203.0.113.0"},
		{"mapped", "from ::ffff:203.0.113.7", "from 203.0.113.0"},
		{"no address", "3 blocked in 15 minutes", "3 blocked in 15 minutes"},
		{"a time is not an address", "at 12:30:45 today", "at 12:30:45 today"},
		{"a version number is cut as a dotted quad", "engine 1.2.3.4", "engine 1.2.3.0"},
		{"not a quad", "section 1.2.3 and 999.1.1.1", "section 1.2.3 and 999.1.1.1"},
		{"empty", "", ""},
		{"only punctuation", "....::::....", "....::::...."},
		{"hex words", "deadbeef cafe face", "deadbeef cafe face"},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			if got := scrubAddresses(row.in); got != row.want {
				t.Fatalf("scrubAddresses(%q) = %q, want %q", row.in, got, row.want)
			}
		})
	}
}

func i(v int) *int           { return &v }
func i64(v int64) *int64     { return &v }
func bp(v bool) *bool        { return &v }
func f64(v float64) *float64 { return &v }

func marshal(t *testing.T, e Event, cut bool) map[string]any {
	t.Helper()
	b, ok := MarshalEvent(e, cut)
	if !ok {
		t.Fatalf("event refused: %+v", e)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

func TestEventFieldsAndLimits(t *testing.T) {
	base := func() Event { return Event{Time: nowAt(), Kind: "block", Sev: "high"} }
	long := func(n int) string { return strings.Repeat("é", n) } // multi-byte, so a byte cut would split a character
	rows := []struct {
		name   string
		change func(e *Event)
		field  string
		check  func(t *testing.T, v any, present bool)
	}{
		{"minimal has only the three required fields", func(e *Event) {}, "", func(t *testing.T, _ any, _ bool) {}},
		{"ip cut", func(e *Event) { e.IP = "198.51.100.77" }, "ip", eq("198.51.100.0")},
		{"empty ip is left out, not sent as an empty string", func(e *Event) { e.IP = "" }, "ip", absent},
		{"an invalid ip is left out", func(e *Event) { e.IP = "999.1.1.1" }, "ip", absent},
		{"channel fw", func(e *Event) { e.Channel = "fw" }, "ch", eq("fw")},
		{"channel update", func(e *Event) { e.Channel = "update" }, "ch", eq("update")},
		{"unknown channel left out", func(e *Event) { e.Channel = "other" }, "ch", absent},
		{"score zero is sent", func(e *Event) { e.Score = i(0) }, "score", eq(float64(0))},
		{"score out of range left out", func(e *Event) { e.Score = i(2_000_000) }, "score", absent},
		{"negative score within range kept", func(e *Event) { e.Score = i(-5) }, "score", eq(float64(-5))},
		{"threshold", func(e *Event) { e.Threshold = i(5) }, "thr", eq(float64(5))},
		{"status zero", func(e *Event) { e.Status = i(0) }, "status", eq(float64(0))},
		{"status negative left out", func(e *Event) { e.Status = i(-1) }, "status", absent},
		{"n", func(e *Event) { e.N = i(7) }, "n", eq(float64(7))},
		{"n negative left out", func(e *Event) { e.N = i(-7) }, "n", absent},
		{"ms", func(e *Event) { e.MS = f64(1.5) }, "ms", eq(1.5)},
		{"ms NaN left out", func(e *Event) { e.MS = f64(math.NaN()) }, "ms", absent},
		{"ms infinite left out", func(e *Event) { e.MS = f64(math.Inf(1)) }, "ms", absent},
		{"ms negative left out", func(e *Event) { e.MS = f64(-1) }, "ms", absent},
		{"trunc false is sent", func(e *Event) { e.Trunc = bp(false) }, "trunc", eq(false)},
		{"until as a number", func(e *Event) { e.UntilUnix = i64(1791014400) }, "until", eq(float64(1791014400))},
		{"until as text", func(e *Event) { e.UntilText = "tomorrow" }, "until", eq("tomorrow")},
		{"until number wins over text", func(e *Event) { e.UntilUnix = i64(5); e.UntilText = "x" }, "until", eq(float64(5))},
		{"until negative number is left out, and the text is not used instead", func(e *Event) { e.UntilUnix = i64(-5); e.UntilText = "x" }, "until", absent},
		{"id clipped to 40", func(e *Event) { e.ID = long(80) }, "id", length(40)},
		{"path clipped to 300", func(e *Event) { e.Path = long(400) }, "path", length(300)},
		{"ua clipped to 200", func(e *Event) { e.UA = long(400) }, "ua", length(200)},
		{"msg clipped to 400", func(e *Event) { e.Msg = long(500) }, "msg", length(400)},
		{"detail clipped to 400", func(e *Event) { e.Detail = long(500) }, "detail", length(400)},
		{"what clipped to 400", func(e *Event) { e.What = long(500) }, "what", length(400)},
		{"why clipped to 300", func(e *Event) { e.Why = long(500) }, "why", length(300)},
		{"user clipped to 60", func(e *Event) { e.User = long(100) }, "user", length(60)},
		{"code clipped to 64", func(e *Event) { e.Code = long(100) }, "code", length(64)},
		{"host clipped to 255", func(e *Event) { e.Host = long(300) }, "host", length(255)},
		{"method clipped to 16", func(e *Event) { e.Method = long(30) }, "method", length(16)},
		{"mode clipped to 20", func(e *Event) { e.Mode = long(30) }, "mode", length(20)},
		{"invalid utf-8 is repaired", func(e *Event) { e.Path = "/a\xff\xfeb" }, "path", func(t *testing.T, v any, _ bool) {
			if s := v.(string); !utf8.ValidString(s) || !strings.HasPrefix(s, "/a") || !strings.HasSuffix(s, "b") {
				t.Fatalf("path = %q", s)
			}
		}},
		{"control characters survive (the reader shows them as pictures)", func(e *Event) { e.Path = "/a\x1b[31m\nb" }, "path", eq("/a\x1b[31m\nb")},
		{"html is escaped by the encoder, not altered", func(e *Event) { e.Path = "/<script>" }, "path", eq("/<script>")},
		{"why is scrubbed when addresses are cut", func(e *Event) { e.Why = "3 blocked from 203.0.113.7" }, "why", eq("3 blocked from 203.0.113.0")},
		{"path is not scrubbed", func(e *Event) { e.Path = "/ip/203.0.113.7" }, "path", eq("/ip/203.0.113.7")},
		{"time in another zone is sent as UTC", func(e *Event) { e.Time = nowAt().In(time.FixedZone("x", 10*3600)) }, "t", eq("2026-10-03T08:00:00Z")},
		{"fractions of a second are dropped", func(e *Event) { e.Time = nowAt().Add(999 * time.Millisecond) }, "t", eq("2026-10-03T08:00:00Z")},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			e := base()
			row.change(&e)
			m := marshal(t, e, true)
			if row.field == "" {
				if len(m) != 3 {
					t.Fatalf("a minimal event has %d fields: %v", len(m), m)
				}
				return
			}
			v, present := m[row.field]
			row.check(t, v, present)
		})
	}
}

func eq(want any) func(t *testing.T, v any, present bool) {
	return func(t *testing.T, v any, present bool) {
		t.Helper()
		if !present || v != want {
			t.Fatalf("got %v (present=%v), want %v", v, present, want)
		}
	}
}

func absent(t *testing.T, v any, present bool) {
	t.Helper()
	if present {
		t.Fatalf("field present with %v", v)
	}
}

func length(n int) func(t *testing.T, v any, present bool) {
	return func(t *testing.T, v any, present bool) {
		t.Helper()
		s, _ := v.(string)
		if !present || utf8.RuneCountInString(s) != n || !utf8.ValidString(s) {
			t.Fatalf("got %d characters (present=%v), want %d", utf8.RuneCountInString(s), present, n)
		}
	}
}

func TestEventsTheReaderWouldRefuseAreNotSent(t *testing.T) {
	rows := []struct {
		name   string
		change func(e *Event)
		ok     bool
	}{
		{"good", func(e *Event) {}, true},
		{"every kind in the vocabulary", func(e *Event) { e.Kind = "would_block" }, true},
		{"kind with a digit", func(e *Event) { e.Kind = "update_ok2" }, true},
		{"kind of 32 characters", func(e *Event) { e.Kind = "a" + strings.Repeat("b", 31) }, true},
		{"kind of 33 characters", func(e *Event) { e.Kind = "a" + strings.Repeat("b", 32) }, false},
		{"kind upper case", func(e *Event) { e.Kind = "Block" }, false},
		{"kind starting with a digit", func(e *Event) { e.Kind = "1block" }, false},
		{"kind with a dash", func(e *Event) { e.Kind = "ip-ban" }, false},
		{"kind empty", func(e *Event) { e.Kind = "" }, false},
		{"kind with a newline at the end", func(e *Event) { e.Kind = "block\n" }, false},
		{"severity info", func(e *Event) { e.Sev = "info" }, true},
		{"severity critical", func(e *Event) { e.Sev = "critical" }, true},
		{"severity unknown", func(e *Event) { e.Sev = "urgent" }, false},
		{"severity empty", func(e *Event) { e.Sev = "" }, false},
		{"severity upper case", func(e *Event) { e.Sev = "High" }, false},
		{"zero time", func(e *Event) { e.Time = time.Time{} }, false},
		{"time before 1970", func(e *Event) { e.Time = time.Unix(-1, 0) }, false},
		{"time after year 9999", func(e *Event) { e.Time = time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC) }, false},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			e := Event{Time: nowAt(), Kind: "block", Sev: "high"}
			row.change(&e)
			if _, ok := MarshalEvent(e, true); ok != row.ok {
				t.Fatalf("ok = %v, want %v", ok, row.ok)
			}
		})
	}
}

func TestSigsAreBounded(t *testing.T) {
	var sg []SigMatch
	for n := 0; n < 80; n++ {
		sg = append(sg, SigMatch{ID: "CRS-942100", Score: i(5), Action: "block", Target: "args", Name: "q"})
	}
	sg = append(sg, SigMatch{ID: ""}) // no id: left out
	e := Event{Time: nowAt(), Kind: "block", Sev: "high", Sigs: sg}
	m := marshal(t, e, true)
	if got := len(m["sigs"].([]any)); got != 50 {
		t.Fatalf("%d signatures, want the first 50", got)
	}
	e.Sigs = []SigMatch{{ID: ""}}
	if _, has := marshal(t, e, true)["sigs"]; has {
		t.Fatal("a list of nothing was sent")
	}
	first := marshal(t, Event{Time: nowAt(), Kind: "block", Sev: "high", Sigs: []SigMatch{{ID: strings.Repeat("S", 100), Action: strings.Repeat("a", 20), Score: i(0)}}}, true)
	s := first["sigs"].([]any)[0].(map[string]any)
	if len(s["id"].(string)) != 64 || len(s["a"].(string)) != 10 || s["s"] != float64(0) {
		t.Fatalf("signature fields: %v", s)
	}
}

func TestWholeAddressesWhenTheKeySaysSo(t *testing.T) {
	e := Event{Time: nowAt(), Kind: "ip_ban", Sev: "high", IP: "2001:0db8:abcd:1234:0:0:0:1", Why: "banned 203.0.113.7"}
	m := marshal(t, e, false)
	if m["ip"] != "2001:db8:abcd:1234::1" || m["why"] != "banned 203.0.113.7" {
		t.Fatalf("whole: %v", m)
	}
	m = marshal(t, e, true)
	if m["ip"] != "2001:db8:abcd::" || m["why"] != "banned 203.0.113.0" {
		t.Fatalf("cut: %v", m)
	}
}

func TestMarshalEventIsDeterministic(t *testing.T) {
	e := goodEvent(1)
	a, _ := MarshalEvent(e, true)
	b, _ := MarshalEvent(e, true)
	if string(a) != string(b) {
		t.Fatal("two encodings of the same event differ")
	}
}

func TestTrafficDay(t *testing.T) {
	good := func() TrafficDay {
		return TrafficDay{Day: "2026-10-02", TZ: "Australia/Brisbane", Requests: 812, Pages: 301, Visitors: 120, Attacks: 14, Bots: i64(260),
			Outcomes: map[string]int64{"c": 790, "m": 8, "b": 12, "B": 2}, Status: map[string]int64{"2xx": 700, "4xx": 100},
			Hours: make([]Hour, 24), MS: &MS{P50: 0.21, P95: 0.9, Max: 3},
			TopPages: []TopEntry{{"/", 120}}, Partial: bp(false)}
	}
	rows := []struct {
		name   string
		change func(d *TrafficDay)
		ok     bool
	}{
		{"good", func(d *TrafficDay) {}, true},
		{"zero counts", func(d *TrafficDay) { d.Requests, d.Pages, d.Visitors, d.Attacks = 0, 0, 0, 0 }, true},
		{"leap day", func(d *TrafficDay) { d.Day = "2028-02-29" }, true},
		{"not a leap year", func(d *TrafficDay) { d.Day = "2026-02-29" }, false},
		{"month 13", func(d *TrafficDay) { d.Day = "2026-13-01" }, false},
		{"no zero padding", func(d *TrafficDay) { d.Day = "2026-1-2" }, false},
		{"a time, not a day", func(d *TrafficDay) { d.Day = "2026-10-02T00:00:00Z" }, false},
		{"empty day", func(d *TrafficDay) { d.Day = "" }, false},
		{"negative requests", func(d *TrafficDay) { d.Requests = -1 }, false},
		{"huge pages", func(d *TrafficDay) { d.Pages = 1 << 50 }, false},
		{"negative attacks", func(d *TrafficDay) { d.Attacks = -1 }, false},
		{"negative hour", func(d *TrafficDay) { d.Hours[3].R = -1 }, false},
		{"more than 24 hours is cut, not refused", func(d *TrafficDay) { d.Hours = make([]Hour, 30) }, true},
		{"ms NaN is left out, not refused", func(d *TrafficDay) { d.MS.P95 = math.NaN() }, true},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			d := good()
			row.change(&d)
			b, ok := MarshalTrafficDay(d)
			if ok != row.ok {
				t.Fatalf("ok = %v, want %v", ok, row.ok)
			}
			if !ok {
				return
			}
			var m map[string]any
			if err := json.Unmarshal(b, &m); err != nil {
				t.Fatal(err)
			}
			if _, has := m["outcomes"].(map[string]any); !has {
				t.Fatalf("outcomes is not an object: %s", b)
			}
			if h := m["hours"].([]any); len(h) > 24 {
				t.Fatalf("%d hours", len(h))
			}
			if row.name == "ms NaN is left out, not refused" {
				if _, has := m["ms"]; has {
					t.Fatal("ms with a NaN was sent")
				}
			}
		})
	}
	t.Run("empty maps are objects or absent, never lists", func(t *testing.T) {
		d := good()
		d.Outcomes, d.Status = map[string]int64{}, map[string]int64{}
		b, _ := MarshalTrafficDay(d)
		if strings.Contains(string(b), `"outcomes":[`) || strings.Contains(string(b), `"status":[`) {
			t.Fatalf("an empty map became a list: %s", b)
		}
	})
	t.Run("maps are cut to the reader's size", func(t *testing.T) {
		d := good()
		d.Outcomes = map[string]int64{}
		for n := 0; n < 40; n++ {
			d.Outcomes[strings.Repeat("k", 1+n)] = 1
		}
		b, _ := MarshalTrafficDay(d)
		var m map[string]any
		_ = json.Unmarshal(b, &m)
		if got := len(m["outcomes"].(map[string]any)); got != maxOutcomes {
			t.Fatalf("%d outcomes", got)
		}
	})
	t.Run("top lists are pairs and cut to 50", func(t *testing.T) {
		d := good()
		d.TopPages = nil
		for n := 0; n < 70; n++ {
			d.TopPages = append(d.TopPages, TopEntry{Name: "/p", N: int64(n)})
		}
		d.TopPages = append(d.TopPages, TopEntry{Name: "/bad", N: -1})
		b, _ := MarshalTrafficDay(d)
		var m map[string]any
		_ = json.Unmarshal(b, &m)
		top := m["top_pages"].([]any)
		if len(top) != 50 {
			t.Fatalf("%d top pages", len(top))
		}
		if pair := top[3].([]any); len(pair) != 2 || pair[0] != "/p" || pair[1] != float64(3) {
			t.Fatalf("pair = %v", pair)
		}
	})
}

func TestIPsMarksAndHealthShapes(t *testing.T) {
	r := newRig(t)
	r.src.ips = IPs{
		Bans: []Ban{
			{IP: "198.51.100.77", At: 1791010000, Until: 1791010900, Why: "3 blocked from 198.51.100.77", By: "auto", N: 1, Active: true},
			{IP: "", At: 1, Until: 2},                            // no address: left out
			{IP: "198.51.100.1", At: -1, Until: 2},               // bad time: left out
			{IP: "2001:db8:abcd:1234::9", At: 5, Until: 6, N: 2}, // v6
		},
		Offenders: []Offender{{IP: "203.0.113.9", Points: 12, Counts: map[string]int64{"not_found": 12}, Last: 1791013000}, {IP: "203.0.113.10"}},
	}
	r.src.marks = []Mark{
		{ID: "0123456789abcdef", Time: nowAt(), Kind: "real_visitor", Note: "an order form", User: "sam",
			Event: &MarkEvent{Time: ptrTime(nowAt()), Kind: "would_block", Sev: "medium", Path: "/order", IP: "198.51.100.77", Sigs: []SigMatch{{ID: "CRS-1"}}}},
		{ID: "0123456789abcdef", Time: nowAt(), Kind: "look_at"},  // no event: still an object
		{ID: "XYZ", Time: nowAt(), Kind: "look_at"},               // bad id: left out
		{ID: "0123456789abcdef", Time: nowAt(), Kind: "Bad Kind"}, // bad kind: left out
	}
	r.src.health = Health{Engine: "carnical-1", Mode: "block", Inspecting: bp(true), Updates: Updates{LastCheck: ptrTime(nowAt()), Failures: 0},
		Errors: []string{"the segmentation check failed"}, Bundle: &Bundle{Version: "crs-4.30.0", Signatures: 4000, Verified: bp(true)}}
	w := r.do(r.signed("/feed"))
	if w.Code != 200 {
		t.Fatalf("%d %s", w.Code, w.Body.String())
	}
	m := decode(t, w)

	ips := m["ips"].(map[string]any)
	bans := ips["bans"].([]any)
	if len(bans) != 2 || bans[0].(map[string]any)["ip"] != "198.51.100.0" || bans[1].(map[string]any)["ip"] != "2001:db8:abcd::" {
		t.Fatalf("bans = %v", bans)
	}
	if why := bans[0].(map[string]any)["why"]; why != "3 blocked from 198.51.100.0" {
		t.Fatalf("why = %v", why)
	}
	offs := ips["offenders"].([]any)
	if len(offs) != 2 {
		t.Fatalf("offenders = %v", offs)
	}
	for _, o := range offs {
		om := o.(map[string]any)
		if _, ok := om["counts"].(map[string]any); !ok {
			t.Fatalf("counts is not an object: %v", om)
		}
		if _, ok := om["sigs"].(map[string]any); !ok {
			t.Fatalf("sigs is not an object: %v", om)
		}
	}

	marks := m["marks"].([]any)
	if len(marks) != 2 {
		t.Fatalf("marks = %v", marks)
	}
	if ev := marks[0].(map[string]any)["event"].(map[string]any); ev["ip"] != "198.51.100.0" || ev["ev"] != "would_block" {
		t.Fatalf("mark event = %v", ev)
	}
	if ev, ok := marks[1].(map[string]any)["event"].(map[string]any); !ok || len(ev) != 0 {
		t.Fatalf("a mark without an event must carry {}: %v", marks[1])
	}

	h := m["health"].(map[string]any)
	if errs := h["errors"].([]any); len(errs) != 1 {
		t.Fatalf("errors = %v", errs)
	}
	notes := h["notes"].([]any)
	if len(notes) != 1 || !strings.Contains(notes[0].(string), "left out") {
		t.Fatalf("left-out entries should be reported in notes, got %v", notes)
	}
	if _, ok := h["updates"].(map[string]any); !ok {
		t.Fatalf("updates missing: %v", h)
	}
	if u := h["updates"].(map[string]any); u["failures"] != float64(0) || u["last_check"] != "2026-10-03T08:00:00Z" {
		t.Fatalf("updates = %v", u)
	}
	if _, has := h["updates"].(map[string]any)["last_error"]; has {
		t.Fatal("an empty last_error was sent")
	}
}

func ptrTime(t time.Time) *time.Time { return &t }

func TestHealthWithNothingToSayStillCarriesTheRequiredLists(t *testing.T) {
	r := newRig(t)
	w := r.do(r.signed("/feed?scopes=health"))
	m := decode(t, w)
	h := m["health"].(map[string]any)
	if e, ok := h["errors"].([]any); !ok || len(e) != 0 {
		t.Fatalf("errors = %v", h["errors"])
	}
	if n, ok := h["notes"].([]any); !ok || len(n) != 0 {
		t.Fatalf("notes = %v", h["notes"])
	}
	if _, ok := h["updates"].(map[string]any); !ok {
		t.Fatalf("updates = %v", h["updates"])
	}
}

func TestListsAreCutToTheirLimits(t *testing.T) {
	r := newRig(t)
	for n := 0; n < 3000; n++ {
		r.src.ips.Bans = append(r.src.ips.Bans, Ban{IP: "198.51.100.1", At: 1, Until: 2})
	}
	for n := 0; n < 100; n++ {
		r.src.ips.Offenders = append(r.src.ips.Offenders, Offender{IP: "198.51.100.1"})
	}
	for n := 0; n < 100; n++ {
		r.src.health.Errors = append(r.src.health.Errors, strings.Repeat("e", 500))
		r.src.health.Notes = append(r.src.health.Notes, "n")
	}
	m := decode(t, r.do(r.signed("/feed?scopes=ips,health")))
	ips := m["ips"].(map[string]any)
	if got := len(ips["bans"].([]any)); got != 2000 {
		t.Fatalf("%d bans", got)
	}
	if got := len(ips["offenders"].([]any)); got != 50 {
		t.Fatalf("%d offenders", got)
	}
	h := m["health"].(map[string]any)
	if got := len(h["errors"].([]any)); got != 50 {
		t.Fatalf("%d errors", got)
	}
	if e := h["errors"].([]any)[0].(string); len(e) != 400 {
		t.Fatalf("error text is %d long", len(e))
	}
	if got := len(h["notes"].([]any)); got != 50 {
		t.Fatalf("%d notes", got)
	}
}

func TestInvalidEventsAreSkippedButTheCursorMovesOn(t *testing.T) {
	r := newRig(t)
	bad := goodEvent(0)
	bad.Kind = "NOT A KIND"
	r.src.events = []Event{goodEvent(3), bad, goodEvent(1), bad}
	w := r.do(r.signed("/feed?scopes=events,health"))
	m := decode(t, w)
	if got := len(m["events"].([]any)); got != 2 {
		t.Fatalf("%d events, want the 2 good ones", got)
	}
	if m["cursor"] != "p4" || m["more"] != false {
		t.Fatalf("cursor %v more %v: a trailing bad event must not hold the cursor back", m["cursor"], m["more"])
	}
	notes := m["health"].(map[string]any)["notes"].([]any)
	if len(notes) != 1 || !strings.Contains(notes[0].(string), "2 entries") {
		t.Fatalf("notes = %v", notes)
	}
}

func TestExactlyMaxEventsIsFine(t *testing.T) {
	r := newRig(t)
	for n := 0; n < MaxEvents; n++ {
		r.src.events = append(r.src.events, goodEvent(0))
	}
	w := r.do(r.signed("/feed?scopes=events"))
	if w.Code != 200 {
		t.Fatalf("%d", w.Code)
	}
	if got := len(decode(t, w)["events"].([]any)); got != MaxEvents {
		t.Fatalf("%d events", got)
	}
}
