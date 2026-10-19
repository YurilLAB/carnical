// SPDX-License-Identifier: Apache-2.0

package netwatch

import (
	"encoding/json"
	"math"
	"math/rand/v2"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

// guards simulates the kernel's counters: cumulative counts that each second adds to, and the two counting sets.
type guards struct {
	t        *testing.T
	d        *Detector
	at       time.Time
	counters map[string]Count
	ports    map[uint16]Count
	refl     map[uint16]Count
	seen     map[uint16]time.Time // when each element of ports was last updated, for its timeout
	seenRefl map[uint16]time.Time
	events   []observed
}

type observed struct {
	sec int
	ev  Event
	rec *Record
}

func newGuards(t *testing.T, cfg Config) *guards {
	g := &guards{t: t, d: New(cfg), at: time.Date(2026, 10, 19, 2, 0, 0, 0, time.UTC), counters: map[string]Count{},
		ports: map[uint16]Count{}, refl: map[uint16]Count{}, seen: map[uint16]time.Time{}, seenRefl: map[uint16]time.Time{}}
	for _, name := range CounterNames() {
		g.counters[name] = Count{}
	}
	g.counters["edge_syn_admitted"] = Count{} // counted by the policy, not a drop
	return g
}

// second adds one second's drops: n packets of size bytes to counter, spread over ports (for the UDP counters).
type traffic struct {
	counter string
	n       int
	size    int
	ports   func(i int) uint16 // destination ports (udp_flood_drop) or source ports (udp_reflection_drop); nil: none
}

func (g *guards) second(sec int, ts ...traffic) {
	g.at = g.at.Add(time.Second)
	// The sets' timeouts, as carnical.nft has them: an element not updated for that long is gone.
	for _, s := range []struct {
		set     map[uint16]Count
		seen    map[uint16]time.Time
		timeout time.Duration
	}{{g.ports, g.seen, 5 * time.Second}, {g.refl, g.seenRefl, 30 * time.Second}} {
		for p, at := range s.seen {
			if g.at.Sub(at) > s.timeout {
				delete(s.set, p)
				delete(s.seen, p)
			}
		}
	}
	for _, tr := range ts {
		c := g.counters[tr.counter]
		g.counters[tr.counter] = Count{c.Packets + uint64(tr.n), c.Bytes + uint64(tr.n*tr.size)}
		if tr.ports == nil {
			continue
		}
		set, seen, limit := g.ports, g.seen, 2048
		if tr.counter == "udp_reflection_drop" {
			set, seen, limit = g.refl, g.seenRefl, 64
		}
		for i := 0; i < tr.n; i++ {
			p := tr.ports(i)
			c, ok := set[p]
			if !ok && len(set) >= limit {
				continue // a full set counts no new port; the counter above still does
			}
			set[p] = Count{c.Packets + 1, c.Bytes + uint64(tr.size)}
			seen[p] = g.at
		}
	}
	r := Reading{At: g.at, Counters: clone(g.counters)}
	if g.d.WantSets() {
		r.Ports, r.Reflectors = cloneP(g.ports), cloneP(g.refl)
		r.PortsFull = len(g.ports) >= 2048
	}
	if ev, rec := g.d.Observe(r); ev != "" {
		g.events = append(g.events, observed{sec, ev, rec})
	}
}

func clone(m map[string]Count) map[string]Count {
	out := make(map[string]Count, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

func cloneP(m map[uint16]Count) map[uint16]Count {
	out := make(map[uint16]Count, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

func (g *guards) kinds() []Event {
	var out []Event
	for _, e := range g.events {
		out = append(out, e.ev)
	}
	return out
}

func (g *guards) first(ev Event) *observed {
	for i := range g.events {
		if g.events[i].ev == ev {
			return &g.events[i]
		}
	}
	return nil
}

// noise is the internet's background on a server: scans and stray datagrams, a few SYNs over budget, some pings.
func noise(r *rand.Rand) []traffic {
	return []traffic{
		{"udp_flood_drop", 20 + r.IntN(60), 80, func(int) uint16 { return uint16(1 + r.IntN(65535)) }},
		{"udp_reflection_drop", r.IntN(5), 200, func(int) uint16 { return []uint16{53, 123, 1900}[r.IntN(3)] }},
		{"edge_syn_source_drop", r.IntN(20), 60, nil},
		{"edge_bad_tcp", r.IntN(10), 40, nil},
		{"edge_echo_drop", r.IntN(5), 84, nil},
	}
}

func TestOrdinaryDropsAreNotAnAttack(t *testing.T) {
	for _, tc := range []struct {
		name  string
		extra func(sec int, r *rand.Rand) []traffic
	}{
		{"an hour of the internet's background", nil},
		{"spikes of two seconds, as a scan gives", func(sec int, r *rand.Rand) []traffic {
			if sec%300 < 2 {
				return []traffic{{"udp_flood_drop", 20_000, 60, func(i int) uint16 { return uint16(1 + i%60000) }}}
			}
			return nil
		}},
		{"a background that grows slowly to 900 drops a second", func(sec int, r *rand.Rand) []traffic {
			return []traffic{{"udp_flood_drop", sec / 4, 80, func(int) uint16 { return uint16(1 + r.IntN(65535)) }}}
		}},
		{"a busy edge whose usual drops are 3,000 a second, rising to 20,000 for a minute", func(sec int, r *rand.Rand) []traffic {
			n := 3000
			if sec > 3000 && sec < 3060 {
				n = 20_000 // under ten times the usual
			}
			return []traffic{{"edge_syn_source_drop", n, 60, nil}}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			g := newGuards(t, Config{})
			r := rand.New(rand.NewPCG(1, 2))
			for sec := 0; sec < 3600; sec++ {
				ts := noise(r)
				if tc.extra != nil {
					ts = append(ts, tc.extra(sec, r)...)
				}
				g.second(sec, ts...)
			}
			if len(g.events) != 0 {
				t.Fatalf("ordinary drops were taken for an attack: %v at %d s", g.kinds(), g.events[0].sec)
			}
		})
	}
}

func TestFloodsAreToldWithTheirPorts(t *testing.T) {
	for _, tc := range []struct {
		name        string
		flood       func(r *rand.Rand) []traffic
		kinds       []string
		ports       []Port // the first ports of the start, protocol and port only
		sourcePorts []uint16
	}{
		{"a UDP flood at 50,000 packets a second, mostly to DNS and HTTP ports", func(r *rand.Rand) []traffic {
			return []traffic{{"udp_flood_drop", 50_000, 512, func(i int) uint16 {
				switch {
				case i%10 < 6:
					return 53
				case i%10 < 9:
					return 80
				}
				return uint16(1024 + r.IntN(60000))
			}}}
		}, []string{KindUDPFlood}, []Port{{Protocol: "udp", Port: 53}, {Protocol: "udp", Port: 80}}, nil},
		{"NTP and DNS reflection at 20,000 packets a second to random ports", func(r *rand.Rand) []traffic {
			return []traffic{{"udp_reflection_drop", 20_000, 468, func(i int) uint16 {
				if i%10 < 7 {
					return 123
				}
				return 53
			}}, {"udp_flood_drop", 0, 0, nil}}
		}, []string{KindReflection}, nil, []uint16{123, 53}},
		{"a SYN flood over the budgets", func(r *rand.Rand) []traffic {
			return []traffic{{"edge_syn_source_drop", 20_000, 60, nil}, {"edge_syn_global_drop", 10_000, 60, nil}}
		}, []string{KindSYNFlood}, []Port{{Protocol: "tcp", Port: 8443}}, nil},
		{"a UDP flood and a SYN flood together", func(r *rand.Rand) []traffic {
			return []traffic{{"udp_flood_drop", 30_000, 900, func(int) uint16 { return 27015 }}, {"edge_syn_source_drop", 20_000, 60, nil}}
		}, []string{KindUDPFlood, KindSYNFlood}, []Port{{Protocol: "udp", Port: 27015}, {Protocol: "tcp", Port: 8443}}, nil},
		{"a UDP flood to the edge's port, dropped before the sets", func(r *rand.Rand) []traffic {
			return []traffic{{"edge_udp_drop", 40_000, 1200, nil}}
		}, []string{KindUDPFlood}, []Port{{Protocol: "udp", Port: 8443}}, nil},
		{"an echo flood", func(r *rand.Rand) []traffic {
			return []traffic{{"edge_echo_drop", 8_000, 1028, nil}}
		}, []string{KindEchoFlood}, nil, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			g := newGuards(t, Config{EdgePort: 8443})
			r := rand.New(rand.NewPCG(3, 4))
			for sec := 0; sec < 900; sec++ { // fifteen minutes of background, two minutes of flood, then background
				ts := noise(r)
				if sec >= 600 && sec < 720 {
					ts = append(ts, tc.flood(r)...)
				}
				g.second(sec, ts...)
			}
			start, end := g.first(Start), g.first(End)
			if start == nil || end == nil {
				t.Fatalf("events %v", g.kinds())
			}
			t.Logf("start at %d s: %s", start.sec, start.rec.Text(Start, "example.com"))
			if start.sec < 600 || start.sec > 604 {
				t.Fatalf("started at %d s, the flood at 600", start.sec)
			}
			if end.sec < 720+25 || end.sec > 720+35 {
				t.Fatalf("ended at %d s, the flood stopped at 720", end.sec)
			}
			var got []string
			for _, k := range start.rec.Kinds {
				got = append(got, k.Kind)
			}
			if !slices.Equal(got, tc.kinds) {
				t.Fatalf("kinds %q, want %q", got, tc.kinds)
			}
			for i, want := range tc.ports {
				if i >= len(start.rec.Ports) || start.rec.Ports[i].Protocol != want.Protocol || start.rec.Ports[i].Port != want.Port {
					t.Fatalf("ports %+v, want %+v first", start.rec.Ports, tc.ports)
				}
			}
			var src []uint16
			for _, p := range start.rec.SourcePorts {
				src = append(src, p.Port)
			}
			if tc.sourcePorts != nil && !slices.Equal(src[:min(len(src), len(tc.sourcePorts))], tc.sourcePorts) {
				t.Fatalf("source ports %v, want %v first", src, tc.sourcePorts)
			}
			if start.rec.Baseline > 200 || start.rec.PeakRate < 8000 || start.rec.Ended != nil || end.rec.Ended == nil {
				t.Fatalf("start %+v end %+v", start.rec, end.rec)
			}
			// Updates every ten seconds while it goes on, and nothing after the end.
			updates := 0
			for _, e := range g.events {
				if e.ev == Update {
					updates++
				}
			}
			if updates < 10 || updates > 16 || g.events[len(g.events)-1].ev != End {
				t.Fatalf("events %v", g.kinds())
			}
			// The end's totals hold the whole flood.
			var flood uint64
			for _, tr := range tc.flood(r) {
				flood += uint64(tr.n)
			}
			if end.rec.Packets < 118*flood || end.rec.Packets > 125*flood+50_000 {
				t.Fatalf("the attack counted %d packets, the flood sent %d", end.rec.Packets, 120*flood)
			}
		})
	}
}

// An attacker who sees the threshold and keeps a flood just under it cannot raise it: a second that is a rise is not
// learnt, and the usual rises at most by itself an hour. Above the ceiling a flood is an attack whatever the usual,
// and a watch that resumes after a restart has no warm-up to learn a flood in.
func TestTheUsualCannotBeTaughtAFlood(t *testing.T) {
	t.Run("a flood kept just under the threshold for an hour", func(t *testing.T) {
		g := newGuards(t, Config{})
		r := rand.New(rand.NewPCG(5, 6))
		for sec := 0; sec < 600; sec++ {
			g.second(sec, noise(r)...)
		}
		before := g.d.Threshold()
		for sec := 600; sec < 4200; sec++ {
			n := int(0.95*g.d.Threshold()) - 200 // under it, with the background on top
			g.second(sec, append(noise(r), traffic{"udp_flood_drop", n, 100, func(i int) uint16 { return 27015 }})...)
		}
		if after := g.d.Threshold(); after > 1.01*before || len(g.events) != 0 {
			t.Fatalf("the threshold went from %.0f to %.0f (events %v): the flood was learnt", before, after, g.kinds())
		}
	})
	t.Run("a flood kept just under twice the usual for an hour", func(t *testing.T) {
		g := newGuards(t, Config{})
		for sec := 0; sec < 600; sec++ { // a usual of 400 drops a second
			g.second(sec, traffic{"edge_syn_source_drop", 400, 60, nil})
		}
		before := g.d.Baseline()
		for sec := 600; sec < 4200; sec++ {
			g.second(sec, traffic{"edge_syn_source_drop", int(1.9 * g.d.Baseline()), 60, nil})
		}
		// Each second is learnt, but the usual (with 100) at most doubles in an hour.
		if after := g.d.Baseline(); after > 2.3*before {
			t.Fatalf("the usual went from %.0f to %.0f in an hour", before, after)
		}
	})
	t.Run("a flood over the ceiling on an edge whose usual is high", func(t *testing.T) {
		// 20,000 drops a second is this edge's usual (its -min-rate is raised to match): ten times it is 200,000.
		g := newGuards(t, Config{MinRate: 2500, Ceiling: 100_000})
		for sec := 0; sec < 600; sec++ {
			g.second(sec, traffic{"edge_syn_source_drop", 20_000, 60, nil})
		}
		if len(g.events) != 0 {
			t.Fatalf("the usual was reported: %v at %d s", g.kinds(), g.events[0].sec)
		}
		for sec := 600; sec < 610; sec++ {
			g.second(sec, traffic{"edge_syn_source_drop", 150_000, 60, nil})
		}
		if g.first(Start) == nil {
			t.Fatalf("150,000 drops a second, over the ceiling of 100,000, was not reported (threshold %.0f)", g.d.Threshold())
		}
	})
	t.Run("a restart during a flood resumes the usual", func(t *testing.T) {
		g := newGuards(t, Config{})
		g.d.Resume(60)
		for sec := 0; sec < 10; sec++ { // 5,000 a second: under the warm-up's 10,000, but 80 times the usual
			g.second(sec, traffic{"udp_flood_drop", 5000, 100, func(i int) uint16 { return 53 }})
		}
		if start := g.first(Start); start == nil || start.sec > 4 {
			t.Fatalf("events %v", g.kinds())
		}
	})
}

// A flood to more ports than the set holds says so: the port it is aimed at may be one the set had no room for.
func TestAFullPortSetIsSaid(t *testing.T) {
	g := newGuards(t, Config{})
	r := rand.New(rand.NewPCG(7, 8))
	for sec := 0; sec < 600; sec++ {
		g.second(sec, noise(r)...)
	}
	for sec := 600; sec < 640; sec++ {
		g.second(sec, traffic{"udp_flood_drop", 30_000, 100, func(i int) uint16 { return uint16(1 + r.IntN(65535)) }})
	}
	start := g.first(Start)
	if start == nil || !start.rec.PortsFull || !strings.Contains(start.rec.Text(Start, ""), "more UDP ports than are counted") {
		t.Fatalf("start %+v", start)
	}
	// A flood that begins on one port and then spreads: the start names the port, and what comes after says the set
	// was full from then on.
	g = newGuards(t, Config{})
	for sec := 0; sec < 600; sec++ {
		g.second(sec, noise(r)...)
	}
	for sec := 600; sec < 760; sec++ {
		port := func(int) uint16 { return 53 }
		if sec >= 620 {
			port = func(int) uint16 { return uint16(1 + r.IntN(65535)) }
		}
		if sec >= 700 {
			g.second(sec, noise(r)...)
			continue
		}
		g.second(sec, traffic{"udp_flood_drop", 30_000, 100, port})
	}
	start, end := g.first(Start), g.first(End)
	if start == nil || start.rec.PortsFull || start.rec.Ports[0].Port != 53 || end == nil || !end.rec.PortsFull {
		t.Fatalf("start %+v end %+v", start, end)
	}
}

func TestTheDetectorSurvivesWhatTheKernelDoes(t *testing.T) {
	flood := traffic{"udp_flood_drop", 40_000, 100, func(i int) uint16 { return uint16(1 + i%5000) }}
	t.Run("a policy reload in the middle of an attack resets the counters without an end or a second start", func(t *testing.T) {
		g := newGuards(t, Config{})
		r := rand.New(rand.NewPCG(5, 6))
		for sec := 0; sec < 300; sec++ {
			ts := noise(r)
			if sec >= 100 && sec < 200 {
				ts = append(ts, flood)
			}
			if sec == 150 { // nft -f: counters and sets start again from zero
				for k := range g.counters {
					g.counters[k] = Count{}
				}
				g.ports, g.refl = map[uint16]Count{}, map[uint16]Count{}
			}
			g.second(sec, ts...)
		}
		if k := g.kinds(); k[0] != Start || slices.Index(k, End) != len(k)-1 || slices.Index(k[1:], Start) >= 0 {
			t.Fatalf("events %v", k)
		}
	})
	t.Run("a reload while quiet is not an attack", func(t *testing.T) {
		g := newGuards(t, Config{})
		r := rand.New(rand.NewPCG(7, 8))
		for sec := 0; sec < 120; sec++ {
			g.second(sec, noise(r)...)
			if sec == 60 {
				g.counters["udp_flood_drop"] = Count{Packets: 1 << 40} // or a counter that jumps: never negative deltas
			}
		}
		if len(g.events) != 0 {
			t.Fatalf("events %v", g.kinds())
		}
	})
	t.Run("a gap in the readings (a suspended machine) is not a second's worth of drops", func(t *testing.T) {
		g := newGuards(t, Config{})
		r := rand.New(rand.NewPCG(9, 10))
		for sec := 0; sec < 60; sec++ {
			g.second(sec, noise(r)...)
		}
		g.at = g.at.Add(time.Hour) // the next reading is an hour later, with an hour's worth of background
		g.counters["udp_flood_drop"] = Count{Packets: g.counters["udp_flood_drop"].Packets + 3600*50}
		for sec := 60; sec < 120; sec++ {
			g.second(sec, noise(r)...)
		}
		if len(g.events) != 0 {
			t.Fatalf("events %v", g.kinds())
		}
	})
	t.Run("a flood to more ports than the set holds is counted in full, its ports bounded", func(t *testing.T) {
		g := newGuards(t, Config{})
		r := rand.New(rand.NewPCG(11, 12))
		wide := traffic{"udp_flood_drop", 60_000, 64, func(int) uint16 { return uint16(1 + r.IntN(65535)) }}
		for sec := 0; sec < 400; sec++ {
			ts := noise(r)
			if sec >= 100 && sec < 200 {
				ts = append(ts, wide)
			}
			g.second(sec, ts...)
		}
		end := g.first(End)
		if end == nil || len(end.rec.Ports) != 0 || !end.rec.RandomPorts || end.rec.OtherPorts < 96*60_000 || end.rec.Packets < 96*60_000 {
			t.Fatalf("end %+v", end.rec)
		}
		if len(g.d.prevPorts) > 2048 {
			t.Fatal("more ports followed than the set holds")
		}
	})
	t.Run("a short flood lasts at least MinAttack", func(t *testing.T) {
		g := newGuards(t, Config{})
		for sec := 0; sec < 200; sec++ {
			if sec >= 100 && sec < 106 {
				g.second(sec, flood)
			} else {
				g.second(sec)
			}
		}
		start, end := g.first(Start), g.first(End)
		if start == nil || end == nil || end.sec-start.sec < 30 {
			t.Fatalf("events %+v", g.events)
		}
	})
	t.Run("missing counters (an older policy) count nothing", func(t *testing.T) {
		d := New(Config{})
		at := time.Unix(1_800_000_000, 0)
		for i := 0; i < 100; i++ {
			if ev, _ := d.Observe(Reading{At: at.Add(time.Duration(i) * time.Second), Counters: map[string]Count{}}); ev != "" {
				t.Fatal(ev)
			}
		}
	})
}

// Real output of nft 1.1.3 for the shipped policy, cut to a few entries.
const counterListing = `{"nftables": [{"metainfo": {"version": "1.1.3", "release_name": "Commodore Bullmoose #4", "json_schema_version": 1}}, {"counter": {"family": "inet", "name": "edge_bad_source", "table": "carnical", "handle": 20, "packets": 3, "bytes": 180}}, {"counter": {"family": "inet", "name": "udp_flood_drop", "table": "carnical", "handle": 24, "packets": 400, "bytes": 36800}}, {"counter": {"family": "inet", "name": "other", "table": "other_table", "handle": 3, "packets": 9, "bytes": 9}}]}`

const setListing = `{"nftables": [{"metainfo": {"version": "1.1.3", "release_name": "Commodore Bullmoose #4", "json_schema_version": 1}}, {"set": {"family": "inet", "name": "udp_ports", "table": "carnical", "type": "inet_service", "handle": 4, "size": 2048, "flags": ["timeout", "dynamic"], "timeout": 120, "elem": [{"elem": {"val": 40001, "expires": 59, "counter": {"packets": 10, "bytes": 1280}}}, {"elem": {"val": 53, "expires": 59, "counter": {"packets": 5, "bytes": 640}}}], "stmt": [{"counter": null}]}}]}`

func TestNftListingsAreRead(t *testing.T) {
	c, err := ParseCounters([]byte(counterListing), "carnical")
	if err != nil || len(c) != 2 || c["udp_flood_drop"] != (Count{400, 36800}) || c["edge_bad_source"] != (Count{3, 180}) {
		t.Fatalf("counters %v %v", c, err)
	}
	s, full, err := ParseSet([]byte(setListing), "carnical", "udp_ports")
	if err != nil || full || len(s) != 2 || s[40001] != (Count{10, 1280}) || s[53] != (Count{5, 640}) {
		t.Fatalf("set %v %v %v", s, full, err)
	}
	// A datagram to port 0 is counted as one: it must not make the whole set unreadable (one packet every five
	// seconds would hide every port).
	if s, _, err := ParseSet([]byte(strings.Replace(setListing, `"val": 53`, `"val": 0`, 1)), "carnical", "udp_ports"); err != nil || s[0] != (Count{5, 640}) {
		t.Fatalf("port 0: %v %v", s, err)
	}
	// A set that holds as many ports as it can says so.
	if _, full, err := ParseSet([]byte(strings.Replace(setListing, `"size": 2048`, `"size": 2`, 1)), "carnical", "udp_ports"); err != nil || !full {
		t.Fatalf("a full set: %v %v", full, err)
	}
	empty := strings.Replace(setListing, `"elem": [{"elem": {"val": 40001, "expires": 59, "counter": {"packets": 10, "bytes": 1280}}}, {"elem": {"val": 53, "expires": 59, "counter": {"packets": 5, "bytes": 640}}}], `, "", 1)
	if s, _, err := ParseSet([]byte(empty), "carnical", "udp_ports"); err != nil || len(s) != 0 {
		t.Fatalf("an empty set: %v %v", s, err)
	}
	for _, tc := range []struct {
		name, data string
	}{
		{"not JSON", "{"},
		{"a duplicate counter", strings.Replace(counterListing, `"other", "table": "other_table"`, `"udp_flood_drop", "table": "carnical"`, 1)},
		{"an element without a counter", strings.Replace(setListing, `, "counter": {"packets": 5, "bytes": 640}`, "", 1)},
		{"an element that is not a port", strings.Replace(setListing, `"val": 53`, `"val": "x"`, 1)},
		{"a port out of range", strings.Replace(setListing, `"val": 53`, `"val": 65536`, 1)},
		{"a set of addresses", strings.Replace(setListing, `"inet_service"`, `"ipv4_addr"`, 1)},
		{"another set", strings.Replace(setListing, `"udp_ports"`, `"udp_reflectors"`, 1)},
		{"too large", `{"nftables": [` + strings.Repeat(" ", MaxListing) + `]}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err1 := ParseCounters([]byte(tc.data), "carnical")
			_, _, err2 := ParseSet([]byte(tc.data), "carnical", "udp_ports")
			if err1 == nil && err2 == nil {
				t.Fatal("accepted")
			}
		})
	}
}

func TestTheStateFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")
	if s, err := ReadState(path); err != nil || s.Seq != 0 {
		t.Fatalf("a missing file: %+v %v", s, err)
	}
	end := time.Unix(1_800_000_100, 0).UTC()
	rec := &Record{Started: time.Unix(1_800_000_000, 0).UTC(), Ended: &end, Kinds: []KindCount{{KindUDPFlood, 10, 100}},
		Ports: []Port{{"udp", 53, 10, 100}}, PeakRate: 5000}
	want := State{Version: 1, Seq: 7, Event: End, At: end, Attack: rec}
	if err := WriteState(path, want); err != nil {
		t.Fatal(err)
	}
	got, err := ReadState(path)
	if err != nil || got.Seq != 7 || got.Event != End || got.Attack.Ports[0].Port != 53 || !got.Attack.Ended.Equal(end) {
		t.Fatalf("read back %+v %v", got, err)
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 1 {
		t.Fatalf("a temporary file was left: %v", entries)
	}
	// A datagram to UDP port 0 is one the set counts, so a record may name it.
	zero := *rec
	zero.Ports = []Port{{"udp", 0, 10, 100}}
	if err := WriteState(path, State{Version: 1, Seq: 8, Event: End, At: end, Attack: &zero}); err != nil {
		t.Fatal(err)
	}
	if got, err := ReadState(path); err != nil || got.Attack.Ports[0].Port != 0 {
		t.Fatalf("UDP port 0: %+v %v", got, err)
	}
	// Stopped belongs to an end: a start or update that says it was stopped is not one the watch writes.
	stopped := *rec
	stopped.Ended, stopped.Stopped = nil, true
	if err := WriteState(path, State{Version: 1, Seq: 8, Event: Update, At: end, Attack: &stopped}); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadState(path); err == nil {
		t.Fatal("an update marked stopped was read")
	}
	if err := WriteState(path, want); err != nil {
		t.Fatal(err)
	}
	good, _ := os.ReadFile(path)
	for _, tc := range []struct {
		name string
		data string
	}{
		{"another version", strings.Replace(string(good), `"version":1`, `"version":2`, 1)},
		{"an unknown event", strings.Replace(string(good), `"network_attack_end"`, `"network_attack_maybe"`, 1)},
		{"an unknown field", strings.Replace(string(good), `"seq":7`, `"seq":7,"x":1`, 1)},
		{"an unknown kind", strings.Replace(string(good), `"udp_flood"`, `"<script>"`, 1)},
		{"TCP port 0", strings.Replace(strings.Replace(string(good), `"port":53`, `"port":0`, 1), `"protocol":"udp"`, `"protocol":"tcp"`, 1)},
		{"another protocol", strings.Replace(string(good), `"protocol":"udp"`, `"protocol":"sctp"`, 1)},
		{"an end without its time", strings.Replace(string(good), `"ended":"2027-01-15T08:01:40Z",`, ``, 1)},
		{"no record", `{"version":1,"seq":1,"event":"network_attack_start","at":"2026-10-19T00:00:00Z","attack":null}`},
		{"a negative rate", strings.Replace(string(good), `"peak_packet_rate":5000`, `"peak_packet_rate":-1`, 1)},
		{"too large", `{"version":1,"x":"` + strings.Repeat("a", MaxState) + `"}`},
		{"not JSON", "{"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.data == string(good) {
				t.Fatal("the change did not apply: the test proves nothing")
			}
			p := filepath.Join(t.TempDir(), "state.json")
			if err := os.WriteFile(p, []byte(tc.data), 0o644); err != nil {
				t.Fatal(err)
			}
			if _, err := ReadState(p); err == nil {
				t.Fatal("accepted")
			}
		})
	}
	if _, err := ReadState(dir); err == nil {
		t.Fatal("a directory was read as a state")
	}
}

// What nft prints is read strictly and boundedly, whatever it is.
func FuzzParseListings(f *testing.F) {
	f.Add([]byte(counterListing))
	f.Add([]byte(setListing))
	f.Add([]byte(`{"nftables": [{"counter": {"name": "x", "table": "carnical", "packets": -1}}]}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		if c, err := ParseCounters(data, "carnical"); err == nil && len(c) > 256 {
			t.Fatalf("%d counters", len(c))
		}
		if s, _, err := ParseSet(data, "carnical", "udp_ports"); err == nil && len(s) > maxElements {
			t.Fatalf("%d elements", len(s))
		}
	})
}

// The edge reads the state file as it would a stranger's: a state it accepts holds only what the watch writes, and
// its text is bounded and printable.
func FuzzReadState(f *testing.F) {
	end := time.Unix(1_800_000_100, 0).UTC()
	good, _ := json.Marshal(State{Version: 1, Seq: 7, Event: End, At: end, Attack: &Record{Started: end, Ended: &end,
		Kinds: []KindCount{{KindUDPFlood, 10, 100}}, Ports: []Port{{"udp", 53, 10, 100}}, SourcePorts: []Port{{"udp", 123, 1, 1}}}})
	f.Add(good)
	f.Add([]byte(`{"version":1,"seq":1,"event":"network_attack_start","at":"2026-10-19T00:00:00Z","attack":{"kinds":[]}}`))
	path := filepath.Join(f.TempDir(), "state.json")
	f.Fuzz(func(t *testing.T, data []byte) {
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
		s, err := ReadState(path)
		if err != nil || s.Seq == 0 {
			return
		}
		text := s.Attack.Text(s.Event, "example.com")
		if len(text) > 1024 || strings.ContainsFunc(text, func(r rune) bool { return r < ' ' || r == 0x7f }) {
			t.Fatalf("text %q", text)
		}
		for _, k := range s.Attack.Kinds {
			if !slices.Contains(knownKinds, k.Kind) {
				t.Fatalf("kind %q", k.Kind)
			}
		}
	})
}

// Whatever the counters do (reset, jump, stand still, go backwards), the detector neither panics nor reports a rate
// that is not a number.
func FuzzDetector(f *testing.F) {
	f.Add([]byte{1, 2, 3, 200, 200, 200, 200, 0, 0, 0}, uint16(1000))
	f.Fuzz(func(t *testing.T, steps []byte, gapMillis uint16) {
		d := New(Config{MinRate: 10, Factor: 2, Confirm: 1, Warmup: time.Second, MinAttack: time.Second, ExitQuiet: time.Second})
		at := time.Unix(1_800_000_000, 0)
		var total uint64
		for i, b := range steps {
			at = at.Add(time.Duration(gapMillis) * time.Millisecond)
			if b == 255 {
				total = 0 // a reload resets the counters
			} else {
				total += uint64(b) * 1000
			}
			r := Reading{At: at, Counters: map[string]Count{"udp_flood_drop": {total, total * 100}, "edge_udp_drop": {total / 3, total}}}
			if d.WantSets() {
				r.Ports = map[uint16]Count{uint16(i%7 + 1): {total, total}}
				r.Reflectors = map[uint16]Count{}
			}
			if _, rec := d.Observe(r); rec != nil {
				for _, v := range []float64{rec.PacketRate, rec.PeakRate, rec.ByteRate, rec.PeakBytes, rec.Baseline} {
					if math.IsNaN(v) || math.IsInf(v, 0) || v < 0 {
						t.Fatalf("rate %v in %+v", v, rec)
					}
				}
				if len(rec.Ports) > MaxPorts {
					t.Fatalf("%d ports", len(rec.Ports))
				}
			}
		}
	})
}
