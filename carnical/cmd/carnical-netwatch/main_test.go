// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/YurilLAB/coraza/carnical/netwatch"
)

// guardsSim is the packet guards as the kernel counts them: cumulative counters, and the set of ports a UDP flood went
// to. Each reading is a second later than the last.
type guardsSim struct {
	at       time.Time
	counters map[string]netwatch.Count
	ports    map[uint16]netwatch.Count
	// second returns what is dropped in the coming second: per counter, and per UDP port for the flood counter.
	second  func(n int) (map[string]uint64, map[uint16]uint64)
	n       int
	stopAt  int
	cancel  context.CancelFunc
	fail    func(n int) error
	setsErr bool
	reads   int
	setRead int
}

func (g *guardsSim) read(ctx context.Context, sets bool) (netwatch.Reading, error) {
	if ctx.Err() != nil {
		return netwatch.Reading{}, ctx.Err()
	}
	g.n++
	if g.n == g.stopAt {
		g.cancel()
		return netwatch.Reading{}, context.Canceled
	}
	g.at = g.at.Add(time.Second)
	drops, ports := g.second(g.n)
	for name, p := range drops {
		c := g.counters[name]
		g.counters[name] = netwatch.Count{Packets: c.Packets + p, Bytes: c.Bytes + 100*p}
	}
	for port, p := range ports {
		c := g.ports[port]
		g.ports[port] = netwatch.Count{Packets: c.Packets + p, Bytes: c.Bytes + 100*p}
	}
	if g.fail != nil {
		if err := g.fail(g.n); err != nil {
			return netwatch.Reading{}, err
		}
	}
	g.reads++
	r := netwatch.Reading{At: g.at, Counters: map[string]netwatch.Count{}}
	for k, v := range g.counters {
		r.Counters[k] = v
	}
	if sets {
		if g.setsErr {
			return r, fmt.Errorf("%w: udp_ports: no such set", errSets)
		}
		g.setRead++
		r.Ports, r.Reflectors = map[uint16]netwatch.Count{}, map[uint16]netwatch.Count{}
		for k, v := range g.ports {
			r.Ports[k] = v
		}
	}
	return r, nil
}

func newSim(t *testing.T, stopAt int, second func(n int) (map[string]uint64, map[uint16]uint64)) (*guardsSim, *watch, *bytes.Buffer, context.Context) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	g := &guardsSim{at: time.Date(2026, 10, 19, 3, 0, 0, 0, time.UTC), counters: map[string]netwatch.Count{},
		ports: map[uint16]netwatch.Count{}, second: second, stopAt: stopAt, cancel: cancel}
	var logs bytes.Buffer
	w := &watch{log: slog.New(slog.NewJSONHandler(&logs, nil)), read: g.read, path: filepath.Join(t.TempDir(), "state.json"),
		det: netwatch.New(netwatch.Config{}), now: func() time.Time { return g.at }}
	return g, w, &logs, ctx
}

// states runs the watch until the simulation stops it and returns the state file it left, if any: the file holds only
// the latest event, and the log has them all.
func states(t *testing.T, w *watch, ctx context.Context) []netwatch.State {
	t.Helper()
	var out []netwatch.State
	if err := w.loop(ctx, time.Microsecond); err != nil {
		t.Fatal(err)
	}
	st, err := netwatch.ReadState(w.path)
	if err != nil {
		t.Fatal(err)
	}
	if st.Seq != 0 {
		out = append(out, st)
	}
	return out
}

// A flood after the warm-up is told with its port, goes on, ends, and nothing else is reported.
func TestTheWatchTellsAFloodWithItsPort(t *testing.T) {
	const quietUntil, floodUntil = 400, 460
	g, w, logs, ctx := newSim(t, 560, func(n int) (map[string]uint64, map[uint16]uint64) {
		if n > quietUntil && n <= floodUntil {
			return map[string]uint64{"udp_flood_drop": 50000}, map[uint16]uint64{53: 40000, 9999: 10000}
		}
		return map[string]uint64{"udp_flood_drop": 20, "edge_syn_source_drop": 2}, map[uint16]uint64{1900: 20}
	})
	got := states(t, w, ctx)
	lines := strings.Split(strings.TrimSpace(logs.String()), "\n")
	var events []string
	for _, l := range lines {
		for _, ev := range []string{"network_attack_start", "network_attack_update", "network_attack_end"} {
			if strings.Contains(l, `"event":"`+ev+`"`) {
				events = append(events, ev)
			}
		}
	}
	if len(events) < 3 || events[0] != "network_attack_start" || events[len(events)-1] != "network_attack_end" {
		t.Fatalf("events %v\n%s", events, logs)
	}
	if !strings.Contains(lines[1], `"ports":["udp/53","udp/9999"]`) || !strings.Contains(lines[1], `"kinds":["udp_flood"]`) {
		t.Fatalf("the start names the ports and the kind: %s", lines[1])
	}
	if len(got) != 1 || got[0].Event != netwatch.End || got[0].Attack.Stopped || int(got[0].Seq) != len(events) {
		t.Fatalf("the state is the last event, numbered: %+v (events %v)", got, events)
	}
	// The sets are read only while the drops are high, which is a few seconds of 560.
	if g.setRead == 0 || g.setRead > floodUntil-quietUntil+60 {
		t.Fatalf("the sets were read %d times in %d readings", g.setRead, g.reads)
	}
}

// Ordinary drops, and a rise that is not an attack, are reported as nothing: no line, no state.
func TestTheWatchIsQuietWithoutAFlood(t *testing.T) {
	_, w, logs, ctx := newSim(t, 900, func(n int) (map[string]uint64, map[uint16]uint64) {
		drops := uint64(40 + n%7*30) // a background of scans that varies
		if n > 600 && n < 610 {
			drops = 900 // a burst under the least rate
		}
		return map[string]uint64{"udp_flood_drop": drops, "edge_echo_drop": 3}, map[uint16]uint64{161: drops}
	})
	if got := states(t, w, ctx); len(got) != 0 || strings.Contains(logs.String(), "network_attack") {
		t.Fatalf("states %+v\n%s", got, logs)
	}
}

// A flood going on when the watch stops is closed as stopped; a record a crash left open is closed at the next start,
// and the numbering goes on.
func TestTheWatchClosesWhatItLeavesOpen(t *testing.T) {
	flood := func(n int) (map[string]uint64, map[uint16]uint64) {
		if n > 350 {
			return map[string]uint64{"udp_reflection_drop": 30000}, nil
		}
		return map[string]uint64{"udp_flood_drop": 5}, nil
	}
	_, w, logs, ctx := newSim(t, 380, flood)
	got := states(t, w, ctx)
	if len(got) != 1 || got[0].Event != netwatch.End || !got[0].Attack.Stopped || !strings.Contains(logs.String(), `"stopped":true`) {
		t.Fatalf("stopping during a flood: %+v\n%s", got, logs)
	}
	if !strings.Contains(got[0].Attack.Text(netwatch.End, ""), "record closed") {
		t.Fatalf("text %q", got[0].Attack.Text(netwatch.End, ""))
	}
	seq := got[0].Seq

	// A crash: the file says the attack goes on.
	open := got[0]
	open.Event, open.Attack.Ended, open.Attack.Stopped = netwatch.Update, nil, false
	if err := netwatch.WriteState(w.path, open); err != nil {
		t.Fatal(err)
	}
	g2, w2, _, ctx2 := newSim(t, 3, flood)
	w2.path = w.path
	restart := g2.at
	got = states(t, w2, ctx2)
	if len(got) != 1 || got[0].Event != netwatch.End || !got[0].Attack.Stopped || got[0].Seq != seq+1 ||
		!got[0].Attack.Ended.Equal(restart) {
		t.Fatalf("after a crash: %+v", got)
	}
}

// Readings that fail are logged once a minute, not once a second; the counters still count when only the sets fail.
func TestTheWatchSurvivesReadingsThatFail(t *testing.T) {
	g, w, logs, ctx := newSim(t, 500, func(n int) (map[string]uint64, map[uint16]uint64) {
		if n > 350 && n < 420 {
			return map[string]uint64{"udp_flood_drop": 40000}, map[uint16]uint64{53: 40000}
		}
		return map[string]uint64{"udp_flood_drop": 10}, nil
	})
	g.setsErr = true
	g.fail = func(n int) error {
		if n > 100 && n <= 250 {
			return errors.New("nft took too long")
		}
		return nil
	}
	got := states(t, w, ctx)
	out := logs.String()
	if n := strings.Count(out, "cannot read the packet guards"); n != 3 {
		t.Fatalf("150 failed readings logged %d times, want 3 (one a minute):\n%s", n, out)
	}
	if strings.Count(out, "reads the packet guards again") != 1 {
		t.Fatalf("the recovery is logged:\n%s", out)
	}
	if !strings.Contains(out, "cannot read the ports of the drops") || len(got) != 1 || got[0].Event != netwatch.End {
		t.Fatalf("a flood without its sets is still told: %+v\n%s", got, out)
	}
}

func TestArguments(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want string
	}{
		{"relative nft", []string{"-nft", "nft"}, "-nft must be an absolute path"},
		{"relative state", []string{"-state", "state.json"}, "-state must be an absolute path"},
		{"no port", []string{"-edge-port", "0"}, "-edge-port must be a port"},
		{"too big a port", []string{"-edge-port", "70000"}, "-edge-port must be a port"},
		{"factor under one", []string{"-factor", "0.5"}, "-factor at least 1"},
		{"table with a space", []string{"-table", "carnical x"}, "-table must be a table name"},
		{"table with a quote", []string{"-table", `carnical"`}, "-table must be a table name"},
		{"table starting with a digit", []string{"-table", "1carnical"}, "-table must be a table name"},
		{"an argument", []string{"extra"}, "unexpected arguments"},
		{"an unknown flag", []string{"-watch"}, "flag provided but not defined"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var out bytes.Buffer
			if code := run(tt.args, &out); code != 2 || !strings.Contains(out.String(), tt.want) {
				t.Fatalf("exit %d: %s", code, &out)
			}
		})
	}
	for _, name := range []string{"carnical", "inet_guards", "a-1"} {
		if !validTable(name) {
			t.Errorf("%q is a table name", name)
		}
	}
}

// nft's output is kept to what a listing can be: more is refused, not buffered.
func TestCapped(t *testing.T) {
	c := capped{max: 10}
	for _, p := range []string{"12345", "678", "90abc"} {
		if n, err := io.WriteString(&c, p); err != nil || n != len(p) {
			t.Fatal(n, err)
		}
	}
	if c.buf.String() != "1234567890" || !c.over {
		t.Fatalf("%q %v", c.buf.String(), c.over)
	}
}

// A restart resumes the usual rate the last run kept: a flood going on then is told at once, not learnt in a warm-up.
// Without a kept rate (the control) the same flood is under the warm-up's threshold and is not told.
func TestTheWatchResumesTheUsualAfterARestart(t *testing.T) {
	background := func(n int) (map[string]uint64, map[uint16]uint64) {
		return map[string]uint64{"udp_flood_drop": 40}, nil
	}
	// A run stopped during its warm-up keeps nothing: its usual is not yet learnt.
	_, early, _, ctx := newSim(t, 200, background)
	states(t, early, ctx)
	if _, err := os.Stat(early.baselinePath()); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("a usual rate was kept during the warm-up: %v", err)
	}
	_, first, _, ctx := newSim(t, 420, background) // past the five-minute warm-up
	states(t, first, ctx)
	if _, err := os.Stat(first.baselinePath()); err != nil {
		t.Fatalf("the usual rate was not kept: %v", err)
	}
	flood := func(n int) (map[string]uint64, map[uint16]uint64) {
		return map[string]uint64{"udp_flood_drop": 5000}, map[uint16]uint64{53: 5000}
	}
	for _, keep := range []bool{true, false} {
		g, w, logs, ctx := newSim(t, 12, flood)
		g.at = g.at.Add(420 * time.Second) // the clock goes on from the first run
		if keep {
			w.path = first.path
		}
		got := states(t, w, ctx)
		told := strings.Contains(logs.String(), `"event":"network_attack_start"`)
		if told != keep {
			t.Fatalf("kept rate %v: start told %v\n%s", keep, told, logs)
		}
		if keep && (len(got) != 1 || !got[0].Attack.Stopped || !strings.Contains(logs.String(), "resumes its usual rate")) {
			t.Fatalf("after the restart: %+v\n%s", got, logs)
		}
	}
}

// The reading itself, against a stand-in for nft: the counters are read; a set that fails leaves the other read and
// the counters counting; port 0 and a full set are reported; an nft that hangs or prints too much is cut off.
func TestReadingTheGuards(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("nft runs on Linux")
	}
	dir := t.TempDir()
	script := func(name, body string) guards {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte("#!/bin/sh\n"+body), 0o700); err != nil {
			t.Fatal(err)
		}
		return guards{nft: path, table: "carnical"}
	}
	const counters = `{"nftables": [{"counter": {"family": "inet", "name": "udp_flood_drop", "table": "carnical", "packets": 7, "bytes": 700}}]}`
	const ports = `{"nftables": [{"set": {"family": "inet", "name": "udp_ports", "table": "carnical", "type": "inet_service", "size": 2, "elem": [{"elem": {"val": 0, "counter": {"packets": 1, "bytes": 60}}}, {"elem": {"val": 53, "counter": {"packets": 6, "bytes": 640}}}]}}]}`
	g := script("nft", `case "$*" in
*counters*) echo '`+counters+`' ;;
*udp_ports*) echo '`+ports+`' ;;
*) echo 'Error: No such file or directory' >&2; exit 1 ;;
esac
`)
	before := time.Now()
	r, err := g.read(context.Background(), true)
	if !errors.Is(err, errSets) || !strings.Contains(err.Error(), "udp_reflectors") || strings.Contains(err.Error(), "udp_ports") {
		t.Fatalf("the reflectors' failure alone: %v", err)
	}
	if r.Counters["udp_flood_drop"].Packets != 7 || r.Ports[0].Packets != 1 || r.Ports[53].Packets != 6 || !r.PortsFull ||
		r.Reflectors != nil || r.At.Before(before) {
		t.Fatalf("reading %+v", r)
	}
	if _, err := g.read(context.Background(), false); err != nil {
		t.Fatalf("without the sets: %v", err)
	}
	// The other way round: the ports fail, the reflectors are still read.
	const refl = `{"nftables": [{"set": {"family": "inet", "name": "udp_reflectors", "table": "carnical", "type": "inet_service", "size": 64, "elem": [{"elem": {"val": 123, "counter": {"packets": 3, "bytes": 1404}}}]}}]}`
	g = script("nft-ports-fail", `case "$*" in
*counters*) echo '`+counters+`' ;;
*udp_reflectors*) echo '`+refl+`' ;;
*) exit 1 ;;
esac
`)
	if r, err := g.read(context.Background(), true); !errors.Is(err, errSets) || r.Ports != nil || r.Reflectors[123].Packets != 3 {
		t.Fatalf("the ports' failure alone: %+v %v", r, err)
	}
	for _, tc := range []struct {
		name, body, want string
	}{
		{"an nft that fails", "echo 'netlink: Error: cache initialization failed: Operation not permitted' >&2; exit 1", "Operation not permitted"},
		{"an nft that hangs", "sleep 10", "nft took too long"},
		{"an nft that prints too much", "head -c 5000000 /dev/zero", "nft printed too much"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			start := time.Now()
			_, err := script(strings.ReplaceAll(tc.name, " ", "-"), tc.body+"\n").read(context.Background(), true)
			if err == nil || !strings.Contains(err.Error(), tc.want) || errors.Is(err, errSets) {
				t.Fatalf("%v, want %q", err, tc.want)
			}
			if time.Since(start) > readTimeout+time.Second {
				t.Fatalf("took %s", time.Since(start))
			}
		})
	}
}
