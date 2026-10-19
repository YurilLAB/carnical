// SPDX-License-Identifier: Apache-2.0

// Command carnical-netwatch tells when the kernel's packet guards (deploy/nftables/carnical.nft) are under a volumetric
// attack the proxy never sees: a UDP flood, UDP reflection, a SYN flood, malformed TCP or an echo flood. Once a second
// it reads the guards' drop counters from the kernel, and while the drops are high also, with nft, the sets that count
// them by port; it logs each attack's start, updates and end as JSON lines, and writes the latest to a state file, which
// the edge reads (-netwatch-state) and sends to its alert endpoint:
//
//	carnical-netwatch -state /run/carnical/netwatch/state.json
//
// It needs CAP_NET_ADMIN to list the rules (see deploy/systemd/carnical-netwatch.service) and opens no socket but
// netlink ones. A record still open when it stops, or that a crash left open, is closed with Stopped set.
package main

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/YurilLAB/coraza/carnical/netwatch"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stderr))
}

// config is what run was asked to do.
type config struct {
	state, nft, table string
	detector          netwatch.Config
	once              bool
}

func run(args []string, stderr io.Writer) int {
	flags := flag.NewFlagSet("carnical-netwatch", flag.ContinueOnError)
	flags.SetOutput(stderr)
	var cfg config
	flags.StringVar(&cfg.state, "state", "/run/carnical/netwatch/state.json", "the state file the edge reads: the latest event and its record")
	flags.StringVar(&cfg.nft, "nft", "/usr/sbin/nft", "the nft program (an absolute path: nothing is looked up in PATH)")
	flags.StringVar(&cfg.table, "table", "carnical", "the inet table of the packet guards")
	edgePort := flags.Uint("edge-port", 443, "the edge's TCP port, which the SYN and malformed TCP guards protect (named in a record of either)")
	flags.Float64Var(&cfg.detector.MinRate, "min-rate", 1000, "the least rate of dropped packets a second that can be an attack")
	flags.Float64Var(&cfg.detector.Factor, "factor", 10, "how many times the usual rate of drops the rate must reach")
	flags.Float64Var(&cfg.detector.Ceiling, "ceiling", 0, "the rate of dropped packets a second that is an attack whatever the usual (default 100 times -min-rate)")
	flags.BoolVar(&cfg.once, "once", false, "read the guards once, print what is counted and exit: a check that nft, the table and its counters are there")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	switch {
	case flags.NArg() != 0:
		fmt.Fprintln(stderr, "carnical-netwatch: unexpected arguments")
		return 2
	case !absolute(cfg.nft):
		fmt.Fprintln(stderr, "carnical-netwatch: -nft must be an absolute path")
		return 2
	case !cfg.once && !absolute(cfg.state):
		fmt.Fprintln(stderr, "carnical-netwatch: -state must be an absolute path")
		return 2
	case *edgePort == 0 || *edgePort > 65535 || cfg.detector.MinRate <= 0 || cfg.detector.Factor < 1 ||
		cfg.detector.Ceiling != 0 && cfg.detector.Ceiling < cfg.detector.MinRate:
		fmt.Fprintln(stderr, "carnical-netwatch: -edge-port must be a port, -min-rate positive, -factor at least 1 and -ceiling at least -min-rate")
		return 2
	case !validTable(cfg.table):
		fmt.Fprintln(stderr, "carnical-netwatch: -table must be a table name")
		return 2
	}
	cfg.detector.EdgePort = uint16(*edgePort) // #nosec G115 -- checked above
	log := slog.New(slog.NewJSONHandler(stderr, nil))
	g := guards{nft: cfg.nft, table: cfg.table, counters: netwatch.ReadCounters}
	if cfg.once {
		return once(context.Background(), g, stderr)
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	w := &watch{log: log, read: g.read, path: cfg.state, det: netwatch.New(cfg.detector), now: time.Now}
	if err := w.loop(ctx, time.Second); err != nil {
		log.Error("netwatch stopped", "error", err.Error())
		return 1
	}
	return 0
}

// absolute says whether p is an absolute path on the Linux machine this runs on (it builds elsewhere too).
func absolute(p string) bool { return strings.HasPrefix(p, "/") || filepath.IsAbs(p) }

// validTable is a name nft accepts for a table, which is passed to it as an argument.
func validTable(s string) bool {
	if s == "" || len(s) > 64 {
		return false
	}
	for i, c := range s {
		letter := c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c == '_'
		if !letter && (i == 0 || (c < '0' || c > '9') && c != '-') {
			return false
		}
	}
	return true
}

// guards reads the packet guards' counters, and their sets with nft.
type guards struct {
	nft, table string
	counters   func(ctx context.Context, table string) (map[string]netwatch.Count, error)
}

// readTimeout bounds one read of the counters and one nft run: under a flood the machine is slow, but a reading that
// takes longer than this is of no use to a once-a-second watch.
const readTimeout = 2 * time.Second

// errSets says that the counters were read but the counting sets were not: the reading counts, without its ports.
var errSets = errors.New("the counting sets cannot be read")

// read is one reading: the counters, and the counting sets when sets is set. A set that fails is left nil, and the
// reading is returned with an error that wraps errSets; the other set is still read.
func (g guards) read(ctx context.Context, sets bool) (netwatch.Reading, error) {
	var r netwatch.Reading
	cctx, cancel := context.WithTimeout(ctx, readTimeout)
	counters, err := g.counters(cctx, g.table)
	cancel()
	if err != nil {
		return r, err
	}
	// The time of the counters, not of the start of the read: a slow read would otherwise put a second's drops in
	// another second.
	r.At, r.Counters = time.Now(), counters
	if !sets {
		return r, nil
	}
	// Both sets within one read's time: an nft that hangs on the first does not cost two.
	sctx, cancel := context.WithTimeout(ctx, readTimeout)
	defer cancel()
	var errPorts, errRefl error
	r.Ports, r.PortsFull, errPorts = g.set(sctx, "udp_ports")
	r.Reflectors, _, errRefl = g.set(sctx, "udp_reflectors")
	return r, errors.Join(errPorts, errRefl)
}

func (g guards) set(ctx context.Context, name string) (map[uint16]netwatch.Count, bool, error) {
	out, err := g.list(ctx, "list", "set", "inet", g.table, name)
	if err == nil {
		m, full, err := netwatch.ParseSet(out, g.table, name)
		if err == nil {
			return m, full, nil
		}
		return nil, false, fmt.Errorf("%w: %s: %v", errSets, name, err)
	}
	return nil, false, fmt.Errorf("%w: %s: %v", errSets, name, err)
}

// list runs nft -j with args and returns what it printed, at most netwatch.MaxListing bytes.
func (g guards) list(ctx context.Context, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, readTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, g.nft, append([]string{"-j"}, args...)...) // #nosec G204 -- an absolute path from the operator, fixed arguments
	cmd.Env = []string{"LC_ALL=C", "PATH=/usr/sbin:/usr/bin:/sbin:/bin"}
	// Killed at the timeout, nft may still leave its output open (a child holds it): the read ends anyway.
	cmd.WaitDelay = 500 * time.Millisecond
	var stdout, stderr capped
	stdout.max, stderr.max = netwatch.MaxListing, 512
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		if ctx.Err() != nil {
			return nil, errors.New("nft took too long")
		}
		return nil, fmt.Errorf("nft %s: %v: %s", args[1], err, bytes.TrimSpace(stderr.buf.Bytes()))
	}
	if stdout.over {
		return nil, errors.New("nft printed too much")
	}
	return stdout.buf.Bytes(), nil
}

// capped keeps the first max bytes written to it and notes that there were more.
type capped struct {
	buf  bytes.Buffer
	max  int
	over bool
}

func (c *capped) Write(p []byte) (int, error) {
	if room := c.max - c.buf.Len(); len(p) > room {
		c.buf.Write(p[:max(room, 0)])
		c.over = true
		return len(p), nil
	}
	return c.buf.Write(p)
}

// once prints one reading of the counters and the sets, or why there is none.
func once(ctx context.Context, g guards, out io.Writer) int {
	r, err := g.read(ctx, true)
	if err != nil {
		fmt.Fprintln(out, "carnical-netwatch:", err)
		return 1
	}
	missing := 0
	for _, name := range netwatch.CounterNames() {
		c, ok := r.Counters[name]
		if !ok {
			missing++
			fmt.Fprintf(out, "%-24s missing\n", name)
			continue
		}
		fmt.Fprintf(out, "%-24s %d packets, %d bytes\n", name, c.Packets, c.Bytes)
	}
	fmt.Fprintf(out, "udp_ports                %d ports\nudp_reflectors           %d ports\n", len(r.Ports), len(r.Reflectors))
	if missing > 0 {
		fmt.Fprintf(out, "carnical-netwatch: %d counters are missing: the guards are not the policy this reads\n", missing)
		return 1
	}
	return 0
}

// watch reads the guards once a tick and reports what the detector makes of them.
type watch struct {
	log  *slog.Logger
	read func(ctx context.Context, sets bool) (netwatch.Reading, error)
	path string
	det  *netwatch.Detector
	now  func() time.Time
	seq  uint64

	failing    bool // the last reading failed
	lastReport time.Time
	setsReport time.Time // when the sets' failure was last logged
	kept       time.Time // when the usual rate was last kept
}

// keepEvery is how often the usual rate is kept beside the state, and keptFor how old a kept one may be to resume.
const (
	keepEvery = time.Minute
	keptFor   = time.Hour
)

// baselinePath is where the usual rate is kept: beside the state, in the watch's own directory.
func (w *watch) baselinePath() string { return filepath.Join(filepath.Dir(w.path), "baseline.json") }

// failureReportGap is the least time between two log lines about readings that fail.
const failureReportGap = time.Minute

func (w *watch) loop(ctx context.Context, tick time.Duration) error {
	w.resume()
	w.log.Info("netwatch on", "state", w.path, "threshold", w.det.Threshold())
	t := time.NewTicker(tick)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			if rec := w.det.Stop(w.now()); rec != nil {
				w.emit(netwatch.End, rec)
			}
			w.log.Info("netwatch stopped")
			return nil
		case <-t.C:
		}
		r, err := w.read(ctx, w.det.WantSets())
		if errors.Is(err, errSets) && r.Counters != nil {
			if now := w.now(); now.Sub(w.setsReport) >= failureReportGap {
				w.log.Warn("netwatch cannot read the ports of the drops", "error", err.Error())
				w.setsReport = now
			}
			err = nil
		}
		if err != nil {
			if ctx.Err() != nil {
				continue // stopping: the select above closes the record
			}
			if now := w.now(); !w.failing || now.Sub(w.lastReport) >= failureReportGap {
				w.log.Error("netwatch cannot read the packet guards", "error", err.Error())
				w.lastReport = now
			}
			w.failing = true
			continue
		}
		if w.failing {
			w.log.Info("netwatch reads the packet guards again")
			w.failing = false
		}
		if ev, rec := w.det.Observe(r); ev != "" {
			w.emit(ev, rec)
		}
		// Only once it is learnt, and while no attack goes on: what is kept is the usual, from before.
		if now := w.now(); !w.det.Learning() && !w.det.Open() && now.Sub(w.kept) >= keepEvery {
			if err := netwatch.WriteBaseline(w.baselinePath(), w.det.Baseline(), now); err != nil {
				w.log.Error("netwatch cannot keep its usual rate", "error", err.Error())
			}
			w.kept = now
		}
	}
}

// resume continues the numbering of the state file there is, closes the record a crash left open, and resumes the
// usual rate kept by the last run, so that a flood going on now is not learnt in a warm-up.
func (w *watch) resume() {
	netwatch.RemoveTemporary(w.path)
	netwatch.RemoveTemporary(w.baselinePath())
	if base, ok := netwatch.ReadBaseline(w.baselinePath(), w.now(), keptFor); ok {
		w.det.Resume(base)
		w.log.Info("netwatch resumes its usual rate", "baseline_packet_rate", base)
	}
	st, err := netwatch.ReadState(w.path)
	if err != nil {
		// Not ours to keep: the next event replaces it.
		w.log.Warn("netwatch state unreadable; starting again", "error", err.Error())
		return
	}
	w.seq = st.Seq
	if st.Event == netwatch.Start || st.Event == netwatch.Update {
		rec := *st.Attack
		end := w.now()
		rec.Ended, rec.Stopped = &end, true
		w.emit(netwatch.End, &rec)
		// The usual from before that attack, whatever was kept since it began.
		w.det.Resume(rec.Baseline)
	}
}

// emit logs an event and writes it to the state file.
func (w *watch) emit(ev netwatch.Event, rec *netwatch.Record) {
	w.seq++
	at := w.now()
	attrs := []any{"event", string(ev), "kinds", kindNames(rec), "ports", portNames(rec.Ports), "packet_rate", rec.PacketRate,
		"peak_packet_rate", rec.PeakRate, "baseline_packet_rate", rec.Baseline, "packets", rec.Packets, "bytes", rec.Bytes}
	if len(rec.SourcePorts) > 0 {
		attrs = append(attrs, "source_ports", portNames(rec.SourcePorts))
	}
	if rec.RandomPorts {
		attrs = append(attrs, "random_ports", true)
	}
	if rec.Stopped {
		attrs = append(attrs, "stopped", true)
	}
	switch ev {
	case netwatch.Start:
		w.log.Warn(rec.Text(ev, ""), attrs...)
	default:
		w.log.Info(rec.Text(ev, ""), attrs...)
	}
	if err := netwatch.WriteState(w.path, netwatch.State{Version: 1, Seq: w.seq, Event: ev, At: at, Attack: rec}); err != nil {
		w.log.Error("netwatch cannot write its state", "error", err.Error())
	}
}

func kindNames(r *netwatch.Record) []string {
	out := make([]string, 0, len(r.Kinds))
	for _, k := range r.Kinds {
		out = append(out, k.Kind)
	}
	return out
}

func portNames(ps []netwatch.Port) []string {
	out := make([]string, 0, len(ps))
	for _, p := range ps {
		out = append(out, fmt.Sprintf("%s/%d", p.Protocol, p.Port))
	}
	return out
}
