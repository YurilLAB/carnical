// SPDX-License-Identifier: Apache-2.0

package main

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"github.com/YurilLAB/coraza/carnical/netwatch"
	"github.com/YurilLAB/coraza/carnical/notify"
)

// netwatchPoll is how often the edge looks at carnical-netwatch's state file: a stat, and a read only when it changed.
const netwatchPoll = time.Second

// netwatchFresh is how old an event found at startup may be and still be told: one from just before a restart was
// probably not, while an older one was, by the edge that ran then.
const netwatchFresh = 15 * time.Second

// netwatchReader tells the log and the alert endpoint of the network attacks carnical-netwatch writes to its state file.
type netwatchReader struct {
	path  string
	log   *slog.Logger
	ep    *endpoint
	site  string
	now   func() time.Time
	owner int // the uid the state file must belong to: root's (0), as carnical-netwatch runs

	started  bool
	seq      uint64
	at       time.Time
	last     os.FileInfo // the file last read: carnical-netwatch replaces it (a rename) with each event
	failedAt time.Time   // when a failure to read was last logged
	stop     chan struct{}
	done     chan struct{}
}

// checkNetwatchState checks -netwatch-state: an absolute path, in a directory that is there (with -confine, the edge may
// read only what was there when it confined itself).
func checkNetwatchState(path string) error {
	if !filepath.IsAbs(path) {
		return errors.New("-netwatch-state must be an absolute path")
	}
	st, err := os.Stat(filepath.Dir(path))
	if err != nil || !st.IsDir() {
		return fmt.Errorf("-netwatch-state: the directory %s must exist (deploy/tmpfiles.d/carnical.conf makes it)", filepath.Dir(path))
	}
	return nil
}

func newNetwatchReader(path string, log *slog.Logger, ep *endpoint, site string) *netwatchReader {
	return &netwatchReader{path: path, log: log, ep: ep, site: site, now: time.Now}
}

// start polls the state file until close.
func (n *netwatchReader) start() {
	n.stop, n.done = make(chan struct{}), make(chan struct{})
	go func() {
		defer close(n.done)
		t := time.NewTicker(netwatchPoll)
		defer t.Stop()
		for {
			n.poll()
			select {
			case <-n.stop:
				return
			case <-t.C:
			}
		}
	}()
}

// close stops the polling; the last poll has ended when it returns.
func (n *netwatchReader) close() {
	if n == nil || n.stop == nil {
		return
	}
	close(n.stop)
	<-n.done
}

// poll reads the state file when it changed, and tells of an event it has not told before.
func (n *netwatchReader) poll() {
	fi, err := os.Stat(n.path)
	switch {
	case errors.Is(err, os.ErrNotExist):
		n.started = true // nothing reported yet: every event from now on is new
		return
	case err != nil:
		n.failed(err)
		return
	case n.last != nil && os.SameFile(fi, n.last) && fi.ModTime().Equal(n.last.ModTime()) && fi.Size() == n.last.Size():
		return
	}
	st, err := netwatch.ReadStateChecked(n.path, func(fi os.FileInfo) error { return checkStateOwner(fi, n.owner) })
	if err != nil {
		n.failed(err)
		return
	}
	n.last = fi
	if st.Seq == 0 || st.Seq == n.seq && st.At.Equal(n.at) {
		n.started = true
		return
	}
	first := !n.started
	n.started, n.seq, n.at = true, st.Seq, st.At
	if first && n.now().Sub(st.At) > netwatchFresh {
		return
	}
	n.tell(st)
}

func (n *netwatchReader) failed(err error) {
	if now := n.now(); n.failedAt.IsZero() || now.Sub(n.failedAt) >= time.Minute {
		n.log.Warn("the network watch's state cannot be read", "error", err.Error())
		n.failedAt = now
	}
}

// tell logs an event and passes it to the alert endpoint.
func (n *netwatchReader) tell(st netwatch.State) {
	rec := st.Attack
	msg := "network flood detected"
	switch {
	case st.Event == netwatch.Update:
		msg = "network flood continues"
	case st.Event == netwatch.End && rec.Stopped:
		msg = "network flood record closed: the watch stopped while it went on"
	case st.Event == netwatch.End:
		msg = "network flood over"
	}
	attrs := []any{"event", string(st.Event), "started", rec.Started, "kinds", nwKinds(rec), "ports", nwPorts(rec.Ports),
		"packet_rate", rec.PacketRate, "peak_packet_rate", rec.PeakRate, "baseline_packet_rate", rec.Baseline,
		"packets", rec.Packets, "bytes", rec.Bytes}
	if len(rec.SourcePorts) > 0 {
		attrs = append(attrs, "source_ports", nwPorts(rec.SourcePorts))
	}
	if rec.RandomPorts {
		attrs = append(attrs, "random_ports", true)
	}
	if st.Event == netwatch.Start {
		n.log.Warn(msg, attrs...)
	} else {
		n.log.Info(msg, attrs...)
	}
	n.ep.networkEvent(st, n.site)
}

func nwKinds(r *netwatch.Record) []string {
	out := make([]string, 0, len(r.Kinds))
	for _, k := range r.Kinds {
		out = append(out, k.Kind)
	}
	return out
}

func nwPorts(ps []netwatch.Port) []string {
	out := make([]string, 0, len(ps))
	for _, p := range ps {
		out = append(out, fmt.Sprintf("%s/%d", p.Protocol, p.Port))
	}
	return out
}

// networkEvent sends a network attack's start, its end and at most one update a minute. It never blocks.
func (e *endpoint) networkEvent(st netwatch.State, site string) {
	if e == nil || e.sender == nil {
		return
	}
	m := notify.FromNetwork(st, site)
	if e.admit(m.Event, m.Subject, st.At) {
		e.sender.Send(m)
	}
}
