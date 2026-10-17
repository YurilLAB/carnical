// SPDX-License-Identifier: Apache-2.0

package alert

import (
	"context"
	"log/slog"
	"net/netip"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

// Kind says what a Record reports.
type Kind uint8

// The kinds of record.
const (
	// KindAlert is the first finding of a (source, signature, action) in a window.
	KindAlert Kind = iota + 1
	// KindRepeated counts the further findings of a (source, signature, action) when its window closes or its entry is
	// evicted.
	KindRepeated
	// KindSuspected is the per-source correlation.
	KindSuspected
	// KindSummary lists the sources with the most refused or would-be-refused findings.
	KindSummary
	// KindTotals carries the exact counters.
	KindTotals
	// KindDropped counts the lines the limiter or the queue dropped, and the repeats those lines carried.
	KindDropped
	// KindSourceBlocked, KindSourceWouldBlock, KindSourceBlockEnded and KindAutoBlockFull report repeat-offender
	// blocking (ADR-0085); the shield builds them and hands them to Aggregator.Emit.
	KindSourceBlocked
	KindSourceWouldBlock
	KindSourceBlockEnded
	KindAutoBlockFull
)

// Record is what the Aggregator hands to a Sink: an alert line, a summary, the totals or a count of drops.
type Record struct {
	Kind      Kind
	Alert     Alert           // KindAlert, KindRepeated, KindSuspected and the auto-block kinds
	Sources   []SourceSummary // KindSummary
	Totals    *Totals         // KindTotals
	Dropped   Drops           // KindDropped: the drops since the last report
	Unwritten []SigCount      // KindDropped: the repeats in Dropped.Repeats by signature and action, most first
}

// control reports whether r is one of the records that are written whatever the load: the drops, the totals and the
// summary. Async gives them a lane of their own.
func (r *Record) control() bool {
	return r.Kind == KindDropped || r.Kind == KindTotals || r.Kind == KindSummary
}

// Message is the msg of the record's log line.
func (r *Record) Message() string {
	switch r.Kind {
	case KindAlert:
		switch r.Alert.Action {
		case WouldBlock, Detected:
			return "intrusion detected"
		case NotInspected:
			return "inspection incomplete"
		}
		return "intrusion blocked"
	case KindRepeated:
		return "alert repeated"
	case KindSuspected:
		return "suspected intrusion"
	case KindSummary:
		return "intrusion summary"
	case KindTotals:
		return "intrusion totals"
	case KindDropped:
		return "alerts dropped"
	case KindSourceBlocked:
		return "source blocked"
	case KindSourceWouldBlock:
		return "source would be blocked"
	case KindSourceBlockEnded:
		return "source block ended"
	case KindAutoBlockFull:
		return "auto-block table full"
	}
	return "alert"
}

// SourceSummary is one source in an "intrusion summary": a source key, or an IPv6 network whose findings came from
// more than one /64.
type SourceSummary struct {
	Src        netip.Addr   // the source key; for a network, its first address
	Net        netip.Prefix // the network, for a network; zero otherwise
	Categories Categories
	Blocked    uint64
	WouldBlock uint64
	Detected   uint64
	First      time.Time
	Last       time.Time
}

// Drops counts lines that were not written.
type Drops struct {
	High  uint64 // high and medium risk lines over the limiter
	Low   uint64 // low and info lines over the limiter
	Queue uint64 // records the queue was too full for
	// Repeats is the findings counted on "alert repeated" lines that were not written: the count of each such line,
	// not the number of lines, so that no repeat goes uncounted.
	Repeats uint64
}

// Total is the number of lines dropped.
func (d Drops) Total() uint64 { return d.High + d.Low + d.Queue }

// SigCount is how many repeats of one signature and action were not written.
type SigCount struct {
	Sig    string
	Action Action
	N      uint64
}

// Sink receives records. Send must not block: wrap a slow sink in Async.
type Sink interface {
	Send(Record)
}

// SinkFunc makes a function a Sink.
type SinkFunc func(Record)

// Send calls f.
func (f SinkFunc) Send(r Record) { f(r) }

// Dropper is a sink that counts the records it could not take; the Aggregator reports the count.
type Dropper interface {
	Dropped() uint64
}

// Offerer is a sink that reports whether it took a record. The Aggregator offers to it so that it can count the
// repeats of an "alert repeated" line the sink refused and send the drops and totals again when they were refused.
type Offerer interface {
	Offer(Record) bool
}

// ------------------------------------------------------------------------------------------------- asynchronous queue

// Async queue sizes.
const (
	DefaultQueue = 1024
	MaxQueue     = 65536
	// controlQueue is the size of the lane of the drops, totals and summary records. They are a few a second at most
	// and are offered again when refused, so a full alert queue never keeps them out.
	controlQueue = 16
)

// Async is a bounded queue in front of a sink, drained by one goroutine, so that Send never blocks the request or the
// lock it is called from. A record that does not fit is counted as dropped. The drops, totals and summary records
// have a small lane of their own that is drained first, so a flood of alerts cannot crowd out the line that counts
// them.
type Async struct {
	next    Sink
	ch      chan Record
	ctl     chan Record
	mu      sync.RWMutex // held for reading by Send, for writing by Close, so that nothing is queued after Close
	closed  bool
	abandon atomic.Bool // Close stopped waiting: what is still queued is counted, not delivered
	dropped atomic.Uint64
	stop    chan struct{}
	done    chan struct{}
}

// NewAsync starts a queue of size records (DefaultQueue when size is 0 or less, at most MaxQueue) in front of next.
func NewAsync(next Sink, size int) *Async {
	if size <= 0 {
		size = DefaultQueue
	}
	size = min(size, MaxQueue)
	q := &Async{next: next, ch: make(chan Record, size), ctl: make(chan Record, controlQueue), stop: make(chan struct{}),
		done: make(chan struct{})}
	go q.run()
	return q
}

// Send queues r, or counts it as dropped when the queue is full or closed. It never blocks.
func (q *Async) Send(r Record) { q.Offer(r) }

// Offer is Send, reporting whether r was queued.
func (q *Async) Offer(r Record) bool {
	q.mu.RLock()
	defer q.mu.RUnlock()
	if !q.closed {
		ch := q.ch
		if r.control() {
			ch = q.ctl
		}
		select {
		case ch <- r:
			return true
		default:
		}
	}
	q.dropped.Add(1)
	return false
}

// Dropped is the number of records not delivered.
func (q *Async) Dropped() uint64 { return q.dropped.Load() }

// Close stops taking records and delivers those queued, waiting at most timeout. It reports whether everything queued
// was delivered; what was not is counted as dropped.
func (q *Async) Close(timeout time.Duration) bool {
	q.mu.Lock()
	if q.closed {
		q.mu.Unlock()
		select {
		case <-q.done:
			return true
		default:
			return false
		}
	}
	q.closed = true
	q.mu.Unlock()
	close(q.stop)
	t := time.NewTimer(timeout)
	defer t.Stop()
	select {
	case <-q.done:
		return true
	case <-t.C:
		// Count what is still queued. A record is taken from the queue once, by this loop or by run, which now
		// counts instead of delivering, so each is counted once.
		q.abandon.Store(true)
		for {
			select {
			case <-q.ctl:
				q.dropped.Add(1)
			case <-q.ch:
				q.dropped.Add(1)
			default:
				return false
			}
		}
	}
}

func (q *Async) run() {
	defer close(q.done)
	for {
		select { // the control lane first
		case r := <-q.ctl:
			q.deliver(r)
			continue
		default:
		}
		select {
		case r := <-q.ctl:
			q.deliver(r)
		case r := <-q.ch:
			q.deliver(r)
		case <-q.stop:
			for {
				select {
				case r := <-q.ctl:
					q.deliver(r)
					continue
				default:
				}
				select {
				case r := <-q.ch:
					q.deliver(r)
				default:
					return
				}
			}
		}
	}
}

func (q *Async) deliver(r Record) {
	if q.abandon.Load() {
		q.dropped.Add(1)
		return
	}
	defer func() {
		if recover() != nil { // a sink that fails must not take the queue down with it
			q.dropped.Add(1)
		}
	}()
	q.next.Send(r)
}

// ---------------------------------------------------------------------------------------------------------- log sink

// LogSink writes records as JSON lines through slog, in the schema of docs/proxy-reference.md: WARN for high and
// medium risk, INFO for low and info.
type LogSink struct {
	l      *slog.Logger
	source SourceMode
}

// NewLogSink writes to l, showing the source as mode says.
func NewLogSink(l *slog.Logger, mode SourceMode) *LogSink { return &LogSink{l: l, source: mode} }

// Send writes one line. It blocks while the logger does: put it behind Async.
func (s *LogSink) Send(r Record) {
	ctx := context.Background()
	switch r.Kind {
	case KindTotals:
		if r.Totals != nil {
			s.l.LogAttrs(ctx, slog.LevelInfo, r.Message(), s.totalsAttrs(r.Totals)...)
		}
	case KindSummary:
		s.l.LogAttrs(ctx, slog.LevelInfo, r.Message(), slog.Any("sources", s.summary(r.Sources)))
	case KindDropped:
		at := []slog.Attr{slog.Uint64("count", r.Dropped.Total()), slog.Uint64("dropped_high", r.Dropped.High),
			slog.Uint64("dropped_low", r.Dropped.Low), slog.Uint64("dropped_queue", r.Dropped.Queue),
			slog.Uint64("repeats_unwritten", r.Dropped.Repeats)}
		if len(r.Unwritten) > 0 {
			by := make(map[string]uint64, len(r.Unwritten))
			for _, u := range r.Unwritten {
				by[u.Sig+"/"+u.Action.String()] += u.N
			}
			at = append(at, slog.Any("repeats_unwritten_by_sig", by))
		}
		s.l.LogAttrs(ctx, slog.LevelWarn, r.Message(), at...)
	default:
		level := slog.LevelInfo
		if r.Alert.Risk >= RiskMedium {
			level = slog.LevelWarn
		}
		s.l.LogAttrs(ctx, level, r.Message(), s.alertAttrs(&r.Alert, r.Kind != KindRepeated)...)
	}
}

const timeFormat = time.RFC3339

// alertAttrs lists the fields of an alert line. status is left out of an "alert repeated" line, whose repeats need not
// have had the first one's.
func (s *LogSink) alertAttrs(a *Alert, status bool) []slog.Attr {
	at := make([]slog.Attr, 0, 24)
	if a.ID != "" {
		at = append(at, slog.String("alert_id", a.ID))
	}
	at = append(at, slog.String("layer", a.Layer.String()), slog.String("sig", a.Sig))
	if a.SigName != "" {
		at = append(at, slog.String("sig_name", a.SigName))
	}
	if len(a.Rules) > 0 {
		at = append(at, slog.Any("rules", a.Rules[:min(len(a.Rules), MaxRules)]))
	}
	if a.Categories != 0 {
		at = append(at, slog.Any("category", a.Categories.Names(MaxCategories)))
	}
	at = append(at, slog.String("risk", a.Risk.String()))
	if a.SeverityRaw != "" {
		at = append(at, slog.String("severity_raw", a.SeverityRaw))
	}
	at = append(at, slog.String("action", a.Action.String()))
	if a.Mode != 0 {
		at = append(at, slog.String("mode", a.Mode.String()))
	}
	if status {
		at = append(at, slog.Int("status", a.Status))
	}
	if a.Score > 0 || a.Threshold > 0 {
		at = append(at, slog.Int("score", a.Score), slog.Int("threshold", a.Threshold))
	}
	at = s.sourceAttrs(at, a)
	if a.Method != "" {
		at = append(at, slog.String("method", a.Method))
	}
	if a.Host != "" {
		at = append(at, slog.String("host", a.Host))
	}
	if a.Path != "" {
		at = append(at, slog.String("path", a.Path))
	}
	at = append(at, slog.Uint64("count", a.Count))
	if !a.First.IsZero() {
		at = append(at, slog.String("first", a.First.UTC().Format(timeFormat)), slog.String("last", a.Last.UTC().Format(timeFormat)))
	}
	if a.Note != "" {
		at = append(at, slog.String("note", a.Note))
	}
	return at
}

// sourceAttrs writes the source as the mode says. With prefix only the network is written: src_key would name the
// address the operator chose to hide. A record about a network writes it as src_net in place of src_key.
func (s *LogSink) sourceAttrs(at []slog.Attr, a *Alert) []slog.Attr {
	if !a.Src.IsValid() || s.source == SourceOff {
		return at
	}
	if s.source == SourcePrefix {
		at = append(at, slog.String("src", SourceNet(a.Src).String()))
	} else {
		at = append(at, slog.String("src", a.Src.Unmap().String()))
	}
	switch {
	case a.Net.IsValid():
		at = append(at, slog.String("src_net", a.Net.String()))
	case s.source == SourceFull:
		at = append(at, slog.String("src_key", SourceKey(a.Src).String()))
	}
	if a.ViaProxy {
		at = append(at, slog.Bool("via_proxy", true))
	}
	return at
}

type summaryLine struct {
	Src        string   `json:"src,omitempty"`
	Categories []string `json:"category,omitempty"`
	Blocked    uint64   `json:"blocked"`
	WouldBlock uint64   `json:"would_block"`
	Detected   uint64   `json:"detected"`
	First      string   `json:"first"`
	Last       string   `json:"last"`
}

func (s *LogSink) summary(src []SourceSummary) []summaryLine {
	out := make([]summaryLine, 0, len(src))
	for _, x := range src {
		l := summaryLine{Categories: x.Categories.Names(MaxCategories), Blocked: x.Blocked, WouldBlock: x.WouldBlock,
			Detected: x.Detected, First: x.First.UTC().Format(timeFormat), Last: x.Last.UTC().Format(timeFormat)}
		switch {
		case !x.Src.IsValid() || s.source == SourceOff:
		case x.Net.IsValid():
			l.Src = x.Net.String()
		case s.source == SourcePrefix:
			l.Src = SourceNet(x.Src).String()
		default:
			l.Src = x.Src.String()
		}
		out = append(out, l)
	}
	return out
}

func (s *LogSink) totalsAttrs(t *Totals) []slog.Attr {
	counts := make(map[string]uint64, len(t.Counts))
	for _, c := range t.Counts {
		counts[c.Layer.String()+"/"+c.Action.String()+"/"+c.Risk.String()] = c.N
	}
	rules := make(map[string]uint64, len(t.Rules))
	for _, r := range t.Rules {
		rules[strconv.Itoa(r.ID)] = r.N
	}
	return []slog.Attr{
		slog.Any("counts", counts),
		slog.Uint64("suppressed", t.Suppressed),
		slog.Uint64("below_min_risk", t.BelowMinRisk),
		slog.Uint64("dropped_high", t.Dropped.High),
		slog.Uint64("dropped_low", t.Dropped.Low),
		slog.Uint64("dropped_queue", t.Dropped.Queue),
		slog.Uint64("repeats_unwritten", t.Dropped.Repeats),
		slog.Any("rules", rules),
		slog.Uint64("rules_other", t.RulesOther),
	}
}
