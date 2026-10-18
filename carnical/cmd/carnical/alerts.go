// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/YurilLAB/coraza/carnical/alert"
	"github.com/YurilLAB/coraza/carnical/proxy"
)

// alertFlags are the flags of the intrusion alerts (ADR-0084).
type alertFlags struct {
	alerts, source, path, minRisk, suppress, exclude, evalDetect *string
	rate, table                                                  *int
	window, totals, summary                                      *time.Duration
	ruleMatches                                                  *bool
}

func declareAlertFlags(flags *flag.FlagSet) alertFlags {
	return alertFlags{
		alerts:      flags.String("alerts", "on", "intrusion alerts: on or off; one deduplicated line per source and signature, with exact totals"),
		source:      flags.String("alert-source", "full", "what an alert shows of the visitor's address: full, prefix (its /24 or /48) or off"),
		path:        flags.String("alert-path", "template", "what an alert shows of the path: template (identifiers replaced), full (without the query) or off"),
		minRisk:     flags.String("alert-min-risk", "low", "lowest risk written as an alert: info, low, medium or high (lower ones are counted only)"),
		suppress:    flags.String("alert-suppress", "", "signatures whose alerts are silenced, never their blocking: 'SIG [PATH-PREFIX] [until=YYYY-MM-DD] [note=TEXT]', separated by ';'"),
		exclude:     flags.String("alert-exclude-sources", "", "comma-separated addresses or networks (no wider than /16 or IPv6 /32) whose alerts are silenced, never their blocking"),
		evalDetect:  flags.String("eval-budget-detect", "forward", "in -mode detect, a request whose rule evaluation runs past -eval-budget: forward (reported as not inspected) or refuse (503)"),
		rate:        flags.Int("alert-rate", alert.DefaultRate, fmt.Sprintf("most alert lines a second, 1 to %d (totals stay exact)", alert.MaxRate)),
		table:       flags.Int("alert-table", alert.DefaultTable, fmt.Sprintf("source and signature pairs remembered for deduplication, %d to %d", alert.MinTable, alert.MaxTable)),
		window:      flags.Duration("alert-repeat-window", alert.DefaultWindow, "how long repeats of one alert are counted before one 'alert repeated' line, 10s to 1h"),
		totals:      flags.Duration("alert-totals-interval", time.Minute, "how often exact 'intrusion totals' are logged when they changed (0 = only at shutdown; else 10s to 24h)"),
		summary:     flags.Duration("alert-summary-interval", 5*time.Minute, "how often the top attacking sources are logged (0 = off; else 1m to 24h)"),
		ruleMatches: flags.Bool("log-rule-matches", true, "also log a 'rule matched' line for every rule a request matches"),
	}
}

// alerting is the configured alert pipeline: the proxy's settings and what to close at shutdown.
type alerting struct {
	onAlert  func(alert.Alert)
	options  proxy.AlertOptions
	source   alert.SourceMode // what an alert, and a ban's event, shows of the source
	exclude  []netip.Prefix   // -alert-exclude-sources, which auto-block never bans either
	evalMode proxy.OverBudget
	agg      *alert.Aggregator
	queue    *alert.Async
	started  bool
}

// configureAlerts checks the alert flags and, unless -alerts off, builds the aggregator that writes alerts to log
// through a bounded queue. Nothing is started; start begins the periodic lines.
func configureAlerts(log *slog.Logger, f alertFlags) (*alerting, error) {
	a := &alerting{evalMode: proxy.OverBudget(*f.evalDetect)}
	if a.evalMode != proxy.OverBudgetForward && a.evalMode != proxy.OverBudgetRefuse {
		return nil, refuseFlag("eval-budget-detect", fmt.Errorf("-eval-budget-detect must be forward or refuse, not %q", *f.evalDetect))
	}
	source, ok := alert.ParseSourceMode(*f.source)
	if !ok {
		return nil, refuseFlag("alert-source", fmt.Errorf("-alert-source must be full, prefix or off, not %q", *f.source))
	}
	var values []string
	if *f.exclude != "" {
		values = []string{*f.exclude}
	}
	exclude, err := alert.ParseExcludeSources(values)
	if err != nil {
		return nil, refuseFlag("alert-exclude-sources", fmt.Errorf("-alert-exclude-sources: %w", err))
	}
	a.source, a.exclude = source, exclude
	switch *f.alerts {
	case "on":
	case "off":
		return a, nil
	default:
		return nil, refuseFlag("alerts", fmt.Errorf("-alerts must be on or off, not %q", *f.alerts))
	}
	path, ok := alert.ParsePathMode(*f.path)
	if !ok {
		return nil, refuseFlag("alert-path", fmt.Errorf("-alert-path must be template, full or off, not %q", *f.path))
	}
	risk, ok := alert.ParseRisk(*f.minRisk)
	if !ok {
		return nil, refuseFlag("alert-min-risk", fmt.Errorf("-alert-min-risk must be info, low, medium or high, not %q", *f.minRisk))
	}
	switch {
	case *f.rate < 1 || *f.rate > alert.MaxRate:
		return nil, refuseFlag("alert-rate", fmt.Errorf("-alert-rate must be from 1 to %d lines a second", alert.MaxRate))
	case *f.table < alert.MinTable || *f.table > alert.MaxTable:
		return nil, refuseFlag("alert-table", fmt.Errorf("-alert-table must be from %d to %d", alert.MinTable, alert.MaxTable))
	case *f.window < alert.MinWindow || *f.window > alert.MaxWindow:
		return nil, refuseFlag("alert-repeat-window", fmt.Errorf("-alert-repeat-window must be from %v to %v", alert.MinWindow, alert.MaxWindow))
	case *f.totals != 0 && (*f.totals < 10*time.Second || *f.totals > 24*time.Hour):
		return nil, refuseFlag("alert-totals-interval", errors.New("-alert-totals-interval must be 0 or from 10s to 24h"))
	case *f.summary != 0 && (*f.summary < time.Minute || *f.summary > 24*time.Hour):
		return nil, refuseFlag("alert-summary-interval", errors.New("-alert-summary-interval must be 0 or from 1m to 24h"))
	}
	values = nil
	if *f.suppress != "" {
		values = []string{*f.suppress}
	}
	suppress, err := alert.ParseSuppressions(values)
	if err != nil {
		return nil, refuseFlag("alert-suppress", fmt.Errorf("-alert-suppress: %w", err))
	}
	a.queue = alert.NewAsync(alert.NewLogSink(log, source), 0)
	a.agg, err = alert.NewAggregator(alert.Config{Sink: a.queue, Table: *f.table, Window: *f.window, Rate: *f.rate,
		MinRisk: risk, Source: source, TotalsInterval: *f.totals, SummaryInterval: *f.summary, Suppress: suppress, Exclude: exclude})
	if err != nil {
		a.queue.Close(0)
		return nil, err
	}
	a.onAlert, a.options = a.agg.Observe, proxy.AlertOptions{Source: source, Path: path}
	// Silencing is reviewed where it is set: each entry is listed, and one that has expired is said to no longer apply.
	now := time.Now()
	for _, s := range suppress {
		if s.Expired(now) {
			log.Warn("alert suppression expired and no longer applies", "suppression", s.String())
		} else {
			log.Info("alert suppression", "suppression", s.String())
		}
	}
	for _, p := range exclude {
		log.Info("alert source excluded", "source", p.String())
	}
	return a, nil
}

// start begins the periodic alert lines.
func (a *alerting) start() {
	if a.agg != nil {
		a.agg.Start()
		a.started = true
	}
}

// matchLog writes the "rule matched" lines from a bounded queue, so that a request never waits on a log that has fallen
// behind, as the alerts do not: under attack every matched rule is a line. A line the queue has no room for is
// dropped, and the drops are written as "rule matched lines dropped", at most once a second and at the end.
type matchLog struct {
	next    slog.Handler
	ch      chan slog.Record
	mu      sync.RWMutex // held for reading by Handle, for writing by close, so that nothing is queued after close
	closed  bool
	dropped atomic.Uint64
	done    chan struct{}
}

// matchQueue is how many lines matchLog holds; a few seconds of a busy attack.
const matchQueue = 8192

func newMatchLog(next slog.Handler) *matchLog {
	l := &matchLog{next: next, ch: make(chan slog.Record, matchQueue), done: make(chan struct{})}
	go l.run()
	return l
}

func (l *matchLog) Enabled(ctx context.Context, level slog.Level) bool {
	return l.next.Enabled(ctx, level)
}
func (l *matchLog) WithAttrs(attrs []slog.Attr) slog.Handler { return l } // not used: the lines carry their own
func (l *matchLog) WithGroup(name string) slog.Handler       { return l }

// Handle queues r, or counts it as dropped: when the queue is full, or after close. It never blocks.
func (l *matchLog) Handle(_ context.Context, r slog.Record) error {
	l.mu.RLock()
	defer l.mu.RUnlock()
	if l.closed {
		l.dropped.Add(1)
		return nil
	}
	select {
	case l.ch <- r.Clone():
	default:
		l.dropped.Add(1)
	}
	return nil
}

func (l *matchLog) run() {
	defer close(l.done)
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	for {
		select {
		case r, ok := <-l.ch:
			if !ok {
				l.reportDrops()
				return
			}
			_ = l.next.Handle(context.Background(), r) // a line the log refuses is lost, as any other line would be
		case <-tick.C:
			l.reportDrops()
		}
	}
}

func (l *matchLog) reportDrops() {
	if n := l.dropped.Swap(0); n > 0 {
		r := slog.NewRecord(time.Now(), slog.LevelWarn, "rule matched lines dropped", 0)
		r.AddAttrs(slog.Uint64("count", n), slog.String("reason", "the log is not keeping up"))
		_ = l.next.Handle(context.Background(), r)
	}
}

// close writes what is queued, waiting at most wait for the log.
func (l *matchLog) close(wait time.Duration) {
	l.mu.Lock()
	if !l.closed {
		l.closed = true
		close(l.ch)
	}
	l.mu.Unlock()
	select {
	case <-l.done:
	case <-time.After(wait):
	}
}

// close writes what the aggregator still holds and the final totals, and waits at most two seconds for the log. A
// process that never served (-check, or a start-up refused) has nothing to report and writes nothing.
func (a *alerting) close() {
	if a.agg == nil {
		return
	}
	if a.started {
		a.agg.Close()
	}
	a.queue.Close(2 * time.Second)
}
