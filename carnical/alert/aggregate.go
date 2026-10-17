// SPDX-License-Identifier: Apache-2.0

package alert

import (
	"cmp"
	"errors"
	"fmt"
	"hash/maphash"
	"net/netip"
	"slices"
	"sync"
	"sync/atomic"
	"time"
)

// Settings of the Aggregator, with their defaults and ranges (-alert-* flags).
const (
	DefaultTable  = 16384
	MinTable      = 1024
	MaxTable      = 262144
	DefaultWindow = time.Minute
	MinWindow     = 10 * time.Second
	MaxWindow     = time.Hour
	DefaultRate   = 20
	MaxRate       = 10000
	maxBurst      = 200
	// DefaultSources is the size of the per-source correlation table.
	DefaultSources = 4096
	MinSources     = 256
	MaxSources     = 262144

	// correlationWindow is how long a source's findings are added up before they start again.
	correlationWindow = 10 * time.Minute
	// suspectEvery is the least time between two "suspected intrusion" alerts for one source.
	suspectEvery = time.Hour
	// The thresholds of a suspected intrusion within the correlation window.
	suspectCategories = 3
	suspectRefused    = 10
	// suspectRate and suspectBurst are the reserved bucket of "suspected intrusion" lines, which they take before the
	// high tier, so that a flood of first alerts cannot crowd out the line that names an attacker.
	suspectRate  = 1
	suspectBurst = 10
	// summaryTop is how many sources an "intrusion summary" lists.
	summaryTop = 10
	// maxRuleCounts is how many distinct rule ids the totals count one by one; the rest are added up in RulesOther.
	maxRuleCounts = 4096
	// maxUnwrittenSigs is how many signatures the unwritten repeats are listed by in "alerts dropped"; the repeats of
	// the others are in its total only.
	maxUnwrittenSigs = 32
	// netBits is the IPv6 network a source is also correlated by: a host or a home connection gets a /48 or a /56,
	// so a source that moves between its /64s stays one network.
	netBits = 48

	shards     = 64
	ruleShards = 16
)

// Config configures an Aggregator. Zero values take the defaults, except the intervals, where zero turns the periodic
// line off.
type Config struct {
	// Sink receives the records; it must not block (use Async). Required.
	Sink Sink
	// Now is the clock; time.Now when nil.
	Now func() time.Time
	// Table is the number of (source, signature, action) entries kept for dedupe.
	Table int
	// Window is how long repeats are counted before they are written as one "alert repeated" line.
	Window time.Duration
	// Rate is the most alert lines a second (1 to MaxRate); the burst is ten times as many, at most 200. Four fifths go
	// to high and medium risk first. "suspected intrusion" lines also have one a second of their own (burst ten).
	Rate int
	// MinRisk is the lowest risk that is written (default low); findings below it are counted only.
	MinRisk Risk
	// Source set to SourceOff dedupes per signature and action only, leaves the source out of every record and writes
	// no "intrusion summary", which is a list of sources.
	Source SourceMode
	// Sources is the size of the per-source correlation table.
	Sources int
	// TotalsInterval is how often "intrusion totals" is written when something changed (zero: only at Close).
	TotalsInterval time.Duration
	// SummaryInterval is how often "intrusion summary" is written (zero: never).
	SummaryInterval time.Duration
	// Suppress and Exclude silence alerts (ParseSuppressions, ParseExcludeSources). They never change blocking.
	Suppress []Suppression
	Exclude  []netip.Prefix
}

func (c *Config) check() error {
	if c.Sink == nil {
		return errors.New("alert: no sink")
	}
	if c.Now == nil {
		c.Now = time.Now
	}
	type rng struct {
		name     string
		v        *int
		def, lo  int
		hi       int
		duration bool
	}
	for _, r := range []rng{
		{"table", &c.Table, DefaultTable, MinTable, MaxTable, false},
		{"rate", &c.Rate, DefaultRate, 1, MaxRate, false},
		{"sources", &c.Sources, DefaultSources, MinSources, MaxSources, false},
	} {
		if *r.v == 0 {
			*r.v = r.def
		}
		if *r.v < r.lo || *r.v > r.hi {
			return fmt.Errorf("alert: %s %d is outside %d to %d", r.name, *r.v, r.lo, r.hi)
		}
	}
	if c.Window == 0 {
		c.Window = DefaultWindow
	}
	if c.Window < MinWindow || c.Window > MaxWindow {
		return fmt.Errorf("alert: repeat window %v is outside %v to %v", c.Window, MinWindow, MaxWindow)
	}
	if c.MinRisk == 0 {
		c.MinRisk = RiskLow
	}
	if int(c.MinRisk) >= numRisks {
		return errors.New("alert: unknown minimum risk")
	}
	if c.TotalsInterval < 0 || c.SummaryInterval < 0 {
		return errors.New("alert: a negative interval")
	}
	if len(c.Suppress) > MaxSuppressions || len(c.Exclude) > MaxExcludeSources {
		return errors.New("alert: too many suppressions or excluded sources")
	}
	return nil
}

// Aggregator dedupes, limits, correlates and counts findings. It is safe for concurrent use; Observe is the only call
// made on the request path.
type Aggregator struct {
	cfg  Config
	sink Sink
	seed maphash.Seed

	dedupe  [shards]dshard
	perDed  int
	corr    [shards]cshard
	perCorr int
	window  int64

	lim limiter

	// Exact totals: never sampled.
	counts       [numLayers][numActions][numRisks]atomic.Uint64
	suppressed   atomic.Uint64
	belowMinRisk atomic.Uint64
	droppedHigh  atomic.Uint64
	droppedLow   atomic.Uint64
	// The repeats of "alert repeated" lines that were not written, in all and by signature and action.
	unwrittenMu sync.Mutex
	unwrittenN  uint64
	unwritten   map[sigKey]uint64
	rules       [ruleShards]ruleShard
	ruleIDs     atomic.Int64 // distinct ids counted one by one
	rulesOther  atomic.Uint64
	gen         atomic.Uint64 // findings observed: totals are written only when it moved
	summaryGen  atomic.Uint32

	tickMu       sync.Mutex // Tick and Close
	recs         []Record
	lastGen      uint64
	lastDrops    Drops
	lastDropAt   int64
	nextTotals   int64
	nextSummary  int64
	stop, done   chan struct{}
	startOnce    sync.Once
	closeOnce    sync.Once
	queueDropped func() uint64
	offer        func(Record) bool
}

type sigKey struct {
	sig    string
	action Action
}

type dkey struct {
	src    netip.Addr
	sig    string
	action Action
}

type dentry struct {
	a       Alert
	start   int64 // window start, Unix nanoseconds
	last    int64
	pending uint64     // repeats not written yet
	repFrom int64      // the first of them
	repCats Categories // their categories
	repRisk Risk       // the highest of their risks
}

type dshard struct {
	mu sync.Mutex
	m  map[dkey]*dentry
}

// ckey is a key of the correlation table: a source key, or the first address of an IPv6 /48.
type ckey struct {
	addr netip.Addr
	net  bool
}

type centry struct {
	start      int64 // correlation window start
	cats       Categories
	refused    uint32 // blocked and would_block findings in the window
	total      uint32
	first      int64
	last       int64
	suspectAt  int64 // the last "suspected intrusion"; 0 never
	suspected  bool
	spread     bool       // a network's findings in the window came from more than one /64
	one        netip.Addr // the /64 of the window's first finding
	sumGen     uint32     // summary period the fields below belong to
	sumSpread  bool
	sumOne     netip.Addr
	sumCats    Categories
	sumBlocked uint64
	sumWould   uint64
	sumDet     uint64
	sumFirst   int64
	sumLast    int64
}

type cshard struct {
	mu sync.Mutex
	m  map[ckey]*centry
}

type ruleShard struct {
	mu sync.Mutex
	m  map[int]uint64
}

// NewAggregator checks cfg and makes an Aggregator. Call Start for the periodic lines, or Tick yourself.
func NewAggregator(cfg Config) (*Aggregator, error) {
	if err := cfg.check(); err != nil {
		return nil, err
	}
	g := &Aggregator{cfg: cfg, sink: cfg.Sink, seed: maphash.MakeSeed(), perDed: max(cfg.Table/shards, 16),
		perCorr: max(cfg.Sources/shards, 4), window: int64(cfg.Window)}
	for i := range g.dedupe {
		g.dedupe[i].m = map[dkey]*dentry{}
		g.corr[i].m = map[ckey]*centry{}
	}
	for i := range g.rules {
		g.rules[i].m = map[int]uint64{}
	}
	if d, ok := cfg.Sink.(Dropper); ok {
		g.queueDropped = d.Dropped
	}
	if o, ok := cfg.Sink.(Offerer); ok {
		g.offer = o.Offer
	}
	g.unwritten = map[sigKey]uint64{}
	now := cfg.Now().UnixNano()
	burst := float64(min(10*cfg.Rate, maxBurst))
	g.lim.hi = bucket{rate: float64(cfg.Rate) * 0.8, max: max(1, burst*0.8), last: now}
	g.lim.lo = bucket{rate: float64(cfg.Rate) * 0.2, max: max(1, burst*0.2), last: now}
	g.lim.sus = bucket{rate: suspectRate, max: suspectBurst, tokens: suspectBurst, last: now}
	g.lim.hi.tokens, g.lim.lo.tokens = g.lim.hi.max, g.lim.lo.max
	if cfg.TotalsInterval > 0 {
		g.nextTotals = now + int64(cfg.TotalsInterval)
	}
	if cfg.SummaryInterval > 0 {
		g.nextSummary = now + int64(cfg.SummaryInterval)
	}
	return g, nil
}

// Observe takes one finding. It counts it in the totals, and unless it is suppressed, from an excluded source, below
// the minimum risk or a repeat within the window, writes it. It never blocks on the sink beyond the sink's own Send.
func (g *Aggregator) Observe(a Alert) {
	now := g.cfg.Now()
	ns := now.UnixNano()
	g.count(&a)
	if a.Action == ClientClosed {
		return
	}
	if g.silenced(&a, now) {
		g.suppressed.Add(1)
		return
	}
	var out [4]Record
	var keys [len(out)]ckey // the key of each suspected intrusion in out
	n := 0
	if a.Src.IsValid() {
		n = g.correlate(&a, ns, out[:2], keys[:2])
	}
	suspects := n
	if a.Risk >= g.cfg.MinRisk {
		n += g.dedupeAlert(&a, ns, out[n:])
	} else {
		g.belowMinRisk.Add(1)
	}
	for i := range n {
		if !g.emit(out[i], ns) && i < suspects {
			g.unsuspect(keys[i], ns) // not written: the next finding that meets the condition tries again
		}
	}
}

// Emit writes a record built elsewhere (the auto-block records), through the limiter's high tier unless its risk is
// low or info.
func (g *Aggregator) Emit(r Record) {
	g.emit(r, g.cfg.Now().UnixNano())
}

func (g *Aggregator) count(a *Alert) {
	l, ac, r := int(a.Layer), int(a.Action), int(a.Risk)
	if l >= numLayers {
		l = 0
	}
	if ac >= numActions {
		ac = 0
	}
	if r >= numRisks {
		r = 0
	}
	g.counts[l][ac][r].Add(1)
	g.gen.Add(1)
	g.countRule(a.RuleID)
	for i, id := range a.Rules {
		if i == MaxRules {
			break
		}
		if id != a.RuleID {
			g.countRule(id)
		}
	}
}

func (g *Aggregator) countRule(id int) {
	if id == 0 {
		return
	}
	s := &g.rules[uint(id)%ruleShards]
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.m[id]; !ok {
		if g.ruleIDs.Add(1) > maxRuleCounts {
			g.ruleIDs.Add(-1)
			g.rulesOther.Add(1)
			return
		}
	}
	s.m[id]++
}

func (g *Aggregator) silenced(a *Alert, now time.Time) bool {
	for i := range g.cfg.Suppress {
		if g.cfg.Suppress[i].matches(a, now) {
			return true
		}
	}
	if a.Src.IsValid() && len(g.cfg.Exclude) > 0 {
		src := a.Src.Unmap()
		for _, p := range g.cfg.Exclude {
			if p.Contains(src) {
				return true
			}
		}
	}
	return false
}

// dedupeAlert writes the first finding of its key in a window and counts the rest. It puts the records to write in out
// (the alert, and the repeats of an entry evicted to make room) and returns how many.
func (g *Aggregator) dedupeAlert(a *Alert, now int64, out []Record) int {
	k := dkey{sig: a.Sig, action: a.Action}
	if g.cfg.Source != SourceOff {
		k.src = SourceKey(a.Src)
	}
	s := &g.dedupe[maphash.Comparable(g.seed, k)%shards]
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	e := s.m[k]
	if e != nil && now-e.start >= g.window {
		// The window closed before Tick saw it: write its repeats and start again.
		if e.pending > 0 {
			out[n] = repeated(e)
			n++
		}
		delete(s.m, k)
		e = nil
	}
	if e != nil {
		if e.pending == 0 {
			e.repFrom, e.repCats, e.repRisk = now, 0, 0
		}
		e.pending++
		e.last = now
		e.repCats |= a.Categories
		e.repRisk = max(e.repRisk, a.Risk)
		return n
	}
	if len(s.m) >= g.perDed {
		if r, ok := g.evict(s); ok {
			out[n] = r
			n++
		}
	}
	e = &dentry{a: *a, start: now, last: now}
	e.a.Count = 1
	e.a.First = time.Unix(0, now)
	e.a.Last = e.a.First
	e.a.MatchPath = "" // not kept: it is only for suppression
	if g.cfg.Source == SourceOff {
		e.a.Src, e.a.ViaProxy = netip.Addr{}, false // one entry stands for every source: name none of them
	}
	s.m[k] = e
	out[n] = Record{Kind: KindAlert, Alert: e.a}
	return n + 1
}

// evict forgets the oldest of up to 32 entries of a full shard, returning its repeats so that no count is lost.
func (g *Aggregator) evict(s *dshard) (Record, bool) {
	var oldest dkey
	var oe *dentry
	n := 0
	for k, e := range s.m { // map order is random: a fair sample
		if oe == nil || e.start < oe.start {
			oldest, oe = k, e
		}
		if n++; n == 32 {
			break
		}
	}
	if oe == nil {
		return Record{}, false
	}
	delete(s.m, oldest)
	if oe.pending == 0 {
		return Record{}, false
	}
	return repeated(oe), true
}

// repeated is the "alert repeated" record of an entry. It names only what its repeats share: the source key, the
// signature and the action of the key, the layer, mode and static fields of the signature, and the categories and the
// highest risk of the repeats. The request id, status, score, method, host, path and rules belong to single requests
// that need not be the first one, so they are left out.
func repeated(e *dentry) Record {
	a := e.a
	a.ID, a.Method, a.Host, a.Path, a.Rules = "", "", "", "", nil
	a.Status, a.Score, a.Threshold, a.ViaProxy = 0, 0, 0, false
	a.Src = SourceKey(a.Src) // the repeats may come from other addresses of an IPv6 /64
	a.Categories, a.Risk = e.repCats, e.repRisk
	a.Count = e.pending
	a.First = time.Unix(0, e.repFrom)
	a.Last = time.Unix(0, e.last)
	return Record{Kind: KindRepeated, Alert: a}
}

// correlate adds a finding to its source's window, and for an IPv6 source to its /48's, and puts in out a "suspected
// intrusion" for each that has just met one of the conditions and was not reported in the last hour. A network is
// reported only when its findings came from more than one /64: one /64 is reported as itself. It returns how many.
// The key of each record goes in keys, so that a record that was not written can be unmarked (unsuspect).
func (g *Aggregator) correlate(a *Alert, now int64, out []Record, keys []ckey) int {
	key := SourceKey(a.Src)
	n := 0
	if r, ok := g.correlateKey(ckey{addr: key}, key, a, now); ok {
		out[n], keys[n] = r, ckey{addr: key}
		n++
	}
	if key.Is6() {
		p, _ := key.Prefix(netBits)
		k := ckey{addr: p.Addr(), net: true}
		if r, ok := g.correlateKey(k, key, a, now); ok {
			if g.cfg.Source != SourceOff {
				r.Alert.Net = p
			}
			out[n], keys[n] = r, k
			n++
		}
	}
	return n
}

// unsuspect takes back the mark correlateKey set at now when its "suspected intrusion" was not written, so that the
// source is not left unreported for an hour.
func (g *Aggregator) unsuspect(k ckey, at int64) {
	s := &g.corr[maphash.Comparable(g.seed, k)%shards]
	s.mu.Lock()
	defer s.mu.Unlock()
	if e := s.m[k]; e != nil && e.suspected && e.suspectAt == at {
		e.suspected, e.suspectAt = false, 0
	}
}

func (g *Aggregator) correlateKey(k ckey, sub netip.Addr, a *Alert, now int64) (Record, bool) {
	s := &g.corr[maphash.Comparable(g.seed, k)%shards]
	s.mu.Lock()
	defer s.mu.Unlock()
	e := s.m[k]
	if e == nil {
		if len(s.m) >= g.perCorr {
			g.evictSource(s, now)
		}
		e = &centry{start: now, first: now, one: sub, sumGen: g.summaryGen.Load(), sumFirst: now, sumOne: sub}
		s.m[k] = e
	}
	if now-e.start >= int64(correlationWindow) {
		e.start, e.first, e.cats, e.refused, e.total, e.one, e.spread = now, now, 0, 0, 0, sub, false
	}
	e.spread = e.spread || sub != e.one
	e.cats |= a.Categories
	e.total++
	if a.Action == Blocked || a.Action == WouldBlock {
		e.refused++
	}
	e.last = now
	if gen := g.summaryGen.Load(); e.sumGen != gen {
		e.sumGen, e.sumCats, e.sumBlocked, e.sumWould, e.sumDet, e.sumFirst = gen, 0, 0, 0, 0, now
		e.sumOne, e.sumSpread = sub, false
	}
	e.sumSpread = e.sumSpread || sub != e.sumOne
	e.sumCats |= a.Categories
	switch a.Action {
	case Blocked:
		e.sumBlocked++
	case WouldBlock:
		e.sumWould++
	case Detected:
		e.sumDet++
	}
	e.sumLast = now
	why := suspicion(e)
	if why == "" || k.net && !e.spread || e.suspected && now-e.suspectAt < int64(suspectEvery) {
		return Record{}, false
	}
	e.suspected, e.suspectAt = true, now
	cats := e.cats & (attack | Of(CatScanner))
	if cats == 0 {
		cats = e.cats
	}
	r := Alert{ID: a.ID, Layer: a.Layer, Sig: "suspected-intrusion", SigName: "Suspected intrusion from one source",
		Categories: cats, Risk: RiskHigh, Action: a.Action, Mode: a.Mode, Src: a.Src,
		ViaProxy: a.ViaProxy, Count: uint64(e.total), First: time.Unix(0, e.first), Last: time.Unix(0, now), Note: why}
	if k.net {
		r.SigName, r.Note = "Suspected intrusion from one network", why+", from several /64s of one /48"
	}
	if g.cfg.Source == SourceOff {
		r.Src, r.ViaProxy = netip.Addr{}, false
	}
	return Record{Kind: KindSuspected, Alert: r}, true
}

// suspicion names the condition a source's window meets, or "".
func suspicion(e *centry) string {
	switch at := e.cats.Attacks(); {
	case e.cats.Has(CatDecoy):
		return "a decoy path was requested"
	case at.Len() >= suspectCategories:
		return "three or more attack categories"
	case e.cats.Has(CatScanner) && at != 0:
		return "a scanner finding and an attack"
	case e.refused >= suspectRefused:
		return "ten or more findings that refuse"
	}
	return ""
}

// evictSource forgets an idle entry or the one seen least recently of up to 32. One that was reported in the last hour
// goes only when the whole sample was.
func (g *Aggregator) evictSource(s *cshard, now int64) {
	var oldest, oldestKept ckey
	oldAt, keptAt, n := int64(-1), int64(-1), 0
	for k, e := range s.m {
		recent := e.suspected && now-e.suspectAt < int64(suspectEvery)
		if !recent && now-e.last >= int64(correlationWindow) {
			delete(s.m, k)
			return
		}
		if recent {
			if keptAt < 0 || e.last < keptAt {
				oldestKept, keptAt = k, e.last
			}
		} else if oldAt < 0 || e.last < oldAt {
			oldest, oldAt = k, e.last
		}
		if n++; n == 32 {
			break
		}
	}
	if oldAt < 0 {
		oldest = oldestKept
	}
	delete(s.m, oldest)
}

// emit writes r through the limiter and reports whether the sink took it: a "suspected intrusion" takes its reserved
// bucket first, high and medium risk take the high tier and then the low one, low and info only the low one. What
// does not pass is counted, and so are the repeats of an "alert repeated" line that is not written.
func (g *Aggregator) emit(r Record, now int64) bool {
	high := r.Alert.Risk >= RiskMedium
	if !g.lim.allow(high, r.Kind == KindSuspected, now) {
		if high {
			g.droppedHigh.Add(1)
		} else {
			g.droppedLow.Add(1)
		}
		g.unwrittenRepeat(&r)
		return false
	}
	if !g.send(r) {
		g.unwrittenRepeat(&r)
		return false
	}
	return true
}

// send hands r to the sink and reports whether it took it. A sink that is not an Offerer takes everything.
func (g *Aggregator) send(r Record) bool {
	if g.offer != nil {
		return g.offer(r)
	}
	g.sink.Send(r)
	return true
}

// unwrittenRepeat counts the repeats of r when it is an "alert repeated" record that was not written.
func (g *Aggregator) unwrittenRepeat(r *Record) {
	if r.Kind != KindRepeated {
		return
	}
	g.unwrittenMu.Lock()
	defer g.unwrittenMu.Unlock()
	g.unwrittenN += r.Alert.Count
	k := sigKey{r.Alert.Sig, r.Alert.Action}
	if _, ok := g.unwritten[k]; ok || len(g.unwritten) < maxUnwrittenSigs {
		g.unwritten[k] += r.Alert.Count
	}
}

type bucket struct {
	tokens, max, rate float64
	last              int64
}

func (b *bucket) refill(now int64) {
	if now > b.last {
		b.tokens = min(b.max, b.tokens+float64(now-b.last)/float64(time.Second)*b.rate)
		b.last = now
	}
}

func (b *bucket) take() bool {
	if b.tokens >= 1 {
		b.tokens--
		return true
	}
	return false
}

type limiter struct {
	mu          sync.Mutex
	hi, lo, sus bucket
}

func (l *limiter) allow(high, suspect bool, now int64) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.hi.refill(now)
	l.lo.refill(now)
	l.sus.refill(now)
	if suspect && l.sus.take() {
		return true
	}
	if high {
		return l.hi.take() || l.lo.take()
	}
	return l.lo.take()
}

// Totals is a snapshot of the exact counters.
type Totals struct {
	At           time.Time
	Counts       []Count // the cells that are not zero, by layer, action and risk
	Suppressed   uint64  // silenced by a suppression or an excluded source
	BelowMinRisk uint64  // below -alert-min-risk
	Dropped      Drops   // since start
	Rules        []RuleCount
	RulesOther   uint64 // findings of rule ids beyond the ones counted one by one
}

// Count is one cell of the totals.
type Count struct {
	Layer  Layer
	Action Action
	Risk   Risk
	N      uint64
}

// RuleCount is how many findings one rule id had.
type RuleCount struct {
	ID int
	N  uint64
}

// Get returns one cell of the totals.
func (t *Totals) Get(l Layer, a Action, r Risk) uint64 {
	for _, c := range t.Counts {
		if c.Layer == l && c.Action == a && c.Risk == r {
			return c.N
		}
	}
	return 0
}

// Rule returns the count of one rule id.
func (t *Totals) Rule(id int) uint64 {
	if i, ok := slices.BinarySearchFunc(t.Rules, id, func(r RuleCount, id int) int { return r.ID - id }); ok {
		return t.Rules[i].N
	}
	return 0
}

// Totals returns the exact counters now.
func (g *Aggregator) Totals() Totals {
	t := Totals{At: g.cfg.Now(), Suppressed: g.suppressed.Load(), BelowMinRisk: g.belowMinRisk.Load(),
		Dropped: g.drops(), RulesOther: g.rulesOther.Load()}
	for l := range numLayers {
		for a := range numActions {
			for r := range numRisks {
				if n := g.counts[l][a][r].Load(); n > 0 {
					t.Counts = append(t.Counts, Count{Layer(l), Action(a), Risk(r), n})
				}
			}
		}
	}
	for i := range g.rules {
		s := &g.rules[i]
		s.mu.Lock()
		for id, n := range s.m {
			t.Rules = append(t.Rules, RuleCount{id, n})
		}
		s.mu.Unlock()
	}
	slices.SortFunc(t.Rules, func(a, b RuleCount) int { return a.ID - b.ID })
	return t
}

func (g *Aggregator) drops() Drops {
	d, _ := g.dropsBySig(false)
	return d
}

// dropsBySig returns the drops since start and, when bySig is set, the unwritten repeats not reported yet by signature,
// most first, read together so that they agree.
func (g *Aggregator) dropsBySig(bySig bool) (Drops, []SigCount) {
	d := Drops{High: g.droppedHigh.Load(), Low: g.droppedLow.Load()}
	if g.queueDropped != nil {
		d.Queue = g.queueDropped()
	}
	g.unwrittenMu.Lock()
	defer g.unwrittenMu.Unlock()
	d.Repeats = g.unwrittenN
	if !bySig || len(g.unwritten) == 0 {
		return d, nil
	}
	by := make([]SigCount, 0, len(g.unwritten))
	for k, n := range g.unwritten {
		by = append(by, SigCount{Sig: k.sig, Action: k.action, N: n})
	}
	slices.SortFunc(by, func(a, b SigCount) int {
		if a.N != b.N {
			return cmp.Compare(b.N, a.N)
		}
		return cmp.Or(cmp.Compare(a.Sig, b.Sig), cmp.Compare(a.Action, b.Action))
	})
	return d, by
}

// reported takes the unwritten repeats of an "alerts dropped" record the sink took off the counts still to report.
func (g *Aggregator) reported(by []SigCount) {
	g.unwrittenMu.Lock()
	defer g.unwrittenMu.Unlock()
	for _, u := range by {
		k := sigKey{u.Sig, u.Action}
		if n := g.unwritten[k] - u.N; n > 0 {
			g.unwritten[k] = n
		} else {
			delete(g.unwritten, k)
		}
	}
}

// Tick closes the windows that ended, writing their repeats, reports drops at most once a second, and writes the totals
// and the summary when they are due. Start calls it every second; a test calls it after moving its clock.
func (g *Aggregator) Tick() {
	g.tickMu.Lock()
	defer g.tickMu.Unlock()
	g.tick(false)
}

func (g *Aggregator) tick(final bool) {
	now := g.cfg.Now().UnixNano()
	recs := g.recs[:0]
	for i := range g.dedupe {
		s := &g.dedupe[i]
		s.mu.Lock()
		for k, e := range s.m {
			if final || now-e.start >= g.window {
				if e.pending > 0 {
					recs = append(recs, repeated(e))
				}
				delete(s.m, k)
			}
		}
		s.mu.Unlock()
	}
	for i := range recs {
		if final {
			// Once, at most one line per entry of the table, past the limiter. What the sink refuses is counted
			// in the drops and the totals below, which take a lane of their own (Async).
			if !g.send(recs[i]) {
				g.unwrittenRepeat(&recs[i])
			}
		} else {
			g.emit(recs[i], now)
		}
	}
	clear(recs)
	g.recs = recs[:0]

	// The drops and the totals are marked as reported only when the sink took them; otherwise the next tick tries again.
	if d, by := g.dropsBySig(true); d != g.lastDrops && (final || now-g.lastDropAt >= int64(time.Second)) {
		l := g.lastDrops
		r := Record{Kind: KindDropped, Dropped: Drops{High: d.High - l.High, Low: d.Low - l.Low, Queue: d.Queue - l.Queue,
			Repeats: d.Repeats - l.Repeats}, Unwritten: by}
		if g.send(r) {
			g.reported(by)
			g.lastDrops, g.lastDropAt = d, now
		}
	}
	if g.cfg.SummaryInterval > 0 && g.cfg.Source != SourceOff && now >= g.nextSummary {
		g.nextSummary = now + int64(g.cfg.SummaryInterval)
		if s := g.summary(); len(s) > 0 {
			g.send(Record{Kind: KindSummary, Sources: s})
		}
	}
	if final || g.cfg.TotalsInterval > 0 && now >= g.nextTotals {
		if !final {
			g.nextTotals = now + int64(g.cfg.TotalsInterval)
		}
		if gen := g.gen.Load(); final || gen != g.lastGen {
			t := g.Totals()
			if g.send(Record{Kind: KindTotals, Totals: &t}) {
				g.lastGen = gen
			}
		}
	}
}

// summary lists the sources with the most refused or would-be-refused findings in the period that just ended, and
// starts the next. An IPv6 network is listed when its findings came from more than one /64.
func (g *Aggregator) summary() []SourceSummary {
	gen := g.summaryGen.Load()
	var top []SourceSummary
	score := func(s *SourceSummary) uint64 { return s.Blocked + s.WouldBlock }
	for i := range g.corr {
		s := &g.corr[i]
		s.mu.Lock()
		for k, e := range s.m {
			if e.sumGen != gen || e.sumBlocked+e.sumWould == 0 || k.net && !e.sumSpread {
				continue
			}
			x := SourceSummary{Src: k.addr, Categories: e.sumCats, Blocked: e.sumBlocked, WouldBlock: e.sumWould,
				Detected: e.sumDet, First: time.Unix(0, e.sumFirst), Last: time.Unix(0, e.sumLast)}
			if k.net {
				x.Net = netip.PrefixFrom(k.addr, netBits)
			}
			if len(top) == summaryTop && score(&x) <= score(&top[summaryTop-1]) {
				continue
			}
			j, _ := slices.BinarySearchFunc(top, score(&x), func(t SourceSummary, v uint64) int {
				if score(&t) > v { // sorted from the most down
					return -1
				}
				return 1
			})
			top = slices.Insert(top, j, x)
			if len(top) > summaryTop {
				top = top[:summaryTop]
			}
		}
		s.mu.Unlock()
	}
	g.summaryGen.Add(1)
	return top
}

// Start calls Tick every second until Close.
func (g *Aggregator) Start() {
	g.startOnce.Do(func() {
		g.stop, g.done = make(chan struct{}), make(chan struct{})
		go func() {
			defer close(g.done)
			t := time.NewTicker(time.Second)
			defer t.Stop()
			for {
				select {
				case <-t.C:
					g.Tick()
				case <-g.stop:
					return
				}
			}
		}()
	})
}

// Close stops the ticker and writes everything still held: the repeats of every open window, the drops and the final
// totals. Findings observed after Close are still counted but no longer written by a tick.
func (g *Aggregator) Close() {
	g.closeOnce.Do(func() {
		g.startOnce.Do(func() {}) // a Start after Close does nothing
		if g.stop != nil {
			close(g.stop)
			<-g.done
		}
		g.tickMu.Lock()
		defer g.tickMu.Unlock()
		g.tick(true)
	})
}
