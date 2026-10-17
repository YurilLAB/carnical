// SPDX-License-Identifier: Apache-2.0

package shield

import (
	"container/heap"
	"fmt"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"
)

// AutoBlockMode is what the shield does with a source whose offences reach AutoBlock.Points.
type AutoBlockMode uint8

const (
	// AutoBlockOff counts nothing: Offend does nothing.
	AutoBlockOff AutoBlockMode = iota
	// AutoBlockMonitor counts offences and reports the sources it would ban (source_would_block), and bans none.
	AutoBlockMonitor
	// AutoBlockOn bans the sources whose offences reach their threshold.
	AutoBlockOn
)

func (m AutoBlockMode) String() string {
	switch m {
	case AutoBlockOff:
		return "off"
	case AutoBlockMonitor:
		return "monitor"
	case AutoBlockOn:
		return "on"
	}
	return "unknown"
}

// AutoBlock is the shield's repeat-offender blocking (see Shield.Offend). Its zero value is off; the zero value of each
// other field means its default.
type AutoBlock struct {
	Mode AutoBlockMode
	// Points is the score that bans a source within Window (default 12, 4 to 1,000). A source with standing (known to
	// the shield, see Config.KnownAfter) needs twice as many.
	Points int
	// Window is how long points count (default 10 minutes, one minute to 24 hours): a source's score is the points of
	// its current window plus a share of the previous window's that falls linearly to nothing as the current one goes on.
	Window time.Duration
	// For is how long a first ban lasts (default 10 minutes, one minute to 24 hours). Each further ban of the same source
	// lasts twice as long as the one before, up to MaxFor (default 24 hours, 10 minutes to 7 days, at least For), and a
	// source not banned for MaxFor after its last ban ended starts again at For.
	For, MaxFor time.Duration
	// Max is the most sources banned by Offend at once (default 10,000 or an eighth of Config.MaxSources if that is
	// fewer; 100 to 262,144, at most an eighth of Config.MaxSources, so that the address table, which holds the bans, has
	// room for them besides its other entries). When it is reached no source is banned until a ban ends: no ban is
	// pushed out for a new one. One network (an IPv4 /24 or an IPv6 /48) holds at most a sixteenth of them, so that an
	// attacker with many addresses in one network, such as the 65,536 /64s of an IPv6 /48, cannot take every ban and
	// leave no room for other sources' bans.
	Max int
	// Exempt are ranges never banned by Offend (at most 256): monitoring, health checks, the origin, the owner's own
	// scanners. A range that overlaps a source's IPv6 /64 exempts the whole /64, which a ban would cover.
	Exempt []netip.Prefix
}

const (
	maxExempt        = 256
	maxOffencePoints = 1000 // one offence counts for at most this many points
	maxOffenceSigs   = 8    // the signatures kept for each source, for its event
	maxSigNames      = 1024 // distinct signature names remembered; later ones are reported as "other"
	maxSigLen        = 64
	sweepBatch       = 512 // ended bans taken off the index in one tick
	netShare         = 16  // one network holds at most 1/netShare of AutoBlock.Max bans
	fullEvery        = 30 * time.Second
)

func (a *AutoBlock) defaults(maxSources int) {
	if a.Points == 0 {
		a.Points = 12
	}
	if a.Window == 0 {
		a.Window = 10 * time.Minute
	}
	if a.For == 0 {
		a.For = 10 * time.Minute
	}
	if a.MaxFor == 0 {
		a.MaxFor = 24 * time.Hour
	}
	if a.Max == 0 {
		a.Max = min(10000, maxSources/8)
	}
}

// validate checks the settings, with the defaults applied.
func (a AutoBlock) validate(maxSources int) error {
	switch {
	case a.Mode > AutoBlockOn:
		return fmt.Errorf("shield: AutoBlock.Mode %d is not off, monitor or on", a.Mode)
	case a.Points < 4 || a.Points > 1000:
		return fmt.Errorf("shield: AutoBlock.Points must be between 4 and 1000, not %d", a.Points)
	case a.Window < time.Minute || a.Window > 24*time.Hour:
		return fmt.Errorf("shield: AutoBlock.Window must be between 1m and 24h, not %s", a.Window)
	case a.For < time.Minute || a.For > 24*time.Hour:
		return fmt.Errorf("shield: AutoBlock.For must be between 1m and 24h, not %s", a.For)
	case a.MaxFor < 10*time.Minute || a.MaxFor > 7*24*time.Hour || a.MaxFor < a.For:
		return fmt.Errorf("shield: AutoBlock.MaxFor must be between 10m and 168h and at least For (%s), not %s", a.For, a.MaxFor)
	case a.Max < 100 || a.Max > 1<<18 || a.Max > maxSources/8:
		return fmt.Errorf("shield: AutoBlock.Max must be between 100 and 262144 and at most an eighth of MaxSources (%d), not %d", maxSources/8, a.Max)
	case len(a.Exempt) > maxExempt:
		return fmt.Errorf("shield: AutoBlock.Exempt holds %d ranges, at most %d", len(a.Exempt), maxExempt)
	}
	for _, p := range a.Exempt {
		if !p.IsValid() || p.Bits() == 0 {
			return fmt.Errorf("shield: AutoBlock.Exempt range %s: a range of /0 would exempt every address; set Mode off instead", p)
		}
	}
	return nil
}

// OffendOutcome is what Offend did with an offence.
type OffendOutcome uint8

const (
	// OffendIgnored: auto-block is off, the offence scored no points, or the address is not valid.
	OffendIgnored OffendOutcome = iota
	// OffendCounted: the points were counted and the source is below its threshold.
	OffendCounted
	// OffendBlocked: the source reached its threshold and is banned.
	OffendBlocked
	// OffendWouldBlock: in monitor mode, the source reached its threshold and would have been banned.
	OffendWouldBlock
	// OffendTableFull: the source reached its threshold, but AutoBlock.Max sources are banned already, or its network's
	// share of them (a sixteenth, see AutoBlock.Max), so it is not. Its points are kept, so a later offence bans it once
	// there is room.
	OffendTableFull
	// OffendExempt: the source is never banned by Offend (a trusted or exempt range, loopback, link-local or
	// unspecified); nothing is counted.
	OffendExempt
	// OffendAlreadyBlocked: the source is banned (or, in monitor mode, would be) already; nothing is counted.
	OffendAlreadyBlocked
)

func (o OffendOutcome) String() string {
	switch o {
	case OffendIgnored:
		return "ignored"
	case OffendCounted:
		return "counted"
	case OffendBlocked:
		return "blocked"
	case OffendWouldBlock:
		return "would_block"
	case OffendTableFull:
		return "table_full"
	case OffendExempt:
		return "exempt"
	case OffendAlreadyBlocked:
		return "already_blocked"
	}
	return "unknown"
}

// OffendResult is what Offend did, for the integrator's own record of the request.
type OffendResult struct {
	Outcome OffendOutcome
	// Source is the range a ban covers: the client's IPv4 address as a /32, or its IPv6 /64.
	Source netip.Prefix
	// Points is the source's score with this offence, and Threshold the score that bans it (twice AutoBlock.Points for
	// a source with standing).
	Points, Threshold int
	// For a ban, or a would-be ban: how long it lasts, when it ends, and which ban of the source in a row it is (1 for
	// the first, which lasts AutoBlock.For).
	TTL   time.Duration
	Until time.Time
	Level int
}

// offender is what the shield remembers of a source's offences. It is made only for a source that offends.
type offender struct {
	start     int64 // when the current window began
	cur, prev int   // the points of the current window and of the one before it
	level     int   // the bans in the current run (see AutoBlock.MaxFor)
	until     int64 // when the last ban (or would-be ban) ends
	keep      int64 // until when forgetting this record loses something
	sigs      [maxOffenceSigs]uint16
	nsigs     uint8
}

// roll moves the windows on to ns.
func (o *offender) roll(ns, window int64) {
	switch {
	case o.cur == 0 && o.prev == 0, ns-o.start >= 2*window:
		o.start, o.cur, o.prev, o.nsigs = ns, 0, 0, 0
	case ns-o.start >= window:
		o.start, o.prev, o.cur = o.start+window, o.cur, 0
	}
}

func (o *offender) score(ns, window int64) int {
	return o.cur + int(float64(o.prev)*(1-float64(ns-o.start)/float64(window)))
}

func (o *offender) addSig(id uint16) {
	for _, have := range o.sigs[:o.nsigs] {
		if have == id {
			return
		}
	}
	if o.nsigs < maxOffenceSigs {
		o.sigs[o.nsigs] = id
		o.nsigs++
	}
}

// sigTable gives each signature name a small number, so that a source keeps its signatures in a few bytes and the
// names an attacker can make the shield remember are bounded.
type sigTable struct {
	mu    sync.Mutex
	ids   map[string]uint16
	names []string // names[0] is "other"
	next  uint16
}

func (t *sigTable) id(sig string) uint16 {
	name := cleanSig(sig)
	t.mu.Lock()
	defer t.mu.Unlock()
	if id, ok := t.ids[name]; ok {
		return id
	}
	if len(t.names) >= maxSigNames {
		return 0
	}
	if t.ids == nil {
		t.ids, t.names, t.next = map[string]uint16{}, []string{"other"}, 1
	}
	id := t.next
	t.next++
	t.ids[name] = id
	t.names = append(t.names, name)
	return id
}

func (t *sigTable) list(ids []uint16) []string {
	if len(ids) == 0 {
		return nil
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	out := make([]string, 0, len(ids))
	for _, id := range ids {
		if int(id) < len(t.names) {
			out = append(out, t.names[id])
		}
	}
	return out
}

// cleanSig is sig as the shield reports it: at most 64 bytes of letters, digits and ._:/- with anything else made _,
// so that a name built from what an attacker sent cannot forge a log line. A clean name is returned as it is.
func cleanSig(sig string) string {
	if sig == "" {
		return "unknown"
	}
	ok := func(c byte) bool {
		return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '.' || c == '_' || c == ':' || c == '/' || c == '-'
	}
	clean := len(sig) <= maxSigLen
	for i := 0; clean && i < len(sig); i++ {
		clean = ok(sig[i])
	}
	if clean {
		return sig
	}
	b := make([]byte, 0, min(len(sig), maxSigLen))
	for i := 0; i < len(sig) && len(b) < maxSigLen; i++ {
		c := sig[i]
		if !ok(c) {
			c = '_'
		}
		b = append(b, c)
	}
	return string(b)
}

// offBan is one ban in the index of the bans Offend made, by when it ends.
type offBan struct {
	key   netip.Addr
	until int64
}

type offHeap []offBan

func (h offHeap) Len() int           { return len(h) }
func (h offHeap) Less(i, j int) bool { return h[i].until < h[j].until }
func (h offHeap) Swap(i, j int)      { h[i], h[j] = h[j], h[i] }
func (h *offHeap) Push(x any)        { *h = append(*h, x.(offBan)) }
func (h *offHeap) Pop() any {
	old := *h
	b := old[len(old)-1]
	*h = old[:len(old)-1]
	return b
}

// offIndex counts the bans Offend made that have not ended, so that their number is bounded.
type offIndex struct {
	mu       sync.Mutex
	bans     map[netip.Addr]int64 // the source and when its ban ends
	nets     map[netip.Prefix]int // the number of bans in bans of each network (netOf)
	order    offHeap              // the same, soonest end first; an entry whose ban was replaced is skipped
	ended    []offBan             // taken off, their source_block_ended not yet sent
	fullN    uint64               // bans not made for lack of room since the last auto_block_full
	fullLast int64
	// unreported counts the repeat-offender events the queue had no room for since the last auto_block_unreported.
	unreported atomic.Uint64
	lostLast   int64
}

// expire takes the bans that have ended off the index, at most n of them.
func (x *offIndex) expire(ns int64, n int) {
	for ; n > 0 && len(x.order) > 0 && x.order[0].until <= ns; n-- {
		b := heap.Pop(&x.order).(offBan)
		if x.bans[b.key] == b.until {
			x.drop(b.key)
			x.ended = append(x.ended, b)
		}
	}
}

// drop takes key, which is in the index, off it.
func (x *offIndex) drop(key netip.Addr) {
	delete(x.bans, key)
	n := netOf(key)
	if x.nets[n] <= 1 {
		delete(x.nets, n)
	} else {
		x.nets[n]--
	}
}

// reserve puts key in the index until until, unless limit bans are there already, or limit/netShare of key's network.
func (x *offIndex) reserve(ns int64, key netip.Addr, until int64, limit int) bool {
	ended, have := x.bans[key]
	if have && ended <= ns { // its last ban ended and was not taken off yet: it is reported as the sweep would
		x.ended = append(x.ended, offBan{key: key, until: ended})
	}
	n := netOf(key)
	full := func() bool { return !have && (len(x.bans) >= limit || x.nets[n] >= limit/netShare) }
	if full() {
		x.expire(ns, sweepBatch)
		_, have = x.bans[key]
	}
	if full() || len(x.order) >= 2*limit {
		return false
	}
	if !have {
		x.nets[n]++
	}
	x.bans[key] = until
	heap.Push(&x.order, offBan{key: key, until: until})
	return true
}

// forgotten is told of a source the full address table forgot (see sourceRank): a repeat offender's ban it held is
// taken off the index and reported as ended now, so that no ban ends unseen and AutoBlockActive counts only the bans
// that hold. The shard's lock is held.
func (s *Shield) forgotten(key netip.Addr, src *source, now int64) {
	if src.off == nil || src.off.until <= now {
		return
	}
	x := &s.offIdx
	x.mu.Lock()
	if until, ok := x.bans[key]; ok && until == src.off.until {
		x.drop(key)
		x.ended = append(x.ended, offBan{key: key, until: now})
	}
	x.mu.Unlock()
}

// sourcePrefix is the range a source key stands for: an IPv4 /32 or an IPv6 /64.
func sourcePrefix(key netip.Addr) netip.Prefix {
	bits := 32
	if key.Is6() {
		bits = 64
	}
	return netip.PrefixFrom(key, bits)
}

// exempt says whether Offend never bans client, whose source is src.
func (s *Shield) exempt(client netip.Addr, src netip.Prefix) bool {
	if s.trusted(client) || client.IsLoopback() || client.IsLinkLocalUnicast() || client.IsLinkLocalMulticast() || client.IsUnspecified() {
		return true
	}
	for _, p := range s.cfg.AutoBlock.Exempt {
		if p.Overlaps(src) {
			return true
		}
	}
	return false
}

// Offend tells the shield of an offence by client (the visitor's address, as for Admit): a request a later check
// refused, worth points (the integrator's scale; at most 1,000 count), named by sig (a signature such as
// "crs-942100", kept for the source's event, at most 64 bytes of letters, digits and ._:/-; anything else is replaced).
// With AutoBlock.Mode off it does nothing. A source (an IPv4 address or an IPv6 /64, never wider) whose score reaches
// AutoBlock.Points within AutoBlock.Window, or twice that for a source with standing, is banned: Admit refuses it
// (403, rule 5004008) and the listener resets its connections, for AutoBlock.For, doubled for each further ban up to
// AutoBlock.MaxFor, and Config.Banner is told. It loses its standing, as with an attack's ban. In monitor mode
// nothing is banned and a source_would_block event says what would have been. A trusted or exempt source, and a
// loopback, link-local or unspecified address, is never banned. While AutoBlock.Max sources are banned no other is,
// and while a sixteenth of them are in one network (an IPv4 /24 or an IPv6 /48) no other source of that network is.
// Each ban, would-be ban and full index is an Event, and the events the queue had no room for are counted in one
// (auto_block_unreported). Nothing is kept across restarts. It is cheap: a few map lookups
// and no I/O; it allocates only for a source's first offence, a signature not seen before, and a ban.
func (s *Shield) Offend(client netip.Addr, points int, sig string) OffendResult {
	ab := &s.cfg.AutoBlock
	client = client.Unmap()
	if ab.Mode == AutoBlockOff || points <= 0 || !client.IsValid() {
		return OffendResult{}
	}
	key := SourceKey(client)
	r := OffendResult{Source: sourcePrefix(key)}
	s.counters.offences.Add(1)
	if s.exempt(client, r.Source) {
		r.Outcome = OffendExempt
		return r
	}
	points = min(points, maxOffencePoints)
	id := s.sigs.id(sig)
	ns := s.now().UnixNano()
	info := s.det.info.Load()
	window, maxFor := int64(ab.Window), int64(ab.MaxFor)
	var sigIDs []uint16
	s.sources.do(key, ns, func(src *source) {
		src.last = ns
		o := src.off
		switch {
		case o == nil:
			o = new(offender)
			src.off = o
		case o.keep < ns:
			*o = offender{}
		}
		if src.bannedUntil > ns || o.until > ns {
			r.Outcome = OffendAlreadyBlocked
			return
		}
		o.roll(ns, window)
		o.cur += points
		o.addSig(id)
		o.keep = max(o.start+2*window, o.until+maxFor)
		r.Points, r.Threshold = o.score(ns, window), ab.Points
		if s.isKnown(src, ns, info) {
			r.Threshold *= 2
		}
		if r.Points < r.Threshold {
			r.Outcome = OffendCounted
			return
		}
		level := o.level
		if o.until != 0 && ns-o.until >= maxFor {
			level = 0
		}
		ttl := ab.For
		for i := 0; i < level && ttl < ab.MaxFor; i++ {
			ttl *= 2
		}
		ttl = min(ttl, ab.MaxFor)
		until := ns + int64(ttl)
		r.Outcome = OffendWouldBlock
		if ab.Mode == AutoBlockOn {
			s.offIdx.mu.Lock()
			ok := s.offIdx.reserve(ns, key, until, ab.Max)
			s.offIdx.mu.Unlock()
			if !ok {
				r.Outcome = OffendTableFull
				return
			}
			r.Outcome = OffendBlocked
			src.bannedUntil, src.knownUntil, src.earned = max(src.bannedUntil, until), 0, earned{}
		}
		sigIDs = append(sigIDs, o.sigs[:o.nsigs]...)
		o.level, o.until, o.keep = min(level+1, 64), until, until+maxFor
		o.start, o.cur, o.prev, o.nsigs = ns, 0, 0, 0
		r.TTL, r.Level = ttl, level+1
	})
	switch r.Outcome {
	case OffendBlocked, OffendWouldBlock:
	case OffendTableFull:
		s.counters.autoBlockFull.Add(1)
		s.offIdx.mu.Lock()
		s.offIdx.fullN++
		s.emitEnded(ns)
		s.offIdx.mu.Unlock()
		s.report(ns)
		return r
	default:
		return r
	}
	ev := Event{Kind: "source_would_block", Mode: ab.Mode.String(), Source: r.Source, Client: client, Points: r.Points,
		Sigs: s.sigs.list(sigIDs), TTL: r.TTL, Level: r.Level}
	if r.Outcome == OffendBlocked {
		ev.Kind = "source_blocked"
		s.counters.autoBlocked.Add(1)
		if s.cfg.Banner != nil {
			s.sendBan(key, r.TTL, "carnical-shield repeat offender")
		}
	} else {
		s.counters.wouldAutoBlock.Add(1)
	}
	// The index's lock is held until this event is queued, after the bans that ended before it, the source's own last
	// among them: no other caller can queue an ended ban in between, so a source's ban never ends after its next one.
	d := s.det
	s.offIdx.mu.Lock()
	s.emitEnded(ns)
	d.mu.Lock()
	r.Until = d.wallTime(ns + int64(r.TTL))
	ev.At, ev.State, ev.Until = d.wallTime(ns), d.state, r.Until
	if d.emitBulk(ev) {
		s.offIdx.unreported.Add(1)
	}
	d.mu.Unlock()
	s.offIdx.mu.Unlock()
	return r
}

// report sends the auto_block_full and auto_block_unreported events that are due. Each counts what was not done or not
// said since the last of its kind (the bans not made for lack of room, the repeat-offender events the queue had no room
// for) and is sent at most once every 30 seconds; the sweep sends the rest. They may use the whole event queue, not
// only the repeat offenders' share, and a count the queue has no room for is kept for the next tick.
func (s *Shield) report(ns int64) {
	x := &s.offIdx
	due := func(n uint64, last int64) bool { return n != 0 && (last == 0 || ns-last >= int64(fullEvery)) }
	var full, lost uint64
	x.mu.Lock()
	if due(x.fullN, x.fullLast) {
		full, x.fullN, x.fullLast = x.fullN, 0, ns
	}
	if due(x.unreported.Load(), x.lostLast) {
		lost, x.lostLast = x.unreported.Swap(0), ns
	}
	x.mu.Unlock()
	if full == 0 && lost == 0 {
		return
	}
	d, mode := s.det, s.cfg.AutoBlock.Mode.String()
	d.mu.Lock()
	fullDropped := full != 0 && d.emit(Event{Kind: "auto_block_full", Mode: mode, At: d.wallTime(ns), State: d.state, Count: full})
	lostDropped := lost != 0 && d.emit(Event{Kind: "auto_block_unreported", Mode: mode, At: d.wallTime(ns), State: d.state, Count: lost})
	d.mu.Unlock()
	if !fullDropped && !lostDropped {
		return
	}
	x.mu.Lock()
	if fullDropped {
		x.fullN, x.fullLast = x.fullN+full, 0
	}
	if lostDropped {
		x.unreported.Add(lost)
		x.lostLast = 0
	}
	x.mu.Unlock()
}

// sweep takes the ended bans off the index, at most sweepBatch a second, and reports them; and reports the bans not
// made for lack of room, and the events not sent, that were not reported yet.
func (s *Shield) sweep(ns int64) {
	if s.cfg.AutoBlock.Mode == AutoBlockOff {
		return
	}
	x := &s.offIdx
	x.mu.Lock()
	x.expire(ns, sweepBatch)
	s.emitEnded(ns)
	x.mu.Unlock()
	s.report(ns)
}

// emitEnded queues a source_block_ended event for each ban taken off the index and not yet reported, in the order they
// were taken off. The index's lock is held, and is taken before the detector's: nothing holding the detector's lock
// takes the index's.
func (s *Shield) emitEnded(ns int64) {
	x := &s.offIdx
	if len(x.ended) == 0 {
		return
	}
	d := s.det
	d.mu.Lock()
	defer d.mu.Unlock()
	ended := x.ended
	x.ended = nil
	for _, b := range ended {
		if d.emitBulk(Event{Kind: "source_block_ended", Mode: s.cfg.AutoBlock.Mode.String(), At: d.wallTime(ns), State: d.state,
			Source: sourcePrefix(b.key), Until: d.wallTime(b.until)}) {
			s.offIdx.unreported.Add(1)
		}
	}
}

// sendBan tells Config.Banner, which must be set, of a ban of key's range, unless the range holds a trusted address: a
// firewall would drop every packet from the range, a trusted proxy's in it too, and the ban then holds only here, where
// the proxy's own requests pass it.
func (s *Shield) sendBan(key netip.Addr, ttl time.Duration, reason string) {
	p := sourcePrefix(key)
	for _, t := range s.cfg.Trusted {
		if t.Overlaps(p) {
			return
		}
	}
	select {
	case s.bans <- banReq{p: p, ttl: ttl, reason: reason}:
	default: // the helper is behind; the ban still holds in this process
		s.counters.banErrors.Add(1)
	}
}
