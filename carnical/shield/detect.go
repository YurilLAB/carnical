// SPDX-License-Identifier: Apache-2.0

package shield

import (
	"math"
	"net/http"
	"net/netip"
	"slices"
	"sync"
	"sync/atomic"
	"time"
)

// The detector decides whether the site is under a denial-of-service attack. It cannot do it by looking at addresses
// one at a time: a botnet of residential routers, cameras and phones sends from tens of thousands of addresses in many
// countries, each one slower than any per-address limit. What gives such an attack away is what all those addresses have
// in common and what they lack compared with the site's ordinary traffic:
//
//   - volume: the request rate is several times the site's own recent baseline, and above an absolute floor;
//   - concentration: one client fingerprint (one program) or one target is a far larger share of the traffic than it
//     usually is;
//   - spread: a burst of addresses that have not been seen before, or many more different addresses than usual;
//   - no engagement: new visitors that are people load a page and then its assets; a flood of new addresses that each
//     ask for one thing and nothing else is not people;
//   - pain: the application starts failing or slowing down.
//
// Volume alone is not an attack (a newsletter goes out, a post is shared), and the detector says so ("elevated") without
// acting. Volume with a concentrated fingerprint from many sources, or with a concentrated target from new sources that
// do not behave like browsers, or with the application in pain and the traffic coming from new places, is an attack.
//
// Everything is measured in one-second windows; decisions use the last ten seconds against a baseline that is an
// exponentially weighted average of the same measures, updated only while the site is not under attack, so that an
// attack cannot teach the detector that it is normal. Nor is it raised while the application fails compared with a
// far slower average of its errors: a flood that grows slowly enough to stay under the threshold would otherwise teach
// the detector its volume, and the failure it causes, as the site's usual.

// State is what the detector thinks is happening.
type State uint8

const (
	// Normal: nothing unusual.
	Normal State = iota
	// Elevated: much more traffic than usual, without the signs of an attack. Nothing extra is done; it is reported.
	Elevated
	// Attack: the mitigations are on (see Shield.Admit).
	Attack
)

func (s State) String() string {
	switch s {
	case Elevated:
		return "elevated"
	case Attack:
		return "attack"
	}
	return "normal"
}

// DetectorConfig tunes the detector. The zero value of each field means its default.
type DetectorConfig struct {
	// Warmup is how long the baseline learns before it is used with its full weight (default 5 minutes). During warm-up
	// the baseline is the plain average of what has been seen.
	Warmup time.Duration
	// Tau is the time constant of the baseline's moving average (default 10 minutes): long enough that an attack that
	// ramps up over a minute stands out, short enough to follow a site's ordinary daily rise and fall.
	Tau time.Duration
	// MinAttackRate is an absolute floor, in requests a second, under which traffic is never an attack (default 20): a
	// small site that goes from 1 to 10 requests a second is not under attack. It only matters to small sites. What
	// decides for every other site is the site's own average and variation: the traffic must exceed the larger of
	// RateFactor times the moving average and the average plus Sigmas standard deviations of the site's own recent rates.
	MinAttackRate float64
	// Sigmas is how many standard deviations above the moving average the rate must be (default 8). The deviation is the
	// site's own, measured on the same ten-second rates and learnt the same way, so a site whose traffic is bursty has to
	// exceed more than a site whose traffic is steady.
	Sigmas float64
	// LimitMargin and MaxScale make the limits of an address, and of a network, follow its own traffic: each is raised to
	// LimitMargin (default 4) times the moving average of the requests a second that address (or network) has had
	// answered well by the application, when that is higher than the configured limit, and at most to MaxScale (default
	// 20) times the configured limit. An address with many visitors behind it (a company's, a mobile carrier's) is then
	// not limited as if it were one person, and what it has earned raises the limit of no other address.
	LimitMargin, MaxScale float64
	// EvidenceTimeout ends an attack that has gone on this long (default 5 minutes) without any of the evidence that
	// declared it (concentration, spread, harm), even if the traffic has not fallen: a baseline that stopped learning
	// when the attack began must never be able to hold a site in "attack" for ever. The mitigation counts as evidence
	// while the traffic is still over the threshold of the baseline from before the attack, at least half of it is
	// refused or shown the challenge, and the share of it whose fingerprint the baseline knew is less than half what
	// it was: once a flood that only showed harm is held off, the application is well again, and the attack must not
	// end, and let the flood back in, while the flood goes on. The site's own clients, whose traffic may grow past the
	// frozen threshold once the flood is over, still look as they did, and so do not hold the attack however much of
	// their traffic the attack's budgets refuse. What an address's or a network's own limit refuses is left out of
	// both, traffic and refusals: it is held whether there is an attack or not, and one address sending more than its
	// limit must not hold a site in "attack" for ever. So are the refusals of banned addresses, unless they come from at
	// least MinClusterSources addresses: the bans of a botnet are the attack's mitigation.
	EvidenceTimeout time.Duration
	// MinHistory is how long the detector must have been running before it can declare an attack (default 60 seconds): with
	// less data nothing is known about what is usual. Until Warmup has passed, only a rise of 2.5 times RateFactor counts.
	MinHistory time.Duration
	// RateFactor is how many times the baseline rate the traffic must be for there to be an attack (default 4).
	RateFactor float64
	// ExitFactor is how far the rate must fall, relative to the baseline at the start of the attack, before the attack
	// can be over (default 2).
	ExitFactor float64
	// Confirm is how many consecutive seconds the evidence must hold before the mitigations start (default 3).
	Confirm int
	// MinAttack is the shortest an attack lasts once declared (default 60 seconds): attackers pulse their floods to make
	// a defence switch off and on.
	MinAttack time.Duration
	// ExitQuiet is how long the traffic must stay below the exit rate before the attack is over (default 30 seconds).
	ExitQuiet time.Duration
	// MinClusterSources is how many different addresses must share a fingerprint for it to count as a distributed
	// cluster (default 20), and how many more addresses than usual must open connections for a flood of connections
	// to count. Fewer is a handful of clients, which the per-address limits deal with.
	MinClusterSources int
	// SeenPeriod is how long an address is remembered as seen (between one and two periods; default 12 hours).
	SeenPeriod time.Duration
	// InitialRate, if set, is the baseline request rate to start from instead of learning it from nothing, so that a
	// restart during an attack does not take the attack for normal traffic. It skips the warm-up of the rate only: what
	// the traffic is made of (its fingerprints, targets, addresses and the application's health) is still learnt as in a
	// warm-up, and only from seconds whose rate is under the threshold.
	InitialRate float64
}

func (c *DetectorConfig) defaults() {
	def := func(d *time.Duration, v time.Duration) {
		if *d == 0 {
			*d = v
		}
	}
	deff := func(f *float64, v float64) {
		if *f == 0 {
			*f = v
		}
	}
	def(&c.Warmup, 5*time.Minute)
	def(&c.Tau, 10*time.Minute)
	def(&c.MinAttack, time.Minute)
	def(&c.ExitQuiet, 30*time.Second)
	def(&c.EvidenceTimeout, 5*time.Minute)
	def(&c.MinHistory, time.Minute)
	def(&c.SeenPeriod, 12*time.Hour)
	deff(&c.MinAttackRate, 20)
	deff(&c.Sigmas, 8)
	deff(&c.LimitMargin, 4)
	deff(&c.MaxScale, 20)
	deff(&c.RateFactor, 4)
	deff(&c.ExitFactor, 2)
	if c.Confirm == 0 {
		c.Confirm = 3
	}
	if c.MinClusterSources == 0 {
		c.MinClusterSources = 20
	}
}

const (
	slowTau     = 6  // how many times Tau the application's health is also averaged over, to tell when it is in pain
	ringSeconds = 64 // windows kept; the last aggSeconds are used for decisions
	aggSeconds  = 10
	topKeys     = 16
	baseKeys    = 64
	// minShare is the usual share below which the baseline forgets a fingerprint or target (see learnShares), and below
	// which a fingerprint it still holds is not one it knows: a flood's fingerprints enter at a sliver in the seconds before
	// the flood crosses the threshold.
	minShare = 0.002
)

type window struct {
	sec                                      int64
	reqs, newSrcs, engaged                   uint32
	familiar                                 uint32 // of reqs, those whose fingerprint is usually at least minShare
	done, errs, latN                         uint32
	refused, challenged, solved, banned      uint32
	held                                     uint32 // of refused, those held by an address's or network's own limit
	banRefused                               uint32 // of refused, those of banned addresses
	connsIn, connsRefused                    uint32
	connClosed, earlyCloses, securityRejects uint32
	wouldRejects                             uint32  // requests a check in detect or monitor mode would have refused (Shield.WouldReject)
	maxSrc, maxNet                           uint32  // the most an address's, and a network's, limit was raised in this second, in thousandths
	lat                                      float64 // milliseconds, summed over latN
	srcs, nets                               hll
	connSrcs                                 hll // the addresses that opened connections, admitted or refused
	banSrcs                                  hll // the banned addresses that were refused
	fps, paths                               topK
}

func (w *window) reset(sec int64) {
	srcs, nets, connSrcs, banSrcs, fps, paths := w.srcs, w.nets, w.connSrcs, w.banSrcs, w.fps, w.paths
	srcs.reset()
	nets.reset()
	connSrcs.reset()
	banSrcs.reset()
	fps.reset()
	paths.reset()
	*w = window{sec: sec, srcs: srcs, nets: nets, connSrcs: connSrcs, banSrcs: banSrcs, fps: fps, paths: paths}
}

// share is one fingerprint or target and its part of the traffic over the last ten seconds.
type share struct {
	key     uint64
	label   string
	share   float64
	sources float64
}

// aggregate is the last ten seconds.
type aggregate struct {
	rate, srcs, nets, newShare, newSrcs  float64
	familiar                             float64 // the share of requests whose fingerprint is usually at least minShare
	engagement                           float64 // -1 when too few new sources to tell
	errRatio, lat                        float64 // -1 when nothing completed
	connRate, connRefused, connSrcs      float64
	closed, earlyCloses, securityRejects float64
	wouldRejects                         float64
	refused, challenged, held            float64
	banRefused, banSrcs                  float64 // the refusals of banned addresses, and how many addresses they came from
	served                               float64 // requests a second the application answered without an error
	scaleSrc, scaleNet                   float64 // the most an address's, and a network's, limit was raised in the ten seconds
	fps, paths                           []share
}

type baseline struct {
	rate, rateVar, srcs, newShare, errRatio, lat, connRate, connSrcs float64
	familiar                                                         float64 // the share of requests whose fingerprint is at least minShare of fps
	errSlow                                                          float64 // errRatio averaged slowTau times slower
	lastSample                                                       float64
	sampled                                                          bool
	// While the application is failing (see hurt): the rate, and the requests it answered well, when it began to.
	hurtRate, hurtServed float64
	hurting              bool
	fps, paths           map[uint64]float64
}

// attackInfo is what the request path needs to know during an attack. It is replaced as a whole and read without a lock.
type attackInfo struct {
	epoch        uint32
	since        int64 // when the attack began
	fps, paths   map[uint64]bool
	unknownRate  float64
	clusterRate  float64
	knownRate    float64
	pathAttack   bool
	fingerprints int
}

type detector struct {
	cfg DetectorConfig

	mu         sync.Mutex
	ring       [ringSeconds]window
	cur        int
	curSec     int64
	started    bool
	seen       seenFilter
	rotated    int64
	base       baseline
	age        int // seconds the rate has been learnt, or Warmup's worth from the start with InitialRate
	shapeAge   int // seconds the rest of the baseline has been learnt
	state      State
	run        int // consecutive seconds of evidence
	since      int64
	quiet      int
	noEvidence int      // consecutive seconds of attack without evidence
	frozen     baseline // the baseline when the attack began
	epoch      uint32
	last       aggregate
	reasons    []string
	scratchS   hll
	scratchN   hll
	scratchC   hll
	scratchB   hll
	incident   *incidentAcc
	history    []Incident

	info atomic.Pointer[attackInfo]
	// learning is true while traffic is ordinary: no attack, no traffic above the usual, no evidence building up. Clients
	// earn their standing only then.
	learning atomic.Bool
	// winMaxSrc and winMaxNet are the most an address's, and a network's, limit was raised in the current second, in
	// thousandths; the request path raises them without a lock and the detector takes them when the second ends.
	winMaxSrc, winMaxNet atomic.Uint32
	// scaleSrc and scaleNet (float64 bits) are the same over the last ten seconds, for the dashboard: 1 when every
	// address and network had the configured limit.
	scaleSrc, scaleNet atomic.Uint64
	// earn is what the request path keeps each address's and network's own average by (see earned). earnSec counts the
	// seconds that were not an attack's, and earnOpen says whether the current one is such a second.
	earn     atomic.Pointer[earning]
	earnSec  uint32
	earnOpen bool

	// set by the Shield
	// wall gives the wall-clock time of an instant on the shield's clock, for what events and records report; nil when
	// the shield's clock is Config.Now.
	wall       func(ns int64) time.Time
	labeler    Labeler
	onEvent    func(Event)
	monitor    bool // Config.MonitorOnly, for Event.Mode
	idsReasons []string
	// idsLast is when each IDS signal was last reported, and idsSent whether it ever was. idsOpen holds the signals
	// reported since the last ids_clear, and idsQuiet when the reasons last became empty, while idsCalm says they are.
	idsLast  [idsCodes]int64
	idsSent  [idsCodes]bool
	idsOpen  uint8
	idsQuiet int64
	idsCalm  bool
	// announced is the state the last elevated, attack_start or normal event reported, and calm how many seconds in a row
	// the state has been Normal.
	announced State
	calm      int
	// pending holds the events found under mu until tick delivers them after releasing it (see deliver), at most
	// maxPendingEvents; droppedEvents counts those that did not fit, and those found after the shield was closed.
	// delivering says that a caller of tick is delivering.
	pending       []Event
	delivering    bool
	closed        bool
	droppedEvents atomic.Uint64
	unknownRate   func(base float64) float64
	knownRate     func(base float64) float64
	clusterRate   float64
	clusterShare  float64
}

func newDetector(cfg DetectorConfig) *detector {
	cfg.defaults()
	d := &detector{cfg: cfg, seen: newSeenFilter(), scratchS: newHLL(10), scratchN: newHLL(8), scratchC: newHLL(10), scratchB: newHLL(6)}
	for i := range d.ring {
		d.ring[i] = window{srcs: newHLL(10), nets: newHLL(8), connSrcs: newHLL(10), banSrcs: newHLL(6), fps: newTopK(topKeys), paths: newTopK(topKeys)}
	}
	d.base = baseline{rate: cfg.InitialRate, fps: map[uint64]float64{}, paths: map[uint64]float64{}}
	if cfg.InitialRate > 0 {
		d.age = int(cfg.Warmup / time.Second)
	}
	return d
}

// netOf is the network an address belongs to for counting how widely an attack is spread: a /24 for IPv4 and a /48 for
// IPv6 (a site or a customer's allocation).
func netOf(a netip.Addr) netip.Prefix {
	if a.Is4() {
		p, _ := a.Prefix(24)
		return p
	}
	p, _ := a.Prefix(48)
	return p
}

// observe counts one request and reports whether its source has not been seen before. key is the client's SourceKey: an
// IPv6 client is counted by its /64, as the limits count it, so that one host that changes the last 64 bits of its
// address does not look to the detector like thousands of new addresses, the spread of a botnet.
func (d *detector) observe(ns int64, key netip.Addr, fp uint64, fpLabel string, pt uint64, ptLabel string) bool {
	h := hashAddr(key)
	d.mu.Lock()
	defer d.mu.Unlock()
	d.advance(ns)
	w := &d.ring[d.cur]
	w.reqs++
	w.srcs.add(h)
	w.nets.add(maphashPrefix(netOf(key)))
	w.fps.add(fp, fpLabel, h, 1)
	w.paths.add(pt, ptLabel, h, 1)
	usual := d.base.fps
	if d.state == Attack {
		usual = d.frozen.fps
	}
	if usual[fp] >= minShare {
		w.familiar++
	}
	isNew := !d.seen.see(h)
	if isNew {
		w.newSrcs++
	}
	if inc := d.incident; inc != nil {
		inc.requests++
		inc.srcs.add(h)
		inc.nets.add(maphashPrefix(netOf(key)))
		if d.labeler != nil {
			if l := d.labeler.Label(key); l != "" {
				lh := hashString(l)
				inc.labels.add(lh, l, h, 1)
				inc.labelSet.add(lh)
			}
		}
	}
	return isNew
}

// count records something the Shield did.
func (d *detector) count(ns int64, f func(w *window)) {
	d.mu.Lock()
	d.advance(ns)
	f(&d.ring[d.cur])
	d.mu.Unlock()
}

// note records something the Shield did, in the window and in the attack's record if there is one.
func (d *detector) note(ns int64, f func(w *window, inc *incidentAcc)) {
	d.mu.Lock()
	d.advance(ns)
	f(&d.ring[d.cur], d.incident)
	d.mu.Unlock()
}

// hangUpWait is the least a client must have waited before a hang-up counts as the application's failure (see done).
const hangUpWait = time.Second

// done records a request the application answered (or failed to answer). latency is negative when unknown. A request
// whose client hung up first (StatusClientClosed) says nothing about the application if the client gave up at once, and
// is left out; one it hung up on after waiting at least hangUpWait and four times the usual latency is a request the
// application did not answer in time, and counts as its failure: an application that queues what it cannot serve,
// instead of failing it, shows its overload in no other way, since the clients give up long before it would fail.
func (d *detector) done(ns int64, status int, latency time.Duration) {
	d.count(ns, func(w *window) {
		if status == StatusClientClosed {
			if latency < max(hangUpWait, time.Duration(4*d.base.lat*float64(time.Millisecond))) {
				return
			}
			status = http.StatusServiceUnavailable
		}
		w.done++
		if status >= 500 {
			w.errs++
		}
		if latency >= 0 {
			w.lat += float64(latency) / float64(time.Millisecond)
			w.latN++
		}
	})
}

// tick closes the windows that have ended and delivers the events found since the last tick. The Shield calls it every
// second so that the state moves on while no requests arrive.
func (d *detector) tick(ns int64) {
	d.mu.Lock()
	d.advance(ns)
	d.deliver()
}

// maxPendingEvents is the most events kept for delivery while onEvent is behind, besides the one it is given.
const maxPendingEvents = 256

// deliver is called with mu held and releases it. It hands the pending events to onEvent in order, with mu released: an
// onEvent that blocks (a log on a stalled pipe) then holds up neither requests nor connections, which only queue events,
// but later events only. Each event leaves the queue as it is handed over, so the queue's bound counts every event not
// yet given to onEvent. Only tick and Close deliver, so onEvent runs on the shield's own goroutine (or Tick's caller with
// Config.Now), and one caller at a time: another that finds the events being delivered leaves its own to that one.
func (d *detector) deliver() {
	if d.delivering || len(d.pending) == 0 {
		d.mu.Unlock()
		return
	}
	d.delivering = true
	for len(d.pending) > 0 {
		ev := d.pending[0]
		d.pending[0] = Event{}
		d.pending = d.pending[1:]
		d.mu.Unlock()
		d.onEvent(ev)
		d.mu.Lock()
	}
	d.delivering = false
	d.mu.Unlock()
}

func (d *detector) advance(ns int64) {
	sec := ns / 1e9
	if !d.started {
		d.started, d.curSec, d.rotated = true, sec, ns
		d.ring[d.cur].reset(sec)
		return
	}
	if sec <= d.curSec {
		return
	}
	steps := sec - d.curSec
	if steps > ringSeconds {
		// A long silence: the closed windows are empty; evaluate a full ring of them and jump.
		d.curSec = sec - ringSeconds
		steps = ringSeconds
	}
	for i := int64(0); i < steps; i++ {
		closing := &d.ring[d.cur]
		closing.maxSrc, closing.maxNet = d.winMaxSrc.Swap(0), d.winMaxNet.Swap(0)
		d.evaluate((d.curSec + 1) * 1e9)
		d.cur = (d.cur + 1) % ringSeconds
		d.curSec++
		d.ring[d.cur].reset(d.curSec)
	}
	if time.Duration(ns-d.rotated) >= d.cfg.SeenPeriod {
		d.seen.rotate()
		d.rotated = ns
	}
}

// aggregate sums the last aggSeconds closed windows (the current, open one is not included).
func (d *detector) aggregate() aggregate {
	var a aggregate
	var reqs, newSrcs, engaged, familiar, done, errs, latN, conns, connsRef, refused, challenged, held, banRefused, maxSrc, maxNet, closed, earlyCloses, securityRejects, wouldRejects float64
	var lat float64
	d.scratchS.reset()
	d.scratchN.reset()
	d.scratchC.reset()
	d.scratchB.reset()
	type acc struct {
		count float64
		label string
		srcs  hll
	}
	fps := map[uint64]*acc{}
	paths := map[uint64]*acc{}
	merge := func(m map[uint64]*acc, t *topK) {
		for i := range t.e {
			e := &t.e[i]
			x := m[e.key]
			if x == nil {
				x = &acc{label: e.label, srcs: newHLL(6)}
				m[e.key] = x
			}
			x.count += float64(e.count)
			x.srcs.merge(&e.srcs)
		}
	}
	for i := 1; i <= aggSeconds; i++ {
		w := &d.ring[(d.cur-i+ringSeconds)%ringSeconds]
		reqs += float64(w.reqs)
		newSrcs += float64(w.newSrcs)
		engaged += float64(w.engaged)
		familiar += float64(w.familiar)
		done += float64(w.done)
		errs += float64(w.errs)
		latN += float64(w.latN)
		lat += w.lat
		conns += float64(w.connsIn)
		connsRef += float64(w.connsRefused)
		closed += float64(w.connClosed)
		earlyCloses += float64(w.earlyCloses)
		securityRejects += float64(w.securityRejects)
		wouldRejects += float64(w.wouldRejects)
		refused += float64(w.refused)
		held += float64(w.held)
		banRefused += float64(w.banRefused)
		maxSrc = math.Max(maxSrc, float64(w.maxSrc))
		maxNet = math.Max(maxNet, float64(w.maxNet))
		challenged += float64(w.challenged)
		d.scratchS.merge(&w.srcs)
		d.scratchN.merge(&w.nets)
		d.scratchC.merge(&w.connSrcs)
		d.scratchB.merge(&w.banSrcs)
		merge(fps, &w.fps)
		merge(paths, &w.paths)
	}
	a.rate = reqs / aggSeconds
	a.scaleSrc, a.scaleNet = maxSrc/1000, maxNet/1000
	a.connRate = conns / aggSeconds
	a.connRefused = connsRef / aggSeconds
	if conns > 0 {
		a.connSrcs = d.scratchC.estimate()
	}
	a.closed, a.earlyCloses, a.securityRejects = closed/aggSeconds, earlyCloses/aggSeconds, securityRejects/aggSeconds
	a.wouldRejects = wouldRejects / aggSeconds
	a.refused = refused / aggSeconds
	a.challenged = challenged / aggSeconds
	a.held = held / aggSeconds
	a.banRefused = banRefused / aggSeconds
	if banRefused > 0 {
		a.banSrcs = d.scratchB.estimate()
	}
	a.served = (done - errs) / aggSeconds
	a.newSrcs = newSrcs
	if reqs > 0 {
		a.srcs = d.scratchS.estimate()
		a.nets = d.scratchN.estimate()
		a.newShare = newSrcs / reqs
		a.familiar = familiar / reqs
	}
	a.engagement = -1
	if newSrcs >= 20 {
		a.engagement = engaged / newSrcs
	}
	a.errRatio, a.lat = -1, -1
	if done > 0 {
		a.errRatio = errs / done
	}
	if latN > 0 {
		a.lat = lat / latN
	}
	list := func(m map[uint64]*acc) []share {
		out := make([]share, 0, len(m))
		for k, x := range m {
			if reqs > 0 {
				out = append(out, share{key: k, label: x.label, share: x.count / reqs, sources: x.srcs.estimate()})
			}
		}
		slices.SortFunc(out, func(p, q share) int {
			switch {
			case p.share > q.share:
				return -1
			case p.share < q.share:
				return 1
			}
			return 0
		})
		return out[:min(len(out), 8)]
	}
	a.fps, a.paths = list(fps), list(paths)
	return a
}

// evaluate runs once a second, at the end of a window.
func (d *detector) evaluate(ns int64) {
	a := d.aggregate()
	d.last = a
	d.scaleSrc.Store(math.Float64bits(a.scaleSrc))
	d.scaleNet.Store(math.Float64bits(a.scaleNet))
	d.detectIDS(ns, a)
	b := &d.base
	if d.state == Attack {
		b = &d.frozen
	}
	rateBase := math.Max(b.rate, 0)
	hurt := d.hurt(a)
	warming := d.age < int(d.cfg.Warmup/time.Second)
	trained := d.age >= int(d.cfg.MinHistory/time.Second) || d.state == Attack // too little data tells nothing about what is usual
	thr := d.threshold(rateBase, b.rateVar)
	if warming { // still learning what is usual: only a far larger rise counts
		thr = math.Max(thr, 2.5*d.cfg.RateFactor*rateBase)
	}
	gate := a.rate >= thr

	var reasons []string
	strongFP, pathConc := false, false
	for _, s := range a.fps {
		if s.share >= 0.3 && s.share-b.fps[s.key] >= 0.25 && s.sources >= float64(d.cfg.MinClusterSources) {
			strongFP = true
			reasons = append(reasons, "one client fingerprint is "+pct(s.share)+" of requests from about "+itoa(s.sources)+" addresses (usually "+pct(b.fps[s.key])+"): "+s.label)
			break
		}
	}
	for _, s := range a.paths {
		if s.share >= 0.3 && s.share-b.paths[s.key] >= 0.25 {
			pathConc = true
			reasons = append(reasons, "one target is "+pct(s.share)+" of requests (usually "+pct(b.paths[s.key])+"): "+s.label)
			break
		}
	}
	newSrc := a.newShare >= 0.5 && a.newShare >= b.newShare+0.3
	burst := a.srcs >= 4*math.Max(b.srcs, 10)
	spread := newSrc || burst
	if newSrc {
		reasons = append(reasons, pct(a.newShare)+" of requests are from addresses not seen before (usually "+pct(b.newShare)+")")
	}
	if burst {
		reasons = append(reasons, "about "+itoa(a.srcs)+" different addresses in ten seconds (usually "+itoa(b.srcs)+")")
	}
	lowEngage := a.engagement < 0.25 // includes "too few new sources to tell"
	if a.engagement >= 0 && lowEngage && spread {
		reasons = append(reasons, "new addresses ask for one thing and nothing else ("+pct(a.engagement)+" go on to a second page or asset)")
	}
	pain := (a.errRatio >= 0.2 && a.errRatio >= b.errRatio+0.1) || (a.lat >= 200 && b.lat > 0 && a.lat >= 4*b.lat)
	if pain {
		reasons = append(reasons, "the application is failing or slow ("+pct(math.Max(a.errRatio, 0))+" errors, "+itoa(math.Max(a.lat, 0))+" ms)")
	}
	// Connections opened without requests are evidence only when they come from many more addresses than usual: at least
	// MinClusterSources more, and twice as many. One address that opens connections as fast as it can is held by its own
	// connection limit and must not put the whole site into attack mode; its refused connections still count in the rate,
	// because the connections of a flood that fills the connection cap are refused too.
	connFlood := a.connRate >= math.Max(d.cfg.RateFactor*b.connRate, d.cfg.MinAttackRate) && a.connRate >= 3*math.Max(a.rate, 1) &&
		a.connSrcs >= math.Max(2*b.connSrcs, b.connSrcs+float64(d.cfg.MinClusterSources))
	if connFlood {
		reasons = append(reasons, "connections are opened without requests ("+itoa(a.connRate)+" a second from about "+itoa(a.connSrcs)+
			" addresses, usually "+itoa(b.connSrcs)+")")
	}
	evidence := gate && (strongFP || pathConc && spread && lowEngage || pain && spread) || connFlood
	evidence = evidence && trained
	if gate {
		reasons = append([]string{"about " + itoa(a.rate) + " requests a second, the usual is " + itoa(rateBase)}, reasons...)
	}

	switch d.state {
	case Normal, Elevated:
		if evidence {
			d.run++
		} else {
			d.run = 0
		}
		if d.run >= d.cfg.Confirm {
			d.startAttack(ns, a, reasons, strongFP, pathConc && spread && lowEngage)
		} else if gate {
			d.state = Elevated
			// Once until the state has been announced normal again: a rate that hovers at the threshold is one rise.
			if d.announced != Elevated {
				d.announced = Elevated
				d.emit(Event{Kind: "elevated", At: d.wallTime(ns), State: Elevated, Rate: a.rate, BaselineRate: rateBase, Reasons: reasons})
			}
		} else {
			d.state = Normal
		}
		if d.state != Attack {
			d.learn(a, gate, hurt)
		}
		// The return to normal is announced once the state has stayed Normal for as long as the rate is averaged over.
		if d.state == Normal {
			d.calm++
		} else {
			d.calm = 0
		}
		if d.state == Normal && d.announced != Normal && d.calm >= aggSeconds {
			d.announced = Normal
			d.emit(Event{Kind: "normal", At: d.wallTime(ns), State: Normal, Rate: a.rate, BaselineRate: rateBase})
		}
	case Attack:
		exitRate := math.Max(d.cfg.ExitFactor*d.frozen.rate, d.cfg.MinAttackRate/2)
		if a.rate < exitRate && !connFlood {
			d.quiet++
		} else {
			d.quiet = 0
		}
		// What an address's or network's own limit holds is held whether there is an attack or not: only what the
		// attack's budgets and bans hold keeps the attack, or one address that sends more than its limit could keep it for
		// ever. The bans of a handful of addresses are left out for the same reason. And the site's own clients, whose
		// traffic may grow past the frozen threshold once the flood is over, must not keep it either, however much of it
		// the budgets refuse: they are told from a flood by their fingerprints, which the baseline knew.
		held := a.held
		if a.banSrcs < float64(d.cfg.MinClusterSources) {
			held += a.banRefused
		}
		rest := a.rate - held
		// A baseline that knows no fingerprint, after a restart into a flood with InitialRate, cannot tell them apart.
		unlike := d.frozen.familiar <= 0 || a.familiar < 0.5*d.frozen.familiar
		if mitigating := rest >= thr && a.refused-held+a.challenged >= 0.5*rest && unlike; evidence || mitigating {
			d.noEvidence = 0
		} else {
			d.noEvidence++
		}
		inc := d.incident
		if a.rate > inc.peak {
			inc.peak = a.rate
		}
		inc.addReasons(reasons)
		d.widen(a, strongFP, pathConc && spread && lowEngage)
		if time.Duration(ns-d.since) >= d.cfg.MinAttack && (time.Duration(d.quiet)*time.Second >= d.cfg.ExitQuiet ||
			time.Duration(d.noEvidence)*time.Second >= d.cfg.EvidenceTimeout) {
			d.endAttack(ns)
		} else if (ns/1e9-d.since/1e9)%10 == 0 {
			ev := d.incidentEvent("attack_update", ns)
			d.emit(ev)
		}
	}
	d.reasons = reasons
	d.learning.Store(d.state == Normal && d.run == 0 && !hurt)
	// What an address earns (see earned) it earns in the seconds the baseline is learnt in: all but an attack's. The
	// second that has ended counts if it was one. From the first second on, a second weighs what it weighs in the
	// warmed-up baseline and counts for at most twice the average: while the detector warms up, its baseline weighs a
	// second far more, and an address's limit, four times its own average, would feed back into that average and reach
	// the ceiling within a minute of every start.
	if d.earnOpen {
		d.earnSec++
	}
	d.earnOpen = d.state != Attack
	d.earn.Store(&earning{sec: d.earnSec + 1, open: d.earnOpen, alpha: 1 / float64(d.cfg.Tau/time.Second)})
}

// The IDS signals, by the code an Event names them with (idsCodeNames).
const (
	idsConnPressure = iota
	idsEarlyClose
	idsRejections
	idsWouldReject
	idsHeld
	idsCodes
)

var idsCodeNames = [idsCodes]string{"conn_pressure", "early_close", "rejections", "would_reject", "held"}

// idsPace is the least time between two reports of one IDS signal, and how long the signals must have been gone before
// they are reported clear.
const idsPace = 30 * time.Second

// detectIDS reports strong admission and rejection signals without changing mitigation.
// A response error alone cannot classify an attack; these bounded alerts let operators
// investigate rejected probes, connection churn or capacity/configuration problems.
//
// An ids_signal event carries every current reason. It is sent when one of them was not reported in the last idsPace,
// so that a new signal is told at once whatever else is going on, and one that goes on is told again every idsPace. An
// ids_clear event says that the signals reported have been gone for idsPace: one that comes and goes at its threshold
// is not reported as many times as it crosses it.
func (d *detector) detectIDS(ns int64, a aggregate) {
	var reasons []string
	var present uint8
	add := func(code int, reason string) {
		reasons = append(reasons, reason)
		present |= 1 << code
	}
	floor := d.cfg.MinAttackRate
	if a.connRefused >= floor && a.connRefused >= 0.5*a.connRate {
		add(idsConnPressure, "IP/network connection admission pressure: "+itoa(a.connRefused)+" refusals a second")
	}
	if a.earlyCloses >= floor && a.earlyCloses >= 0.75*a.closed {
		add(idsEarlyClose, "connections close before HTTP activity: "+itoa(a.earlyCloses)+" a second")
	}
	// Later checks see only the requests the shield admitted: a scanner whose own limit refuses most of what it sends
	// must not hide the share of the rest that the checks reject.
	admitted := math.Max(a.rate-a.refused-a.challenged, 0)
	if a.securityRejects >= floor && a.securityRejects >= 0.5*admitted {
		add(idsRejections, "requests rejected before the origin: "+itoa(a.securityRejects)+" a second")
	}
	// What a check in detect or monitor mode lets through is held to the same share as what it would have refused in
	// block mode, so that one campaign is reported in either mode.
	if a.wouldRejects >= floor && a.wouldRejects >= 0.5*admitted {
		add(idsWouldReject, "requests that would have been rejected in detect/monitor mode: "+itoa(a.wouldRejects)+" a second")
	}
	if a.held >= floor {
		add(idsHeld, "addresses held over their own limit: "+itoa(a.held)+" refusals a second")
	}
	d.idsReasons = reasons
	if present == 0 {
		switch {
		case d.idsOpen == 0:
		case !d.idsCalm:
			d.idsQuiet, d.idsCalm = ns, true
		case ns-d.idsQuiet >= int64(idsPace):
			d.emit(Event{Kind: "ids_clear", At: d.wallTime(ns), State: d.state, Rate: a.rate, BaselineRate: d.base.rate, Codes: idsNames(d.idsOpen)})
			d.idsOpen, d.idsCalm = 0, false
		}
		return
	}
	d.idsCalm = false
	due := false
	for c := range idsCodes {
		if present&(1<<c) != 0 && (!d.idsSent[c] || ns-d.idsLast[c] >= int64(idsPace)) {
			due = true
		}
	}
	if !due {
		return
	}
	for c := range idsCodes {
		if present&(1<<c) != 0 {
			d.idsLast[c], d.idsSent[c] = ns, true
		}
	}
	d.idsOpen |= present
	d.emit(Event{Kind: "ids_signal", At: d.wallTime(ns), State: d.state, Rate: a.rate, BaselineRate: d.base.rate, Reasons: append([]string(nil), reasons...),
		Codes: idsNames(present)})
}

// idsNames lists the codes of a set of IDS signals, in the order of their reasons.
func idsNames(set uint8) []string {
	var out []string
	for c := range idsCodes {
		if set&(1<<c) != 0 {
			out = append(out, idsCodeNames[c])
		}
	}
	return out
}

// hurt says whether the application is failing in the last ten seconds compared with its errors over a far longer time
// (slowTau times Tau): seconds in which the baseline learns little it could raise (see learn). The longer average still learns them,
// so an application that stays worse for hours (a broken endpoint) is in time taken as it is. Latency is left out: it is
// measured until the response has been sent, so a few clients that read slowly could hold it up, and with it keep the
// baseline from following the site's own growth until that growth is taken for an attack.
func (d *detector) hurt(a aggregate) bool {
	return d.shapeAge > 0 && a.errRatio >= 0.2 && a.errRatio >= d.base.errSlow+0.1
}

// learn moves the baseline towards the last ten seconds. The rate may at most double per step's worth of weight, so a
// sudden rise is not learnt at once. gate says the rate is over the threshold, and hurt that the application is failing
// (see hurt): then the application's errors and latency may only fall, what the traffic is made of is not learnt at
// all, and the rate may rise only as far as the requests the application answers well rise from when it began to fail.
// A flood that grows slowly enough never to cross the threshold, once it is more than the application can answer, is
// then not taken as the usual, while the site's own visitors, whom an application that fails whatever the load (a
// broken dependency) still answers in proportion, are followed as they grow.
func (d *detector) learn(a aggregate, gate, hurt bool) {
	warm := int(d.cfg.Warmup / time.Second)
	weight := func(age int) float64 { // while warming up the baseline is the plain average of what was seen, whatever it is
		if age > warm {
			return 1 / float64(d.cfg.Tau/time.Second)
		}
		return 1 / float64(age)
	}
	d.age++
	alpha := weight(d.age)
	b := &d.base
	ew := func(x *float64, v float64) { *x += alpha * (v - *x) }
	rate := a.rate
	if d.age > warm {
		rate = math.Min(rate, math.Max(2*b.rate, d.cfg.MinAttackRate/2))
	}
	if hurt {
		if !b.hurting {
			b.hurting, b.hurtRate, b.hurtServed = true, b.rate, a.served
		}
		most := b.rate
		if b.hurtServed > 0 {
			most = math.Max(most, b.hurtRate*a.served/b.hurtServed)
		}
		rate = math.Min(rate, most)
	} else {
		b.hurting = false
	}
	// The spread of the site's rate is measured between ten-second rates that do not overlap, so that a steady rise or
	// fall (a day's ramp, or the baseline still catching up) is not mistaken for noise.
	if d.age%10 == 0 {
		if b.sampled {
			diff := rate - b.lastSample
			b.rateVar += math.Min(1, 10*alpha) * (diff*diff/2 - b.rateVar)
		}
		b.lastSample, b.sampled = rate, true
	}
	ew(&b.rate, rate)
	// The rest has a warm-up of its own, which InitialRate does not skip: it starts from nothing, and a second weighing a
	// six-hundredth from the start would leave the site's own fingerprints and targets "usually 0%" for many minutes. While
	// it warms up it learns only from seconds whose rate is ordinary, so that a restart into a flood, which the rate given
	// shows for what it is, does not teach it the flood's look.
	if d.shapeAge < warm && gate {
		return
	}
	d.shapeAge++
	alpha = weight(d.shapeAge) / slowTau
	if d.shapeAge <= warm {
		alpha = weight(d.shapeAge)
	}
	if a.errRatio >= 0 {
		ew(&b.errSlow, a.errRatio)
	}
	alpha = weight(d.shapeAge)
	if a.errRatio >= 0 && (!hurt || a.errRatio < b.errRatio) {
		ew(&b.errRatio, a.errRatio)
	}
	if a.lat >= 0 {
		if b.lat == 0 {
			b.lat = a.lat
		}
		if !hurt || a.lat < b.lat {
			ew(&b.lat, a.lat)
		}
	}
	if hurt {
		return
	}
	ew(&b.srcs, a.srcs)
	ew(&b.newShare, a.newShare)
	ew(&b.connRate, a.connRate)
	ew(&b.connSrcs, a.connSrcs)
	// Nor are the fingerprints and targets learnt from a second over the threshold: a flood that runs there for a while
	// before it hurts would otherwise teach the baseline its fingerprints, which would then pass for the site's own, and
	// the site's own clients do not hold an attack (see evaluate).
	if gate {
		return
	}
	if a.rate > 0 {
		ew(&b.familiar, a.familiar)
	}
	learnShares(b.fps, a.fps, alpha)
	learnShares(b.paths, a.paths, alpha)
}

// learnShares moves the usual shares of fingerprints or targets towards the last ten seconds. A key that has faded below
// a fifth of a percent is forgotten, but never in a second it was seen in: once warmed up a second weighs a six-hundredth,
// so a key that is new enters below that and would otherwise be forgotten at once, and a browser or app released after
// the start would stay "usually 0%" for ever.
func learnShares(m map[uint64]float64, now []share, alpha float64) {
	for k := range m {
		m[k] *= 1 - alpha
	}
	for _, s := range now {
		m[s.key] += alpha * s.share
	}
	for k, v := range m {
		if v < minShare && !slices.ContainsFunc(now, func(s share) bool { return s.key == k }) {
			delete(m, k)
		}
	}
	for len(m) > baseKeys {
		var lk uint64
		lv := math.Inf(1)
		for k, v := range m {
			if v < lv {
				lk, lv = k, v
			}
		}
		delete(m, lk)
	}
}

func (d *detector) startAttack(ns int64, a aggregate, reasons []string, fpAttack, pathAttack bool) {
	d.state, d.since, d.quiet, d.noEvidence, d.run = Attack, ns, 0, 0, 0
	d.epoch++
	d.frozen = baseline{rate: d.base.rate, rateVar: d.base.rateVar, srcs: d.base.srcs, newShare: d.base.newShare, familiar: d.base.familiar, errRatio: d.base.errRatio, lat: d.base.lat,
		connRate: d.base.connRate, connSrcs: d.base.connSrcs, fps: cloneMap(d.base.fps), paths: cloneMap(d.base.paths)}
	d.incident = &incidentAcc{start: ns, peak: a.rate, baseRate: d.base.rate, srcs: newHLL(14), nets: newHLL(12),
		labels: newTopK(32), labelSet: newHLL(10)}
	d.incident.addReasons(reasons)
	unknown, known := d.cfg.MinAttackRate, d.cfg.MinAttackRate
	if d.unknownRate != nil {
		unknown = d.unknownRate(d.base.rate)
	}
	if d.knownRate != nil {
		known = d.knownRate(d.base.rate)
	}
	cluster := math.Max(d.clusterRate, d.clusterShare*d.base.rate) // look-alike requests may be a small share of a big site
	d.info.Store(&attackInfo{epoch: d.epoch, since: ns, fps: map[uint64]bool{}, paths: map[uint64]bool{}, unknownRate: unknown,
		clusterRate: cluster, knownRate: known})
	d.widen(a, fpAttack, pathAttack)
	d.announced = Attack
	d.emit(d.incidentEvent("attack_start", ns))
}

// widen adds the fingerprints and targets that stand out to the attack's clusters. A cluster stays for the whole attack:
// once the mitigation works, the attack is still in the counts (requests are counted before they are refused), so it
// keeps standing out, but an attacker who rotates fingerprints must not be able to free an old one.
func (d *detector) widen(a aggregate, fpAttack, pathAttack bool) {
	old := d.info.Load()
	if old == nil {
		return
	}
	fps, paths := cloneSet(old.fps), cloneSet(old.paths)
	changed := false
	for _, s := range a.fps {
		if len(fps) >= topKeys {
			break
		}
		if s.share >= 0.1 && s.share-d.frozen.fps[s.key] >= 0.1 && s.sources >= 3 && !fps[s.key] {
			fps[s.key], changed = true, true
			d.incident.addCluster("fingerprint", s)
		}
	}
	if pathAttack || old.pathAttack {
		for _, s := range a.paths {
			if len(paths) >= topKeys {
				break
			}
			if s.share >= 0.1 && s.share-d.frozen.paths[s.key] >= 0.1 && !paths[s.key] {
				paths[s.key], changed = true, true
				d.incident.addCluster("target", s)
			}
		}
	}
	_ = fpAttack
	if changed || pathAttack != old.pathAttack {
		n := *old
		n.fps, n.paths, n.pathAttack, n.fingerprints = fps, paths, old.pathAttack || pathAttack, len(fps)
		d.info.Store(&n)
	}
}

func (d *detector) endAttack(ns int64) {
	ev := d.incidentEvent("attack_end", ns)
	d.history = append(d.history, ev.Incident)
	if len(d.history) > 20 {
		d.history = d.history[len(d.history)-20:]
	}
	d.state, d.incident, d.quiet = Normal, nil, 0
	d.info.Store(nil)
	d.emit(ev)
}

// wallTime is the time an instant on the shield's clock is reported as.
func (d *detector) wallTime(ns int64) time.Time {
	if d.wall != nil {
		return d.wall(ns)
	}
	return time.Unix(0, ns)
}

// emit queues an event for tick to deliver once mu is released (see deliver), and reports whether it was dropped for
// lack of room or after Close (and counted in droppedEvents).
func (d *detector) emit(ev Event) (dropped bool) {
	if d.onEvent == nil {
		return false
	}
	if ev.Mode == "" {
		ev.Mode = "on"
		if d.monitor {
			ev.Mode = "monitor"
		}
	}
	if d.closed || len(d.pending) >= maxPendingEvents {
		d.droppedEvents.Add(1)
		return true
	}
	d.pending = append(d.pending, ev)
	return false
}

// bulkEventRoom is the share of the event queue left to the events of repeat offenders, of which a spray of addresses
// can make many: the rest is kept for an attack's.
const bulkEventRoom = maxPendingEvents * 3 / 4

// emitBulk queues an event of a repeat offender, as emit does, while the queue holds fewer than bulkEventRoom.
func (d *detector) emitBulk(ev Event) (dropped bool) {
	if d.onEvent != nil && len(d.pending) >= bulkEventRoom {
		d.droppedEvents.Add(1)
		return true
	}
	return d.emit(ev)
}

func cloneMap(m map[uint64]float64) map[uint64]float64 {
	out := make(map[uint64]float64, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

func cloneSet(m map[uint64]bool) map[uint64]bool {
	out := make(map[uint64]bool, len(m)+2)
	for k, v := range m {
		out[k] = v
	}
	return out
}

// threshold is the request rate, in a second of ten, above which traffic is more than the site's own normal: the largest
// of RateFactor times the moving average, the average plus Sigmas standard deviations of the site's own rates, and the
// absolute floor. A steady site is held to the first; a bursty one, whose ordinary rate swings widely, to the second.
func (d *detector) threshold(mean, variance float64) float64 {
	return math.Max(math.Max(d.cfg.RateFactor*mean, mean+d.cfg.Sigmas*math.Sqrt(math.Max(variance, 0))), d.cfg.MinAttackRate)
}

// rateThreshold is threshold for the detector's own baseline.
func (d *detector) rateThreshold() float64 {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.threshold(d.base.rate, d.base.rateVar)
}

// scales returns the largest factors by which an address's, and a network's, limit was raised in the last ten seconds.
func (d *detector) scales() (src, net float64) {
	src, net = math.Float64frombits(d.scaleSrc.Load()), math.Float64frombits(d.scaleNet.Load())
	if src < 1 {
		src = 1
	}
	if net < 1 {
		net = 1
	}
	return src, net
}

// noteScales raises the second's record of how far an address's, and a network's, limit was raised. Most requests come
// under the configured limits and touch nothing here.
func (d *detector) noteScales(src, net float64) {
	raise := func(most *atomic.Uint32, scale float64) {
		if scale <= 1 {
			return
		}
		for v := uint32(scale * 1000); ; {
			cur := most.Load()
			if v <= cur || most.CompareAndSwap(cur, v) {
				return
			}
		}
	}
	raise(&d.winMaxSrc, src)
	raise(&d.winMaxNet, net)
}
