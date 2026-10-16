// SPDX-License-Identifier: Apache-2.0

// Package shield protects a site against denial of service: floods of requests and connections, from one address or
// from a botnet of many thousands spread over many countries. Coraza and the Core Rule Set judge each request on its own
// and cannot see a flood; the shield sees the traffic as a whole.
//
// It works at three points:
//
//   - Connections (Listener, ConnState): before a connection costs the proxy anything. A connection rate per address,
//     a cap per /24 (IPv4) or /48 (IPv6) network, a cap on all connections with a share kept back for clients the shield
//     knows, idle keep-alive connections of unknown clients closed first when connections run short, banned addresses
//     closed at once, and on Linux the kernel told not to hand over a connection until the client has sent something
//     (TCP_DEFER_ACCEPT) and to drop one whose data goes unacknowledged (TCP_USER_TIMEOUT).
//   - Requests (Admit): a token bucket per address and per network, always; and during an attack (see detect.go) a
//     small shared budget for requests that look like the attack (its fingerprints and targets) and a budget for clients
//     the shield does not know, while clients it knows (that used the site normally before the attack) and browsers
//     that answered a challenge go on as usual. Addresses that keep being refused during an attack are banned for a
//     while: their connections are reset at accept and their requests refused. A Banner, if set, is told of each ban.
//   - Answers (Done): what the application answered and how quickly, which is how clients become known, and how the
//     detector sees that the application is in trouble.
//
// The shield never logs a line per refused request: during a flood that would be a second flood. It reports attacks as
// a few Events, and its state with Snapshot.
package shield

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"math"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

// Rule identifiers, in the range Carnical keeps for the shield.
const (
	idRate            = 5004001 // one address sent too many requests
	idSubnetRate      = 5004002 // one network sent too many requests
	idCluster         = 5004003 // during an attack: a request that looks like the attack, over the attack's budget
	idUnknown         = 5004004 // during an attack: a client the shield does not know, over the budget for them
	idChallenge       = 5004005 // a browser was asked to answer a challenge
	idChallengeFailed = 5004006
	idChallengeSolved = 5004007
	idBanned          = 5004008 // an address banned during an attack
)

// Action is what to do with a request.
type Action uint8

const (
	// Allow: let it through to the rest of the checks.
	Allow Action = iota
	// Refuse: answer with Status and close the connection.
	Refuse
	// Challenge: answer with the challenge page.
	Challenge
	// Respond: the shield answers the request itself (the challenge's answer).
	Respond
)

// Decision is the shield's verdict on one request. Pass it to Write if it is not Allow, and to Done when the request is
// finished.
type Decision struct {
	Action     Action
	ID         int
	Status     int
	RetryAfter int
	resp       *response
	key        netip.Addr
	start      int64
	counted    bool
	trusted    bool
}

type response struct {
	body, contentType, location string
	cookie                      *http.Cookie
}

// Banner is told of each address range the shield bans, so that something outside the process that the integrator runs
// (a firewall) can drop the range's packets for a while too, before they cost the proxy a connection. Nothing in this
// repository implements it: without one, a ban holds in this process only, which resets the range's connections at
// accept and refuses its requests. It must return quickly; the shield calls it from a background goroutine with a
// deadline.
type Banner interface {
	Ban(ctx context.Context, p netip.Prefix, ttl time.Duration, reason string) error
}

// Config is the shield's settings. The zero value of a field means its default (see DefaultConfig).
type Config struct {
	// RequestRate and RequestBurst limit each address (default 50 a second, bursts of 200). They apply at all times and to
	// every client, known or not: a page with many assets is a burst, a script is a rate.
	RequestRate, RequestBurst float64
	// SubnetRate and SubnetBurst limit each /24 or /48 network (default 500 a second, bursts of 2,000).
	SubnetRate, SubnetBurst float64
	// MaxConns is the most connections held open at once (default 20,000). ReservedShare of them (default 0.2) are only
	// for clients the shield knows, so that a connection flood cannot lock out the site's regular visitors. Both the
	// starting floor and any later growth are capped at 80% of the process's soft file-descriptor limit where known.
	MaxConns      int
	ReservedShare float64
	// MaxConnsCeiling is the most MaxConns can be raised to as the site's average number of connections grows (default
	// 250,000, and in any case 80% of the process's file-descriptor limit where that is known).
	MaxConnsCeiling int
	// ClusterShare makes the budget for look-alike requests during an attack at least this share of the site's usual
	ClusterShare float64
	// The limits above and below are floors. An address's and a network's are raised to follow what that address or
	// network has itself had answered well (see DetectorConfig.LimitMargin and MaxScale), so many visitors behind one
	// company or carrier address are not limited as if they were one person; the number of connections follows the
	// site's own (MaxConnsCeiling).
	// SubnetConns is the most connections one /24 or /48 may hold (default 1,024).
	SubnetConns int
	// ConnRate and ConnBurst limit new connections from each address (default 20 a second, bursts of 60).
	ConnRate, ConnBurst float64
	// DeferAccept (Linux) is how long the kernel holds a connection that has sent nothing before the proxy sees it
	// (default 10 seconds; negative leaves the socket alone). UserTimeout (Linux) is how long data the proxy sent may
	// go unacknowledged before the kernel drops the connection (default 30 seconds; negative leaves it alone).
	DeferAccept, UserTimeout time.Duration

	// MonitorOnly detects and reports attacks without acting on them (the per-address and per-network limits still apply,
	// and an address they refuse during an attack is never banned for it).
	MonitorOnly bool
	// ClusterRate is the requests a second, in total, let through during an attack for requests that look like the
	// attack (default 5). The rest are challenged or refused.
	ClusterRate float64
	// UnknownFactor and MinUnknownRate set the budget during an attack for clients the shield does not know:
	// UnknownFactor times the usual request rate, and at least MinUnknownRate a second (defaults 1 and 10).
	UnknownFactor, MinUnknownRate float64
	// KnownFactor and MinKnownRate set the budget during an attack for known clients: KnownFactor times the usual request
	// rate, and at least MinKnownRate a second (defaults 2 and 50). Beyond it a known client is treated like any other, so
	// standing that a botnet earned before it attacks cannot carry the flood past the other budgets. A browser that
	// answered the challenge is not held to it: the challenge is how people get in when a crowd is taken for an attack.
	KnownFactor, MinKnownRate float64
	// BanAfter is how many requests refused during an attack get an address banned (default 30, at most 65535), for
	// BanFor (default 10 minutes). Each challenge shown counts as a tenth of a refusal, and each right answer to it takes
	// back one shown. The count starts again after each ban.
	BanAfter int
	BanFor   time.Duration
	// NoChallenge refuses unknown browsers during an attack instead of asking them to answer a challenge.
	NoChallenge bool
	// ChallengeBits is the challenge's difficulty: the number of leading zero bits (default 17, about 131,000 hashes,
	// a second or so on a phone; at most 24). ClearanceFor is how long an answer admits the browser (default 30 minutes).
	ChallengeBits int
	ClearanceFor  time.Duration

	// KnownAfter answered requests (status below 400), the first at least KnownMinAge before the last, make a client
	// known for KnownFor (defaults 5, one minute and seven days). Nothing is learnt during an attack.
	KnownAfter  int
	KnownMinAge time.Duration
	KnownFor    time.Duration
	// MaxSources bounds how many addresses are remembered (default 262,144), and a quarter as many networks. At the
	// default, the two tables hold about 55 MB of live heap with the address table full, about 70 MB with both full; with
	// the default GOGC the heap in use grows to about twice that.
	MaxSources int

	// Trusted are the load balancers or CDN in front of the proxy: their connections bypass per-source and per-network
	// limits, but share the global connection cap (visitors are limited by the verified address of each request).
	Trusted []netip.Prefix
	// Detector tunes attack detection.
	Detector DetectorConfig
	// Banner, if set, is told of the ranges the shield bans (an IPv4 address, an IPv6 /64), except a range that holds a
	// Trusted one, to drop them outside the process too (see Banner).
	Banner Banner
	// Labeler, if set, names the country or network of the addresses in an attack, for the attack's record.
	Labeler Labeler
	// OnEvent is told when an attack starts, every ten seconds while it goes on, and when it ends, and of the other
	// Events. It is called on the shield's own goroutine once a second (with Now set, by Tick), and by Close for the events
	// still queued, one event at a time and in order, never while a request or a connection waits on it. It should return
	// quickly: while it blocks, at most 256 later events wait, and those past them are dropped and counted in
	// Snapshot.DroppedEvents.
	OnEvent func(Event)
	// Now is the clock (tests). With it set the shield starts no goroutine: the caller advances the detector with Tick.
	Now func() time.Time
}

// DefaultConfig is the configuration the zero Config stands for.
func DefaultConfig() Config {
	c := Config{}
	c.defaults()
	return c
}

// Preset is the configuration of a protection strength: "normal" is the zero Config, which stands for DefaultConfig;
// "strict" limits each address and strangers during an attack more tightly, bans sooner and for longer, and declares an
// attack on a smaller rise, for a small site or one that is often attacked (in a crowd it takes for an attack, an
// address many people share, such as a carrier's, can be banned for 30 minutes); "relaxed" does the opposite, for an API
// or a site with many visitors behind one carrier's addresses. Only the fields that make the protection stronger or
// weaker are set; the zero fields mean their defaults, and the capacity of the connection limits and the challenge's
// difficulty are the same at every strength. A name it does not know is an error, which suggests the one meant.
func Preset(name string) (Config, error) {
	switch name {
	case "normal":
		return Config{}, nil
	case "strict":
		return Config{
			RequestRate: 20, RequestBurst: 80, // the default burst of four seconds' rate; the network's 500 is unchanged
			UnknownFactor: 0.5, MinUnknownRate: 5,
			ConnRate: 10, ConnBurst: 30,
			BanAfter: 15, BanFor: 30 * time.Minute,
			// MaxScale 10 still covers the 5.7x a busy site's shared addresses were measured to need (flood-validation.md).
			Detector: DetectorConfig{MaxScale: 10, RateFactor: 3, Sigmas: 6, Confirm: 2, MinAttackRate: 10},
		}, nil
	case "relaxed":
		return Config{
			RequestRate: 100, RequestBurst: 400, SubnetRate: 1000,
			// KnownFactor and MinKnownRate keep their defaults: doubled, they let a botnet that first earned standing
			// through (flood-validation.md).
			UnknownFactor: 2, MinUnknownRate: 20,
			ConnRate: 40, ConnBurst: 120,
			BanAfter: 60, BanFor: 5 * time.Minute,
			Detector: DetectorConfig{MaxScale: 50, RateFactor: 6, Sigmas: 10, Confirm: 5, MinAttackRate: 50},
		}, nil
	}
	err := fmt.Sprintf("shield: unknown strength %q: want relaxed, normal or strict", name)
	if s := closest(name, "relaxed", "normal", "strict"); s != "" {
		err += " (did you mean " + s + "?)"
	}
	return Config{}, errors.New(err)
}

// closest is the word of words within two edits of s, or "" if there is none. Longer input is not compared: it is no typo
// of a short word, and comparing it would cost its length squared.
func closest(s string, words ...string) string {
	if len(s) > 16 {
		return ""
	}
	best, bestD := "", 3
	for _, w := range words {
		if len(w) > 16 {
			continue
		}
		if d := editDistance(s, w); d < bestD {
			best, bestD = w, d
		}
	}
	return best
}

// editDistance is the Levenshtein distance between two short strings, in bytes.
func editDistance(a, b string) int {
	var prev, cur [17]int
	for j := 0; j <= len(b); j++ {
		prev[j] = j
	}
	for i := 1; i <= len(a); i++ {
		cur[0] = i
		for j := 1; j <= len(b); j++ {
			cost := 1
			if a[i-1] == b[j-1] {
				cost = 0
			}
			cur[j] = min(prev[j]+1, cur[j-1]+1, prev[j-1]+cost)
		}
		prev = cur
	}
	return prev[len(b)]
}

func (c *Config) defaults() {
	f := func(p *float64, v float64) {
		if *p == 0 {
			*p = v
		}
	}
	d := func(p *time.Duration, v time.Duration) {
		if *p == 0 {
			*p = v
		}
	}
	i := func(p *int, v int) {
		if *p == 0 {
			*p = v
		}
	}
	f(&c.RequestRate, 50)
	f(&c.RequestBurst, 200)
	f(&c.SubnetRate, 500)
	f(&c.SubnetBurst, 2000)
	i(&c.MaxConns, 20000)
	f(&c.ReservedShare, 0.2)
	i(&c.SubnetConns, 1024)
	f(&c.ConnRate, 20)
	f(&c.ConnBurst, 60)
	d(&c.DeferAccept, 10*time.Second)
	d(&c.UserTimeout, 30*time.Second)
	f(&c.ClusterRate, 5)
	f(&c.ClusterShare, 0.02)
	i(&c.MaxConnsCeiling, 250000)
	f(&c.UnknownFactor, 1)
	f(&c.MinUnknownRate, 10)
	f(&c.KnownFactor, 2)
	f(&c.MinKnownRate, 50)
	i(&c.BanAfter, 30)
	d(&c.BanFor, 10*time.Minute)
	i(&c.ChallengeBits, 17)
	d(&c.ClearanceFor, 30*time.Minute)
	i(&c.KnownAfter, 5)
	d(&c.KnownMinAge, time.Minute)
	d(&c.KnownFor, 7*24*time.Hour)
	i(&c.MaxSources, 1<<18)
	c.Detector.defaults()
}

// Validate reports a setting that cannot work.
func (c Config) Validate() error {
	c.defaults()
	for _, field := range []struct {
		name  string
		value float64
	}{
		{"RequestRate", c.RequestRate}, {"RequestBurst", c.RequestBurst},
		{"SubnetRate", c.SubnetRate}, {"SubnetBurst", c.SubnetBurst},
		{"ReservedShare", c.ReservedShare}, {"ClusterShare", c.ClusterShare},
		{"ConnRate", c.ConnRate}, {"ConnBurst", c.ConnBurst},
		{"ClusterRate", c.ClusterRate}, {"UnknownFactor", c.UnknownFactor}, {"MinUnknownRate", c.MinUnknownRate},
		{"KnownFactor", c.KnownFactor}, {"MinKnownRate", c.MinKnownRate},
		{"Detector.MinAttackRate", c.Detector.MinAttackRate}, {"Detector.Sigmas", c.Detector.Sigmas},
		{"Detector.LimitMargin", c.Detector.LimitMargin}, {"Detector.MaxScale", c.Detector.MaxScale},
		{"Detector.RateFactor", c.Detector.RateFactor}, {"Detector.ExitFactor", c.Detector.ExitFactor},
		{"Detector.InitialRate", c.Detector.InitialRate},
		{"scaled connection rate", c.ConnRate * c.Detector.MaxScale},
		{"scaled connection burst", c.ConnBurst * c.Detector.MaxScale},
		{"scaled network connections", float64(c.SubnetConns) * c.Detector.MaxScale},
		{"scaled request rate", c.RequestRate * c.Detector.MaxScale},
		{"scaled request burst", c.RequestBurst * c.Detector.MaxScale},
		{"scaled network rate", c.SubnetRate * c.Detector.MaxScale},
		{"scaled network burst", c.SubnetBurst * c.Detector.MaxScale},
	} {
		if math.IsNaN(field.value) || math.IsInf(field.value, 0) {
			return fmt.Errorf("shield: %s must be finite", field.name)
		}
	}
	switch {
	case c.RequestRate < 0 || c.RequestBurst < 1 || c.SubnetRate < 0 || c.SubnetBurst < 1:
		return errors.New("shield: request rates must be positive and bursts at least 1")
	case c.RequestBurst < c.RequestRate/10 || c.SubnetRate < c.RequestRate:
		return errors.New("shield: a network's rate must be at least an address's, and a burst at least a tenth of the rate")
	case c.MaxConns < 16 || c.SubnetConns < 1 || c.ReservedShare < 0 || c.ReservedShare > 0.9:
		return errors.New("shield: MaxConns must be at least 16, SubnetConns at least 1 and ReservedShare between 0 and 0.9")
	case c.ConnRate < 0 || c.ConnBurst < 1:
		return errors.New("shield: the connection rate must be positive and its burst at least 1")
	case c.ClusterRate < 0 || c.UnknownFactor < 0 || c.MinUnknownRate < 0 || c.KnownFactor < 0 || c.MinKnownRate < 0 ||
		c.BanAfter < 1 || c.BanAfter > 65535 || c.BanFor < time.Second:
		return errors.New("shield: attack budgets must not be negative, BanAfter 1 to 65535 and BanFor at least a second")
	case c.ChallengeBits < 8 || c.ChallengeBits > 24:
		return errors.New("shield: ChallengeBits must be between 8 and 24")
	case c.ClearanceFor < time.Minute || c.KnownAfter < 1 || c.KnownFor < time.Minute || c.MaxSources < 1024:
		return errors.New("shield: ClearanceFor and KnownFor must be at least a minute, KnownAfter at least 1, MaxSources at least 1024")
	case c.Detector.RateFactor < 1.5 || c.Detector.ExitFactor < 1 || c.Detector.ExitFactor > c.Detector.RateFactor:
		return errors.New("shield: the detector's RateFactor must be at least 1.5 and ExitFactor between 1 and RateFactor")
	case c.Detector.Sigmas < 3 || c.Detector.LimitMargin < 1 || c.Detector.MaxScale < 1 || c.ClusterShare < 0 || c.ClusterShare > 0.5 || c.MaxConnsCeiling < c.MaxConns:
		return errors.New("shield: Sigmas must be at least 3, LimitMargin and MaxScale at least 1, ClusterShare at most 0.5 and MaxConnsCeiling at least MaxConns")
	case c.Detector.EvidenceTimeout < time.Minute || c.Detector.MinHistory < time.Second:
		return errors.New("shield: the detector's EvidenceTimeout must be at least a minute and MinHistory at least a second")
	case c.Detector.MinAttackRate < 1 || c.Detector.Confirm < 1 || c.Detector.Tau < time.Minute:
		return errors.New("shield: the detector's MinAttackRate and Confirm must be at least 1 and Tau at least a minute")
	}
	for _, p := range c.Trusted {
		if !p.IsValid() || p.Bits() == 0 {
			return fmt.Errorf("shield: trusted range %s: a range of /0 would switch the shield off", p)
		}
	}
	return nil
}

// Shield is one site's protection. It is safe for concurrent use.
type Shield struct {
	cfg     Config
	key     []byte
	det     *detector
	sources *table[netip.Addr, source]
	subnets *table[netip.Prefix, subnet]
	conns   atomic.Int64
	connAvg atomic.Uint64 // float64 bits: the moving average of the number of open connections
	connN   atomic.Int64
	fdLimit int64
	// start is when the shield was made, and wall reads the wall clock (time.Now): see now.
	start time.Time
	wall  func() time.Time
	// connMu makes capacity reservation atomic across listeners. Live network counts are separate from the evictable
	// request history: address churn must not reset a network's open-connection count. Zero counts are removed.
	connMu   sync.Mutex
	connNets map[netip.Prefix]int64

	budgetMu    sync.Mutex
	epoch       uint32
	cluster     bucket
	unknown     bucket
	knownBudget bucket

	idleMu sync.Mutex
	idle   idleList

	bans     chan banReq
	stop     chan struct{}
	stopOnce sync.Once
	wg       sync.WaitGroup
	counters counters
}

type counters struct {
	allowed, refused, challenged, solved, banned, connsRefused, evicted, banErrors atomic.Uint64
	writeErrors, socketOptionErrors                                                atomic.Uint64
	earlyCloses, securityRejections                                                atomic.Uint64
}

type banReq struct {
	p      netip.Prefix
	ttl    time.Duration
	reason string
}

// New makes a shield.
func New(cfg Config) (*Shield, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	cfg.defaults()
	cfg.Trusted = append([]netip.Prefix(nil), cfg.Trusted...)
	s := &Shield{cfg: cfg, wall: time.Now, key: newKey(), det: newDetector(cfg.Detector), stop: make(chan struct{}), bans: make(chan banReq, 256),
		connNets: make(map[netip.Prefix]int64)}
	s.start = s.wall()
	// A limit that an address or a network has earned is standing too: a flood of new addresses must not push it out.
	raisedSrc := func(v *source) bool {
		return s.raise(v.earned.at(s.det.earn.Load(), cfg.RequestRate), cfg.RequestRate) > 1
	}
	raisedNet := func(v *subnet) bool {
		return s.raise(v.earned.at(s.det.earn.Load(), cfg.SubnetRate), cfg.SubnetRate) > 1
	}
	s.sources = newTable[netip.Addr, source](cfg.MaxSources,
		func(v *source, now int64) bool { return sourceIdle(v, now) && !raisedSrc(v) }, sourceLast,
		func(v *source, now int64) bool { return sourceKeep(v, now) || raisedSrc(v) })
	s.subnets = newTable[netip.Prefix, subnet](cfg.MaxSources/4,
		func(v *subnet, now int64) bool { return subnetIdle(v, now) && !raisedNet(v) }, subnetLast,
		func(v *subnet, _ int64) bool { return raisedNet(v) })
	s.det.labeler, s.det.onEvent = cfg.Labeler, cfg.OnEvent
	s.det.clusterRate, s.det.clusterShare = cfg.ClusterRate, cfg.ClusterShare
	s.fdLimit = fdLimit()
	s.det.unknownRate = func(base float64) float64 { return max(base*cfg.UnknownFactor, cfg.MinUnknownRate) }
	s.det.knownRate = func(base float64) float64 { return max(base*cfg.KnownFactor, cfg.MinKnownRate) }
	if cfg.Now == nil {
		// What the shield reports (events and attack records) is in wall-clock time: an instant on its own clock is as
		// far before the wall clock's now as it is before its own.
		s.det.wall = func(ns int64) time.Time { return s.wall().Add(time.Duration(ns - s.now().UnixNano())).Round(0) }
		s.wg.Add(1)
		go s.ticker()
	}
	if cfg.Banner != nil {
		for range 4 {
			s.wg.Add(1)
			go s.banWorker()
		}
	}
	return s, nil
}

// Close stops the shield's goroutines and gives Config.OnEvent the events still queued for it. Events found after Close
// are counted in Snapshot.DroppedEvents.
func (s *Shield) Close() {
	s.stopOnce.Do(func() { close(s.stop) })
	s.wg.Wait()
	s.det.mu.Lock()
	s.det.closed = true
	s.det.deliver()
}

// now is the shield's clock: Config.Now if set, and otherwise the wall clock as it read when the shield was made, moved
// on by the monotonic clock. Every limit and the detector run on it, and the wall clock can be stepped (an NTP correction,
// a virtual machine restored): a step back would stop every bucket refilling, and the detector, until the wall clock had
// caught up, and a step forward would refill every bucket and end every ban at once. Challenge tokens and clearance
// cookies are made and checked only by this process, with its own key, so they run on this clock too.
func (s *Shield) now() time.Time {
	if s.cfg.Now != nil {
		return s.cfg.Now()
	}
	return s.start.Add(time.Since(s.start))
}

func (s *Shield) ticker() {
	defer s.wg.Done()
	t := time.NewTicker(time.Second)
	defer t.Stop()
	for {
		select {
		case <-s.stop:
			return
		case <-t.C:
			s.tick(s.now().UnixNano())
		}
	}
}

// Tick moves the detector on to now. Only needed with Config.Now set.
func (s *Shield) Tick() { s.tick(s.now().UnixNano()) }

// tick advances the detector and samples the number of connections, which is learnt like the rest of the baseline: only
// while traffic is ordinary.
func (s *Shield) tick(ns int64) {
	s.det.tick(ns)
	if !s.det.learning.Load() {
		return
	}
	n := s.connN.Add(1)
	alpha := 1 / math.Min(float64(n), float64(s.cfg.Detector.Tau/time.Second))
	avg := math.Float64frombits(s.connAvg.Load())
	s.connAvg.Store(math.Float64bits(avg + alpha*(float64(s.conns.Load())-avg)))
}

// maxConns is the number of connections allowed at once: the configured number, or twice the moving average of the number
// open if the site normally holds more, up to the ceiling and the file-descriptor limit.
func (s *Shield) maxConns() int64 {
	limit := int64(s.cfg.MaxConns)
	if grown := int64(2 * math.Float64frombits(s.connAvg.Load())); grown > limit {
		ceiling := int64(s.cfg.MaxConnsCeiling)
		limit = max(limit, min(grown, ceiling))
	}
	// The starting floor must respect the process's capacity too, including on small hosts with a low soft limit.
	if s.fdLimit > 0 {
		limit = min(limit, s.fdLimit*8/10)
	}
	return limit
}

func (s *Shield) trusted(a netip.Addr) bool {
	for _, p := range s.cfg.Trusted {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// Admit decides about a request from client (the visitor's address, as the proxy worked it out). It is cheap: a few map
// lookups and hashes, no I/O.
func (s *Shield) Admit(r *http.Request, client netip.Addr) Decision {
	now := s.now()
	ns := now.UnixNano()
	client = client.Unmap()
	key := SourceKey(client)
	trusted := s.trusted(client)
	fp, fpLabel := fingerprint(r)
	pt, ptLabel := pathTemplate(r)
	isNew := s.det.observe(ns, key, fp, fpLabel, pt, ptLabel)
	info := s.det.info.Load()

	earn := s.det.earn.Load()
	scaleSrc, scaleNet := 1.0, 1.0
	var banned, known, rateOK, engaged bool
	retry := 0
	s.sources.do(key, ns, func(src *source) {
		src.last = ns
		switch {
		case isNew:
			src.newAt, src.lastTpl, src.distinct = ns, pt, 1
		case src.distinct == 1 && pt != src.lastTpl && ns-src.newAt <= 10e9:
			src.distinct, engaged = 2, true
		}
		banned = src.bannedUntil > ns
		known = s.isKnown(src, ns, info)
		scaleSrc = s.raise(src.earned.roll(earn, s.cfg.RequestRate), s.cfg.RequestRate)
		rateOK = trusted || src.req.take(ns, s.cfg.RequestRate*scaleSrc, s.cfg.RequestBurst*scaleSrc)
		switch {
		case banned && !trusted:
			retry = retryAfter(float64(src.bannedUntil-ns)/1e9, math.MaxInt32)
		case !rateOK:
			retry = retryAfter(src.req.wait(s.cfg.RequestRate*scaleSrc), 3600)
		}
	})
	if engaged {
		s.det.count(ns, func(w *window) { w.engaged++ })
	}
	d := Decision{key: key, start: ns, counted: true, trusted: trusted}
	switch {
	// An IPv6 ban covers the client's /64, which a trusted proxy may share with the address that earned it.
	case banned && !trusted:
		return s.refuse(ns, d, info, idBanned, http.StatusForbidden, retry)
	case !rateOK:
		return s.refuse(ns, d, info, idRate, http.StatusTooManyRequests, retry)
	}
	if !trusted {
		subOK := true
		s.subnets.do(netOf(client), ns, func(n *subnet) {
			n.last = ns
			scaleNet = s.raise(n.earned.roll(earn, s.cfg.SubnetRate), s.cfg.SubnetRate)
			subOK = n.req.take(ns, s.cfg.SubnetRate*scaleNet, s.cfg.SubnetBurst*scaleNet)
			if !subOK {
				retry = retryAfter(n.req.wait(s.cfg.SubnetRate*scaleNet), 3600)
			}
		})
		if !subOK {
			return s.refuse(ns, d, info, idSubnetRate, http.StatusTooManyRequests, retry)
		}
		s.det.noteScales(scaleSrc, scaleNet)
	}
	if r.URL.Path == VerifyPath {
		v := s.verify(r, key, now)
		if info != nil && !s.cfg.MonitorOnly && !trusted {
			if v.ID == idChallengeSolved {
				s.forgive(ns, key, info)
			} else {
				s.strike(ns, key, info) // a wrong answer is a refusal like any other
			}
		}
		return v
	}
	if info == nil || s.cfg.MonitorOnly || trusted {
		s.counters.allowed.Add(1)
		return d
	}
	cleared := s.cleared(r, key, now)
	inCluster := info.fps[fp] || info.paths[pt]
	s.budgetMu.Lock()
	if s.epoch != info.epoch { // a new attack: fresh budgets
		s.epoch, s.cluster, s.unknown, s.knownBudget = info.epoch, bucket{}, bucket{}, bucket{}
	}
	var ok bool
	switch {
	case cleared:
		ok = true
	// A known client passes the attack's budgets only within a budget of its own; beyond it, it is like any other client.
	case known && s.knownBudget.take(ns, info.knownRate, max(info.knownRate, s.cfg.RequestBurst)):
		ok = true
	case inCluster:
		ok = s.cluster.take(ns, info.clusterRate, max(info.clusterRate, 1))
	default:
		ok = s.unknown.take(ns, info.unknownRate, max(info.unknownRate, 1))
	}
	s.budgetMu.Unlock()
	if ok {
		s.counters.allowed.Add(1)
		return d
	}
	id := idUnknown
	if inCluster {
		id = idCluster
	}
	// Showing the challenge is not a refusal: a browser can answer it, and many people behind one address are each shown
	// it. It counts as a tenth of one, so that a flood of page loads is banned as a flood of other requests is.
	if !s.cfg.NoChallenge && isNavigation(r) {
		s.mark(ns, key, info, true)
		s.counters.challenged.Add(1)
		s.det.note(ns, func(w *window, inc *incidentAcc) {
			w.challenged++
			if inc != nil {
				inc.challenged++
			}
		})
		d.Action, d.ID, d.Status = Challenge, idChallenge, http.StatusServiceUnavailable
		return d
	}
	return s.refuse(ns, d, info, id, http.StatusServiceUnavailable, 5)
}

// raise is the factor that a limit configured as ref is multiplied by for an address, or a network, whose own average
// is avg requests a second: LimitMargin times that average over the configured limit, at most MaxScale, never below 1.
func (s *Shield) raise(avg, ref float64) float64 {
	if ref <= 0 {
		return 1
	}
	return math.Min(math.Max(s.det.cfg.LimitMargin*avg/ref, 1), s.det.cfg.MaxScale)
}

// isKnown says whether a client counts as one the site knows. During an attack, only a standing earned well before the
// attack began counts: bots that used the site normally in the seconds before the detector was sure (or that ramp up
// slowly to earn it) are strangers like any other.
func (s *Shield) isKnown(src *source, ns int64, info *attackInfo) bool {
	if src.knownUntil <= ns {
		return false
	}
	return info == nil || src.knownAt < info.since-int64(s.cfg.KnownMinAge)
}

// retryAfter is a wait in seconds as a Retry-After value: rounded up to whole seconds, at least 1 and at most most.
func retryAfter(wait, most float64) int {
	if !(wait < most) { // NaN too
		return int(most)
	}
	return max(1, int(math.Ceil(wait)))
}

// refuse refuses a request with status and, if retry is positive, a Retry-After of retry seconds. During an attack the
// refusal counts toward the address's ban.
func (s *Shield) refuse(ns int64, d Decision, info *attackInfo, id, status, retry int) Decision {
	d.Action, d.ID, d.Status, d.RetryAfter = Refuse, id, status, retry
	s.counters.refused.Add(1)
	held, banned := id == idRate || id == idSubnetRate, id == idBanned
	var h uint64
	if banned {
		h = hashAddr(d.key)
	}
	s.det.note(ns, func(w *window, inc *incidentAcc) {
		w.refused++
		switch {
		case held:
			w.held++
		case banned:
			w.banRefused++
			w.banSrcs.add(h)
		}
		if inc != nil {
			inc.refused++
		}
	})
	// A ban is the attack's mitigation, not a baseline limit: in monitor mode an address over its own limit is refused
	// as at any other time, and never banned for it.
	if info != nil && id != idBanned && !s.cfg.MonitorOnly {
		s.strike(ns, d.key, info)
	}
	return d
}

// showsPerStrike is how many times the challenge shown to an address counts as one refusal toward its ban. The people
// behind one shared address are each shown it about once before they answer it, so it takes some 300 of them (BanAfter
// 30) to get the address banned; a bot that loads pages at an address's own limit (50 a second) is banned in six seconds.
const showsPerStrike = 10

// strike counts a refusal against an address during an attack, and bans it when it has had enough.
func (s *Shield) strike(ns int64, key netip.Addr, info *attackInfo) { s.mark(ns, key, info, false) }

// mark counts a refusal, or the challenge shown (a tenth of one), against an address during an attack, and bans it when
// it has had enough.
func (s *Shield) mark(ns int64, key netip.Addr, info *attackInfo, shown bool) {
	ban := false
	s.sources.do(key, ns, func(src *source) {
		if src.strikeEpoch != info.epoch {
			src.strikeEpoch, src.strikes, src.fromShown, src.shown = info.epoch, 0, 0, 0
		}
		if shown {
			if src.shown++; src.shown < showsPerStrike {
				return
			}
			src.shown = 0
		}
		if src.strikes < 65535 {
			src.strikes++
			if shown {
				src.fromShown++
			}
		}
		// Counting starts again, so an address that goes on after its ban runs out is banned again. Its standing goes
		// with the ban: being known, and the higher limit it had earned.
		if int(src.strikes) >= s.cfg.BanAfter {
			src.bannedUntil, src.knownUntil, src.strikes, src.fromShown, src.shown, ban = ns+int64(s.cfg.BanFor), 0, 0, 0, 0, true
			src.earned = earned{}
		}
	})
	if !ban {
		return
	}
	s.counters.banned.Add(1)
	s.det.note(ns, func(w *window, inc *incidentAcc) {
		w.banned++
		if inc != nil {
			inc.banned++
		}
	})
	if s.cfg.Banner == nil {
		return
	}
	bits := 32
	if key.Is6() {
		bits = 64
	}
	p := netip.PrefixFrom(key, bits)
	// A firewall would drop every packet from the range, a trusted proxy's in it too: the ban then holds only here, where
	// the proxy's own requests pass it.
	for _, t := range s.cfg.Trusted {
		if t.Overlaps(p) {
			return
		}
	}
	select {
	case s.bans <- banReq{p: p, ttl: s.cfg.BanFor, reason: "carnical-shield attack " + strconv.Itoa(int(info.epoch))}:
	default: // the helper is behind; the ban still holds in this process
		s.counters.banErrors.Add(1)
	}
}

// forgive takes back one challenge shown to an address during an attack, for a right answer to it: the many people
// behind one address who are each shown it and answer it add nothing toward its ban. An answer sent many times takes
// back no more than the address was shown, and never a refusal or a wrong answer.
func (s *Shield) forgive(ns int64, key netip.Addr, info *attackInfo) {
	s.sources.do(key, ns, func(src *source) {
		switch {
		case src.strikeEpoch != info.epoch: // nothing counted in this attack yet
		case src.shown > 0:
			src.shown--
		case src.fromShown > 0:
			src.fromShown, src.strikes, src.shown = src.fromShown-1, src.strikes-1, showsPerStrike-1
		}
	})
}

func (s *Shield) banWorker() {
	defer s.wg.Done()
	for {
		select {
		case <-s.stop:
			return
		case b := <-s.bans:
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			if err := s.cfg.Banner.Ban(ctx, b.p, b.ttl, b.reason); err != nil {
				s.counters.banErrors.Add(1)
			}
			cancel()
		}
	}
}

// Write answers a request the shield did not allow. The answer is small, never cached, and closes the connection unless
// a trusted proxy relayed the request and no HTTP/1 body is left to read (see ConnContext).
func (s *Shield) Write(w http.ResponseWriter, r *http.Request, d Decision) {
	h := w.Header()
	h.Set("Cache-Control", "no-store")
	h.Set("X-Content-Type-Options", "nosniff")
	switch d.Action {
	case Respond:
		if d.resp.cookie != nil {
			http.SetCookie(w, d.resp.cookie)
		}
		if d.resp.location != "" {
			h.Set("Location", d.resp.location)
		}
		h.Set("Content-Type", d.resp.contentType)
		if d.Status >= http.StatusBadRequest { // a wrong answer to the challenge counts as a refusal and ends as one
			s.closeUnlessRelayed(h, r)
		}
		w.WriteHeader(d.Status)
		if r.Method != http.MethodHead {
			if _, err := w.Write([]byte(d.resp.body)); err != nil {
				s.counters.writeErrors.Add(1)
			}
		}
		return
	case Challenge:
		body, nonce := s.challengePage(r, d.key, s.now())
		h.Set("Content-Type", "text/html; charset=utf-8")
		h.Set("Content-Security-Policy", "default-src 'none'; script-src 'nonce-"+nonce+"'; style-src 'unsafe-inline'; img-src data:; frame-ancestors 'none'; base-uri 'none'; form-action 'none'")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Retry-After", "5")
		w.WriteHeader(d.Status)
		if r.Method != http.MethodHead {
			if _, err := w.Write([]byte(body)); err != nil {
				s.counters.writeErrors.Add(1)
			}
		}
		return
	}
	s.closeUnlessRelayed(h, r)
	h.Set("Content-Type", "text/plain; charset=utf-8")
	if d.RetryAfter > 0 {
		h.Set("Retry-After", strconv.Itoa(d.RetryAfter))
	}
	w.WriteHeader(d.Status)
	if r.Method != http.MethodHead {
		if _, err := w.Write([]byte(http.StatusText(d.Status) + "\n")); err != nil {
			s.counters.writeErrors.Add(1)
		}
	}
}

// closeUnlessRelayed closes the connection after a refusal. A trusted proxy's connection carries other visitors' requests
// too, so it stays open, except after an HTTP/1 request with a body: net/http would wait for the rest of that body before
// answering, and a refused request is never read.
func (s *Shield) closeUnlessRelayed(h http.Header, r *http.Request) {
	if !s.relayed(r) || (r.ProtoMajor == 1 && r.ContentLength != 0) {
		h.Set("Connection", "close")
	}
}

// StatusClientClosed is the status to give Done, with fromOrigin, for a request whose client hung up (or whose response
// was ended to free a place) while the application had it and before it answered.
const StatusClientClosed = 499

// Done tells the shield how a request it allowed ended: the status sent and whether it came from the application.
// fromOrigin is false for a refusal by a later check (the rule set, a format check), which says nothing about the
// application's health. A request the client hung up on before the application answered is StatusClientClosed: it counts
// as the application's failure only if the client had waited well beyond the application's usual latency.
func (s *Shield) Done(d Decision, status int, fromOrigin bool) {
	if !d.counted || d.Action != Allow {
		return
	}
	now := s.now().UnixNano()
	if fromOrigin {
		s.det.done(now, status, time.Duration(now-d.start))
	} else if status >= 400 && status < 500 && status != http.StatusRequestTimeout { // a 408 is a slow client, not a finding
		s.counters.securityRejections.Add(1)
		s.det.count(now, func(w *window) { w.securityRejects++ })
	}
	// Nothing is learnt from errors, nor from a trusted proxy, whose limits do not apply: its entry is its whole /64 for
	// IPv6, which the proxy may share with addresses that are not trusted, and its standing would be theirs.
	if status >= 400 || d.trusted {
		return
	}
	// A higher limit is earned by what the application itself answered well, in any second that is not an attack's.
	earn := s.det.earn.Load()
	if earn != nil && (!earn.open || !fromOrigin) {
		earn = nil
	}
	if earn != nil {
		s.subnets.do(netOf(d.key), now, func(n *subnet) {
			n.earned.roll(earn, s.cfg.SubnetRate)
			n.earned.n++
		})
	}
	learning := s.det.learning.Load() // standing is earned only while traffic is ordinary
	if earn == nil && !learning {
		return
	}
	s.sources.do(d.key, now, func(src *source) {
		if earn != nil {
			src.earned.roll(earn, s.cfg.RequestRate)
			src.earned.n++
		}
		if !learning {
			return
		}
		if src.good == 0 {
			src.goodFirst = now
		}
		if src.good < 65535 {
			src.good++
		}
		if int(src.good) >= s.cfg.KnownAfter && now-src.goodFirst >= int64(s.cfg.KnownMinAge) {
			if src.knownUntil < now {
				src.knownAt = now
			}
			src.knownUntil = now + int64(s.cfg.KnownFor)
		}
	})
}

// State is the detector's current verdict.
func (s *Shield) State() State {
	s.det.mu.Lock()
	defer s.det.mu.Unlock()
	return s.det.state
}

// Snapshot is the shield's state for a dashboard.
type Snapshot struct {
	State                                   State
	Rate, BaselineRate                      float64
	Sources, NewShare, Engagement, ErrRatio float64
	Reasons                                 []string
	// IDSReasons describes observation-only signals, independent of attack mitigation.
	IDSReasons                                                                   []string
	ConnectionRate, ConnectionRefusalRate, EarlyCloseRate, SecurityRejectionRate float64
	// EarlyCloses counts nontrusted connections closed before HTTP StateActive.
	// SecurityRejections counts 4xx responses from checks after shield admission, excluding origin responses and 408 (a
	// client too slow to send its request).
	EarlyCloses, SecurityRejections      uint64
	Connections, MaxConnections          int64
	RequestScale, NetworkScale           float64 // the most an address's, and a network's, limit was raised above its configured value in the last ten seconds
	Remembered                           int
	Allowed, Refused, Challenged, Solved uint64
	Banned, ConnsRefused, Evicted        uint64
	BanErrors                            uint64
	// WriteErrors counts failed response body writes; SocketOptionErrors counts failed optional TCP tuning.
	WriteErrors, SocketOptionErrors uint64
	// DroppedEvents counts the Events not given to Config.OnEvent: those found while 256 were already waiting for it, and
	// those found after Close.
	DroppedEvents uint64
	Current       *Incident
	Recent        []Incident
}

// Snapshot returns the current state.
func (s *Shield) Snapshot() Snapshot {
	d := s.det
	d.mu.Lock()
	snap := Snapshot{State: d.state, Rate: d.last.rate, BaselineRate: d.base.rate, Sources: d.last.srcs, NewShare: d.last.newShare,
		Engagement: d.last.engagement, ErrRatio: d.last.errRatio, Reasons: append([]string(nil), d.reasons...),
		Recent: append([]Incident(nil), d.history...), IDSReasons: append([]string(nil), d.idsReasons...),
		ConnectionRate: d.last.connRate, ConnectionRefusalRate: d.last.connRefused, EarlyCloseRate: d.last.earlyCloses, SecurityRejectionRate: d.last.securityRejects}
	if d.incident != nil {
		inc := d.incidentEvent("attack_update", s.now().UnixNano()).Incident
		snap.Current = &inc
	}
	d.mu.Unlock()
	snap.Connections, snap.MaxConnections = s.conns.Load(), s.maxConns()
	snap.RequestScale, snap.NetworkScale = s.det.scales()
	snap.Remembered = s.sources.len()
	c := &s.counters
	snap.Allowed, snap.Refused, snap.Challenged = c.allowed.Load(), c.refused.Load(), c.challenged.Load()
	snap.Solved, snap.Banned, snap.ConnsRefused, snap.Evicted, snap.BanErrors = c.solved.Load(), c.banned.Load(), c.connsRefused.Load(), c.evicted.Load(), c.banErrors.Load()
	snap.WriteErrors, snap.SocketOptionErrors = c.writeErrors.Load(), c.socketOptionErrors.Load()
	snap.EarlyCloses, snap.SecurityRejections = c.earlyCloses.Load(), c.securityRejections.Load()
	snap.DroppedEvents = s.det.droppedEvents.Load()
	return snap
}

// unwrapConn finds the shield's connection under a TLS one.
func unwrapConn(c net.Conn) *conn {
	if tc, ok := c.(*tls.Conn); ok {
		c = tc.NetConn()
	}
	sc, _ := c.(*conn)
	return sc
}
