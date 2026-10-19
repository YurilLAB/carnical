// SPDX-License-Identifier: Apache-2.0

// Package netwatch tells when the kernel's packet guards (deploy/nftables/carnical.nft) are under a volumetric attack:
// a UDP flood, UDP reflection, a SYN flood, malformed TCP or an echo flood, which the proxy never sees. It reads the
// guards' drop counters once a second, learns how many drops are usual, and reports an attack when the drops rise far
// above it, with the ports the flood went to (and, for reflection, the services it came from), its rate and its size.
//
// Only what the guards drop is counted, and the guards drop only what this host does not serve or what is over a
// budget: a reply to what the host asked, a visitor's connection and anything else accepted is in no count, so an
// ordinary rise in traffic is not an attack here.
//
// The Detector is pure: Observe takes readings and returns the events. carnical-netwatch reads the counters with nft and
// writes the latest event to a state file, which the edge reads and passes to the alert endpoint.
package netwatch

import (
	"cmp"
	"math"
	"slices"
	"strconv"
	"time"
)

// Count is a counter's packets and bytes.
type Count struct {
	Packets, Bytes uint64
}

// Reading is one reading of the guards: the cumulative named counters, and, when they were read, the counting sets
// (each element's cumulative count).
type Reading struct {
	At       time.Time
	Counters map[string]Count
	// Ports (the set udp_ports, unsolicited UDP by destination port) and Reflectors (udp_reflectors, reflection
	// replies by source port) are nil when the sets were not read. PortsFull says that udp_ports held as many ports
	// as it can: a port that came after was not counted by port.
	Ports, Reflectors map[uint16]Count
	PortsFull         bool
}

// The kinds of attack, by the counters they are told by.
const (
	KindUDPFlood   = "udp_flood"      // unsolicited UDP, and UDP to the edge's port
	KindReflection = "udp_reflection" // replies from reflection services nobody here asked
	KindSYNFlood   = "syn_flood"      // SYNs over the source, network or global budgets
	KindBadTCP     = "malformed_tcp"  // impossible flag combinations or sources
	KindEchoFlood  = "icmp_flood"     // echo requests over their budget
)

// kinds maps each kind to its counters in carnical.nft. A counter that is missing (an older policy) counts nothing.
var kinds = []struct {
	name     string
	counters []string
}{
	{KindUDPFlood, []string{"udp_flood_drop", "edge_udp_drop"}},
	{KindReflection, []string{"udp_reflection_drop"}},
	{KindSYNFlood, []string{"edge_syn_source_drop", "edge_syn_network_drop", "edge_syn_global_drop", "edge_syn_peer_drop"}},
	{KindBadTCP, []string{"edge_bad_tcp", "edge_bad_source"}},
	{KindEchoFlood, []string{"edge_echo_drop"}},
}

// edgeUDP is the counter of UDP to the edge's port, dropped before the set udp_ports sees it: its port is EdgePort.
const edgeUDP = "edge_udp_drop"

// CounterNames are the counters the Detector reads.
func CounterNames() []string {
	var out []string
	for _, k := range kinds {
		out = append(out, k.counters...)
	}
	return out
}

// Config tunes the Detector. The zero value of a field is its default.
type Config struct {
	// MinRate is the least rate of dropped packets a second that can be an attack: 1,000. The internet's background of
	// scans and stray packets is a few to a few hundred a second.
	MinRate float64
	// Factor is how many times the usual rate of drops the rate must reach: 10.
	Factor float64
	// Confirm is how many seconds in a row the rate must be over the threshold: 3.
	Confirm int
	// ExitQuiet is how long the rate must stay under half the threshold for the attack to end: 30 seconds.
	ExitQuiet time.Duration
	// MinAttack is the least an attack lasts: 30 seconds.
	MinAttack time.Duration
	// Tau is the time constant the usual rate is learnt with: 10 minutes.
	Tau time.Duration
	// UpdateEvery is how often an attack going on is reported: 10 seconds.
	UpdateEvery time.Duration
	// EdgePort is the edge's TCP port, which the SYN and malformed TCP guards protect: 443.
	EdgePort uint16
	// Warmup is how long after the first start the usual rate is still being learnt: 5 minutes. Meanwhile it is learnt
	// five times as fast, and only a rise to Factor times MinRate is an attack, so that an edge whose usual drops are
	// high does not report them as one. A watch that restarts resumes its usual rate instead (Resume): a flood going on
	// then is not learnt as usual.
	Warmup time.Duration
	// Ceiling is the rate of drops that is an attack whatever the usual: 100 times MinRate (100,000).
	Ceiling float64
}

func (c *Config) defaults() {
	if c.MinRate <= 0 {
		c.MinRate = 1000
	}
	if c.Factor <= 0 {
		c.Factor = 10
	}
	if c.Confirm <= 0 {
		c.Confirm = 3
	}
	if c.ExitQuiet <= 0 {
		c.ExitQuiet = 30 * time.Second
	}
	if c.MinAttack <= 0 {
		c.MinAttack = 30 * time.Second
	}
	if c.Tau <= 0 {
		c.Tau = 10 * time.Minute
	}
	if c.UpdateEvery <= 0 {
		c.UpdateEvery = 10 * time.Second
	}
	if c.EdgePort == 0 {
		c.EdgePort = 443
	}
	if c.Warmup <= 0 {
		c.Warmup = 5 * time.Minute
	}
	if c.Ceiling <= 0 {
		c.Ceiling = 100 * c.MinRate
	}
	c.Ceiling = math.Max(c.Ceiling, c.MinRate)
}

// Event is what the Detector reports.
type Event string

// The events.
const (
	Start  Event = "network_attack_start"
	Update Event = "network_attack_update"
	End    Event = "network_attack_end"
)

// Port is a port and the packets dropped that went to it (or, for a reflector, came from it).
type Port struct {
	Protocol string `json:"protocol"` // udp or tcp
	Port     uint16 `json:"port"`
	Packets  uint64 `json:"packets"`
	Bytes    uint64 `json:"bytes"`
}

// KindCount is a kind of attack and what it dropped.
type KindCount struct {
	Kind    string `json:"kind"`
	Packets uint64 `json:"packets"`
	Bytes   uint64 `json:"bytes"`
}

// Record is an attack as the guards saw it.
type Record struct {
	Started time.Time  `json:"started"`
	Ended   *time.Time `json:"ended,omitempty"`
	// Kinds are those with at least a tenth of the attack's packets, the most first, and what each dropped.
	Kinds []KindCount `json:"kinds"`
	// Ports are the destination ports with at least a hundredth of the attack's packets, the most first (at most
	// MaxPorts). UDP ports come from the set udp_ports, and UDP to EdgePort from its own counter; a SYN flood or
	// malformed TCP is to EdgePort. OtherPorts counts
	// the UDP flood's packets to any other port, and RandomPorts says that they were at least half of it: a flood
	// spread over random ports, which has no port to name.
	Ports       []Port `json:"ports"`
	OtherPorts  uint64 `json:"other_ports,omitempty"`
	RandomPorts bool   `json:"random_ports,omitempty"`
	// SourcePorts are the reflection services the replies came from, the most first (at most MaxPorts).
	SourcePorts []Port  `json:"source_ports,omitempty"`
	PacketRate  float64 `json:"packet_rate"` // dropped packets a second, now
	PeakRate    float64 `json:"peak_packet_rate"`
	ByteRate    float64 `json:"byte_rate"`
	PeakBytes   float64 `json:"peak_byte_rate"`
	Baseline    float64 `json:"baseline_packet_rate"` // the usual, from before the attack
	Packets     uint64  `json:"packets"`              // dropped during the attack
	Bytes       uint64  `json:"bytes"`
	// PortsFull says that the set that counts the ports was full during the attack: more ports were hit than it
	// holds, so a port may be missing from Ports (a flood to many decoy ports can hide the one it is aimed at).
	PortsFull bool `json:"ports_full,omitempty"`
	// Stopped says, on an end, that the watch stopped while the attack went on: its record ends there.
	Stopped bool `json:"stopped,omitempty"`
}

// MaxPorts is the most ports a record names.
const MaxPorts = 8

// maxTracked bounds the ports followed during an attack: the sets hold at most 2,048 and 512.
const maxTracked = 4096

// Detector turns readings into events. It is not safe for concurrent use.
type Detector struct {
	cfg      Config
	prev     Reading
	havePrev bool
	learnt   time.Duration // how long the usual rate has been learnt
	base     float64       // the usual rate of drops, packets a second
	over     int           // seconds in a row over the threshold
	quiet    time.Duration
	attack   *acc
	// prevPorts and prevRefl are the sets of the last reading, to take deltas from; nil when they were not read.
	prevPorts, prevRefl map[uint16]Count
}

type acc struct {
	start, lastUpdate      time.Time
	baseline               float64
	peak, peakBytes        float64
	rate, byteRate         float64
	kinds                  map[string]Count
	ports, refl            map[uint16]Count
	packets, bytes, others uint64
	edgeUDP                Count // the UDP flood's packets to EdgePort
	portsFull              bool
}

// New returns a Detector.
func New(cfg Config) *Detector {
	cfg.defaults()
	return &Detector{cfg: cfg}
}

// WantSets says whether the next reading should include the counting sets: while drops are over the threshold or an
// attack goes on. Reading them costs more than the counters, and they matter only then.
func (d *Detector) WantSets() bool { return d.attack != nil || d.over > 0 }

// Threshold is the rate of drops that counts as an attack now.
func (d *Detector) Threshold() float64 {
	thr := math.Max(d.cfg.MinRate, d.cfg.Factor*d.base)
	if d.learnt < d.cfg.Warmup {
		thr = math.Max(thr, d.cfg.Factor*d.cfg.MinRate)
	}
	return math.Min(thr, d.cfg.Ceiling)
}

// Resume starts from the usual rate of an earlier run, without a warm-up, so that a flood going on at a restart is not
// learnt as usual.
func (d *Detector) Resume(baseline float64) {
	if baseline >= 0 && !math.IsInf(baseline, 0) && !math.IsNaN(baseline) {
		d.base, d.learnt = baseline, d.cfg.Warmup
	}
}

// Baseline is the usual rate of drops, packets a second, to Resume from after a restart.
func (d *Detector) Baseline() float64 { return d.base }

// Learning says that the warm-up is not over: the usual rate is not yet one to keep.
func (d *Detector) Learning() bool { return d.learnt < d.cfg.Warmup }

// learn takes a second under the threshold into the usual rate. After the warm-up, only a second that is not itself
// a rise counts (under twice the usual, or under MinRate/Factor, where it cannot move the threshold), and the usual
// (with a tenth of MinRate) at most doubles in an hour: a flood kept under the threshold, or one that ramps up slowly,
// cannot teach the watch that it is usual.
func (d *Detector) learn(rate, secs float64, dt time.Duration) {
	warm := d.learnt < d.cfg.Warmup
	d.learnt += dt
	if warm {
		d.base += (rate - d.base) * math.Min(secs/(d.cfg.Warmup/5).Seconds(), 1)
		return
	}
	if rate >= math.Max(d.cfg.MinRate/d.cfg.Factor, 2*d.base) {
		return
	}
	step := (rate - d.base) * math.Min(secs/d.cfg.Tau.Seconds(), 1)
	d.base += math.Min(step, (d.base+d.cfg.MinRate/10)*secs*math.Ln2/3600)
}

// Observe takes the next reading and returns the event it makes, if any, with the attack's record. A reading less
// than half a second or more than ten seconds after the last, or one whose counters went down (the policy was
// reloaded), only becomes the reference for the next.
func (d *Detector) Observe(r Reading) (Event, *Record) {
	defer func() { d.prev, d.havePrev = r, true }()
	if !d.havePrev {
		d.prevPorts, d.prevRefl = r.Ports, r.Reflectors
		return "", nil
	}
	dt := r.At.Sub(d.prev.At)
	if dt < 500*time.Millisecond || dt > 10*time.Second {
		d.prevPorts, d.prevRefl = r.Ports, r.Reflectors
		return "", nil
	}
	byKind := make(map[string]Count, len(kinds))
	var total, toEdge Count
	for _, k := range kinds {
		var c Count
		for _, name := range k.counters {
			cur, ok := r.Counters[name]
			if !ok {
				continue
			}
			old := d.prev.Counters[name]
			if cur.Packets < old.Packets || cur.Bytes < old.Bytes {
				// A reload resets the counters: nothing can be said of this second.
				d.prevPorts, d.prevRefl = r.Ports, r.Reflectors
				return "", nil
			}
			c.Packets += cur.Packets - old.Packets
			c.Bytes += cur.Bytes - old.Bytes
			if name == edgeUDP {
				toEdge = Count{cur.Packets - old.Packets, cur.Bytes - old.Bytes}
			}
		}
		byKind[k.name] = c
		total.Packets += c.Packets
		total.Bytes += c.Bytes
	}
	secs := dt.Seconds()
	rate, byteRate := float64(total.Packets)/secs, float64(total.Bytes)/secs
	thr := d.Threshold()
	// A set that was not read now leaves no reference: the next reading of it only becomes one, so that what it counted
	// while it was not read is not taken for this second's.
	portsNow, reflNow := setDelta(r.Ports, d.prevPorts), setDelta(r.Reflectors, d.prevRefl)
	d.prevPorts, d.prevRefl = r.Ports, r.Reflectors

	if d.attack == nil {
		if rate >= thr {
			d.over++
		} else {
			d.over = 0
			d.learn(rate, secs, dt)
		}
		if d.over < d.cfg.Confirm {
			return "", nil
		}
		d.over = 0
		d.attack = &acc{start: r.At, lastUpdate: r.At, baseline: d.base, kinds: map[string]Count{},
			ports: map[uint16]Count{}, refl: map[uint16]Count{}}
		d.add(byKind, total, toEdge, portsNow, reflNow, rate, byteRate)
		d.attack.portsFull = r.PortsFull
		return Start, d.record(nil)
	}
	d.add(byKind, total, toEdge, portsNow, reflNow, rate, byteRate)
	d.attack.portsFull = d.attack.portsFull || r.PortsFull
	if rate < thr/2 {
		d.quiet += dt
	} else {
		d.quiet = 0
	}
	a := d.attack
	if r.At.Sub(a.start) >= d.cfg.MinAttack && d.quiet >= d.cfg.ExitQuiet {
		end := r.At
		rec := d.record(&end)
		d.attack, d.quiet = nil, 0
		return End, rec
	}
	if r.At.Sub(a.lastUpdate) >= d.cfg.UpdateEvery {
		a.lastUpdate = r.At
		return Update, d.record(nil)
	}
	return "", nil
}

// Open says whether an attack goes on.
func (d *Detector) Open() bool { return d.attack != nil }

// Stop closes the record of an attack going on at at, because the watch stops: the End to report, or nil when no
// attack goes on.
func (d *Detector) Stop(at time.Time) *Record {
	if d.attack == nil {
		return nil
	}
	rec := d.record(&at)
	rec.Stopped = true
	d.attack, d.quiet, d.over = nil, 0, 0
	return rec
}

// setDelta is what each element of a set counted since the last reading. An element that went down timed out and came
// back: all of what it holds is new. Nil when the set was not read now or before.
func setDelta(now, before map[uint16]Count) map[uint16]Count {
	if now == nil || before == nil {
		return nil
	}
	out := make(map[uint16]Count)
	for port, c := range now {
		old := before[port]
		if c.Packets < old.Packets || c.Bytes < old.Bytes {
			old = Count{}
		}
		if d := (Count{c.Packets - old.Packets, c.Bytes - old.Bytes}); d.Packets > 0 {
			out[port] = d
		}
	}
	return out
}

func (d *Detector) add(byKind map[string]Count, total, toEdge Count, ports, refl map[uint16]Count, rate, byteRate float64) {
	a := d.attack
	a.edgeUDP = Count{a.edgeUDP.Packets + toEdge.Packets, a.edgeUDP.Bytes + toEdge.Bytes}
	for k, c := range byKind {
		cur := a.kinds[k]
		a.kinds[k] = Count{cur.Packets + c.Packets, cur.Bytes + c.Bytes}
	}
	a.packets += total.Packets
	a.bytes += total.Bytes
	a.rate, a.byteRate = rate, byteRate
	a.peak, a.peakBytes = math.Max(a.peak, rate), math.Max(a.peakBytes, byteRate)
	addPorts(a.ports, ports, &a.others)
	var dropped uint64
	addPorts(a.refl, refl, &dropped)
}

// addPorts adds what each port counted to m, which follows at most maxTracked ports; the rest go to others.
func addPorts(m, now map[uint16]Count, others *uint64) {
	for port, c := range now {
		cur, ok := m[port]
		if !ok && len(m) >= maxTracked {
			*others += c.Packets
			continue
		}
		m[port] = Count{cur.Packets + c.Packets, cur.Bytes + c.Bytes}
	}
}

// record is the attack's record now; end is set when it is over.
func (d *Detector) record(end *time.Time) *Record {
	a := d.attack
	rec := &Record{Started: a.start, Ended: end, PacketRate: round(a.rate), PeakRate: round(a.peak), ByteRate: round(a.byteRate),
		PeakBytes: round(a.peakBytes), Baseline: round(a.baseline), Packets: a.packets, Bytes: a.bytes, OtherPorts: a.others,
		PortsFull: a.portsFull}
	for _, k := range kinds {
		if c := a.kinds[k.name]; c.Packets > 0 && c.Packets*10 >= a.packets {
			rec.Kinds = append(rec.Kinds, KindCount{Kind: k.name, Packets: c.Packets, Bytes: c.Bytes})
		}
	}
	slices.SortStableFunc(rec.Kinds, func(x, y KindCount) int { return cmp.Compare(y.Packets, x.Packets) })
	ports := top(a.ports, "udp")
	if a.edgeUDP.Packets > 0 {
		ports = append(ports, Port{Protocol: "udp", Port: d.cfg.EdgePort, Packets: a.edgeUDP.Packets, Bytes: a.edgeUDP.Bytes})
		slices.SortStableFunc(ports, func(x, y Port) int { return cmp.Compare(y.Packets, x.Packets) })
	}
	var listed uint64
	for i, p := range ports {
		if p.Packets*100 < a.packets {
			ports = ports[:i]
			break
		}
		listed += p.Packets
	}
	if flood := a.kinds[KindUDPFlood].Packets; flood > listed {
		rec.OtherPorts = flood - listed
		rec.RandomPorts = rec.OtherPorts*2 >= flood
	}
	// The TCP guards protect one port; it is named when they are part of the attack.
	var tcp Count
	for _, k := range []string{KindSYNFlood, KindBadTCP} {
		tcp.Packets += a.kinds[k].Packets
		tcp.Bytes += a.kinds[k].Bytes
	}
	if tcp.Packets > 0 && tcp.Packets*10 >= a.packets {
		ports = append(ports, Port{Protocol: "tcp", Port: d.cfg.EdgePort, Packets: tcp.Packets, Bytes: tcp.Bytes})
	}
	slices.SortStableFunc(ports, func(x, y Port) int { return cmp.Compare(y.Packets, x.Packets) })
	if len(ports) > MaxPorts {
		for _, p := range ports[MaxPorts:] {
			if p.Protocol == "udp" {
				rec.OtherPorts += p.Packets
			}
		}
		ports = ports[:MaxPorts]
	}
	rec.Ports = ports
	if rec.Ports == nil {
		rec.Ports = []Port{}
	}
	if rec.Kinds == nil {
		rec.Kinds = []KindCount{}
	}
	rec.SourcePorts = top(a.refl, "udp")
	for i, p := range rec.SourcePorts {
		if p.Packets*100 < a.packets || i == MaxPorts {
			rec.SourcePorts = rec.SourcePorts[:i]
			break
		}
	}
	if len(rec.SourcePorts) == 0 {
		rec.SourcePorts = nil
	}
	return rec
}

// top lists a port map, the most packets first (ties by port, so that the order is stable).
func top(m map[uint16]Count, proto string) []Port {
	out := make([]Port, 0, len(m))
	for port, c := range m {
		out = append(out, Port{Protocol: proto, Port: port, Packets: c.Packets, Bytes: c.Bytes})
	}
	slices.SortFunc(out, func(x, y Port) int { return cmp.Or(cmp.Compare(y.Packets, x.Packets), cmp.Compare(x.Port, y.Port)) })
	return out
}

func round(f float64) float64 {
	if math.IsNaN(f) || math.IsInf(f, 0) {
		return 0
	}
	return math.Round(f)
}

// Text is a line for a person: what the attack is, how big, and where it goes.
func (r *Record) Text(ev Event, site string) string {
	var b []byte
	switch ev {
	case Start:
		b = append(b, "Network flood detected"...)
	case Update:
		b = append(b, "Network flood continues"...)
	case End:
		if r.Stopped {
			b = append(b, "Network flood record closed"...)
		} else {
			b = append(b, "Network flood over"...)
		}
	default:
		return ""
	}
	if site != "" {
		b = append(b, " on "+site...)
	}
	if len(r.Kinds) > 0 {
		b = append(b, " ("...)
		for i, k := range r.Kinds {
			if i > 0 {
				b = append(b, ", "...)
			}
			b = append(b, k.Kind...)
		}
		b = append(b, ')')
	}
	b = append(b, ": "...)
	b = strconv.AppendFloat(b, r.PeakRate, 'f', 0, 64)
	b = append(b, " packets/s dropped at peak, usually "...)
	b = strconv.AppendFloat(b, r.Baseline, 'f', 0, 64)
	if len(r.Ports) > 0 {
		b = append(b, ", to"...)
		for _, p := range r.Ports[:min(len(r.Ports), 5)] {
			b = append(b, ' ')
			b = append(b, p.Protocol...)
			b = append(b, '/')
			b = strconv.AppendUint(b, uint64(p.Port), 10)
		}
	}
	switch {
	case r.PortsFull:
		b = append(b, ", to more UDP ports than are counted"...)
	case r.RandomPorts:
		b = append(b, ", to random UDP ports"...)
	}
	if len(r.SourcePorts) > 0 {
		b = append(b, ", reflected from"...)
		for _, p := range r.SourcePorts[:min(len(r.SourcePorts), 5)] {
			b = append(b, " udp/"...)
			b = strconv.AppendUint(b, uint64(p.Port), 10)
		}
	}
	if r.Stopped {
		b = append(b, "; the watch stopped while it went on"...)
	} else {
		b = append(b, "; the packet guards drop it"...)
	}
	return string(b)
}
