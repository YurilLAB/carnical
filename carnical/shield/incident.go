// SPDX-License-Identifier: Apache-2.0

package shield

import (
	"cmp"
	"hash/maphash"
	"math"
	"net/netip"
	"slices"
	"strconv"
	"time"
)

// Event is something the owner should hear about: an attack began, is going on, or ended, traffic is unusually high or
// back to normal, or an IDS signal was seen or cleared. Events are few (a handful per attack) and never carry request
// content; the shield never logs one line per refused request, because during a flood that would be a second flood,
// into the log.
type Event struct {
	// Kind is "elevated", "normal", "attack_start", "attack_update", "attack_end", "ids_signal" or "ids_clear", or for
	// repeat offenders (see Shield.Offend) "source_blocked", "source_would_block", "source_block_ended",
	// "auto_block_full" or "auto_block_unreported". "normal" follows "elevated" or "attack_end" once the state has stayed normal for ten seconds.
	Kind string
	// Mode is "on" when the shield mitigates attacks and "monitor" when it only reports them (Config.MonitorOnly); for
	// the repeat-offender events it is AutoBlock.Mode, "on" or "monitor".
	Mode         string
	At           time.Time
	State        State
	Rate         float64 // requests a second over the last ten seconds
	BaselineRate float64
	Reasons      []string
	// Codes name the IDS signals: for ids_signal one for each reason, in the same order ("conn_pressure",
	// "early_close", "rejections", "would_reject", "held"), and for ids_clear those reported since the last ids_clear.
	Codes []string
	// Incident is filled for the attack events.
	Incident Incident
	// Source is the range a repeat offender's ban covers (an IPv4 /32 or an IPv6 /64), and Client the address whose
	// offence banned it (not set for source_block_ended). Points is the score that banned it, Sigs the signatures it
	// scored with (at most 8, as Offend cleaned them), TTL and Until how long its ban lasts and when it ends, and Level
	// which ban of the source in a row it is. Until is also set for source_block_ended.
	Source netip.Prefix
	Client netip.Addr
	Points int
	Sigs   []string
	TTL    time.Duration
	Until  time.Time
	Level  int
	// Count is, for auto_block_full, the bans not made for lack of room since the last auto_block_full, and for
	// auto_block_unreported, the repeat-offender events (source_blocked, source_would_block, source_block_ended) the
	// event queue had no room for since the last auto_block_unreported.
	Count uint64
}

// Incident is the record of one attack.
type Incident struct {
	Start, End   time.Time // End is zero while it goes on
	BaselineRate float64
	PeakRate     float64
	Requests     uint64
	// Sources and Networks are estimates (within a few per cent) of the different addresses (an IPv6 client counted by
	// its /64) and the different /24 (IPv4) or /48 (IPv6) networks the attack came from.
	Sources, Networks int
	// Labels are the most common labels (country or network, from the Labeler) with their request counts, and
	// DistinctLabels about how many different ones there were. Empty without a Labeler.
	Labels         []LabelCount
	DistinctLabels int
	Reasons        []string
	Clusters       []Cluster
	// Kinds name what the attack is, from the evidence the detector found during it, in this order: "request_flood"
	// (far more requests than usual), "connection_flood" (connections opened without requests), "one_client_tool" (one
	// client fingerprint), "one_target" (one page or endpoint), "many_new_addresses" (addresses not seen before, or
	// many more of them) and "application_strain" (the application failing or slow).
	Kinds []string
	// Ports are the local TCP ports the attack's requests and connections came to, the most requested first, at most
	// maxIncidentPorts of them; OtherPorts counts what came to any other port (Port is 0).
	Ports      []PortCount
	OtherPorts PortCount
	// The requests by how they came: over TLS or plain HTTP, and as HTTP/1.x or HTTP/2. A request the server did not say
	// the port of is in neither port count.
	TLS, Plain, HTTP1, HTTP2 uint64
	// Window says that the counts are those of the ten seconds that showed the attack, as in an attack_start event, which
	// comes before anything of the attack itself has been counted: Requests, Sources, Networks, Ports, OtherPorts and the
	// protocols.
	Window bool
	// What the shield did during the attack.
	Refused, Challenged, Solved, Banned uint64
	// Stopped says, on an attack_end, that the shield stopped (the process is shutting down) while the attack went on:
	// the record ends there, not the attack.
	Stopped bool
}

// PortCount is one local TCP port and what an attack sent to it.
type PortCount struct {
	Port        uint16
	Requests    uint64
	Connections uint64
}

// maxIncidentPorts is the most local ports an attack's record names; an edge listens on one or two.
const maxIncidentPorts = 4

// The kinds of attack evidence (Incident.Kinds), as bits.
const (
	kindRequestFlood uint8 = 1 << iota
	kindConnFlood
	kindOneTool
	kindOneTarget
	kindNewAddresses
	kindStrain
	numKinds = iota
)

var kindNames = [numKinds]string{"request_flood", "connection_flood", "one_client_tool", "one_target", "many_new_addresses", "application_strain"}

// kindList names the kinds in the set, in kindNames order.
func kindList(set uint8) []string {
	var out []string
	for i, name := range kindNames {
		if set&(1<<i) != 0 {
			out = append(out, name)
		}
	}
	return out
}

// reqMeta is what the detector is told of how a request came: its local port (0 when unknown) and, when known is
// set, its protocol.
type reqMeta struct {
	port    uint16
	known   bool
	tls, h2 bool
}

// LabelCount is one label and how many requests carried it.
type LabelCount struct {
	Label    string
	Requests uint64
}

// Cluster is a fingerprint or a target that the attack was recognised by.
type Cluster struct {
	Kind    string // "fingerprint" or "target"
	Label   string
	Share   float64
	Sources int
}

// Labeler names an address's country, network or both (for example "BR AS28573"). It is called for every request during
// an attack, so it must be fast; Ranges is one.
type Labeler interface {
	Label(netip.Addr) string
}

type incidentAcc struct {
	start          int64
	peak, baseRate float64
	requests       uint64
	srcs, nets     hll
	labels         topK
	labelSet       hll
	reasons        []string
	clusters       []Cluster
	refused        uint64
	challenged     uint64
	solved         uint64
	banned         uint64
	kinds          uint8
	via            viaCounts
}

// viaCounts counts requests and connections by the local port they came to and requests by protocol, for a second's
// window and for an attack's record. It is a few words: nothing is allocated.
type viaCounts struct {
	// ports holds the first nports local ports seen, other what came to any further port.
	ports              [maxIncidentPorts]PortCount
	nports             int
	other              PortCount
	tls, plain, h1, h2 uint64
}

// addPort counts reqs requests and conns connections to a local port; port 0 (unknown) is not counted.
func (i *viaCounts) addPort(port uint16, reqs, conns uint64) {
	if port == 0 {
		return
	}
	for k := 0; k < i.nports; k++ {
		if i.ports[k].Port == port {
			i.ports[k].Requests += reqs
			i.ports[k].Connections += conns
			return
		}
	}
	if i.nports < maxIncidentPorts {
		i.ports[i.nports] = PortCount{Port: port, Requests: reqs, Connections: conns}
		i.nports++
		return
	}
	i.other.Requests += reqs
	i.other.Connections += conns
}

// addRequest counts one request by its port and protocol.
func (i *viaCounts) addRequest(m reqMeta) {
	i.addPort(m.port, 1, 0)
	if !m.known {
		return
	}
	if m.tls {
		i.tls++
	} else {
		i.plain++
	}
	if m.h2 {
		i.h2++
	} else {
		i.h1++
	}
}

// add counts what o counted.
func (i *viaCounts) add(o *viaCounts) {
	for k := 0; k < o.nports; k++ {
		i.addPort(o.ports[k].Port, o.ports[k].Requests, o.ports[k].Connections)
	}
	i.other.Requests += o.other.Requests
	i.other.Connections += o.other.Connections
	i.tls, i.plain, i.h1, i.h2 = i.tls+o.tls, i.plain+o.plain, i.h1+o.h1, i.h2+o.h2
}

// fill puts the counts in an Incident.
func (i *viaCounts) fill(out *Incident) {
	out.OtherPorts, out.TLS, out.Plain, out.HTTP1, out.HTTP2 = i.other, i.tls, i.plain, i.h1, i.h2
	out.Ports = nil
	if i.nports > 0 {
		out.Ports = slices.Clone(i.ports[:i.nports])
		slices.SortStableFunc(out.Ports, func(a, b PortCount) int {
			return cmp.Or(cmp.Compare(b.Requests, a.Requests), cmp.Compare(b.Connections, a.Connections))
		})
	}
}

func (i *incidentAcc) addReasons(rs []string) {
	for _, r := range rs {
		if len(i.reasons) >= 12 {
			return
		}
		if !slices.Contains(i.reasons, r) && !slices.ContainsFunc(i.reasons, func(s string) bool { return sameKind(s, r) }) {
			i.reasons = append(i.reasons, r)
		}
	}
}

// sameKind says whether two reasons are the same finding with different numbers, so that the record keeps the first
// statement of each and does not fill up with "about 5,120 requests a second", "about 5,140 requests a second", ...
func sameKind(a, b string) bool {
	strip := func(s string) string {
		out := make([]byte, 0, len(s))
		for i := 0; i < len(s); i++ {
			if c := s[i]; (c < '0' || c > '9') && c != '.' && c != ',' {
				out = append(out, c)
			}
		}
		return string(out)
	}
	return strip(a) == strip(b)
}

func (i *incidentAcc) addCluster(kind string, s share) {
	if len(i.clusters) < 16 {
		i.clusters = append(i.clusters, Cluster{Kind: kind, Label: s.label, Share: s.share, Sources: int(s.sources)})
	}
}

func (d *detector) incidentEvent(kind string, ns int64) Event {
	inc := d.incident
	out := Incident{
		Start: d.wallTime(inc.start), BaselineRate: inc.baseRate, PeakRate: inc.peak, Requests: inc.requests,
		Sources: int(inc.srcs.estimate()), Networks: int(inc.nets.estimate()),
		Reasons: slices.Clone(inc.reasons), Clusters: slices.Clone(inc.clusters),
		Refused: inc.refused, Challenged: inc.challenged, Solved: inc.solved, Banned: inc.banned,
		Kinds: kindList(inc.kinds),
	}
	inc.via.fill(&out)
	if inc.requests == 0 {
		out.Sources, out.Networks = 0, 0
	}
	if len(inc.labels.e) > 0 {
		out.DistinctLabels = int(inc.labelSet.estimate())
		for _, e := range inc.labels.e {
			out.Labels = append(out.Labels, LabelCount{Label: e.label, Requests: e.count})
		}
		slices.SortFunc(out.Labels, func(a, b LabelCount) int { return cmp.Compare(b.Requests, a.Requests) })
		out.Labels = out.Labels[:min(len(out.Labels), 10)]
	}
	if kind == "attack_end" {
		out.End = d.wallTime(ns)
	}
	return Event{Kind: kind, At: d.wallTime(ns), State: d.state, Rate: d.last.rate, BaselineRate: inc.baseRate,
		Reasons: slices.Clone(d.reasons), Incident: out}
}

var prefixSeed = maphash.MakeSeed()

func maphashPrefix(p netip.Prefix) uint64 { return maphash.Comparable(prefixSeed, p) }

func pct(f float64) string {
	return strconv.FormatFloat(math.Round(f*1000)/10, 'f', -1, 64) + "%"
}

func itoa(f float64) string {
	if math.IsNaN(f) || math.IsInf(f, 0) {
		return "0"
	}
	return strconv.FormatInt(int64(math.Round(f)), 10)
}
