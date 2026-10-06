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

// Event is something the owner should hear about: an attack began, is going on, or ended, or traffic is unusually high.
// Events are few (a handful per attack) and never carry request content; the shield never logs one line per refused
// request, because during a flood that would be a second flood, into the log.
type Event struct {
	// Kind is "elevated", "attack_start", "attack_update" or "attack_end".
	Kind         string
	At           time.Time
	State        State
	Rate         float64 // requests a second over the last ten seconds
	BaselineRate float64
	Reasons      []string
	// Incident is filled for the attack events.
	Incident Incident
}

// Incident is the record of one attack.
type Incident struct {
	Start, End   time.Time // End is zero while it goes on
	BaselineRate float64
	PeakRate     float64
	Requests     uint64
	// Sources and Networks are estimates (within a few per cent) of the different addresses and the different /24 (IPv4)
	// or /48 (IPv6) networks the attack came from.
	Sources, Networks int
	// Labels are the most common labels (country or network, from the Labeler) with their request counts, and
	// DistinctLabels about how many different ones there were. Empty without a Labeler.
	Labels         []LabelCount
	DistinctLabels int
	Reasons        []string
	Clusters       []Cluster
	// What the shield did during the attack.
	Refused, Challenged, Solved, Banned uint64
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
		Start: time.Unix(0, inc.start), BaselineRate: inc.baseRate, PeakRate: inc.peak, Requests: inc.requests,
		Sources: int(inc.srcs.estimate()), Networks: int(inc.nets.estimate()),
		Reasons: slices.Clone(inc.reasons), Clusters: slices.Clone(inc.clusters),
		Refused: inc.refused, Challenged: inc.challenged, Solved: inc.solved, Banned: inc.banned,
	}
	if inc.requests == 0 {
		out.Sources, out.Networks = 0, 0
	}
	if len(inc.labels.e) > 0 {
		out.DistinctLabels = int(inc.labelSet.estimate())
		for _, e := range inc.labels.e {
			out.Labels = append(out.Labels, LabelCount{Label: e.label, Requests: uint64(e.count)})
		}
		slices.SortFunc(out.Labels, func(a, b LabelCount) int { return cmp.Compare(b.Requests, a.Requests) })
		out.Labels = out.Labels[:min(len(out.Labels), 10)]
	}
	if kind == "attack_end" {
		out.End = time.Unix(0, ns)
	}
	return Event{Kind: kind, At: time.Unix(0, ns), State: d.state, Rate: d.last.rate, BaselineRate: inc.baseRate,
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
