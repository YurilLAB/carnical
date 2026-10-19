// SPDX-License-Identifier: Apache-2.0

package notify

import (
	"time"

	"github.com/YurilLAB/coraza/carnical/netwatch"
)

// Event is what a message reports.
type Event string

// The events.
const (
	AttackStart  Event = "attack_start"  // the shield declared an HTTP-layer attack
	AttackUpdate Event = "attack_update" // it goes on (at most one a minute per attack)
	AttackEnd    Event = "attack_end"    // it is over
	// A volumetric attack on the kernel's packet guards (UDP, SYN, malformed TCP, echo), told by carnical-netwatch.
	NetworkStart  = Event(netwatch.Start)
	NetworkUpdate = Event(netwatch.Update) // at most one a minute per attack
	NetworkEnd    = Event(netwatch.End)
)

func (e Event) update() bool { return e == AttackUpdate || e == NetworkUpdate }

// Severity is how urgent a message is.
func (e Event) Severity() string {
	switch e {
	case AttackStart, NetworkStart:
		return "critical"
	case AttackUpdate, NetworkUpdate:
		return "warning"
	}
	return "info"
}

// Message is one alert. Every string in it is carnical's own text, a number, or a label carnical made and bounded
// (a client fingerprint, a path template, a country or network); no query, body, cookie or visitor's address.
type Message struct {
	Version  int       `json:"version"`  // 1
	ID       string    `json:"id"`       // the delivery id, also in X-Carnical-Delivery; filled when sent
	Event    Event     `json:"event"`    // what it reports
	Severity string    `json:"severity"` // critical, warning or info
	At       time.Time `json:"at"`
	Site     string    `json:"site,omitempty"` // the site's first name, so that one endpoint can serve several edges
	Text     string    `json:"text"`           // one line for a person, a chat or a pager
	// Subject says which attack an update is about (its start, as text), so that a newer update replaces one still
	// waiting. It is not sent.
	Subject string  `json:"-"`
	Attack  *Attack `json:"attack,omitempty"`
	// Network is the record of a network attack, as the packet guards counted it.
	Network *netwatch.Record `json:"network,omitempty"`
	// Dropped counts the messages before this one that were not sent: the queue was full.
	Dropped uint64 `json:"dropped,omitempty"`
}

// Port is a port and what an attack sent to it.
type Port struct {
	Protocol    string `json:"protocol"` // tcp
	Port        uint16 `json:"port"`
	Requests    uint64 `json:"requests,omitempty"`
	Connections uint64 `json:"connections,omitempty"`
}

// Origin is a country or network label and its share of an attack.
type Origin struct {
	Label    string `json:"label"`
	Requests uint64 `json:"requests"`
}

// Cluster is a fingerprint or a target an attack was recognised by.
type Cluster struct {
	Kind      string  `json:"kind"` // fingerprint or target
	Label     string  `json:"label"`
	Share     float64 `json:"share"` // of the requests, 0 to 1
	Addresses int     `json:"addresses"`
}

// Attack is the record of an HTTP-layer attack, as the shield keeps it.
type Attack struct {
	Mode         string     `json:"mode"` // on (mitigated) or monitor (only reported)
	Started      time.Time  `json:"started"`
	Ended        *time.Time `json:"ended,omitempty"`
	Kinds        []string   `json:"kinds"`
	Ports        []Port     `json:"ports"`
	OtherPorts   *Port      `json:"other_ports,omitempty"`
	Rate         float64    `json:"rate"`          // requests a second now
	PeakRate     float64    `json:"peak_rate"`     // the highest
	BaselineRate float64    `json:"baseline_rate"` // the usual
	Requests     uint64     `json:"requests"`
	Addresses    int        `json:"addresses"` // estimated
	Networks     int        `json:"networks"`  // estimated
	TLS          uint64     `json:"tls"`
	Plain        uint64     `json:"plain"`
	HTTP1        uint64     `json:"http1"`
	HTTP2        uint64     `json:"http2"`
	TopOrigins   []Origin   `json:"top_origins,omitempty"`
	Clusters     []Cluster  `json:"clusters,omitempty"`
	Reasons      []string   `json:"reasons,omitempty"`
	Refused      uint64     `json:"refused"`
	Challenged   uint64     `json:"challenged"`
	Banned       uint64     `json:"banned"`
	// Window says that the counts (requests, addresses, networks, ports and protocols) are those of the ten seconds that
	// showed the attack, as on attack_start, which comes before anything of the attack itself was counted.
	Window bool `json:"window,omitempty"`
	// Stopped says, on attack_end, that Carnical stopped while the attack went on: its record ends there.
	Stopped bool `json:"stopped,omitempty"`
}
