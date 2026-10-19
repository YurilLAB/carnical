// SPDX-License-Identifier: Apache-2.0

package notify

import (
	"math"
	"strconv"
	"strings"

	"github.com/YurilLAB/coraza/carnical/alert"
	"github.com/YurilLAB/coraza/carnical/shield"
)

// FromShield is the message for one of the shield's attack events: kind is AttackStart, AttackUpdate or AttackEnd, site
// the site's name and subject the attack's start, as text (see Message.Subject).
func FromShield(kind Event, ev shield.Event, site, subject string) Message {
	inc := ev.Incident
	a := &Attack{
		Mode: ev.Mode, Started: inc.Start.UTC(), Kinds: inc.Kinds, Ports: make([]Port, 0, len(inc.Ports)),
		Rate: whole(ev.Rate), PeakRate: whole(inc.PeakRate), BaselineRate: whole(inc.BaselineRate),
		Requests: inc.Requests, Addresses: inc.Sources, Networks: inc.Networks, TLS: inc.TLS, Plain: inc.Plain,
		HTTP1: inc.HTTP1, HTTP2: inc.HTTP2, Refused: inc.Refused, Challenged: inc.Challenged, Banned: inc.Banned,
		Window: inc.Window, Stopped: inc.Stopped,
	}
	if a.Mode == "" {
		a.Mode = "on"
	}
	if a.Kinds == nil {
		a.Kinds = []string{}
	}
	if !inc.End.IsZero() {
		end := inc.End.UTC()
		a.Ended = &end
	}
	for _, p := range inc.Ports {
		a.Ports = append(a.Ports, Port{Protocol: "tcp", Port: p.Port, Requests: p.Requests, Connections: p.Connections})
	}
	if o := inc.OtherPorts; o.Requests+o.Connections > 0 {
		a.OtherPorts = &Port{Protocol: "tcp", Requests: o.Requests, Connections: o.Connections}
	}
	for _, l := range inc.Labels[:min(len(inc.Labels), 5)] {
		a.TopOrigins = append(a.TopOrigins, Origin{Label: label(l.Label, 64), Requests: l.Requests})
	}
	// A fingerprint's label and a target's path template are made from what clients sent: cleaned and bounded.
	for _, c := range inc.Clusters[:min(len(inc.Clusters), 5)] {
		a.Clusters = append(a.Clusters, Cluster{Kind: c.Kind, Label: label(c.Label, 96),
			Share: whole(c.Share*1000) / 1000, Addresses: c.Sources})
	}
	for _, r := range inc.Reasons[:min(len(inc.Reasons), 6)] {
		a.Reasons = append(a.Reasons, label(r, 200))
	}
	return Message{Event: kind, At: ev.At.UTC(), Site: site, Text: attackText(kind, a, site), Subject: subject, Attack: a}
}

// attackText is the message's line for a person.
func attackText(kind Event, a *Attack, site string) string {
	var b strings.Builder
	switch kind {
	case AttackStart:
		b.WriteString("DDoS attack detected")
	case AttackUpdate:
		b.WriteString("DDoS attack continues")
	case AttackEnd:
		if a.Stopped {
			b.WriteString("DDoS attack record closed, Carnical stopping while it goes on")
		} else {
			b.WriteString("DDoS attack over")
		}
	}
	if site != "" {
		b.WriteString(" on " + site)
	}
	if len(a.Kinds) > 0 {
		b.WriteString(" (" + strings.Join(a.Kinds, ", ") + ")")
	}
	b.WriteString(": " + strconv.FormatFloat(a.PeakRate, 'f', 0, 64) + " requests/s at peak, usually " +
		strconv.FormatFloat(a.BaselineRate, 'f', 0, 64))
	if len(a.Ports) > 0 {
		ports := make([]string, 0, len(a.Ports))
		for _, p := range a.Ports {
			ports = append(ports, "tcp/"+strconv.Itoa(int(p.Port)))
		}
		b.WriteString(", to " + strings.Join(ports, " "))
	}
	b.WriteString(", from about " + strconv.Itoa(a.Addresses) + " addresses in " + strconv.Itoa(a.Networks) + " networks")
	switch {
	case a.Mode == "monitor":
		b.WriteString("; monitor mode, not mitigated")
	case kind != AttackEnd:
		b.WriteString("; mitigation on")
	}
	return b.String()
}

// angle makes the angle brackets of a label harmless to a chat that reads them as markup (Slack's "<!channel>").
var angle = strings.NewReplacer("<", "‹", ">", "›")

// label is a label made from what clients sent, fit to pass on: no markup, no controls, at most max bytes.
func label(s string, max int) string { return alert.Clean(angle.Replace(s), max) }

// whole rounds f, and makes a number JSON cannot hold (NaN, an infinity) 0.
func whole(f float64) float64 {
	if math.IsNaN(f) || math.IsInf(f, 0) {
		return 0
	}
	return math.Round(f)
}
