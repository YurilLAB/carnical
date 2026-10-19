// SPDX-License-Identifier: Apache-2.0

package bots

import (
	"context"
	"fmt"
	"net/http"
	"net/netip"
	"strings"

	"github.com/YurilLAB/coraza/carnical/alert"
)

// ruleBase is the first id of the bot policy: a refusal's id is it plus the number of the kind of client refused, 5005003
// for an AI crawler and so on (alert's catalog names them).
const ruleBase = 5005000

// RuleID is the id a refusal of the kind c is reported under.
func RuleID(c alert.Client) int { return ruleBase + int(c) }

// Refusable are the kinds a site can refuse, in the order -bots lists them. People, search engines that are what they
// claim, link previews and uptime checks cannot be: a site that does not want them says so in robots.txt or its policy.
var Refusable = []alert.Client{alert.ClientFake, alert.ClientScanner, alert.ClientAI, alert.ClientSEO, alert.ClientTool,
	alert.ClientHeadless, alert.ClientDisguised, alert.ClientBot}

// Policy is which kinds of client a site refuses, and which it only reports.
type Policy struct {
	// Refuse is the kinds refused, a bit for each alert.Client; Watch the kinds reported as would-be refusals and let
	// through. A kind in both is refused.
	Refuse, Watch uint32
	// Verifier checks search engine claims. Without it no client is taken for a fake search engine crawler.
	Verifier *Verifier
	// Exempt are the addresses never refused for their kind, such as the site's own scanners; their requests are still
	// read and counted.
	Exempt []netip.Prefix
}

// ParseKinds reads a comma-separated list of the kinds to refuse: fake, scanner, ai, seo, tool, headless, disguised and
// bot, or "none" (the same as an empty list).
func ParseKinds(s string) (uint32, error) {
	var set uint32
	s = strings.TrimSpace(s)
	if s == "" || s == "none" {
		return 0, nil
	}
	for _, name := range strings.Split(s, ",") {
		name = strings.ToLower(strings.TrimSpace(name))
		c, ok := alert.ParseClient(name)
		if !ok || !refusable(c) {
			return 0, fmt.Errorf("%q is not a kind of bot that can be refused: use none, or some of %s", name, KindNames())
		}
		set |= 1 << c
	}
	return set, nil
}

// KindNames lists the kinds that can be refused, separated by commas.
func KindNames() string {
	names := make([]string, len(Refusable))
	for i, c := range Refusable {
		names[i] = c.String()
	}
	return strings.Join(names, ",")
}

// Kinds lists the kinds in a set, in the order Refusable gives them, separated by commas, or "none".
func Kinds(set uint32) string {
	var names []string
	for _, c := range Refusable {
		if set&(1<<c) != 0 {
			names = append(names, c.String())
		}
	}
	if len(names) == 0 {
		return "none"
	}
	return strings.Join(names, ",")
}

func refusable(c alert.Client) bool {
	for _, r := range Refusable {
		if r == c {
			return true
		}
	}
	return false
}

// Refuses reports whether the policy refuses the kind c.
func (p *Policy) Refuses(c alert.Client) bool { return p != nil && p.Refuse&(1<<c) != 0 }

// Watches reports whether the policy reports the kind c without refusing it.
func (p *Policy) Watches(c alert.Client) bool {
	return p != nil && p.Watch&(1<<c) != 0 && !p.Refuses(c)
}

// Action is what the policy does with a request.
type Action uint8

// The actions.
const (
	Pass   Action = iota // let through
	Watch                // let through, reported as a would-be refusal
	Refuse               // refused
)

// Judge reads what kind of client sent r from addr, the visitor's verified address, and what the policy does with it;
// hello is the request's TLS handshake (see Classify). A claim to be a crawler of an operator that publishes its DNS
// names is checked only when the policy refuses or watches fakes: one that fails is ClientFake. An exempt address is
// always let through.
func (p *Policy) Judge(ctx context.Context, r *http.Request, addr netip.Addr, hello Hello) (alert.Client, Action) {
	c, engine := Classify(r, hello)
	fakes := p.Refuses(alert.ClientFake) || p.Watches(alert.ClientFake)
	if engine != 0 && fakes && p.Verifier != nil && !p.Verifier.Verify(ctx, addr, engine) {
		c = alert.ClientFake
	}
	var action Action
	switch {
	case p.Refuses(c):
		action = Refuse
	case p.Watches(c):
		action = Watch
	default:
		return c, Pass
	}
	if p.Exempts(addr) {
		return c, Pass
	}
	return c, action
}

// Claim judges a request as Judge does from what it says alone, with no DNS check, for where a check must stay cheap (the
// shield's admission): a claim to be a search engine's crawler, which Judge would check, is refused or reported when a
// fake one would be.
func (p *Policy) Claim(r *http.Request, addr netip.Addr, hello Hello) (alert.Client, Action) {
	c, engine := Classify(r, hello)
	checked := engine != 0 && p != nil && p.Verifier != nil
	var action Action
	switch {
	case p.Refuses(c) || checked && p.Refuses(alert.ClientFake):
		action = Refuse
	case p.Watches(c) || checked && p.Watches(alert.ClientFake):
		action = Watch
	default:
		return c, Pass
	}
	if p.Exempts(addr) {
		return c, Pass
	}
	return c, action
}

// Exempts reports whether addr is one the policy never refuses for its kind.
func (p *Policy) Exempts(addr netip.Addr) bool {
	if p == nil {
		return false
	}
	a := addr.Unmap()
	for _, e := range p.Exempt {
		if e.Contains(a) {
			return true
		}
	}
	return false
}
