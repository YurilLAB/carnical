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
var Refusable = []alert.Client{alert.ClientFake, alert.ClientAI, alert.ClientSEO, alert.ClientTool, alert.ClientHeadless,
	alert.ClientScanner, alert.ClientBot}

// Policy is which kinds of client a site refuses.
type Policy struct {
	// Refuse is the kinds refused, a bit for each alert.Client.
	Refuse uint32
	// Monitor reports the clients the policy would refuse and lets them through.
	Monitor bool
	// Verifier checks search engine claims. Without it no client is taken for a fake search engine crawler.
	Verifier *Verifier
}

// ParseKinds reads a comma-separated list of the kinds to refuse: fake, ai, seo, tool, headless, scanner and bot, or
// "none" (the same as an empty list).
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

// Judge reads what kind of client sent r from addr, the visitor's verified address, and whether the policy refuses
// it. A search engine claim is checked by DNS only when the policy refuses fakes: one that fails is ClientFake.
func (p *Policy) Judge(ctx context.Context, r *http.Request, addr netip.Addr) (alert.Client, bool) {
	c, engine := Classify(r.Header, r.ProtoMajor, r.ProtoMinor, r.Method)
	if c == alert.ClientSearch && engine != 0 && p.Refuses(alert.ClientFake) && p.Verifier != nil &&
		!p.Verifier.Verify(ctx, addr, engine) {
		c = alert.ClientFake
	}
	return c, p.Refuses(c)
}
