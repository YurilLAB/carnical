// SPDX-License-Identifier: Apache-2.0

package main

import (
	"flag"
	"fmt"

	"github.com/YurilLAB/coraza/carnical/alert"
	"github.com/YurilLAB/coraza/carnical/bots"
)

// botFlags are the flags of the bot policy (ADR-0087).
type botFlags struct {
	kinds, mode *string
}

func declareBotFlags(flags *flag.FlagSet) botFlags {
	return botFlags{
		kinds: flags.String("bots", "", "kinds of bot to refuse, separated by commas: "+bots.KindNames()+" (fake: claims to be a search engine, checked by DNS; default none, only counted)"),
		mode:  flags.String("bots-mode", "block", "block the kinds -bots lists, or monitor (only log the ones it would block)"),
	}
}

// botPolicy checks the bot flags. With no kind to refuse there is no policy: alerts still name the kind of client.
func botPolicy(f botFlags) (*bots.Policy, error) {
	set, err := bots.ParseKinds(*f.kinds)
	if err != nil {
		return nil, refuseFlag("bots", fmt.Errorf("-bots: %w", err))
	}
	p := &bots.Policy{Refuse: set}
	switch *f.mode {
	case "block":
	case "monitor":
		p.Monitor = true
	default:
		return nil, refuseFlag("bots-mode", fmt.Errorf("-bots-mode must be block or monitor, not %q", *f.mode))
	}
	if set == 0 {
		return nil, nil
	}
	if p.Refuses(alert.ClientFake) {
		p.Verifier = bots.NewVerifier(nil, 0, 0)
	}
	return p, nil
}

// botsMode is the bot policy as the listening line gives it: the kinds refused, with "(monitor)" when they are only
// logged, or none.
func botsMode(p *bots.Policy) string {
	if p == nil {
		return "none"
	}
	if p.Monitor {
		return bots.Kinds(p.Refuse) + " (monitor)"
	}
	return bots.Kinds(p.Refuse)
}
