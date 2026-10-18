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
	kinds, watch, mode, exempt *string
}

func declareBotFlags(flags *flag.FlagSet) botFlags {
	return botFlags{
		kinds: flags.String("bots", "scanner", "kinds of bot to refuse, separated by commas: "+bots.KindNames()+
			" (fake: claims to be a search engine, checked by DNS; disguised: a program sending a browser's user agent), or none"),
		watch:  flags.String("bots-monitor", "", "kinds of bot only logged as ones that would be refused, in the same words as -bots"),
		mode:   flags.String("bots-mode", "block", "block the kinds -bots lists, or monitor (only log them, as -bots-monitor does)"),
		exempt: flags.String("bots-exempt", "", "comma-separated addresses or ranges never refused by -bots, such as your own scanners"),
	}
}

// botPolicy checks the bot flags. With no kind to refuse there is no policy: alerts still name the kind of client. By
// default scanners and attack tools are refused, in every mode: nothing but an attack sends their user agents.
func botPolicy(f botFlags) (*bots.Policy, error) {
	set, err := bots.ParseKinds(*f.kinds)
	if err != nil {
		return nil, refuseFlag("bots", fmt.Errorf("-bots: %w", err))
	}
	watch, err := bots.ParseKinds(*f.watch)
	if err != nil {
		return nil, refuseFlag("bots-monitor", fmt.Errorf("-bots-monitor: %w", err))
	}
	p := &bots.Policy{Refuse: set, Watch: watch}
	switch *f.mode {
	case "block":
	case "monitor":
		p.Refuse, p.Watch = 0, set|watch
	default:
		return nil, refuseFlag("bots-mode", fmt.Errorf("-bots-mode must be block or monitor, not %q", *f.mode))
	}
	if set|watch == 0 {
		return nil, nil
	}
	var values []string
	if *f.exempt != "" {
		values = []string{*f.exempt}
	}
	exempt, err := alert.ParseExcludeSources(values) // the same grammar and the same /16 and /32 floor as auto-block's
	if err != nil {
		return nil, refuseFlag("bots-exempt", fmt.Errorf("-bots-exempt: %w", err))
	}
	p.Exempt = exempt
	if (p.Refuse|p.Watch)&(1<<alert.ClientFake) != 0 {
		p.Verifier = bots.NewVerifier(nil, 0, 0)
	}
	return p, nil
}

// botsMode is the bot policy as the listening line gives it: the kinds refused, and those only logged after "monitor".
func botsMode(p *bots.Policy) string {
	if p == nil {
		return "none"
	}
	watched := p.Watch &^ p.Refuse
	switch {
	case watched == 0:
		return bots.Kinds(p.Refuse)
	case p.Refuse == 0:
		return "monitor " + bots.Kinds(watched)
	}
	return bots.Kinds(p.Refuse) + "; monitor " + bots.Kinds(watched)
}
