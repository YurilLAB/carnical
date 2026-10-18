// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"net/netip"
	"strings"

	"github.com/YurilLAB/coraza/carnical/alert"
	"github.com/YurilLAB/coraza/carnical/bots"
)

// botFlags are the flags of the bot policy (ADR-0087).
type botFlags struct {
	kinds, watch, mode, exempt, ranges *string
	trustNetworks                      *bool
}

func declareBotFlags(flags *flag.FlagSet) botFlags {
	return botFlags{
		kinds: flags.String("bots", "scanner", "kinds of bot to refuse, separated by commas: "+bots.KindNames()+
			" (fake: claims to be a search engine, checked by DNS; disguised: a program sending a browser's user agent), or none"),
		watch:  flags.String("bots-monitor", "", "kinds of bot only logged as ones that would be refused, in the same words as -bots"),
		mode:   flags.String("bots-mode", "block", "block the kinds -bots lists, or monitor (only log them, as -bots-monitor does)"),
		exempt: flags.String("bots-exempt", "", "comma-separated addresses or ranges never refused by -bots, such as your own scanners"),
		trustNetworks: flags.Bool("bots-trust-networks", false, "when every DNS check of a crawler is busy, let an address pass unchecked if a crawler "+
			"of the same engine was verified in its /24 or /48 (off: such an address is a fake until checked)"),
		ranges: flags.String("bots-ranges", "", "ENGINE=FILE pairs separated by commas: the address ranges an engine publishes for its crawlers, "+
			"as its JSON file or one range a line; an address in them is verified without DNS. Engines: "+bots.EngineNames()),
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
	if *f.ranges != "" && (set|watch)&(1<<alert.ClientFake) == 0 {
		return nil, refuseFlag("bots-ranges", errors.New("-bots-ranges verifies crawlers, which only -bots or -bots-monitor with fake does"))
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
		p.Verifier.TrustNetworks = *f.trustNetworks
		ranges, err := crawlerRanges(*f.ranges)
		if err != nil {
			return nil, refuseFlag("bots-ranges", fmt.Errorf("-bots-ranges: %w", err))
		}
		p.Verifier.SetRanges(ranges)
	}
	return p, nil
}

// crawlerRanges reads the files -bots-ranges names. An engine may be named more than once, to join lists it publishes apart.
func crawlerRanges(spec string) (map[bots.Engine][]netip.Prefix, error) {
	if spec == "" {
		return nil, nil
	}
	ranges := map[bots.Engine][]netip.Prefix{}
	for _, pair := range strings.Split(spec, ",") {
		name, path, ok := strings.Cut(strings.TrimSpace(pair), "=")
		engine, known := bots.EngineNamed(name)
		if !ok || !known || path == "" {
			return nil, fmt.Errorf("%q is not ENGINE=FILE with one of the engines %s", pair, bots.EngineNames())
		}
		data, err := readSiteFile(path, bots.MaxRangesFile, false)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", name, err)
		}
		list, err := bots.ParseRanges(bytes.NewReader(data))
		if err != nil {
			return nil, fmt.Errorf("%s: %w", name, err)
		}
		ranges[engine] = append(ranges[engine], list...)
	}
	return ranges, nil
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
