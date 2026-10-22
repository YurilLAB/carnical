// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"time"

	"github.com/YurilLAB/coraza/carnical/alert"
	"github.com/YurilLAB/coraza/carnical/shield"
)

// autoBlockFlags are the flags of repeat-offender blocking (ADR-0085).
type autoBlockFlags struct {
	mode, exempt           *string
	points, max            *int
	window, first, longest *time.Duration
}

func declareAutoBlockFlags(flags *flag.FlagSet) autoBlockFlags {
	return autoBlockFlags{
		mode:    flags.String("auto-block", "monitor", "ban a source (an address or IPv6 /64) whose requests keep being refused as attacks: off, monitor (only log who would be banned) or on; needs -ddos on or monitor"),
		points:  flags.Int("auto-block-points", 12, "points that ban a source within -auto-block-window, 4 to 1000 (a blocked attack scores 3 or 4; a source with standing needs twice as many)"),
		window:  flags.Duration("auto-block-window", 10*time.Minute, "how long a source's points count, 1m to 24h"),
		first:   flags.Duration("auto-block-for", 10*time.Minute, "how long a first ban lasts, 1m to 24h; each further ban of the source lasts twice as long, up to -auto-block-max-for"),
		longest: flags.Duration("auto-block-max-for", 24*time.Hour, "longest ban, 10m to 7 days and at least -auto-block-for"),
		max:     flags.Int("auto-block-max", 0, "most sources banned at once, 100 to 262144 (0 = 10000, or an eighth of the flood protection's address table if fewer)"),
		exempt:  flags.String("auto-block-exempt", "", "comma-separated addresses or ranges never banned (monitoring, health checks, your own scanners); trusted proxies, loopback, this host's addresses and -alert-exclude-sources are never banned either"),
	}
}

// autoBlockSettings checks the auto-block flags. ddos is the -ddos value: without flood protection there is no address
// table to ban in, so asking for auto-block then is refused, while its default is quietly off. excluded are the
// -alert-exclude-sources ranges, which are never banned either.
func autoBlockSettings(f autoBlockFlags, set map[string]bool, ddos string, excluded []netip.Prefix) (shield.AutoBlock, error) {
	var ab shield.AutoBlock
	switch *f.mode {
	case "off":
		return ab, nil
	case "monitor":
		ab.Mode = shield.AutoBlockMonitor
	case "on":
		ab.Mode = shield.AutoBlockOn
	default:
		return ab, refuseFlag("auto-block", fmt.Errorf("-auto-block must be off, monitor or on, not %q", *f.mode))
	}
	if mode, _, err := parseDDoS(ddos); err == nil && mode == "off" {
		if set["auto-block"] {
			return ab, refuseFlag("auto-block", fmt.Errorf("-auto-block %s needs -ddos on or monitor: bans are held by the flood protection", *f.mode))
		}
		return shield.AutoBlock{}, nil
	}
	switch {
	case *f.points < 4 || *f.points > 1000:
		return ab, refuseFlag("auto-block-points", errors.New("-auto-block-points must be from 4 to 1000"))
	case *f.window < time.Minute || *f.window > 24*time.Hour:
		return ab, refuseFlag("auto-block-window", errors.New("-auto-block-window must be from 1m to 24h"))
	case *f.first < time.Minute || *f.first > 24*time.Hour:
		return ab, refuseFlag("auto-block-for", errors.New("-auto-block-for must be from 1m to 24h"))
	case *f.longest < 10*time.Minute || *f.longest > 7*24*time.Hour:
		return ab, refuseFlag("auto-block-max-for", errors.New("-auto-block-max-for must be from 10m to 168h (7 days)"))
	case *f.longest < *f.first:
		return ab, refuseFlag("auto-block-max-for", fmt.Errorf("-auto-block-max-for (%v) must be at least -auto-block-for (%v)", *f.longest, *f.first))
	case *f.max != 0 && (*f.max < 100 || *f.max > 262144):
		return ab, refuseFlag("auto-block-max", errors.New("-auto-block-max must be 0 or from 100 to 262144"))
	}
	ab.Points, ab.Window, ab.For, ab.MaxFor, ab.Max = *f.points, *f.window, *f.first, *f.longest, *f.max
	var values []string
	if *f.exempt != "" {
		values = []string{*f.exempt}
	}
	exempt, err := alert.ParseExcludeSources(values) // the same grammar and the same /16 and /32 floor
	if err != nil {
		return ab, refuseFlag("auto-block-exempt", fmt.Errorf("-auto-block-exempt: %w", err))
	}
	ab.Exempt = append(append(exempt, excluded...), hostPrefixes()...)
	if len(ab.Exempt) > 256 {
		return ab, refuseFlag("auto-block-exempt", fmt.Errorf("-auto-block-exempt, -alert-exclude-sources and this host's addresses come to %d ranges, at most 256", len(ab.Exempt)))
	}
	return ab, nil
}

// hostPrefixes are this host's own addresses, which a ban must never cover: a request the host sends itself (a health
// check, a cron job) would otherwise lock the host out. Loopback and link-local addresses are exempt anyway.
func hostPrefixes() []netip.Prefix {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil
	}
	var out []netip.Prefix
	for _, a := range addrs {
		ipnet, ok := a.(*net.IPNet)
		if !ok {
			continue
		}
		ip, ok := netip.AddrFromSlice(ipnet.IP)
		if !ok {
			continue
		}
		ip = ip.Unmap()
		if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsUnspecified() {
			continue
		}
		out = append(out, netip.PrefixFrom(ip, ip.BitLen()))
	}
	return out
}

// logOffenderEvent writes the events of repeat-offender blocking as offenderLine gives them.
func logOffenderEvent(log *slog.Logger, ev shield.Event, source alert.SourceMode) {
	l, level, ok := offenderLine(ev, source)
	if !ok {
		return
	}
	b := l.Ban
	attrs := []any{"mode", b.Mode}
	if b.SrcKey != "" {
		attrs = append(attrs, "src_key", b.SrcKey)
	}
	if b.Src != "" {
		attrs = append(attrs, "src", b.Src)
	}
	if b.Points != nil {
		attrs = append(attrs, "points", *b.Points)
	}
	if len(b.Sigs) > 0 {
		attrs = append(attrs, "sigs", b.Sigs)
	}
	if b.TTL != "" {
		attrs = append(attrs, "ttl", b.TTL)
	}
	if b.Until != nil {
		attrs = append(attrs, "until", *b.Until)
	}
	if b.BanLevel != nil {
		attrs = append(attrs, "ban_level", *b.BanLevel)
	}
	if b.Note != "" {
		attrs = append(attrs, "note", b.Note)
	}
	if b.Count != nil {
		attrs = append(attrs, "count", *b.Count)
	}
	log.Log(context.Background(), level, l.Msg, attrs...)
}

// offenderLine is an event of repeat-offender blocking as its log line writes it, the source as -alert-source asks,
// with the line's level; false for any other event. The alert endpoint is sent the same line.
func offenderLine(ev shield.Event, source alert.SourceMode) (alert.Line, slog.Level, bool) {
	b := &alert.BanLine{Mode: ev.Mode}
	switch source {
	case alert.SourceFull:
		if ev.Source.IsValid() {
			b.SrcKey = ev.Source.String()
		}
		if ev.Client.IsValid() {
			b.Src = ev.Client.String()
		}
	case alert.SourcePrefix:
		if ev.Source.IsValid() {
			b.Src = alert.SourceNet(ev.Source.Addr()).String()
		}
	}
	l, level := alert.Line{Ban: b}, slog.LevelWarn
	switch ev.Kind {
	case "source_blocked", "source_would_block":
		points, until, banLevel := ev.Points, ev.Until, ev.Level
		b.Points, b.Sigs, b.TTL, b.Until, b.BanLevel = &points, ev.Sigs, ev.TTL.String(), &until, &banLevel
		l.Msg = "source would be blocked"
		if ev.Kind == "source_blocked" {
			l.Msg, b.Note = "source blocked", "an address may be shared by many users; exempt it with -auto-block-exempt"
		}
	case "source_block_ended":
		until := ev.Until
		l.Msg, b.Until, level = "source block ended", &until, slog.LevelInfo
	case "auto_block_full", "auto_block_unreported":
		count := ev.Count
		l.Msg, b.Count = "auto-block table full; sources not blocked", &count
		if ev.Kind == "auto_block_unreported" {
			l.Msg = "auto-block events not reported"
		}
	default:
		return alert.Line{}, 0, false
	}
	return l, level, true
}

// offenderEvent says an event is one of repeat-offender blocking.
func offenderEvent(kind string) bool {
	switch kind {
	case "source_blocked", "source_would_block", "source_block_ended", "auto_block_full", "auto_block_unreported":
		return true
	}
	return false
}

// autoBlockMode is what the listening line says of auto-block: off when there is no flood protection to hold bans.
func autoBlockMode(guard *shield.Shield, ab shield.AutoBlock) string {
	if guard == nil {
		return shield.AutoBlockOff.String()
	}
	return ab.Mode.String()
}
