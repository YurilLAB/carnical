// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"slices"
	"strings"
	"time"

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
// default scanners and attack tools are refused, in every mode: nothing but an attack sends their user agents. The
// crawler lists -bots-ranges names are read here; lists keeps them current, and is nil without any.
func botPolicy(f botFlags) (p *bots.Policy, lists *crawlerLists, err error) {
	set, err := bots.ParseKinds(*f.kinds)
	if err != nil {
		return nil, nil, refuseFlag("bots", fmt.Errorf("-bots: %w", err))
	}
	watch, err := bots.ParseKinds(*f.watch)
	if err != nil {
		return nil, nil, refuseFlag("bots-monitor", fmt.Errorf("-bots-monitor: %w", err))
	}
	p = &bots.Policy{Refuse: set, Watch: watch}
	switch *f.mode {
	case "block":
	case "monitor":
		p.Refuse, p.Watch = 0, set|watch
	default:
		return nil, nil, refuseFlag("bots-mode", fmt.Errorf("-bots-mode must be block or monitor, not %q", *f.mode))
	}
	if *f.ranges != "" && (set|watch)&(1<<alert.ClientFake) == 0 {
		return nil, nil, refuseFlag("bots-ranges", errors.New("-bots-ranges verifies crawlers, which only -bots or -bots-monitor with fake does"))
	}
	if set|watch == 0 {
		return nil, nil, nil
	}
	var values []string
	if *f.exempt != "" {
		values = []string{*f.exempt}
	}
	exempt, err := alert.ParseExcludeSources(values) // the same grammar and the same /16 and /32 floor as auto-block's
	if err != nil {
		return nil, nil, refuseFlag("bots-exempt", fmt.Errorf("-bots-exempt: %w", err))
	}
	p.Exempt = exempt
	if (p.Refuse|p.Watch)&(1<<alert.ClientFake) != 0 {
		p.Verifier = bots.NewVerifier(nil, 0, 0)
		p.Verifier.TrustNetworks = *f.trustNetworks
		if *f.ranges != "" {
			if lists, err = readCrawlerLists(*f.ranges, p.Verifier); err != nil {
				return nil, nil, refuseFlag("bots-ranges", fmt.Errorf("-bots-ranges: %w", err))
			}
		}
	}
	return p, lists, nil
}

// Keeping the crawler lists current.
const (
	// crawlerListsEvery is how often the files are looked at for a new copy.
	crawlerListsEvery = time.Minute
	// crawlerListsStale is how old a file may be before Carnical warns, once a day, that it has not been refreshed.
	crawlerListsStale = 7 * 24 * time.Hour
)

// crawlerLists are the files -bots-ranges names, as last read into the verifier. A file that is replaced (a new copy
// moved into place) is read again; the lists change only when every file reads and parses, and a mistake leaves the
// lists as they were. A process confined with -confine can read the files again only from a -confine-read directory.
type crawlerLists struct {
	files    []crawlerFile
	verifier *bots.Verifier
	failed   string    // the last failure reported, so that it is reported once
	warned   time.Time // when staleness was last reported
}

// crawlerFile is one ENGINE=FILE pair of -bots-ranges.
type crawlerFile struct {
	name, path string
	engine     bots.Engine
	info       os.FileInfo // the file as read
	ranges     int
	published  time.Time
}

// readCrawlerLists reads the files spec names into v. An engine may be named more than once, to join lists it publishes
// apart.
func readCrawlerLists(spec string, v *bots.Verifier) (*crawlerLists, error) {
	l := &crawlerLists{verifier: v}
	for _, pair := range strings.Split(spec, ",") {
		name, path, ok := strings.Cut(strings.TrimSpace(pair), "=")
		engine, known := bots.EngineNamed(name)
		if !ok || !known || path == "" {
			return nil, fmt.Errorf("%q is not ENGINE=FILE with one of the engines %s", pair, bots.EngineNames())
		}
		l.files = append(l.files, crawlerFile{name: name, path: path, engine: engine})
	}
	files, ranges, err := l.read()
	if err != nil {
		return nil, err
	}
	l.files = files
	v.SetRanges(ranges)
	return l, nil
}

// read reads every file again, returning them as read and the ranges they hold, or the first that fails.
func (l *crawlerLists) read() ([]crawlerFile, map[bots.Engine][]netip.Prefix, error) {
	files := slices.Clone(l.files)
	ranges := map[bots.Engine][]netip.Prefix{}
	for i, f := range files {
		before, err := os.Lstat(f.path)
		if err != nil {
			return nil, nil, fmt.Errorf("%s: %w", f.name, err)
		}
		data, err := readSiteFile(f.path, bots.MaxRangesFile, false)
		if err != nil {
			return nil, nil, fmt.Errorf("%s: %w", f.name, err)
		}
		if after, err := os.Lstat(f.path); err != nil || !sameCopy(before, after) {
			return nil, nil, fmt.Errorf("%s: %s changed while it was read", f.name, f.path)
		}
		list, published, err := bots.ParseRanges(bytes.NewReader(data))
		if err != nil {
			return nil, nil, fmt.Errorf("%s: %w", f.name, err)
		}
		files[i].info, files[i].ranges, files[i].published = before, len(list), published
		ranges[f.engine] = append(ranges[f.engine], list...)
	}
	return files, ranges, nil
}

// sameCopy reports whether a and b are the same copy of a file: the same file, unchanged.
func sameCopy(a, b os.FileInfo) bool {
	return os.SameFile(a, b) && a.Size() == b.Size() && a.ModTime().Equal(b.ModTime())
}

// logRead logs each file as read, and warns of those not refreshed for crawlerListsStale.
func (l *crawlerLists) logRead(log *slog.Logger, msg string, now time.Time) {
	for _, f := range l.files {
		log.Info(msg, f.attrs(now)...)
	}
	l.warnStale(log, now)
}

func (f crawlerFile) attrs(now time.Time) []any {
	attrs := []any{"engine", f.name, "file", f.path, "ranges", f.ranges, "fetched", f.info.ModTime().UTC().Format(time.RFC3339),
		"age_days", int(now.Sub(f.info.ModTime()) / (24 * time.Hour))}
	if !f.published.IsZero() {
		attrs = append(attrs, "published", f.published.UTC().Format(time.RFC3339))
	}
	return attrs
}

// warnStale warns, at most once a day, of each file last written more than crawlerListsStale ago.
func (l *crawlerLists) warnStale(log *slog.Logger, now time.Time) {
	if !l.warned.IsZero() && now.Sub(l.warned) < 24*time.Hour {
		return
	}
	for _, f := range l.files {
		if now.Sub(f.info.ModTime()) > crawlerListsStale {
			log.Warn("crawler ranges not refreshed", append(f.attrs(now),
				"note", "engines change their crawlers' addresses; fetch the list again (deploy/ranges/refresh.sh)")...)
			l.warned = now
		}
	}
}

// refresh reads the files again if any was replaced or changed, and reports what it did.
func (l *crawlerLists) refresh(log *slog.Logger, now time.Time) {
	changed := false
	for _, f := range l.files {
		if info, err := os.Lstat(f.path); err != nil || !sameCopy(f.info, info) {
			changed = true
			break
		}
	}
	if changed {
		files, ranges, err := l.read()
		switch {
		case err != nil:
			if msg := err.Error(); msg != l.failed {
				log.Warn("crawler ranges not reloaded", "error", msg,
					"note", "the lists read before are still used; a confined process reads them again only from a -confine-read directory")
				l.failed = msg
			}
		default:
			l.files, l.failed = files, ""
			l.verifier.SetRanges(ranges)
			l.logRead(log, "crawler ranges reloaded", now)
			return
		}
	}
	l.warnStale(log, now)
}

// keepCurrent looks at the files every crawlerListsEvery until ctx ends.
func (l *crawlerLists) keepCurrent(ctx context.Context, log *slog.Logger) {
	tick := time.NewTicker(crawlerListsEvery)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-tick.C:
			l.refresh(log, now)
		}
	}
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
