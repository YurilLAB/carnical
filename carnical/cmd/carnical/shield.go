// SPDX-License-Identifier: Apache-2.0

package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"math"
	"net/netip"
	"os"
	"slices"
	"strconv"
	"strings"
	"syscall"

	"github.com/YurilLAB/coraza/carnical/shield"
)

const maxRangesBytes = 256 << 20

// maxLimitRaise is the highest -ddos-max-raise: beyond it the limit of an address is no limit.
const maxLimitRaise = 100

// The words -ddos takes: a mode, a strength, or one of each.
var (
	ddosModes     = []string{"on", "monitor", "off"}
	ddosStrengths = []string{"relaxed", "normal", "strict"}
)

type shieldFlags struct {
	mode        string
	rate, burst float64
	maxConns    int
	challenge   bool
	baseline    float64
	ranges      string
	// knownFactor and knownRate are the budget returning visitors with standing share during an attack (0 means the
	// strength's).
	knownFactor, knownRate float64
	// maxRaise is the most times its configured limit an address, or a network, may earn; 1 keeps the limits fixed.
	maxRaise float64
}

// declareShieldFlags declares the flood protection's flags. The numbers default to 0, which stands for the value of
// the strength -ddos names: a flag that is not given leaves that value alone.
func declareShieldFlags(fs *flag.FlagSet) *shieldFlags {
	f := &shieldFlags{}
	fs.StringVar(&f.mode, "ddos", "on", "flood protection: on, monitor or off, optionally with a strength relaxed, normal or strict (as in -ddos strict or -ddos monitor,strict); -ddos-* flags you set override the strength")
	fs.Float64Var(&f.rate, "ddos-rate", 0, "the least requests a second one address may make at all times (0 = the strength's: 20 strict, 50 normal, 100 relaxed); raised for an address that is answered well at a higher pace, as one with many visitors behind it is")
	fs.Float64Var(&f.burst, "ddos-burst", 0, "requests one address may make at once (0 = the strength's: 80 strict, 200 normal, 400 relaxed)")
	fs.IntVar(&f.maxConns, "ddos-max-conns", 0, "the least connections held open at once (0 = 20000), raised with the site's average; a fifth are kept for clients that used the site before")
	fs.Float64Var(&f.knownFactor, "ddos-known-factor", 0, "during an attack, returning visitors who earned standing share this many times the site's usual requests a second before they are treated like strangers (0 = 2)")
	fs.Float64Var(&f.knownRate, "ddos-known-rate", 0, "the least requests a second that returning visitors with standing share during an attack (0 = 50)")
	fs.Float64Var(&f.maxRaise, "ddos-max-raise", 0, fmt.Sprintf("the most times -ddos-rate an address, or a network, may earn by its own well-answered requests, 1 to %d (default: the strength's, 10 strict, 20 normal, 50 relaxed); 1 keeps every address at -ddos-rate", maxLimitRaise))
	fs.BoolVar(&f.challenge, "ddos-challenge", true, "during an attack, ask unknown browsers to pass a short JavaScript check instead of refusing them")
	fs.Float64Var(&f.baseline, "ddos-baseline-rate", 0, "the site's usual requests a second, to start from instead of learning it, so a restart during an attack is not fooled (0 = learn it)")
	fs.StringVar(&f.ranges, "ddos-ranges", "", "address-range table (ip2asn TSV) naming the countries and networks an attack comes from, in the attack logs")
	return f
}

// parseDDoS reads -ddos: a mode (on, monitor or off), a strength (relaxed, normal or strict), or one of each separated
// by a comma, in either order. A strength alone means on, and a mode alone means normal; off has no strength ("").
func parseDDoS(s string) (mode, strength string, err error) {
	if strings.TrimSpace(s) == "" {
		return "", "", errors.New("-ddos needs on, monitor or off, a strength relaxed, normal or strict, or one of each, as in -ddos monitor,strict")
	}
	for _, word := range strings.Split(s, ",") {
		word = strings.TrimSpace(word)
		var have *string
		kind := "modes"
		switch {
		case word == "":
			return "", "", fmt.Errorf("-ddos: %q has an empty part", s)
		case slices.Contains(ddosModes, word):
			have = &mode
		case slices.Contains(ddosStrengths, word):
			have, kind = &strength, "strengths"
		default:
			err := fmt.Sprintf("-ddos: %q is not one of %s", word, strings.Join(append(slices.Clone(ddosModes), ddosStrengths...), ", "))
			// The words are matched exactly, but a word in capitals is still told which one it is near.
			if near := closestWord(strings.ToLower(word), append(slices.Clone(ddosModes), ddosStrengths...)); near != "" {
				err += " (did you mean " + near + "?)"
			}
			return "", "", errors.New(err)
		}
		switch *have {
		case "":
			*have = word
		case word:
			return "", "", fmt.Errorf("-ddos: %q names %s twice", s, word)
		default:
			return "", "", fmt.Errorf("-ddos: %q names two %s", s, kind)
		}
	}
	switch {
	case mode == "off" && strength != "":
		return "", "", fmt.Errorf("-ddos %s: a strength needs -ddos on or monitor", s)
	case mode == "":
		mode = "on"
	}
	if strength == "" && mode != "off" {
		strength = "normal"
	}
	return mode, strength, nil
}

// closestWord is the one of words within two edits of s, or "" if there is none. Longer input is not compared: it is
// no typo of a short word, and comparing it would cost its length squared.
func closestWord(s string, words []string) string {
	if len(s) > 16 {
		return ""
	}
	best, bestDistance := "", 3
	for _, w := range words {
		// The Levenshtein distance between s and w, in bytes, one row at a time.
		prev, cur := make([]int, len(w)+1), make([]int, len(w)+1)
		for j := range prev {
			prev[j] = j
		}
		for i := 1; i <= len(s); i++ {
			cur[0] = i
			for j := 1; j < len(cur); j++ {
				cost := 1
				if s[i-1] == w[j-1] {
					cost = 0
				}
				cur[j] = min(prev[j]+1, cur[j-1]+1, prev[j-1]+cost)
			}
			prev, cur = cur, prev
		}
		if d := prev[len(prev)-1]; d < bestDistance {
			best, bestDistance = w, d
		}
	}
	return best
}

// ddosOverrides is the -ddos-* flags given, sorted, that change a setting of the strength: a 0 that stands for the
// strength's value is left out, as is -ddos-ranges, which only names where an attack comes from.
func ddosOverrides(f shieldFlags, set map[string]bool) []string {
	strengths := map[string]bool{"ddos-rate": f.rate == 0, "ddos-burst": f.burst == 0, "ddos-max-conns": f.maxConns == 0,
		"ddos-known-factor": f.knownFactor == 0, "ddos-known-rate": f.knownRate == 0, "ddos-baseline-rate": f.baseline == 0}
	out := []string{}
	for name := range set {
		if strings.HasPrefix(name, "ddos-") && name != "ddos-ranges" && !strengths[name] {
			out = append(out, "-"+name)
		}
	}
	slices.Sort(out)
	return out
}

// ddosLogAttrs are the start-up log's fields for the flood protection: its mode, its strength and the flags that change
// the strength's settings. It is called once the flags have been accepted.
func ddosLogAttrs(f shieldFlags, set map[string]bool) []any {
	mode, strength, _ := parseDDoS(f.mode)
	return []any{"ddos", mode, "ddos_strength", strength, "ddos_overrides", ddosOverrides(f, set)}
}

// configureShield builds the flood protection from the command line; set holds the flags given there or in the site
// configuration. It returns nil for -ddos off. The address-range table, if any, is read here, before the process
// confines itself.
func configureShield(log *slog.Logger, f shieldFlags, set map[string]bool, trusted []netip.Prefix) (*shield.Shield, error) {
	mode, _, err := parseDDoS(f.mode)
	if err != nil {
		return nil, err
	}
	if mode == "off" {
		if f.ranges != "" {
			return nil, errors.New("-ddos-ranges needs -ddos on or monitor")
		}
		if given := ddosOverrides(f, set); len(given) > 0 {
			log.Warn("flood protection flags have no effect with -ddos off", "flags", given)
		}
		return nil, nil
	}
	cfg, err := shieldSettings(f, set, trusted)
	if err != nil {
		return nil, err
	}
	cfg.OnEvent = func(ev shield.Event) { logShieldEvent(log, ev, cfg.MonitorOnly) }
	if f.ranges != "" {
		// Opened without blocking, so a FIFO cannot hold start-up.
		file, err := os.OpenFile(f.ranges, os.O_RDONLY|syscall.O_NONBLOCK|syscall.O_NOCTTY, 0)
		if err != nil {
			return nil, fmt.Errorf("-ddos-ranges: %w", err)
		}
		defer file.Close()
		if st, err := file.Stat(); err != nil || !st.Mode().IsRegular() || st.Size() > maxRangesBytes {
			return nil, fmt.Errorf("-ddos-ranges: %s must be a regular file of at most 256 MiB", f.ranges)
		}
		r, err := shield.LoadRanges(io.LimitReader(file, maxRangesBytes))
		if err != nil {
			return nil, fmt.Errorf("-ddos-ranges: %w", err)
		}
		cfg.Labeler = r
	}
	return shield.New(cfg)
}

// shieldSettings is the flood protection's settings: those of the strength -ddos names, with the flags in set (given on
// the command line or in the site configuration) put over them. A rate, burst, number of connections or known-client
// budget of 0 keeps the strength's value.
func shieldSettings(f shieldFlags, set map[string]bool, trusted []netip.Prefix) (shield.Config, error) {
	mode, strength, err := parseDDoS(f.mode)
	if err != nil {
		return shield.Config{}, err
	}
	if mode == "off" {
		return shield.Config{}, errors.New("-ddos off has no flood protection settings")
	}
	given := func(name string, v float64) bool { return set[name] && v != 0 }
	for _, c := range []struct {
		name      string
		value     float64
		lo, hi    float64
		zeroMeans string
		unit      string
	}{
		// A raise of 0 would be no raise at all, not the strength's, so it is refused.
		{"ddos-max-raise", f.maxRaise, 1, maxLimitRaise, "", ""},
	} {
		// The comparisons are written so that a number that is not one fails them.
		if set[c.name] && !(c.value >= c.lo && c.value <= c.hi) && (c.value != 0 || c.zeroMeans == "") {
			msg := fmt.Sprintf("-%s must be a number from %s to %s%s", c.name, number(c.lo), number(c.hi), c.unit)
			if c.zeroMeans != "" {
				msg += " (0 = " + c.zeroMeans + ")"
			}
			return shield.Config{}, errors.New(msg)
		}
	}
	cfg, err := shield.Preset(strength)
	if err != nil {
		return shield.Config{}, err
	}
	def := shield.DefaultConfig()
	or := func(v, d float64) float64 {
		if v == 0 {
			return d
		}
		return v
	}
	cfg.MonitorOnly, cfg.Trusted = mode == "monitor", trusted
	if given("ddos-rate", f.rate) {
		cfg.RequestRate = f.rate
		cfg.SubnetRate = math.Max(or(cfg.SubnetRate, def.SubnetRate), 10*f.rate)
	}
	if given("ddos-burst", f.burst) {
		cfg.RequestBurst = f.burst
	}
	if given("ddos-max-conns", float64(f.maxConns)) {
		cfg.MaxConns = f.maxConns
	}
	if given("ddos-known-factor", f.knownFactor) {
		cfg.KnownFactor = f.knownFactor
	}
	if given("ddos-known-rate", f.knownRate) {
		cfg.MinKnownRate = f.knownRate
	}
	if set["ddos-max-raise"] {
		cfg.Detector.MaxScale = f.maxRaise
	}
	if set["ddos-challenge"] {
		cfg.NoChallenge = !f.challenge
	}
	if given("ddos-baseline-rate", f.baseline) {
		cfg.Detector.InitialRate = f.baseline
	}
	if err := cfg.Validate(); err != nil {
		return shield.Config{}, fmt.Errorf("-ddos %s: %w", strength, err)
	}
	return cfg, nil
}

// number writes a flag's value as it would be typed.
func number(v float64) string { return strconv.FormatFloat(v, 'f', -1, 64) }

// logShieldEvent writes attack transitions and bounded IDS signals. Per-request logs would amplify a flood. monitor says
// that an attack is only reported (-ddos monitor), so the log does not claim it is being mitigated.
func logShieldEvent(log *slog.Logger, ev shield.Event, monitor bool) {
	attrs := []any{"state", ev.State.String(), "rate", math.Round(ev.Rate), "baseline_rate", math.Round(ev.BaselineRate), "reasons", ev.Reasons}
	if strings.HasPrefix(ev.Kind, "attack") {
		inc := ev.Incident
		clusters := make([]string, 0, len(inc.Clusters))
		for _, c := range inc.Clusters {
			clusters = append(clusters, fmt.Sprintf("%s %.0f%% from about %d addresses: %s", c.Kind, 100*c.Share, c.Sources, c.Label))
		}
		labels := make([]string, 0, len(inc.Labels))
		for _, l := range inc.Labels {
			labels = append(labels, fmt.Sprintf("%s %d", l.Label, l.Requests))
		}
		attrs = append(attrs, "started", inc.Start, "peak_rate", math.Round(inc.PeakRate), "requests", inc.Requests,
			"addresses", inc.Sources, "networks", inc.Networks, "clusters", clusters,
			"refused", inc.Refused, "challenged", inc.Challenged, "solved", inc.Solved, "banned", inc.Banned)
		if inc.DistinctLabels > 0 {
			attrs = append(attrs, "countries_or_networks", inc.DistinctLabels, "top_origins", labels)
		}
		if !inc.End.IsZero() {
			attrs = append(attrs, "ended", inc.End)
		}
	}
	msg := map[string]string{"elevated": "traffic is unusually high", "attack_start": "denial-of-service attack detected; mitigation on",
		"attack_update": "denial-of-service attack continues", "attack_end": "denial-of-service attack over", "ids_signal": "network or HTTP intrusion signal detected"}[ev.Kind]
	if monitor && ev.Kind == "attack_start" {
		msg = "denial-of-service attack detected; monitor mode, not mitigated"
	}
	if ev.Kind == "elevated" {
		log.Info(msg, attrs...)
		return
	}
	log.Warn(msg, attrs...)
}
