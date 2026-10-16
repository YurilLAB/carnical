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

// The ranges of the flood flags. The highest values are far beyond any one site's need, so that a value above them is a
// typo, and low enough that every limit the shield derives from them, multiplied by the largest raise, is a finite number.
const (
	minFloodRate    = 0.01       // -ddos-rate, -ddos-known-rate, -ddos-known-factor and -ddos-baseline-rate
	maxFloodRate    = 1_000_000  // -ddos-rate and -ddos-known-rate, requests a second
	maxFloodBurst   = 10_000_000 // -ddos-burst, requests
	minFloodConns   = 16         // -ddos-max-conns, connections
	maxFloodConns   = 10_000_000
	maxKnownFactor  = 1000       // -ddos-known-factor
	maxBaselineRate = 10_000_000 // -ddos-baseline-rate, requests a second to the whole site
	maxLimitRaise   = 100        // -ddos-max-raise: beyond it the limit of an address is no limit
)

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
	fs.Float64Var(&f.rate, "ddos-rate", 0, fmt.Sprintf("the least requests a second one address may make at all times, %v to %d (0 = the strength's: 20 strict, 50 normal, 100 relaxed); raised for an address that is answered well at a higher pace, as one with many visitors behind it is", minFloodRate, maxFloodRate))
	fs.Float64Var(&f.burst, "ddos-burst", 0, fmt.Sprintf("requests one address may make at once, 1 to %d (0 = the strength's: 80 strict, 200 normal, 400 relaxed, and at least a tenth of -ddos-rate)", maxFloodBurst))
	fs.IntVar(&f.maxConns, "ddos-max-conns", 0, fmt.Sprintf("the least connections held open at once, %d to %d (0 = 20000), raised with the site's average; a fifth are kept for clients that used the site before", minFloodConns, maxFloodConns))
	fs.Float64Var(&f.knownFactor, "ddos-known-factor", 0, fmt.Sprintf("during an attack, returning visitors who earned standing share this many times the site's usual requests a second before they are treated like strangers, %v to %d (0 = 2)", minFloodRate, maxKnownFactor))
	fs.Float64Var(&f.knownRate, "ddos-known-rate", 0, fmt.Sprintf("the least requests a second that returning visitors with standing share during an attack, %v to %d (0 = 50)", minFloodRate, maxFloodRate))
	fs.Float64Var(&f.maxRaise, "ddos-max-raise", 0, fmt.Sprintf("the most times -ddos-rate an address, or a network, may earn by its own well-answered requests, 1 to %d (default: the strength's, 10 strict, 20 normal, 50 relaxed); 1 keeps every address at -ddos-rate", maxLimitRaise))
	fs.BoolVar(&f.challenge, "ddos-challenge", true, "during an attack, ask unknown browsers to pass a short JavaScript check instead of refusing them")
	fs.Float64Var(&f.baseline, "ddos-baseline-rate", 0, fmt.Sprintf("the site's usual requests a second, %v to %d, to start from instead of learning it, so a restart during an attack is not fooled (0 = learn it)", minFloodRate, maxBaselineRate))
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
		return nil, refuseFlag("ddos", err)
	}
	// A value out of range is refused with protection off too, so that -check does not pass what switching it on fails.
	if err := checkShieldRanges(f, set); err != nil {
		return nil, err
	}
	if mode == "off" {
		if f.ranges != "" {
			return nil, refuseFlag("ddos-ranges", errors.New("-ddos-ranges needs -ddos on or monitor"))
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
	if err := checkShieldRanges(f, set); err != nil {
		return shield.Config{}, err
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
	given := func(name string, v float64) bool { return set[name] && v != 0 }
	cfg.MonitorOnly, cfg.Trusted = mode == "monitor", trusted
	burstChanged := false
	if given("ddos-rate", f.rate) {
		cfg.RequestRate = f.rate
		cfg.SubnetRate = math.Max(or(cfg.SubnetRate, def.SubnetRate), 10*f.rate)
		// A burst must be at least a tenth of the rate: a rate given alone brings its own.
		if !given("ddos-burst", f.burst) && f.rate/10 > or(cfg.RequestBurst, def.RequestBurst) {
			cfg.RequestBurst, burstChanged = f.rate/10, true
		}
	}
	if given("ddos-burst", f.burst) {
		if rate := or(cfg.RequestRate, def.RequestRate); f.burst < rate/10 {
			of := fmt.Sprintf("the request rate of -ddos %s (%s)", strength, number(rate))
			if given("ddos-rate", f.rate) {
				of = fmt.Sprintf("-ddos-rate (%s)", number(rate))
			}
			return shield.Config{}, refuseFlag("ddos-burst", fmt.Errorf("-ddos-burst (%s) must be at least a tenth of %s: use -ddos-burst %s or more",
				number(f.burst), of, number(math.Ceil(rate/10))))
		}
		cfg.RequestBurst, burstChanged = f.burst, true
	}
	if burstChanged {
		// Every request also takes from its network's bucket, whose burst would otherwise cap the address's.
		cfg.SubnetBurst = math.Max(or(cfg.SubnetBurst, def.SubnetBurst), 10*cfg.RequestBurst)
	}
	if given("ddos-max-conns", float64(f.maxConns)) {
		cfg.MaxConns = f.maxConns
		// The floor may not be above the most it can grow to, so a floor above the strength's ceiling is the ceiling.
		if f.maxConns > max(cfg.MaxConnsCeiling, def.MaxConnsCeiling) {
			cfg.MaxConnsCeiling = f.maxConns
		}
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

// checkShieldRanges refuses a -ddos-* flag in set whose value is outside its range, naming the flag and the range. A
// rate, burst, number of connections or known-client budget of 0 stands for the strength's value.
func checkShieldRanges(f shieldFlags, set map[string]bool) error {
	for _, c := range []struct {
		name      string
		value     float64
		lo, hi    float64
		zeroMeans string
		unit      string
	}{
		{"ddos-rate", f.rate, minFloodRate, maxFloodRate, "the strength's value", " requests a second"},
		{"ddos-burst", f.burst, 1, maxFloodBurst, "the strength's value", " requests"},
		{"ddos-max-conns", float64(f.maxConns), minFloodConns, maxFloodConns, "the strength's value", " connections"},
		{"ddos-known-factor", f.knownFactor, minFloodRate, maxKnownFactor, "the strength's value", ""},
		{"ddos-known-rate", f.knownRate, minFloodRate, maxFloodRate, "the strength's value", " requests a second"},
		{"ddos-baseline-rate", f.baseline, minFloodRate, maxBaselineRate, "learn it", " requests a second"},
		// A raise of 0 would be no raise at all, not the strength's, so it is refused.
		{"ddos-max-raise", f.maxRaise, 1, maxLimitRaise, "", ""},
	} {
		// The comparisons are written so that a number that is not one fails them.
		if set[c.name] && !(c.value >= c.lo && c.value <= c.hi) && (c.value != 0 || c.zeroMeans == "") {
			msg := fmt.Sprintf("-%s must be a number from %s to %s%s", c.name, number(c.lo), number(c.hi), c.unit)
			if c.zeroMeans != "" {
				msg += " (0 = " + c.zeroMeans + ")"
			}
			return refuseFlag(c.name, errors.New(msg))
		}
	}
	return nil
}

// number writes a flag's value as it would be typed.
func number(v float64) string { return strconv.FormatFloat(v, 'f', -1, 64) }

// logShieldEvent writes attack transitions, the return to normal traffic, and bounded IDS signals and their clearing, with
// the shield's mode and the signals' codes. Per-request logs would amplify a flood. monitor says
// that an attack is only reported (-ddos monitor), so the log does not claim it is being mitigated.
func logShieldEvent(log *slog.Logger, ev shield.Event, monitor bool) {
	attrs := []any{"state", ev.State.String(), "mode", ev.Mode, "rate", math.Round(ev.Rate), "baseline_rate", math.Round(ev.BaselineRate), "reasons", ev.Reasons}
	if len(ev.Codes) > 0 {
		attrs = append(attrs, "codes", ev.Codes)
	}
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
	msg := map[string]string{"elevated": "traffic is unusually high", "normal": "traffic is back to normal",
		"attack_start": "denial-of-service attack detected; mitigation on", "attack_update": "denial-of-service attack continues",
		"attack_end": "denial-of-service attack over", "ids_signal": "network or HTTP intrusion signal detected",
		"ids_clear": "intrusion signals cleared"}[ev.Kind]
	if monitor && ev.Kind == "attack_start" {
		msg = "denial-of-service attack detected; monitor mode, not mitigated"
	}
	switch ev.Kind {
	case "elevated", "normal", "ids_clear":
		log.Info(msg, attrs...)
	default:
		if msg == "" { // a kind this binary does not know is still reported, as a warning
			msg = "flood protection event"
			attrs = append(attrs, "kind", ev.Kind)
		}
		log.Warn(msg, attrs...)
	}
}
