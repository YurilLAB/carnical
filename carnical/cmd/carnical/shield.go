// SPDX-License-Identifier: Apache-2.0

package main

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math"
	"net/netip"
	"os"
	"strings"

	"github.com/YurilLAB/coraza/carnical/shield"
)

const maxRangesBytes = 256 << 20

type shieldFlags struct {
	mode        string
	rate, burst float64
	maxConns    int
	challenge   bool
	baseline    float64
	ranges      string
	// knownFactor and knownRate are the budget returning visitors with standing share during an attack (0 means the default).
	knownFactor, knownRate float64
	// maxRaise is the most times its configured limit an address, or a network, may earn; 1 keeps the limits fixed.
	maxRaise float64
}

// configureShield builds the flood protection from the command line. It returns nil for -ddos off. The address-range
// table, if any, is read here, before the process confines itself.
func configureShield(log *slog.Logger, f shieldFlags, trusted []netip.Prefix) (*shield.Shield, error) {
	switch f.mode {
	case "off":
		if f.ranges != "" {
			return nil, errors.New("-ddos-ranges needs -ddos on or monitor")
		}
		return nil, nil
	case "on", "monitor":
	default:
		return nil, fmt.Errorf("-ddos must be on, monitor or off, not %q", f.mode)
	}
	cfg, err := shieldSettings(f, trusted)
	if err != nil {
		return nil, err
	}
	cfg.OnEvent = func(ev shield.Event) { logShieldEvent(log, ev, cfg.MonitorOnly) }
	if f.ranges != "" {
		file, err := os.Open(f.ranges)
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

// shieldSettings is the flood protection's settings as the command line gives them.
func shieldSettings(f shieldFlags, trusted []netip.Prefix) (shield.Config, error) {
	// Zero would be taken for "not set" and become the default, and a number that is not one compares as neither.
	if !(f.maxRaise >= 1 && f.maxRaise <= maxLimitRaise) {
		return shield.Config{}, fmt.Errorf("-ddos-max-raise must be between 1 and %d", maxLimitRaise)
	}
	cfg := shield.Config{
		RequestRate: f.rate, RequestBurst: f.burst, MaxConns: f.maxConns, NoChallenge: !f.challenge,
		MonitorOnly: f.mode == "monitor", Trusted: trusted, KnownFactor: f.knownFactor, MinKnownRate: f.knownRate,
		Detector: shield.DetectorConfig{InitialRate: f.baseline, MaxScale: f.maxRaise},
	}
	if cfg.SubnetRate == 0 && f.rate > 0 {
		cfg.SubnetRate = math.Max(500, 10*f.rate)
	}
	return cfg, nil
}

// maxLimitRaise is the highest -ddos-max-raise: beyond it the limit of an address is no limit.
const maxLimitRaise = 100

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
