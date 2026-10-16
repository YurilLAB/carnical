// SPDX-License-Identifier: Apache-2.0

package main

import (
	"errors"
	"fmt"
	"strings"

	"github.com/YurilLAB/coraza/carnical/proxy"
)

// limitFlag is -limit: per-client rate rules, separated by ';' in one value or given as repeated flags. Each value is
// read with the ones before it, so that the bounds on the rules (32 of them, 4 KiB of text) hold for all of them and
// an error numbers a rule as it stands among them all.
type limitFlag struct {
	text  string           // every value given, joined with ';'
	rules []proxy.RateRule // the rules, normalized
}

func (l *limitFlag) Set(s string) error {
	if strings.Trim(s, " \t;") == "" {
		return errors.New("-limit: no rule; write [METHODS] PATHS COUNT/WINDOW, such as POST /login 5/m")
	}
	text := s
	if l.text != "" {
		text = l.text + ";" + s
	}
	rules, err := proxy.ParseRateRules(text)
	if err != nil {
		return err
	}
	l.text, l.rules = text, rules
	return nil
}

// String is the rules normalized, joined with "; ".
func (l *limitFlag) String() string {
	if l == nil {
		return ""
	}
	texts := make([]string, len(l.rules))
	for i, rule := range l.rules {
		texts[i] = rule.String()
	}
	return strings.Join(texts, "; ")
}

// Get makes -limit a string to the site configuration, which gives it as a JSON string.
func (l *limitFlag) Get() any { return l.String() }

// The ranges of -login-per-minute and -api-per-minute, and the most -api-rate-paths, as the proxy takes them.
const (
	maxLoginRate = 100_000
	maxAPIRate   = 100_000
	maxAPIPaths  = 100
)

// checkRateFlags checks -login-per-minute, -api-per-minute and -api-rate-paths before the proxy does, so that an error
// names the flag and the value at fault. set holds the flags given.
func checkRateFlags(loginRate, apiRate int, apiPaths string, set map[string]bool) error {
	if loginRate < 1 || loginRate > maxLoginRate {
		return refuseFlag("login-per-minute", fmt.Errorf("-login-per-minute must be from 1 to %d", maxLoginRate))
	}
	if apiRate < 0 || apiRate > maxAPIRate {
		return refuseFlag("api-per-minute", fmt.Errorf("-api-per-minute must be 0 (off) or from 1 to %d", maxAPIRate))
	}
	paths := splitList(apiPaths)
	switch {
	case set["api-rate-paths"] && len(paths) == 0:
		// The proxy would take no prefixes for its own, /api and /graphql, which is not what was written.
		return refuseFlag("api-rate-paths", errors.New("-api-rate-paths has no path; give path prefixes separated by commas, such as /api,/graphql"))
	case len(paths) > maxAPIPaths:
		return refuseFlag("api-rate-paths", fmt.Errorf("-api-rate-paths: at most %d paths", maxAPIPaths))
	}
	for _, p := range paths {
		if trimmed := strings.TrimRight(p, "/"); trimmed != p && trimmed != "" && proxy.CheckPathPrefix(trimmed) == nil {
			return refuseFlag("api-rate-paths", fmt.Errorf("-api-rate-paths: %q has a trailing slash; write %s", p, trimmed))
		}
		if err := proxy.CheckPathPrefix(p); err != nil {
			return refuseFlag("api-rate-paths", fmt.Errorf("-api-rate-paths: %w", err))
		}
	}
	return nil
}

// rateFlagWarnings are the rate flags given that cfg, the configuration as it will run, makes no use of.
func rateFlagWarnings(cfg proxy.Config, set map[string]bool) []string {
	var out []string
	if set["login-per-minute"] && !cfg.WordPress.Enabled {
		out = append(out, "-login-per-minute has no effect without -wordpress")
	}
	if set["api-rate-paths"] && cfg.APIRate.PerMinute == 0 {
		out = append(out, "-api-rate-paths has no effect with -api-per-minute 0")
	}
	return out
}

// rateLimitAttrs are the start-up log's field for the rate limits cfg holds once the flags, the site configuration and
// a local policy are applied: each rule as text, normalized, followed by where it comes from, in the order the proxy
// applies them. A monitor rule ends in "monitor", as it is written. set holds the flags given; limitSource is where the
// -limit rules come from, "flag" or "site configuration".
func rateLimitAttrs(cfg proxy.Config, set map[string]bool, limitSource string) []any {
	rules := []string{}
	if wp := cfg.WordPress; wp.Enabled {
		login, source := wp.LoginPerMinute, "-wordpress"
		if !set["wordpress"] {
			source = "-policy" // nothing else switches it on
		}
		rules = append(rules, fmt.Sprintf("POST */wp-login.php %d/1m (%s)", login, source))
	}
	if api := cfg.APIRate; api.PerMinute > 0 {
		paths := make([]string, 0, len(api.Paths))
		for _, p := range api.Paths {
			paths = append(paths, strings.ToLower(p))
		}
		if len(paths) == 0 {
			paths = []string{"/api", "/graphql"}
		}
		rules = append(rules, fmt.Sprintf("%s %d/1m (-api-per-minute)", strings.Join(paths, ","), api.PerMinute))
	}
	for _, rule := range cfg.Limits {
		rules = append(rules, rule.String()+" ("+limitSource+")")
	}
	return []any{"rate_limits", rules}
}
