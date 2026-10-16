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

// rateLimitAttrs are the start-up log's field for the rate limits cfg holds once the flags, the site configuration and
// a local policy are applied: each rule as text, normalized, followed by where it comes from, in the order the proxy
// applies them. A monitor rule ends in "monitor", as it is written. set holds the flags given; limitSource is where the
// -limit rules come from, "flag" or "site configuration".
func rateLimitAttrs(cfg proxy.Config, set map[string]bool, limitSource string) []any {
	rules := []string{}
	if wp := cfg.WordPress; wp.Enabled {
		login, source := wp.LoginPerMinute, "-wordpress"
		if login <= 0 {
			login = 10 // as the proxy takes it
		}
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
