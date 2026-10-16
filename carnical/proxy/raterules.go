// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"errors"
	"fmt"
	"net/http"
	"path"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

// RateRule is one per-client rate limit: a client (an IPv4 address or an IPv6 /64, as the shield counts it) may make at
// most Count requests that match the rule in any span of Window. Rules are written as text, as in "POST /login 5/m"
// (see ParseRateRules).
type RateRule struct {
	// Methods are the HTTP methods the rule counts, in upper case. GET also counts HEAD. None counts every method.
	Methods []string
	// Paths are plain path prefixes, matched by path segment as APIRatePolicy matches them: /api counts /api and
	// /api/orders, also as the path info after a PHP script in the first segment (/index.php/api), but not /apiary;
	// / counts every path.
	Paths []string
	// Count is how many requests a client may make in a window, 1 to 1,000,000.
	Count int
	// Window is the span counted: whole seconds, from 1s to 1h.
	Window time.Duration
	// Monitor only reports a request the rule would refuse, and never refuses it.
	Monitor bool
}

// Bounds on the rate rules, which keep the work a request costs and the memory the rules hold small.
const (
	maxRateRules       = 32
	maxRatePathsInRule = 16
	maxRatePaths       = 100
	maxRateMethods     = 8
	maxRateCount       = 1_000_000
	maxRateRulesText   = 4 << 10
)

var (
	errRateCount  = errors.New("the count must be a whole number from 1 to 1000000, optionally with k (to switch a rule off, remove it)")
	errRateWindow = errors.New("the window must be between 1s and 1h")
)

// String is the rule in the form ParseRateRules reads, normalized, as in "POST /login 5/1m".
func (r RateRule) String() string {
	var b strings.Builder
	if len(r.Methods) > 0 {
		b.WriteString(strings.Join(r.Methods, ","))
		b.WriteByte(' ')
	}
	b.WriteString(strings.Join(r.Paths, ","))
	b.WriteByte(' ')
	b.WriteString(strconv.Itoa(r.Count))
	b.WriteByte('/')
	switch w := r.Window; {
	case w%time.Hour == 0:
		b.WriteString(strconv.FormatInt(int64(w/time.Hour), 10) + "h")
	case w%time.Minute == 0:
		b.WriteString(strconv.FormatInt(int64(w/time.Minute), 10) + "m")
	default:
		b.WriteString(strconv.FormatInt(int64(w/time.Second), 10) + "s")
	}
	if r.Monitor {
		b.WriteString(" monitor")
	}
	return b.String()
}

// matches reports whether the rule counts a request whose route path (see routePath) is route.
func (r *RateRule) matches(req *http.Request, route string) bool {
	if len(r.Methods) > 0 {
		found := false
		for _, m := range r.Methods {
			if m == req.Method || m == http.MethodGet && req.Method == http.MethodHead {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return matchesPrefix(r.Paths, route)
}

// knownMethods are the methods a misspelling is compared with.
var knownMethods = []string{http.MethodGet, http.MethodHead, http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete, http.MethodOptions}

// normalized checks one rule and returns it with its methods in upper case, its paths in lower case and neither
// repeated, sharing nothing with r.
func (r RateRule) normalized() (RateRule, error) {
	out := RateRule{Count: r.Count, Window: r.Window, Monitor: r.Monitor}
	if len(r.Methods) > maxRateMethods {
		return out, fmt.Errorf("at most %d methods in a rule", maxRateMethods)
	}
	for _, m := range r.Methods {
		if m == "*" && len(r.Methods) == 1 {
			break // every method, which is no method named
		}
		// A method this proxy does not know is allowed (WebDAV has MKCOL, PROPFIND and others), unless it looks like a
		// misspelling of one it does: a rule for "PSOT" would never count anything.
		upper := strings.ToUpper(m)
		near, distance := closest(upper, knownMethods)
		if len(m) == 0 || len(m) > 16 || strings.Trim(upper, "ABCDEFGHIJKLMNOPQRSTUVWXYZ") != "" || distance > 0 && distance <= 2 {
			hint := ""
			if distance <= 2 {
				hint = " (did you mean " + strings.Join(near, " or ") + "?)"
			}
			return out, fmt.Errorf("%q is not an HTTP method%s", m, hint)
		}
		if !contains(out.Methods, upper) {
			out.Methods = append(out.Methods, upper)
		}
	}
	if len(r.Paths) == 0 {
		return out, errors.New("no path; write [METHODS] PATHS COUNT/WINDOW, such as POST /login 5/m")
	}
	if len(r.Paths) > maxRatePathsInRule {
		return out, fmt.Errorf("at most %d paths in a rule (%d in all)", maxRatePathsInRule, maxRatePaths)
	}
	paths, err := normalizePrefixes(r.Paths)
	if err != nil {
		return out, err
	}
	for _, p := range paths {
		if strings.Contains(p, ",") {
			return out, fmt.Errorf("path %q has a comma, which separates paths", p)
		}
		if !contains(out.Paths, p) {
			out.Paths = append(out.Paths, p)
		}
	}
	if r.Count < 1 || r.Count > maxRateCount {
		return out, errRateCount
	}
	if r.Window < time.Second || r.Window > time.Hour {
		return out, errRateWindow
	}
	if r.Window%time.Second != 0 {
		return out, errors.New("the window must be a whole number of seconds")
	}
	return out, nil
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

// normalizeRateRules checks a set of rules as a whole and returns a normalized copy. On an error it also returns the
// index of the rule at fault.
func normalizeRateRules(rules []RateRule) ([]RateRule, int, error) {
	if len(rules) == 0 {
		return nil, 0, nil
	}
	out := make([]RateRule, 0, len(rules))
	seen := make(map[string]int, len(rules))
	paths := 0
	for i, rule := range rules {
		if i == maxRateRules {
			return nil, i, fmt.Errorf("at most %d rules", maxRateRules)
		}
		n, err := rule.normalized()
		if err != nil {
			return nil, i, err
		}
		if paths += len(n.Paths); paths > maxRatePaths {
			return nil, i, fmt.Errorf("at most %d paths in all the rules (this rule brings them to %d)", maxRatePaths, paths)
		}
		text := n.String()
		if j, found := seen[text]; found {
			return nil, i, fmt.Errorf("repeats rule %d", j+1)
		}
		seen[text] = i
		out = append(out, n)
	}
	return out, 0, nil
}

// ParseRateRules reads rate rules written as text, separated by ';':
//
//	[METHODS] PATHS COUNT/WINDOW [monitor]
//
// METHODS is "*" or methods separated by commas, each letters only and at most 16 of them (GET also counts HEAD; with
// none, every method counts); PATHS are path prefixes separated by commas; COUNT is a whole number, optionally with k
// for thousands; WINDOW is s, m or h with an optional whole multiplier, from 1s to 1h. For example
// "POST /login,/register 10/m; /api 600/m; GET /search 30/10s monitor". There are at most 32 rules, 16 paths in a rule
// and 100 in all, and the text is at most 4 KiB, also when written out in full by String. The errors are worded for the
// -limit flag; a caller that collects rules from several places parses them joined with ';', so that the bounds hold
// for all of them.
func ParseRateRules(text string) ([]RateRule, error) {
	if len(text) > maxRateRulesText {
		return nil, errors.New("-limit is longer than 4 KiB")
	}
	var rules []RateRule
	var texts []string
	for _, segment := range strings.Split(text, ";") {
		segment = strings.Trim(segment, " \t")
		if segment == "" {
			continue
		}
		if len(rules) == maxRateRules {
			return nil, ruleError(len(rules)+1, segment, fmt.Errorf("at most %d rules", maxRateRules))
		}
		rule, err := parseRateRule(segment)
		if err == nil {
			_, err = rule.normalized()
		}
		if err != nil {
			return nil, ruleError(len(rules)+1, segment, err)
		}
		rules, texts = append(rules, rule), append(texts, segment)
	}
	if len(rules) == 0 {
		return nil, errors.New("-limit: no rule; write [METHODS] PATHS COUNT/WINDOW, such as POST /login 5/m")
	}
	normalized, at, err := normalizeRateRules(rules)
	if err != nil {
		return nil, ruleError(at+1, texts[at], err)
	}
	// The rules written out in full, as a caller writes them back (joined with "; "), must read again: "1k/h" becomes
	// "1000/1h".
	written := 2 * (len(normalized) - 1)
	for _, rule := range normalized {
		written += len(rule.String())
	}
	if written > maxRateRulesText {
		return nil, errors.New("-limit is longer than 4 KiB when written out in full, as in 1000/1h for 1k/h")
	}
	return normalized, nil
}

// ruleError names the rule a problem is in, by its number and its text.
func ruleError(n int, text string, problem error) error {
	return fmt.Errorf("-limit rule %d (%q): %w", n, excerpt(text), problem)
}

// excerpt is a rule's text cut to at most 80 bytes, for an error.
func excerpt(text string) string {
	if len(text) <= 80 {
		return text
	}
	cut := 77
	for cut > 0 && !utf8.RuneStart(text[cut]) {
		cut--
	}
	return text[:cut] + "..."
}

// parseRateRule reads one rule. Each word's role comes from its place: the rate is the one word with a slash after its
// first character, the paths come right before it, and the methods, if any, before them.
func parseRateRule(segment string) (RateRule, error) {
	words := strings.FieldsFunc(segment, func(c rune) bool { return c == ' ' || c == '\t' })
	rate := -1
	for i, w := range words {
		if !strings.HasPrefix(w, "/") && strings.Contains(w, "/") {
			if rate >= 0 {
				return RateRule{}, errors.New("two rates; split them into two rules")
			}
			rate = i
		}
	}
	if rate < 0 {
		return RateRule{}, errors.New("no rate; write [METHODS] PATHS COUNT/WINDOW, such as POST /login 5/m")
	}
	var rule RateRule
	before := words[:rate]
	// "monitor" before the rate would otherwise be taken as a method or a path, giving a rule that never counts.
	for _, w := range before {
		for _, part := range strings.Split(w, ",") {
			if strings.EqualFold(part, "monitor") {
				return rule, errors.New(`"monitor" goes after the rate, as in /login 5/m monitor`)
			}
		}
	}
	if len(before) >= 2 && !strings.HasPrefix(before[0], "/") {
		if before[0] != "*" {
			rule.Methods = strings.Split(before[0], ",")
		}
		before = before[1:]
	}
	switch {
	case len(before) == 0:
		return rule, errors.New("no path; write [METHODS] PATHS COUNT/WINDOW, such as POST /login 5/m")
	case len(before) > 1:
		if strings.HasPrefix(before[1], "/") {
			return rule, fmt.Errorf("%q: write several paths with commas, as in /login,/register", before[1])
		}
		return rule, fmt.Errorf("%q is not a path; paths start with /, as in /login", before[1])
	}
	rule.Paths = strings.Split(before[0], ",")
	for _, p := range rule.Paths {
		if !strings.HasPrefix(p, "/") {
			return rule, fmt.Errorf("%q is not a path; paths start with /, as in /login", p)
		}
	}
	for i, w := range words[rate+1:] {
		if i == 0 && strings.EqualFold(w, "monitor") {
			rule.Monitor = true
			continue
		}
		return rule, fmt.Errorf("unknown word %q%s", w, didYouMean(strings.ToLower(w), []string{"monitor"}))
	}
	count, window, _ := strings.Cut(words[rate], "/")
	var err error
	if rule.Count, err = parseRateCount(count); err != nil {
		return rule, err
	}
	if rule.Window, err = parseRateWindow(words[rate], window); err != nil {
		return rule, err
	}
	return rule, nil
}

// parseRateCount reads digits with an optional k (thousands). Anything else, or a count out of range, is refused with
// the same words.
func parseRateCount(s string) (int, error) {
	scale := 1
	if strings.HasSuffix(s, "k") || strings.HasSuffix(s, "K") {
		s, scale = s[:len(s)-1], 1000
	}
	if s == "" || len(s) > 7 || strings.Trim(s, "0123456789") != "" {
		return 0, errRateCount
	}
	// The range is checked before multiplying: seven digits times a thousand overflow a 32-bit int.
	n, err := strconv.Atoi(s)
	if err != nil || n < 1 || n > maxRateCount/scale {
		return 0, errRateCount
	}
	return n * scale, nil
}

// parseRateWindow reads an optional whole multiplier and a unit, s, m or h.
func parseRateWindow(rate, s string) (time.Duration, error) {
	digits := len(s) - len(strings.TrimLeft(s, "0123456789"))
	multiplier, unit := 1, s[digits:]
	if digits > 0 {
		if digits > 4 {
			return 0, errRateWindow
		}
		multiplier, _ = strconv.Atoi(s[:digits]) // at most four digits
	}
	var size time.Duration
	switch strings.ToLower(unit) {
	case "s":
		size = time.Second
	case "m":
		size = time.Minute
	case "h":
		size = time.Hour
	case "":
		// A bare number is most likely seconds: show it with its unit, and in minutes when it is whole minutes.
		count, _, _ := strings.Cut(rate, "/")
		write := []string{}
		if digits > 0 && multiplier <= 3600 {
			write = append(write, count+"/"+strconv.Itoa(multiplier)+"s")
		}
		if digits > 0 && multiplier%60 == 0 && multiplier <= 3600 {
			write = append(write, count+"/"+strconv.Itoa(multiplier/60)+"m")
		}
		if len(write) == 0 {
			write = []string{count + "/s", count + "/m", count + "/h"}
		}
		last := len(write) - 1
		if last > 0 {
			write = []string{strings.Join(write[:last], ", "), write[last]}
		}
		return 0, fmt.Errorf("%q: the window needs a unit, s, m or h; write %s", rate, strings.Join(write, " or "))
	default:
		hint := ""
		if strings.Trim(strings.ToLower(unit), "abcdefghijklmnopqrstuvwxyz") == "" {
			hint = didYouMean(strings.ToLower(unit), []string{"s", "m", "h"})
		}
		return 0, fmt.Errorf("%q: unknown window unit %q; use s, m or h, such as 5/m, 100/10s or 1k/h%s", rate, unit, hint)
	}
	window := time.Duration(multiplier) * size
	if window < time.Second || window > time.Hour {
		return 0, errRateWindow
	}
	return window, nil
}

// closest returns the choices nearest to word in edits, and how many edits that is; a word longer than 32 bytes is
// near nothing.
func closest(word string, choices []string) (near []string, distance int) {
	distance = 1 << 30
	if len(word) > 32 {
		return nil, distance
	}
	for _, c := range choices {
		switch d := editDistance(word, c); {
		case d < distance:
			near, distance = []string{c}, d
		case d == distance:
			near = append(near, c)
		}
	}
	return near, distance
}

// didYouMean suggests the one choice one or two edits from word, as " (did you mean X?)", or nothing when there is no
// such choice or two are equally near.
func didYouMean(word string, choices []string) string {
	if near, distance := closest(word, choices); len(near) == 1 && distance > 0 && distance <= 2 {
		return " (did you mean " + near[0] + "?)"
	}
	return ""
}

// editDistance is the number of edits between two short strings, in bytes, where an edit adds, removes or changes a
// byte or swaps two next to each other (the optimal string alignment distance): "PSOT" is one edit from POST.
func editDistance(a, b string) int {
	before, prev, row := make([]int, len(b)+1), make([]int, len(b)+1), make([]int, len(b)+1)
	for j := range prev {
		prev[j] = j
	}
	for i := 1; i <= len(a); i++ {
		row[0] = i
		for j := 1; j <= len(b); j++ {
			cost := 1
			if a[i-1] == b[j-1] {
				cost = 0
			}
			row[j] = min(prev[j]+1, row[j-1]+1, prev[j-1]+cost)
			if i > 1 && j > 1 && a[i-1] == b[j-2] && a[i-2] == b[j-1] {
				row[j] = min(row[j], before[j-2]+1)
			}
		}
		before, prev, row = prev, row, before
	}
	return prev[len(b)]
}

// CheckPathPrefix reports what is wrong with a path prefix of APIRatePolicy.Paths or RateRule.Paths, if anything, so that
// a caller can name the setting it came from.
func CheckPathPrefix(prefix string) error {
	_, err := normalizePrefixes([]string{prefix})
	return err
}

// normalizePrefixes checks path prefixes and returns them in lower case: plain absolute paths, with no trailing slash,
// query, percent-encoding or path parameters, which are matched by path segment against a request's routePath.
func normalizePrefixes(paths []string) ([]string, error) {
	out := make([]string, len(paths))
	for i, prefix := range paths {
		if prefix == "" || prefix[0] != '/' {
			return nil, fmt.Errorf("%q is not a path; paths start with /, as in /login", prefix)
		}
		if len(prefix) > 2048 || path.Clean(prefix) != prefix || strings.ContainsAny(prefix, "%?;#\\") || (PathPolicy{}).check(prefix) != nil {
			return nil, fmt.Errorf("path %q must be a plain absolute path without a trailing slash, query, %%-encoding or ; parameters", prefix)
		}
		out[i] = strings.ToLower(prefix)
	}
	return out, nil
}

// matchesPrefix reports whether a route path (see routePath) is one of the prefixes or under one, either as it is or as
// the path info after a PHP script in its first segment, so that a limit on /login also counts /index.php/login, which
// Laravel, Symfony, Drupal and WordPress route as /login, and Symfony's older /app.php/login. routePath leaves the route
// in lower case, as runsScript reads it, so /INDEX.PHP/login is the same.
func matchesPrefix(prefixes []string, route string) bool {
	if matchesRoute(prefixes, route) {
		return true
	}
	if len(route) < 2 || route[0] != '/' {
		return false
	}
	end := strings.IndexByte(route[1:], '/') + 1
	return end > 0 && strings.HasSuffix(route[:end], ".php") && matchesRoute(prefixes, route[end:])
}

// matchesRoute reports whether route is one of the prefixes or under one, or a prefix with a format suffix such as
// .json, which Rails routes to the same action by default: /login.json is /login. A script extension, as in
// /login.php, names another script, so it is not the prefix.
func matchesRoute(prefixes []string, route string) bool {
	for _, prefix := range prefixes {
		if prefix == "/" || route == prefix {
			return true
		}
		if len(route) <= len(prefix) || route[:len(prefix)] != prefix {
			continue
		}
		switch rest := route[len(prefix):]; rest[0] {
		case '/':
			return true
		case '.':
			if isFormatSuffix(rest[1:]) && !wpScript.MatchString(rest) {
				return true
			}
		}
	}
	return false
}

// isFormatSuffix reports whether ext, the text after the last dot of a route, is a format such as json or xml: one to
// 16 ASCII letters and digits.
func isFormatSuffix(ext string) bool {
	if ext == "" || len(ext) > 16 {
		return false
	}
	for i := 0; i < len(ext); i++ {
		if c := ext[i]; (c < 'a' || c > 'z') && (c < '0' || c > '9') {
			return false
		}
	}
	return true
}
