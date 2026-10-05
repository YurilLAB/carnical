// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"bytes"
	"fmt"
	"net/netip"
	"sort"
	"strings"
)

// Change is one difference between two policies, in words, with a stable code.
type Change struct {
	// Code names the kind of change. It does not change between releases, so a UI can key on it ("mode.lowered").
	Code string `json:"code"`
	// Section is the part of the policy it is in (the name of its field).
	Section string `json:"section"`
	// Message says what changed, in a plain sentence. It holds only values from the policy's own vocabulary (names, numbers,
	// paths, addresses), never the customer's notes.
	Message string `json:"message"`
	// Weakens is true if the change lowers protection. The UI asks the customer to confirm it with their password.
	Weakens bool `json:"weakens"`
	// Risk is true if the change could turn every visitor away (a very wide block range). It asks for confirmation too.
	Risk bool `json:"risk,omitempty"`
}

// Diff lists every difference between two policies, in the order of the policy's sections. Both are normalised first, so a
// change of order or case is not a difference. The revision is not a setting and is not compared. Nothing is reported for
// a note's text on an exclusion or rule, because it changes nothing the edge does.
func Diff(oldP, newP Policy) []Change {
	a, b := oldP.Normalize(), newP.Normalize()
	var d differ
	d.mode(a, b)
	d.protection(a, b)
	d.body(a, b)
	d.methods(a, b)
	d.hosts(a, b)
	d.groups(a, b)
	d.exclusions(a, b)
	d.rules(a, b)
	d.ipLists(a, b)
	d.allowPaths(a, b)
	d.flags(a, b)
	d.denyHeaders(a, b)
	d.vpatch(a, b)
	d.api(a, b)
	if a.Note != b.Note {
		d.add("note.changed", "note", false, "The note was changed.")
	}
	return d.out
}

// Weakens returns the changes from oldP to newP that lower protection: the mode lowered, a higher threshold or a lower paranoia
// level, a rule group turned off or to log only, an exclusion added, an address or page added to what is never inspected, a
// block-list entry taken away, a body limit raised, an upload or path restriction relaxed, a host or method added (or the host
// list emptied), a deny-header or virtual-patch tier or declared software removed, API protection lowered, and an API or
// body-format section changed while it is enforced. The web UI asks the customer to confirm a change that has any, with their
// password. A change that only strengthens, or that narrows an exclusion or allow list, is not reported.
func Weakens(oldP, newP Policy) []Change {
	var out []Change
	for _, c := range Diff(oldP, newP) {
		if c.Weakens {
			out = append(out, c)
		}
	}
	return out
}

// Confirm returns the changes that need the customer's password: the ones that weaken protection (Weakens) and the ones that
// could turn every visitor away (a block-list range wider than /16 for IPv4 or /32 for IPv6).
func Confirm(oldP, newP Policy) []Change {
	var out []Change
	for _, c := range Diff(oldP, newP) {
		if c.Weakens || c.Risk {
			out = append(out, c)
		}
	}
	return out
}

type differ struct{ out []Change }

func (d *differ) add(code, section string, weakens bool, format string, args ...any) {
	d.out = append(d.out, Change{Code: code, Section: section, Weakens: weakens, Message: fmt.Sprintf(format, args...)})
}

var modeRank = map[Mode]int{ModeOff: 0, ModeMonitor: 1, ModeBlock: 2}
var modeWords = map[Mode]string{ModeBlock: "block (attacks are refused)", ModeMonitor: "monitor (attacks are recorded and let through)", ModeOff: "off (no rules run)"}

func (d *differ) mode(a, b Policy) {
	if a.Mode == b.Mode {
		return
	}
	lowered := modeRank[b.Mode] < modeRank[a.Mode]
	code := "mode.raised"
	if lowered {
		code = "mode.lowered"
	}
	d.add(code, "mode", lowered, "Mode changed from %s to %s.", modeWords[a.Mode], modeWords[b.Mode])
}

func (d *differ) protection(a, b Policy) {
	pa, ta := a.effective()
	pb, tb := b.effective()
	if pb != pa {
		code := "paranoia.raised"
		if pb < pa {
			code = "paranoia.lowered"
		}
		d.add(code, "sensitivity", pb < pa, "The rule set's paranoia level changed from %d to %d (sensitivity %s to %s): %s.", pa, pb, a.Sensitivity, b.Sensitivity,
			map[bool]string{true: "fewer kinds of attack are looked for", false: "more kinds of attack are looked for"}[pb < pa])
	}
	if tb != ta {
		code := "threshold.lowered"
		if tb > ta {
			code = "threshold.raised"
		}
		d.add(code, "sensitivity", tb > ta, "The score that blocks a request changed from %d to %d (sensitivity %s to %s): %s.", ta, tb, a.Sensitivity, b.Sensitivity,
			map[bool]string{true: "a request has to look worse to be stopped", false: "a request is stopped sooner"}[tb > ta])
	}
	if pb == pa && tb == ta && (a.Sensitivity != b.Sensitivity || !sameInt(a.Threshold, b.Threshold)) {
		d.add("sensitivity.changed", "sensitivity", false, "The sensitivity setting changed from %s to %s, which blocks exactly the same requests.", a.Sensitivity, b.Sensitivity)
	}
}

func sameInt(a, b *int) bool {
	return (a == nil && b == nil) || (a != nil && b != nil && *a == *b)
}

func (d *differ) body(a, b Policy) {
	for _, f := range []struct {
		name, code string
		old, new   int64
	}{
		{"The largest request body (and file upload) allowed", "body.upload_limit", a.Body.MaxUploadBytes, b.Body.MaxUploadBytes},
		{"The largest body that is not a file upload", "body.form_limit", a.Body.MaxFormBytes, b.Body.MaxFormBytes},
	} {
		switch {
		case f.new > f.old:
			d.add(f.code+"_raised", "body", true, "%s was raised from %d to %d bytes: larger requests are inspected, at more cost, and let through.", f.name, f.old, f.new)
		case f.new < f.old:
			d.add(f.code+"_lowered", "body", false, "%s was lowered from %d to %d bytes.", f.name, f.old, f.new)
		}
	}
}

func (d *differ) methods(a, b Policy) {
	added, removed := setDiff(b.AllowedMethods, a.AllowedMethods), setDiff(a.AllowedMethods, b.AllowedMethods)
	for _, m := range added {
		d.add("method.added", "allowed_methods", true, "The method %s is now accepted.", m)
	}
	for _, m := range removed {
		d.add("method.removed", "allowed_methods", false, "The method %s is no longer accepted.", m)
	}
}

func (d *differ) hosts(a, b Policy) {
	switch {
	case len(a.AllowedHosts) == 0 && len(b.AllowedHosts) > 0:
		d.add("hosts.restricted", "allowed_hosts", false, "The site now answers only to %d host name(s).", len(b.AllowedHosts))
	case len(a.AllowedHosts) > 0 && len(b.AllowedHosts) == 0:
		d.add("hosts.opened", "allowed_hosts", true, "The list of host names was emptied: the site now answers to any host name.")
	default:
		for _, h := range setDiff(b.AllowedHosts, a.AllowedHosts) {
			d.add("host.added", "allowed_hosts", true, "The site now also answers to the host name %s.", h)
		}
		for _, h := range setDiff(a.AllowedHosts, b.AllowedHosts) {
			d.add("host.removed", "allowed_hosts", false, "The site no longer answers to the host name %s.", h)
		}
	}
}

var stateRank = map[GroupState]int{GroupOff: 0, GroupLog: 1, GroupOn: 2}
var stateWords = map[GroupState]string{GroupOn: "on", GroupLog: "log only", GroupOff: "off"}

func groupState(p Policy, name string) GroupState {
	if s, ok := p.RuleGroups[name]; ok && validStates[s] {
		return s
	}
	return GroupOn
}

func (d *differ) groups(a, b Policy) {
	for _, g := range groups {
		sa, sb := groupState(a, g.Name), groupState(b, g.Name)
		if sa == sb {
			continue
		}
		code := "rule_group." + map[GroupState]string{GroupOn: "on", GroupLog: "log", GroupOff: "off"}[sb]
		d.add(code, "rule_groups", stateRank[sb] < stateRank[sa], "The %s rules (%s) went from %s to %s.", g.Name, g.Title, stateWords[sa], stateWords[sb])
	}
}

// exclusionTuple is one (path prefix, category, target) an exclusion keeps rules away from; target "" is the whole request.
type exclusionTuple struct{ path, cat, target string }

func tuples(list []Exclusion) []exclusionTuple {
	var out []exclusionTuple
	for _, e := range list {
		targets := e.Targets
		if len(targets) == 0 {
			targets = []string{""}
		}
		for _, c := range e.Categories {
			for _, t := range targets {
				out = append(out, exclusionTuple{e.Path, c, t})
			}
		}
	}
	return out
}

// covers says whether an exclusion tuple already keeps rules away from everything another does: the same category, a path
// that is the same or a prefix of the other's, and the whole request, the same part, or the whole of a kind of part
// (args covers arg:NAME).
func (s exclusionTuple) covers(t exclusionTuple) bool {
	if s.cat != t.cat || !strings.HasPrefix(t.path, s.path) {
		return false
	}
	switch {
	case s.target == "" || s.target == t.target:
		return true
	case s.target == "args":
		return strings.HasPrefix(t.target, "arg:")
	case s.target == "cookies":
		return strings.HasPrefix(t.target, "cookie:")
	case s.target == "headers":
		return strings.HasPrefix(t.target, "header:")
	}
	return false
}

func anyCovers(set []exclusionTuple, t exclusionTuple) bool {
	for _, s := range set {
		if s.covers(t) {
			return true
		}
	}
	return false
}

func describeExclusion(e Exclusion) string {
	what := "the whole request"
	if len(e.Targets) > 0 {
		what = strings.Join(e.Targets, ", ")
	}
	return fmt.Sprintf("%s rules are kept away from %s on %s", strings.Join(e.Categories, ", "), what, e.Path)
}

func (d *differ) exclusions(a, b Policy) {
	ta, tb := tuples(a.Exclusions), tuples(b.Exclusions)
	for _, e := range b.Exclusions {
		if widened(tuples([]Exclusion{e}), ta) {
			d.add("exclusion.added", "exclusions", true, "An exclusion was added: %s.", describeExclusion(e))
		}
	}
	for _, e := range a.Exclusions {
		if widened(tuples([]Exclusion{e}), tb) {
			d.add("exclusion.removed", "exclusions", false, "An exclusion was removed: %s.", describeExclusion(e))
		}
	}
}

// widened reports whether any of the tuples is not covered by the set.
func widened(ts, set []exclusionTuple) bool {
	for _, t := range ts {
		if !anyCovers(set, t) {
			return true
		}
	}
	return false
}

func sameMatching(x, y CustomRule) bool {
	return x.Field == y.Field && x.Operator == y.Operator && x.Value == y.Value && x.CaseSensitive == y.CaseSensitive && strings.Join(x.Values, "\x00") == strings.Join(y.Values, "\x00")
}

func (d *differ) rules(a, b Policy) {
	old := map[int]CustomRule{}
	for _, r := range a.CustomRules {
		old[r.ID] = r
	}
	seen := map[int]bool{}
	for _, n := range b.CustomRules {
		seen[n.ID] = true
		o, had := old[n.ID]
		switch {
		case !had:
			d.add("custom_rule.added", "custom_rules", false, "Custom rule %d was added (%s).", n.ID, n.Action)
		case o.Action == ActionBlock && n.Action == ActionLog:
			d.add("custom_rule.relaxed", "custom_rules", true, "Custom rule %d was changed from block to log only.", n.ID)
		case o.Action == ActionLog && n.Action == ActionBlock:
			d.add("custom_rule.raised", "custom_rules", false, "Custom rule %d was changed from log only to block.", n.ID)
		case !sameMatching(o, n):
			// What a rule matches cannot be compared in general, so changing one that blocks counts as lowering protection.
			d.add("custom_rule.changed", "custom_rules", n.Action == ActionBlock, "Custom rule %d was changed to match something else (%s).", n.ID, n.Action)
		}
	}
	for _, o := range a.CustomRules {
		if !seen[o.ID] {
			d.add("custom_rule.removed", "custom_rules", o.Action == ActionBlock, "Custom rule %d was removed (it was %s).", o.ID, o.Action)
		}
	}
}

func prefixCovered(p netip.Prefix, set []netip.Prefix) bool {
	for _, s := range set {
		if s.Addr().Is4() == p.Addr().Is4() && s.Bits() <= p.Bits() && s.Contains(p.Addr()) {
			return true
		}
	}
	return false
}

// uncovered returns the entries of list that no entry of set contains.
func uncovered(list, set []netip.Prefix) []netip.Prefix {
	var out []netip.Prefix
	for _, p := range list {
		if !prefixCovered(p, set) {
			out = append(out, p)
		}
	}
	return out
}

func listWords(ps []netip.Prefix) string {
	const show = 5
	var parts []string
	for i, p := range ps {
		if i == show {
			parts = append(parts, fmt.Sprintf("and %d more", len(ps)-show))
			break
		}
		parts = append(parts, p.String())
	}
	return strings.Join(parts, ", ")
}

func (d *differ) ipLists(a, b Policy) {
	allowOld, allowNew := prefixes(a.AllowIPs), prefixes(b.AllowIPs)
	if added := uncovered(allowNew, allowOld); len(added) > 0 {
		d.add("allow_ip.added", "allow_ips", true, "%d address range(s) were added to the allow list, which is never inspected, banned or blocked: %s.", len(added), listWords(added))
	}
	if removed := uncovered(allowOld, allowNew); len(removed) > 0 {
		d.add("allow_ip.removed", "allow_ips", false, "%d address range(s) were taken off the allow list: %s.", len(removed), listWords(removed))
	}
	blockOld, blockNew := prefixes(a.BlockIPs), prefixes(b.BlockIPs)
	if added := uncovered(blockNew, blockOld); len(added) > 0 {
		d.add("block_ip.added", "block_ips", false, "%d address range(s) were added to the block list: %s.", len(added), listWords(added))
		for _, p := range added {
			if wideBlock(p) {
				d.out = append(d.out, Change{Code: "block_ip.wide", Section: "block_ips", Risk: true,
					Message: fmt.Sprintf("The block list now holds %s, a range wider than /%d: in block mode every visitor from it is refused, which can be a whole provider, a whole country, or everyone.", p, map[bool]int{true: 16, false: 32}[p.Addr().Is4()])})
			}
		}
	}
	if removed := uncovered(blockOld, blockNew); len(removed) > 0 {
		d.add("block_ip.removed", "block_ips", true, "%d address range(s) were taken off the block list: %s.", len(removed), listWords(removed))
	}
}

func pathCovered(p string, set []string) bool {
	for _, s := range set {
		if strings.HasPrefix(p, s) {
			return true
		}
	}
	return false
}

func (d *differ) allowPaths(a, b Policy) {
	var added, removed []string
	for _, p := range b.AllowPaths {
		if !pathCovered(p, a.AllowPaths) {
			added = append(added, p)
		}
	}
	for _, p := range a.AllowPaths {
		if !pathCovered(p, b.AllowPaths) {
			removed = append(removed, p)
		}
	}
	if len(added) > 0 {
		d.add("allow_path.added", "allow_paths", true, "%d page(s) were added to those that are never inspected: %s.", len(added), joinShort(added))
	}
	if len(removed) > 0 {
		d.add("allow_path.removed", "allow_paths", false, "%d page(s) were taken off those that are never inspected: %s.", len(removed), joinShort(removed))
	}
}

func joinShort(list []string) string {
	if len(list) > 5 {
		return strings.Join(list[:5], ", ") + fmt.Sprintf(" and %d more", len(list)-5)
	}
	return strings.Join(list, ", ")
}

// flag is a yes/no setting that lowers protection when it is on (or when it is off, for weakerOff).
type flag struct {
	section, onCode, offCode, onWords, offWords string
	get                                         func(Policy) bool
	weakerWhenOn                                bool
}

var flags = []flag{
	{"paths", "paths.encoded_slash_allowed", "paths.encoded_slash_refused", "Encoded slashes (%2f) in a path are now let through.", "Encoded slashes (%2f) in a path are now refused.",
		func(p Policy) bool { return p.Paths.AllowEncodedSlash }, true},
	{"paths", "paths.path_params_allowed", "paths.path_params_refused", "Semicolons (path parameters) in a path are now let through.", "Semicolons (path parameters) in a path are now refused.",
		func(p Policy) bool { return p.Paths.AllowPathParams }, true},
	{"uploads", "uploads.script_names_allowed", "uploads.script_names_refused", "Uploads with the name of a script or a server configuration file are now let through.", "Uploads with the name of a script or a server configuration file are now refused.",
		func(p Policy) bool { return p.Uploads.AllowScriptNames }, true},
	{"uploads", "uploads.script_content_allowed", "uploads.script_content_refused", "Uploads whose content holds the opening tag of a script are now let through.", "Uploads whose content holds the opening tag of a script are now refused.",
		func(p Policy) bool { return p.Uploads.AllowScriptContent }, true},
	{"wordpress", "wordpress.enabled", "wordpress.disabled", "The WordPress protections were switched on.", "The WordPress protections were switched off.",
		func(p Policy) bool { return p.WordPress.Enabled }, false},
	{"wordpress", "wordpress.xmlrpc_allowed", "wordpress.xmlrpc_refused", "xmlrpc.php is now reachable.", "xmlrpc.php is now refused.",
		func(p Policy) bool { return p.WordPress.AllowXMLRPC }, true},
	{"responses", "responses.banners_kept", "responses.banners_hidden", "Software banners in responses are now left as the application sent them.", "Software banners are now removed from responses.",
		func(p Policy) bool { return p.Responses.KeepBanners }, true},
	{"responses", "responses.caching_kept", "responses.caching_protected", "Caching headers on personal responses are now left as the application sent them.", "Responses that set a cookie or look like a static file but are HTML are now marked as not to be cached.",
		func(p Policy) bool { return p.Responses.KeepCaching }, true},
	{"responses", "responses.inspection_enabled", "responses.inspection_disabled", "Responses are now inspected for leaks.", "Responses are no longer inspected for leaks.",
		func(p Policy) bool { return p.Responses.Inspect }, false},
	{"framework", "framework.next_action_denied", "framework.next_action_allowed", "Requests with a Next-Action header are now refused.", "Requests with a Next-Action header are now let through.",
		func(p Policy) bool { return p.Framework.DenyNextAction }, false},
}

func (d *differ) flags(a, b Policy) {
	for _, f := range flags {
		was, now := f.get(a), f.get(b)
		if was == now {
			continue
		}
		if now {
			d.add(f.onCode, f.section, f.weakerWhenOn, "%s", f.onWords)
		} else {
			d.add(f.offCode, f.section, !f.weakerWhenOn, "%s", f.offWords)
		}
	}
	switch ra, rb := a.WordPress.LoginPerMinute, b.WordPress.LoginPerMinute; {
	case rb > ra:
		d.add("wordpress.login_rate_raised", "wordpress", true, "The login attempts allowed a minute were raised from %d to %d.", ra, rb)
	case rb < ra:
		d.add("wordpress.login_rate_lowered", "wordpress", false, "The login attempts allowed a minute were lowered from %d to %d.", ra, rb)
	}
}

func (d *differ) denyHeaders(a, b Policy) {
	for _, h := range setDiff(a.DenyHeaders, b.DenyHeaders) {
		d.add("deny_header.removed", "deny_headers", true, "Requests with the header %s are no longer refused.", h)
	}
	for _, h := range setDiff(b.DenyHeaders, a.DenyHeaders) {
		d.add("deny_header.added", "deny_headers", false, "Requests with the header %s are now refused.", h)
	}
}

func (d *differ) vpatch(a, b Policy) {
	for _, t := range setDiff(a.VPatch.Tiers, b.VPatch.Tiers) {
		d.add("vpatch.tier_removed", "vpatch", true, "The %s virtual patches were switched off.", t)
	}
	for _, t := range setDiff(b.VPatch.Tiers, a.VPatch.Tiers) {
		d.add("vpatch.tier_added", "vpatch", false, "The %s virtual patches were switched on.", t)
	}
	for _, s := range setDiff(a.VPatch.Software, b.VPatch.Software) {
		d.add("vpatch.software_removed", "vpatch", true, "%s is no longer declared as running on the site, so the virtual patches for it are off.", s)
	}
	for _, s := range setDiff(b.VPatch.Software, a.VPatch.Software) {
		d.add("vpatch.software_added", "vpatch", false, "%s is now declared as running on the site, so the virtual patches for it are on.", s)
	}
}

var apiRank = map[APIMode]int{APIOff: 0, APILearn: 1, APIMonitor: 2, APIEnforce: 3}

func (d *differ) api(a, b Policy) {
	if a.APIMode != b.APIMode {
		lowered := apiRank[b.APIMode] < apiRank[a.APIMode]
		code := "api.mode_raised"
		if lowered {
			code = "api.mode_lowered"
		}
		d.add(code, "api_mode", lowered, "API protection changed from %s to %s.", a.APIMode, b.APIMode)
	}
	if !bytes.Equal(a.API, b.API) {
		// The settings inside belong to another package, so whether a change loosens them cannot be said here. While they are
		// acted on (monitor or enforce) a change counts as lowering protection.
		d.add("api.config_changed", "api", apiRank[b.APIMode] >= apiRank[APIMonitor], "The API protection settings were changed.")
	}
	if !bytes.Equal(a.BodyFormats, b.BodyFormats) {
		d.add("body_formats.config_changed", "body_formats", true, "The body-format settings were changed.")
	}
}

// setDiff returns the entries of a that are not in b (both sorted sets).
func setDiff(a, b []string) []string {
	in := make(map[string]bool, len(b))
	for _, s := range b {
		in[s] = true
	}
	var out []string
	for _, s := range a {
		if !in[s] {
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out
}
