// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"bytes"
	"net/netip"
	"sort"
	"strings"
)

// Normalize returns the policy in its canonical form, which is what Decode, Encode, Hash, Diff and Compile all work on:
//
//   - lists that are sets (methods, hosts, header names, address lists, paths, categories, targets, tiers, software, the words
//     of a pm rule) are sorted and have their duplicates removed;
//   - names that do not depend on case are in one case: methods upper, hosts, header names, targets, fields, categories, tiers
//     and software lower (a header name has "_" written "-", as the proxy reads it); an address or range is written
//     in its shortest canonical form, with the host bits of a range cleared (10.1.2.3/8 is 10.0.0.0/8);
//   - exclusions are sorted, custom rules are sorted by id, and rule groups set to "on" (the default) are left out of the map;
//   - an absent list is an empty one, and a section for another package is rewritten in canonical JSON (or dropped if it is
//     empty or null); notes are trimmed.
//
// It changes nothing else: a value that is wrong stays wrong, for Validate to say so. It never panics, and
// Normalize(Normalize(p)) equals Normalize(p).
func (p Policy) Normalize() Policy {
	q := p
	if p.Threshold != nil {
		t := *p.Threshold
		q.Threshold = &t
	}
	q.AllowedMethods = sortedUnique(mapStrings(p.AllowedMethods, strings.ToUpper))
	q.AllowedHosts = sortedUnique(mapStrings(p.AllowedHosts, strings.ToLower))
	q.DenyHeaders = sortedUnique(mapStrings(p.DenyHeaders, func(s string) string {
		return strings.ReplaceAll(strings.ToLower(strings.TrimSpace(s)), "_", "-")
	}))
	q.AllowPaths = sortedUnique(append([]string(nil), p.AllowPaths...))
	q.AllowIPs = normalizeIPList(p.AllowIPs)
	q.BlockIPs = normalizeIPList(p.BlockIPs)
	q.VPatch = VPatchOptions{
		Tiers:    sortedUnique(mapStrings(p.VPatch.Tiers, strings.ToLower)),
		Software: sortedUnique(mapStrings(p.VPatch.Software, strings.ToLower)),
	}
	q.RuleGroups = make(map[string]GroupState, len(p.RuleGroups))
	for name, state := range p.RuleGroups {
		if state != GroupOn {
			q.RuleGroups[strings.ToLower(name)] = state
		}
	}
	q.Exclusions = make([]Exclusion, 0, len(p.Exclusions))
	for _, e := range p.Exclusions {
		q.Exclusions = append(q.Exclusions, Exclusion{
			Path:       e.Path,
			Categories: sortedUnique(mapStrings(e.Categories, strings.ToLower)),
			Targets:    sortedUnique(mapStrings(e.Targets, strings.ToLower)),
			Note:       strings.TrimSpace(e.Note),
		})
	}
	sort.SliceStable(q.Exclusions, func(i, j int) bool { return exclusionKey(q.Exclusions[i]) < exclusionKey(q.Exclusions[j]) })
	q.Exclusions = dedupeExclusions(q.Exclusions)
	q.CustomRules = make([]CustomRule, 0, len(p.CustomRules))
	for _, r := range p.CustomRules {
		n := r
		n.Field = strings.ToLower(r.Field)
		n.Note = strings.TrimSpace(r.Note)
		n.Values = nil
		if r.Operator == OpPM {
			n.Values = sortedUnique(append([]string(nil), r.Values...))
		} else if len(r.Values) > 0 {
			n.Values = append([]string(nil), r.Values...) // not for this operator: Validate says so
		}
		q.CustomRules = append(q.CustomRules, n)
	}
	sort.SliceStable(q.CustomRules, func(i, j int) bool { return q.CustomRules[i].ID < q.CustomRules[j].ID })
	q.API = canonicalSection(p.API)
	q.BodyFormats = canonicalSection(p.BodyFormats)
	q.Note = strings.TrimSpace(p.Note)
	return q
}

func exclusionKey(e Exclusion) string {
	return e.Path + "\x00" + strings.Join(e.Categories, ",") + "\x00" + strings.Join(e.Targets, ",")
}

func dedupeExclusions(in []Exclusion) []Exclusion {
	out := in[:0:0]
	for i, e := range in {
		if i > 0 && exclusionKey(e) == exclusionKey(in[i-1]) {
			continue
		}
		out = append(out, e)
	}
	return out
}

// canonicalSection rewrites a section for another package in canonical JSON, or drops it if it holds nothing. A section that
// is not JSON is left as it is for Validate to refuse.
func canonicalSection(raw []byte) []byte {
	t := bytes.TrimSpace(raw)
	if len(t) == 0 || string(t) == "null" {
		return nil
	}
	if c, err := canonicalJSON(t); err == nil {
		return c
	}
	return append([]byte(nil), raw...)
}

func mapStrings(in []string, f func(string) string) []string {
	out := make([]string, len(in))
	for i, s := range in {
		out[i] = f(s)
	}
	return out
}

func sortedUnique(in []string) []string {
	out := make([]string, len(in))
	copy(out, in)
	sort.Strings(out)
	w := 0
	for i, s := range out {
		if i > 0 && s == out[w-1] {
			continue
		}
		out[w] = s
		w++
	}
	return out[:w]
}

// parsePrefix reads an address or a CIDR range into a masked prefix. An IPv4 address written as an IPv6 one
// (::ffff:192.0.2.1) is the IPv4 address; a zone (fe80::1%eth0) is refused.
func parsePrefix(s string) (netip.Prefix, bool) {
	if strings.ContainsAny(s, "% \t\r\n") || s == "" {
		return netip.Prefix{}, false
	}
	var p netip.Prefix
	if strings.Contains(s, "/") {
		var err error
		if p, err = netip.ParsePrefix(s); err != nil {
			return netip.Prefix{}, false
		}
	} else {
		a, err := netip.ParseAddr(s)
		if err != nil {
			return netip.Prefix{}, false
		}
		p = netip.PrefixFrom(a, a.BitLen())
	}
	if p.Addr().Is4In6() {
		if p.Bits() < 96 {
			return netip.Prefix{}, false
		}
		p = netip.PrefixFrom(p.Addr().Unmap(), p.Bits()-96)
	}
	return p.Masked(), p.IsValid()
}

// normalizeIPList writes each entry in its canonical form, sorted by address then length, without duplicates. An entry that
// is not an address stays as it was, after the others, for Validate to refuse.
func normalizeIPList(in []string) []string {
	var good []netip.Prefix
	var bad []string
	seen := map[netip.Prefix]bool{}
	for _, s := range in {
		if p, ok := parsePrefix(s); ok {
			if !seen[p] {
				seen[p] = true
				good = append(good, p)
			}
		} else {
			bad = append(bad, s)
		}
	}
	sort.Slice(good, func(i, j int) bool {
		if c := good[i].Addr().Compare(good[j].Addr()); c != 0 {
			return c < 0
		}
		return good[i].Bits() < good[j].Bits()
	})
	out := make([]string, 0, len(in))
	for _, p := range good {
		out = append(out, p.String())
	}
	return append(out, sortedUnique(bad)...)
}
