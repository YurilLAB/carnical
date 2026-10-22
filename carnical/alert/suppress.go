// SPDX-License-Identifier: Apache-2.0

package alert

import (
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"time"
)

// Limits of -alert-suppress and -alert-exclude-sources.
const (
	MaxSuppressions    = 256
	MaxExcludeSources  = 256
	maxSuppressEntry   = 512 // bytes of one entry
	maxSuppressPath    = 128 // bytes of a path prefix
	minExcludeBitsIPv4 = 16  // an excluded IPv4 network is no wider than a /16
	minExcludeBitsIPv6 = 32  // an excluded IPv6 network is no wider than a /32
)

// Suppression silences the alerts of one signature, optionally only under a path prefix and only until a date
// (UniFi's Allow Signature). It never changes what is blocked; what it silences is counted as suppressed.
type Suppression struct {
	Sig        string
	PathPrefix string    // "" for every path
	Until      time.Time // the first instant it no longer applies (the day after until=, 00:00 UTC); zero for never
	Note       string
}

// Expired reports whether the suppression no longer applies at now.
func (s Suppression) Expired(now time.Time) bool { return !s.Until.IsZero() && !now.Before(s.Until) }

// String gives the suppression in the form it is written in.
func (s Suppression) String() string {
	var b strings.Builder
	b.WriteString(s.Sig)
	if s.PathPrefix != "" {
		b.WriteString(" ")
		b.WriteString(s.PathPrefix)
	}
	if !s.Until.IsZero() {
		b.WriteString(" until=")
		b.WriteString(s.Until.AddDate(0, 0, -1).Format(time.DateOnly))
	}
	if s.Note != "" {
		b.WriteString(" note=")
		b.WriteString(s.Note)
	}
	return b.String()
}

// matches reports whether the suppression silences a, which has signature sig, at now. A path prefix covers only a
// path in plain form: one that could resolve somewhere else ("/search/../admin") is never under it.
func (s *Suppression) matches(a *Alert, now time.Time) bool {
	if s.Sig != a.Sig || s.Expired(now) {
		return false
	}
	return s.PathPrefix == "" || plainPath(a.MatchPath) && underPrefix(a.MatchPath, s.PathPrefix)
}

// plainPath reports whether p is a path that means what it says: it starts with '/', has no empty, "." or ".."
// segment except an empty last one, and no '%', backslash or ';', which a server could decode or split into another
// path.
func plainPath(p string) bool {
	if p == "" || p[0] != '/' || strings.ContainsAny(p, "%\\;") {
		return false
	}
	for seg := range strings.SplitSeq(p[1:], "/") {
		if seg == "." || seg == ".." {
			return false
		}
	}
	return !strings.Contains(p, "//")
}

// underPrefix reports whether path is prefix or below it, by whole segments: /search covers /search and /search/x
// but not /searchx.
func underPrefix(path, prefix string) bool {
	if !strings.HasPrefix(path, prefix) {
		return false
	}
	return len(path) == len(prefix) || prefix[len(prefix)-1] == '/' || path[len(prefix)] == '/'
}

// ParseSuppressions reads -alert-suppress values: each value holds one or more entries separated by ';', each entry
// SIG [PATH-PREFIX] [until=YYYY-MM-DD] [note=TEXT], where note= takes the rest of the entry. Empty entries are skipped.
// An entry that has expired is kept, so that it can be listed with a warning; it no longer applies.
func ParseSuppressions(values []string) ([]Suppression, error) {
	var out []Suppression
	for _, v := range values {
		for e := range strings.SplitSeq(v, ";") {
			if strings.TrimSpace(e) == "" {
				continue
			}
			if len(out) == MaxSuppressions {
				return nil, fmt.Errorf("alert suppressions: more than %d entries", MaxSuppressions)
			}
			s, err := ParseSuppression(e)
			if err != nil {
				return nil, err
			}
			for _, o := range out {
				if o.Sig == s.Sig && o.PathPrefix == s.PathPrefix {
					return nil, fmt.Errorf("alert suppression %q: the signature and path are given twice", Clean(s.String(), 80))
				}
			}
			out = append(out, s)
		}
	}
	return out, nil
}

// ParseSuppression reads one entry: SIG [PATH-PREFIX] [until=YYYY-MM-DD] [note=TEXT].
func ParseSuppression(entry string) (Suppression, error) {
	var s Suppression
	entry = strings.TrimSpace(entry)
	shown := Clean(entry, 80)
	fail := func(why string) (Suppression, error) {
		return Suppression{}, fmt.Errorf("alert suppression %q: %s", shown, why)
	}
	if len(entry) > maxSuppressEntry {
		return fail(fmt.Sprintf("longer than %d bytes", maxSuppressEntry))
	}
	rest := entry
	for first := true; ; first = false {
		rest = strings.TrimLeft(rest, " \t")
		if rest == "" {
			break
		}
		tok := rest
		if i := strings.IndexAny(rest, " \t"); i >= 0 {
			tok = rest[:i]
		}
		switch {
		case first:
			if !ValidSignature(tok) {
				return fail("the signature is not one carnical writes (crs-942100, carnical-5000010, formats-5002103, " +
					"apiguard-5003113, shield-5004001, policy-1030000 or vpatch-ID)")
			}
			s.Sig = tok
		case strings.HasPrefix(tok, "note="):
			note := strings.TrimSpace(rest[len("note="):])
			if note == "" {
				return fail("note= is empty")
			}
			if len(note) > MaxNote || Clean(note, MaxNote) != note {
				return fail(fmt.Sprintf("the note must be printable text of at most %d bytes", MaxNote))
			}
			s.Note = note
			return s, nil // the note takes the rest of the entry
		case strings.HasPrefix(tok, "until="):
			if !s.Until.IsZero() {
				return fail("until= is given twice")
			}
			d, err := time.Parse(time.DateOnly, tok[len("until="):])
			if err != nil {
				return fail("until= must be a date in the form YYYY-MM-DD")
			}
			if d.Year() < 2000 { // the day after 0000-12-31 is the zero time, which would mean never
				return fail("until= must be a date from the year 2000 on")
			}
			s.Until = d.AddDate(0, 0, 1) // it applies through the whole day
		case strings.HasPrefix(tok, "/"):
			if s.PathPrefix != "" {
				return fail("more than one path prefix")
			}
			if len(tok) > maxSuppressPath || Clean(tok, maxSuppressPath) != tok {
				return fail(fmt.Sprintf("the path prefix must be printable text of at most %d bytes", maxSuppressPath))
			}
			if !plainPath(tok) {
				return fail("the path prefix must be in plain form, without //, . or .. segments, %, \\ or ;")
			}
			s.PathPrefix = tok
		default:
			return fail("expected a path starting with /, until=YYYY-MM-DD or note=TEXT after the signature")
		}
		rest = rest[len(tok):]
	}
	if s.Sig == "" {
		return fail("no signature")
	}
	return s, nil
}

// ParseExcludeSources reads -alert-exclude-sources values: addresses or networks separated by commas or spaces. A
// network may be no wider than a /16 (IPv4) or a /32 (IPv6), so that an exclusion cannot silence the whole Internet.
// Networks are returned masked; an IPv4-mapped IPv6 form is read as IPv4.
func ParseExcludeSources(values []string) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for _, v := range values {
		for f := range strings.FieldsFuncSeq(v, func(r rune) bool { return r == ',' || r == ' ' || r == '\t' }) {
			if len(out) == MaxExcludeSources {
				return nil, fmt.Errorf("alert exclude sources: more than %d entries", MaxExcludeSources)
			}
			p, err := parseSource(f)
			if err != nil {
				return nil, fmt.Errorf("alert exclude source %q: %w", Clean(f, 64), err)
			}
			out = append(out, p)
		}
	}
	return out, nil
}

func parseSource(s string) (netip.Prefix, error) {
	var p netip.Prefix
	if strings.Contains(s, "/") {
		var err error
		if p, err = netip.ParsePrefix(s); err != nil {
			return p, errors.New("not an address or network in CIDR form")
		}
	} else {
		a, err := netip.ParseAddr(s)
		if err != nil {
			return p, errors.New("not an address or network in CIDR form")
		}
		if a.Zone() != "" {
			return p, errors.New("an address with a zone")
		}
		p = netip.PrefixFrom(a, a.BitLen())
	}
	if p.Addr().Is4In6() {
		if p.Bits() < 96 {
			return p, errors.New("an IPv4-mapped network wider than ::ffff:0:0/96")
		}
		p = netip.PrefixFrom(p.Addr().Unmap(), p.Bits()-96)
	}
	if p.Addr().Is4() && p.Bits() < minExcludeBitsIPv4 {
		return p, fmt.Errorf("wider than a /%d; name the networks to leave out more narrowly", minExcludeBitsIPv4)
	}
	if p.Addr().Is6() && p.Bits() < minExcludeBitsIPv6 {
		return p, fmt.Errorf("wider than a /%d; name the networks to leave out more narrowly", minExcludeBitsIPv6)
	}
	return p.Masked(), nil
}
