// SPDX-License-Identifier: Apache-2.0

package feed

import (
	"net/netip"
	"regexp"
	"strings"
)

// CutAddress shortens an address for a customer who has not asked to see whole ones: an IPv4 address becomes its /24
// (a.b.c.0) and an IPv6 address its /48. An IPv4 address carried inside IPv6 (::ffff:a.b.c.d) is treated as the IPv4
// address it is, so it cannot be used to keep the last byte. A 6to4 address (2002::/16) holds a whole IPv4 address in
// its /48, so it is cut to the /40 that holds that address's /24. A zone ("%eth0") is dropped. The second result is
// false when the text is not an address, and then nothing should be sent.
func CutAddress(s string) (string, bool) {
	a, ok := parseAddr(s)
	if !ok {
		return "", false
	}
	if a.Is4() {
		b := a.As4()
		b[3] = 0
		return netip.AddrFrom4(b).String(), true
	}
	if sixToFour.Contains(a) {
		return netip.PrefixFrom(a, 40).Masked().Addr().String(), true
	}
	return netip.PrefixFrom(a, 48).Masked().Addr().String(), true
}

var sixToFour = netip.MustParsePrefix("2002::/16")

// WholeAddress returns an address in its one canonical spelling, so the same address is always the same text (the
// reader recognises a repeated event by its exact bytes). The second result is false when the text is not an address.
func WholeAddress(s string) (string, bool) {
	a, ok := parseAddr(s)
	if !ok {
		return "", false
	}
	return a.String(), true
}

func parseAddr(s string) (netip.Addr, bool) {
	// The longest address text is 45 characters; anything longer is not one, and checking first keeps the work bounded.
	if len(s) == 0 || len(s) > 64 {
		return netip.Addr{}, false
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Addr{}, false
	}
	return a.WithZone("").Unmap(), true
}

var dottedQuad = regexp.MustCompile(`[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}`)

// scrubAddresses finds addresses written inside free text and shortens each as CutAddress does. It exists because a
// customer who chose cut addresses expects none to leave whole, and a sentence such as "banned 203.0.113.7 for 15
// minutes" would otherwise carry one. It is best effort for free text (the address fields themselves are exact): a
// dotted quad is cut wherever it appears, and so is a run of address characters that reads as an IPv6 address. Both
// passes are linear in the length of the text whatever the text holds.
func scrubAddresses(s string) string {
	if !strings.ContainsAny(s, ".:") {
		return s
	}
	s = dottedQuad.ReplaceAllStringFunc(s, func(m string) string {
		if cut, ok := CutAddress(m); ok {
			return cut
		}
		return m
	})
	if strings.Count(s, ":") < 2 {
		return s
	}
	var b strings.Builder
	last := 0
	for i := 0; i < len(s); {
		if !isAddrChar(s[i]) {
			i++
			continue
		}
		j := i
		for j < len(s) && isAddrChar(s[j]) {
			j++
		}
		if cut, from, to, ok := cutRun(s, i, j); ok {
			b.WriteString(s[last:from])
			b.WriteString(cut)
			last = to
		}
		i = j
	}
	if last == 0 {
		return s
	}
	b.WriteString(s[last:])
	return b.String()
}

// cutRun looks at one run of address characters, s[i:j], for an IPv6 address. A sentence can put a full stop or a
// colon after an address and a label can put a single colon before it, and none of those is part of the address.
// A whole address can also be glued to more address characters, such as the hex end of a label ("blocked:") or a
// port written without brackets (":443"). Then the longest start of the run that reads as an IPv6 address is cut
// and stands for the whole run, so no address leaves whole and a second scrub finds the run already cut. Failing that,
// a first label is set aside and the run is read once more from just after its colon; a label that can be a group goes
// into the cut with the address.
func cutRun(s string, i, j int) (cut string, from, to int, ok bool) {
	if cut, from, to, ok = cutRunFrom(s, i, j); ok {
		return cut, from, to, ok
	}
	k := strings.IndexByte(s[i:j], ':')
	if k <= 0 {
		return "", 0, 0, false
	}
	if cut, from, to, ok = cutRunFrom(s, i+k+1, j); !ok || from != i+k+1 {
		return cut, from, to, ok
	}
	// A label that can be a group ("ed:" of "blocked:") would read as part of the cut on a second scrub, so it goes into
	// the cut too, and the result is cut once and for all.
	if c, good := CutAddress(s[i:i+k+1] + cut); good {
		return c, i, to, true
	}
	return cut, from, to, ok
}

func cutRunFrom(s string, i, j int) (cut string, from, to int, ok bool) {
	run := s[i:j]
	if strings.Count(run, ":") < 2 {
		return "", 0, 0, false
	}
	from = i
	if strings.HasPrefix(run, ":") && !strings.HasPrefix(run, "::") {
		run = run[1:]
		from++
	}
	// The run without a sentence's full stop; then without any colon or full stop after it, but for the "::" an address
	// can end in ("2001:db8:abcd:1234::: slow down"); then without every colon.
	var core string
	bare := strings.TrimRight(run, ".:")
	tries := []string{strings.TrimRight(run, ".")}
	if strings.HasPrefix(run[len(bare):], "::") {
		tries = append(tries, bare+"::")
	}
	for _, core = range append(tries, bare) {
		if len(core) < 3 {
			continue
		}
		if c, good := CutAddress(core); good {
			if alreadyCut(core, c) {
				return "", 0, 0, false
			}
			return c, from, from + len(core), true
		}
	}
	// An address is never longer than parseAddr allows, so only the start of a long run is worth trying.
	head := core[:min(len(core), 64)]
	for k := strings.LastIndexByte(head, ':'); k > 0; k = strings.LastIndexByte(head[:k], ':') {
		if strings.Count(head[:k], ":") < 2 {
			break
		}
		if c, good := CutAddress(head[:k]); good {
			return c, from, from + len(core), true
		}
	}
	return "", 0, 0, false
}

// alreadyCut says whether text names the same IPv6 address as its cut, however it is spelt: cutting it again would only
// respell it, and a second scrub must leave the first one's output as it is. An IPv4 address written in IPv6 form is
// still rewritten as IPv4.
func alreadyCut(text, cut string) bool {
	a, _ := parseAddr(text)
	b, _ := parseAddr(cut)
	return text == cut || a.Is6() && a == b
}

func isAddrChar(c byte) bool {
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F') || c == '.' || c == ':'
}
