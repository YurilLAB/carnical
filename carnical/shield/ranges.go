// SPDX-License-Identifier: Apache-2.0

package shield

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"slices"
	"strings"
)

// Ranges is a Labeler built from a table of address ranges, such as the public-domain "ip2asn" tables
// (https://iptoasn.com: one range per line, tab-separated: first address, last address, AS number, country code, AS
// name). It answers "<country> AS<number>" with a binary search. No table is shipped with Carnical: load one the owner
// has downloaded and keeps up to date, and the attack records say which countries and networks an attack came from.
type Ranges struct {
	v4, v6 []span
}

type span struct {
	first, last netip.Addr
	label       string
}

const maxRanges = 2_000_000

// LoadRanges reads an ip2asn-style table. Ranges with AS number 0 ("not routed") are skipped. Lines must be sorted by
// first address and must not overlap; a table that is not is refused rather than answered wrongly.
func LoadRanges(r io.Reader) (*Ranges, error) {
	out := &Ranges{}
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64<<10), 64<<10)
	line := 0
	labels := map[string]string{} // share label strings
	for sc.Scan() {
		line++
		text := sc.Text()
		if text == "" || text[0] == '#' {
			continue
		}
		f := strings.Split(text, "\t")
		if len(f) < 4 {
			return nil, fmt.Errorf("ranges line %d: want at least 4 tab-separated fields", line)
		}
		first, err1 := netip.ParseAddr(f[0])
		last, err2 := netip.ParseAddr(f[1])
		if err1 != nil || err2 != nil || first.Is4() != last.Is4() || last.Less(first) {
			return nil, fmt.Errorf("ranges line %d: not a range of addresses", line)
		}
		if f[2] == "0" {
			continue
		}
		cc := printable(cut(strings.TrimSpace(f[3]), 8))
		as := printable(cut(strings.TrimSpace(f[2]), 10))
		l := cc + " AS" + as
		if v, ok := labels[l]; ok {
			l = v
		} else {
			labels[l] = l
		}
		list := &out.v6
		if first.Is4() {
			list = &out.v4
		}
		if n := len(*list); n > 0 && !(*list)[n-1].last.Less(first) {
			return nil, fmt.Errorf("ranges line %d: not sorted, or overlaps the line before", line)
		}
		*list = append(*list, span{first: first, last: last, label: l})
		if len(out.v4)+len(out.v6) > maxRanges {
			return nil, errors.New("ranges: more than 2,000,000 ranges")
		}
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("ranges line %d: %w", line+1, err)
	}
	return out, nil
}

// Label implements Labeler.
func (r *Ranges) Label(a netip.Addr) string {
	a = a.Unmap()
	list := r.v6
	if a.Is4() {
		list = r.v4
	}
	i, _ := slices.BinarySearchFunc(list, a, func(s span, a netip.Addr) int {
		switch {
		case s.last.Less(a):
			return -1
		case a.Less(s.first):
			return 1
		}
		return 0
	})
	if i < len(list) && !a.Less(list[i].first) && !list[i].last.Less(a) {
		return list[i].label
	}
	return ""
}
