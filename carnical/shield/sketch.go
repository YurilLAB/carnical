// SPDX-License-Identifier: Apache-2.0

package shield

import (
	"hash/maphash"
	"math"
	"math/bits"
	"net/netip"
)

// The detector has to count things whose number the attacker chooses (source addresses, fingerprints, paths) without
// letting the attacker choose how much memory or time that takes. Everything here is fixed-size: a HyperLogLog for "how
// many different", a space-saving table for "which ones are the most common", and a pair of Bloom filters for "seen
// before". Hashes are keyed with a seed made at random for each process, so collisions cannot be engineered from outside.

var seed = maphash.MakeSeed()

func hashAddr(a netip.Addr) uint64 { return maphash.Comparable(seed, a) }

func hashString(s string) uint64 { return maphash.String(seed, s) }

// hll is a HyperLogLog counter with 2^p one-byte registers (relative error about 1.04/sqrt(2^p)).
type hll struct {
	p   uint8
	reg []uint8
}

func newHLL(p uint8) hll { return hll{p: p, reg: make([]uint8, 1<<p)} }

func (h *hll) add(x uint64) {
	idx := x >> (64 - h.p)
	w := x<<h.p | 1<<(h.p-1) // the sentinel bit bounds the run of zeros
	if r := uint8(bits.LeadingZeros64(w)) + 1; r > h.reg[idx] {
		h.reg[idx] = r
	}
}

func (h *hll) merge(o *hll) {
	for i, v := range o.reg {
		if v > h.reg[i] {
			h.reg[i] = v
		}
	}
}

func (h *hll) reset() { clear(h.reg) }

func (h *hll) estimate() float64 {
	m := float64(len(h.reg))
	sum, zeros := 0.0, 0
	for _, v := range h.reg {
		sum += 1 / float64(uint64(1)<<v)
		if v == 0 {
			zeros++
		}
	}
	var alpha float64
	switch len(h.reg) {
	case 16:
		alpha = 0.673
	case 32:
		alpha = 0.697
	case 64:
		alpha = 0.709
	default:
		alpha = 0.7213 / (1 + 1.079/m)
	}
	e := alpha * m * m / sum
	if e <= 2.5*m && zeros > 0 {
		e = m * math.Log(m/float64(zeros)) // linear counting for small numbers
	}
	return e
}

// topEntry is one tracked key of a topK, with the number of different sources seen sending it.
type topEntry struct {
	key   uint64
	count uint32
	label string
	srcs  hll
}

// topK is a space-saving table: the k most frequent keys, where a newcomer replaces the least frequent entry and inherits
// its count. A key that is truly frequent is never lost; counts are overestimates by at most the replaced count.
type topK struct {
	e []topEntry
	k int
}

func newTopK(k int) topK { return topK{k: k, e: make([]topEntry, 0, k)} }

func (t *topK) add(key uint64, label string, src uint64, n uint32) {
	low := -1
	for i := range t.e {
		if t.e[i].key == key {
			t.e[i].count += n
			t.e[i].srcs.add(src)
			return
		}
		if low < 0 || t.e[i].count < t.e[low].count {
			low = i
		}
	}
	if len(t.e) < t.k {
		t.e = append(t.e, topEntry{key: key, count: n, label: label, srcs: newHLL(6)})
		t.e[len(t.e)-1].srcs.add(src)
		return
	}
	victim := &t.e[low]
	victim.key, victim.count, victim.label = key, victim.count+n, label
	victim.srcs.reset()
	victim.srcs.add(src)
}

func (t *topK) reset() { t.e = t.e[:0] }

// seenFilter answers "has this source been seen in the last one or two periods" with two rotating Bloom filters. False
// positives make a few new sources look old (which only weakens the new-source signal); there are no false negatives.
type seenFilter struct {
	cur, old []uint64
}

const seenBits = 1 << 21 // 256 KiB per filter; about 1.5% false positives at 300,000 sources with three hashes

func newSeenFilter() seenFilter {
	return seenFilter{cur: make([]uint64, seenBits/64), old: make([]uint64, seenBits/64)}
}

func bloomIdx(h uint64, i int) uint64 {
	h1, h2 := h, h>>32|h<<32|1
	return (h1 + uint64(i)*h2) % seenBits
}

func (f *seenFilter) has(h uint64) bool {
	in := func(b []uint64) bool {
		for i := 0; i < 3; i++ {
			j := bloomIdx(h, i)
			if b[j/64]&(1<<(j%64)) == 0 {
				return false
			}
		}
		return true
	}
	return in(f.cur) || in(f.old)
}

func (f *seenFilter) add(h uint64) {
	for i := 0; i < 3; i++ {
		j := bloomIdx(h, i)
		f.cur[j/64] |= 1 << (j % 64)
	}
}

func (f *seenFilter) rotate() {
	f.old, f.cur = f.cur, f.old
	clear(f.cur)
}

// bucket is a token bucket. Times are Unix nanoseconds so that the zero value is "full at the first use".
type bucket struct {
	tokens float64
	last   int64
}

// take spends one token if there is one. A refused request spends nothing, so a client that keeps pushing is held to the
// rate rather than locked out for longer.
func (b *bucket) take(now int64, rate, burst float64) bool {
	if b.last == 0 {
		b.tokens, b.last = burst, now
	} else if now > b.last {
		b.tokens = math.Min(burst, b.tokens+float64(now-b.last)/1e9*rate)
		b.last = now
	}
	if b.tokens >= 1 {
		b.tokens--
		return true
	}
	return false
}
