// SPDX-License-Identifier: Apache-2.0

package vpatch

import (
	"hash/maphash"
	"math"
	"sort"
	"strings"
	"sync/atomic"
	"unicode/utf8"

	"github.com/YurilLAB/coraza/carnical/inspect"
)

// matchCtx is the working state of matching one request. It is pooled: the arrays are sized for the loaded set and reused, and a
// number that is compared with the request's epoch (instead of a clear) tells whether an entry belongs to this request.
type matchCtx struct {
	e     *Engine
	snap  *snapshot
	req   *inspect.Request
	epoch uint32

	views       [numKinds]view
	bodyReady   uint32
	ctReady     uint32
	ct          string
	bodyStr     string
	truncated   bool
	multipartOK bool

	seenCond []uint32 // epoch at which a condition's required literal was found
	candMark []uint32 // epoch at which a signature was nominated
	patMark  [numKinds][]uint32
	stamp    uint32
	cands    []int32
	hits     []int32
	hitBuf   []int32

	tc      []tcEntry
	nChains int
	touched []int32

	work, maxWork int
	over          bool

	dtext     []string
	dmask     []uint64
	classVals [][]string
}

// tcEntry caches the values of one kind after one transform chain, for one request.
type tcEntry struct {
	epoch uint32
	vals  []string
}

type matchRes struct {
	snap    *snapshot
	hits    []int32
	limited bool
}

func (e *Engine) getCtx(snap *snapshot) *matchCtx {
	c, _ := e.pool.Get().(*matchCtx)
	if c == nil {
		c = &matchCtx{e: e}
	}
	if c.snap != snap {
		c.prepare(snap)
	}
	c.epoch++
	if c.epoch == 0 {
		c.wrap()
	}
	return c
}

// prepare sizes the arrays for a snapshot. Entries left over from a previous snapshot carry old epochs, which never equal a
// later one, so they need no clearing.
func (c *matchCtx) prepare(snap *snapshot) {
	c.snap = snap
	if len(c.seenCond) < len(snap.conds) {
		c.seenCond = make([]uint32, len(snap.conds))
	}
	if len(c.candMark) < len(snap.sigs) {
		c.candMark = make([]uint32, len(snap.sigs))
	}
	for k := range c.patMark {
		if n := snap.kinds[k].nPat; len(c.patMark[k]) < n {
			c.patMark[k] = make([]uint32, n)
		}
	}
	if c.nChains != len(snap.chains) {
		c.nChains = len(snap.chains)
		c.tc = make([]tcEntry, numKinds*c.nChains)
		c.touched = c.touched[:0]
	}
}

// wrap handles the epoch counter coming round to zero, after four billion requests on one context.
func (c *matchCtx) wrap() {
	clear(c.seenCond)
	clear(c.candMark)
	for k := range c.patMark {
		clear(c.patMark[k])
	}
	for k := range c.views {
		c.views[k].ready = 0
	}
	for i := range c.tc {
		c.tc[i].epoch = 0
	}
	c.bodyReady, c.ctReady, c.stamp, c.epoch = 0, 0, 0, 1
}

// release drops everything that refers to the request, so that a pooled context does not keep a body alive.
func (c *matchCtx) release() {
	c.req = nil
	c.bodyStr = ""
	for k := range c.views {
		c.views[k].reset()
	}
	for _, i := range c.touched {
		clear(c.tc[i].vals)
		c.tc[i].vals = c.tc[i].vals[:0]
	}
	c.touched = c.touched[:0]
	clear(c.dtext)
	clear(c.classVals)
	c.classVals = c.classVals[:0]
	c.cands, c.hits = c.cands[:0], c.hits[:0]
}

// run matches a request against the current signatures. With brute set it ignores the index.
func (e *Engine) run(r *inspect.Request, brute bool) matchRes {
	snap := e.cur.Load()
	res := matchRes{snap: snap}
	if r == nil || len(snap.sigs) == 0 {
		return res
	}
	c := e.getCtx(snap)
	c.req = r
	c.truncated, c.over, c.work = false, false, 0
	c.cands, c.hits = c.cands[:0], c.hits[:0]
	c.maxWork = e.opts.MaxWork
	if brute {
		c.maxWork = math.MaxInt
		for si := range snap.sigs {
			if c.evalSig(int32(si), false) {
				c.hits = append(c.hits, int32(si))
			}
		}
	} else {
		c.scanAll()
		evaluated := uint64(0)
		for _, si := range snap.unindexed {
			if c.over {
				break
			}
			evaluated++
			if c.evalSig(si, false) {
				c.hits = append(c.hits, si)
			}
		}
		for _, si := range c.cands {
			if c.over {
				break
			}
			evaluated++
			if c.evalSig(si, true) {
				c.hits = append(c.hits, si)
			}
		}
		e.evaluated.Add(evaluated)
	}
	e.requests.Add(1)
	if len(c.hits) > 0 {
		e.hitsN.Add(uint64(len(c.hits)))
		res.hits = append([]int32(nil), c.hits...)
		sort.Slice(res.hits, func(a, b int) bool { return res.hits[a] < res.hits[b] })
	}
	res.limited = c.over
	if c.over {
		e.limited.Add(1)
	}
	if c.truncated {
		e.truncated.Add(1)
	}
	c.release()
	e.pool.Put(c)
	return res
}

// mark records that a condition's required literal was found in a value it reads, and nominates its signature if the condition
// is the one that signature is found by.
func (c *matchCtx) mark(cond int32) {
	c.seenCond[cond] = c.epoch
	if s := c.snap.condDriver[cond]; s >= 0 && c.candMark[s] != c.epoch {
		c.candMark[s] = c.epoch
		c.cands = append(c.cands, s)
	}
}

// scanAll runs the literal index over every kind of value that some signature requires a literal of.
func (c *matchCtx) scanAll() {
	for k := 0; k < numKinds; k++ {
		if ki := &c.snap.kinds[k]; ki.auto != nil {
			c.scanKind(k, ki)
		}
	}
}

// scanKind scans each value of one kind, once for every distinct text that the transform chains in use turn it into.
func (c *matchCtx) scanKind(k int, ki *kindIndex) {
	v := c.raw(k)
	n := len(v.vals)
	if n == 0 {
		return
	}
	nc, w := len(ki.classes), ki.words
	c.classVals = c.classVals[:0]
	for _, ch := range ki.classes {
		c.classVals = append(c.classVals, c.tvals(k, ch))
	}
	if len(c.dtext) < nc {
		c.dtext = make([]string, nc)
	}
	if len(c.dmask) < nc*w {
		c.dmask = make([]uint64, nc*w)
	}
	for i := 0; i < n; i++ {
		nd := 0
		for ci := 0; ci < nc; ci++ {
			t := c.classVals[ci][i]
			if len(t) < minAnchor {
				continue
			}
			j := 0
			for ; j < nd; j++ {
				if c.dtext[j] == t {
					break
				}
			}
			if j == nd {
				c.dtext[nd] = t
				m := c.dmask[nd*w : nd*w+w]
				for x := range m {
					m[x] = 0
				}
				nd++
			}
			c.dmask[j*w+ci>>6] |= 1 << (uint(ci) & 63)
		}
		for j := 0; j < nd; j++ {
			c.scanText(k, ki, c.dtext[j], c.dmask[j*w:j*w+w])
		}
	}
}

func (c *matchCtx) scanText(k int, ki *kindIndex, text string, mask []uint64) {
	c.stamp++
	if c.stamp == 0 {
		for x := range c.patMark {
			clear(c.patMark[x])
		}
		c.stamp = 1
	}
	hits := ki.auto.scan(text, c.stamp, c.patMark[k], c.hitBuf[:0])
	for _, p := range hits {
		for _, e := range ki.pats[ki.patStart[p]:ki.patStart[p+1]] {
			if mask[e.class>>6]&(1<<(uint(e.class)&63)) != 0 {
				c.mark(e.cond)
			}
		}
	}
	c.hitBuf = hits[:0]
}

// tvals returns the values of kind k after the transform chain, cached for the request. The chain's prefix is cached too, so
// "urldecode1, lowercase" and "urldecode1, normpath, lowercase" decode once.
func (c *matchCtx) tvals(k int, chain int32) []string {
	v := c.raw(k)
	if chain == 0 {
		return v.vals
	}
	idx := k*c.nChains + int(chain)
	e := &c.tc[idx]
	if e.epoch == c.epoch {
		return e.vals
	}
	ch := c.snap.chains[chain]
	parent := c.tvals(k, ch.parent)
	out := e.vals[:0]
	for _, s := range parent {
		out = append(out, ch.fn(s))
	}
	e.vals, e.epoch = out, c.epoch
	c.touched = append(c.touched, int32(idx))
	return out
}

// evalSig reports whether every condition of a signature holds. With gated set, a condition whose required literal was not found
// by the index is known not to hold and the signature fails without evaluating anything.
func (c *matchCtx) evalSig(si int32, gated bool) bool {
	sg := &c.snap.sigs[si]
	if gated {
		for _, ci := range sg.gates {
			if c.seenCond[ci] != c.epoch {
				return false
			}
		}
	}
	for _, ci := range sg.conds {
		if !c.condHolds(&c.snap.conds[ci], ci) || c.over {
			return false
		}
	}
	return true
}

// condHolds evaluates one condition: the operator must match some value of some target (after the transforms), and Negate
// inverts that. A target with no values (no cookie, no body) has nothing to match, so a negated condition holds there.
func (c *matchCtx) condHolds(cd *condC, ci int32) bool {
	matched := false
	for ti := range cd.targets {
		tg := &cd.targets[ti]
		v := c.raw(int(tg.kind))
		vals := c.tvals(int(tg.kind), cd.chain)
		for i, s := range vals {
			if tg.name != "" && !nameOK(v, i, tg.name) {
				continue
			}
			if c.opMatch(cd, ci, s) {
				matched = true
				break
			}
			if c.over {
				return false
			}
		}
		if matched {
			break
		}
	}
	return matched != cd.neg
}

func (c *matchCtx) opMatch(cd *condC, ci int32, s string) bool {
	switch cd.op {
	case opRx:
		return c.rxMatch(cd, ci, s)
	case opContains:
		if cd.fold {
			return containsFold(s, cd.str)
		}
		return strings.Contains(s, cd.str)
	case opEquals:
		if cd.fold {
			return len(s) == len(cd.str) && containsFold(s, cd.str)
		}
		return s == cd.str
	case opPrefix:
		if cd.fold {
			return len(s) >= len(cd.str) && containsFold(s[:len(cd.str)], cd.str)
		}
		return strings.HasPrefix(s, cd.str)
	case opSuffix:
		if cd.fold {
			return len(s) >= len(cd.str) && containsFold(s[len(s)-len(cd.str):], cd.str)
		}
		return strings.HasSuffix(s, cd.str)
	case opPM:
		for _, w := range cd.strs {
			if cd.fold {
				if containsFold(s, w) {
					return true
				}
			} else if strings.Contains(s, w) {
				return true
			}
		}
	}
	return false
}

// containsFold reports whether s contains the lower-case ASCII string lower, ignoring the case of ASCII letters in s.
func containsFold(s, lower string) bool {
	n := len(lower)
	if n == 0 {
		return true
	}
	for i := 0; i+n <= len(s); i++ {
		j := 0
		for ; j < n; j++ {
			if foldTable[s[i+j]] != lower[j] {
				break
			}
		}
		if j == n {
			return true
		}
	}
	return false
}

// latin1ToUTF8 gives each byte its own code point, which is how a byte-oriented PCRE pattern sees a value. A value with no byte
// above 0x7F is returned as it is.
func latin1ToUTF8(s string) string {
	i := 0
	for i < len(s) && s[i] < utf8.RuneSelf {
		i++
	}
	if i == len(s) {
		return s
	}
	b := make([]byte, 0, len(s)+len(s)/4)
	b = append(b, s[:i]...)
	for ; i < len(s); i++ {
		b = utf8.AppendRune(b, rune(s[i]))
	}
	return string(b)
}

// rxMatch runs a condition's regular expression on a value, or remembers that it already did. The table is consulted only when
// the engine was given one, and only a finished answer is stored: a value that was skipped because the request ran out of work
// allowance is not remembered as a non-match.
func (c *matchCtx) rxMatch(cd *condC, ci int32, s string) bool {
	e := c.e
	var slot *atomic.Uint64
	var key uint64
	if e.cache != nil {
		key = (maphash.String(c.snap.cacheSeed, s) ^ (uint64(ci)+1)*0x9E3779B97F4A7C15) &^ 1
		slot = &e.cache[(key>>1)&e.cacheMask]
		if v := slot.Load(); v&^1 == key && v != 0 {
			return v&1 == 1
		}
	}
	if c.work > c.maxWork {
		c.over = true
		return false
	}
	c.work += len(s)
	in := s
	if cd.prog.byteMode {
		in = latin1ToUTF8(s)
	}
	ok := true
	for _, re := range cd.prog.res {
		if !re.MatchString(in) {
			ok = false
			break
		}
	}
	if slot != nil {
		v := key
		if ok {
			v |= 1
		}
		slot.Store(v)
	}
	return ok
}
