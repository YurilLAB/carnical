// SPDX-License-Identifier: Apache-2.0

package vpatch

import (
	"sort"
	"strings"
)

// automaton is an Aho-Corasick multi-pattern matcher over lower-case ASCII literals. It reports which of up to tens of
// thousands of literals occur in a text, in one pass over the text, whatever the number of literals.
//
// It is built for a text that mostly matches nothing: a URL scanned against 20,000 literals spends nearly all its time in the
// root, so the root's transitions are a dense table and the loop that skips bytes which cannot start any literal is a single
// array lookup per byte. The deeper nodes are sparse (a sorted run of edges each), which keeps tens of thousands of literals in
// a few megabytes.
//
// The scan folds case itself (A to Z become a to z), so the caller never makes a lower-case copy of a text. The two non-ASCII
// characters that Unicode case folding makes equal to an ASCII letter (the Kelvin sign and the long s, which a case-insensitive
// regular expression treats as k and s) are handled by a second pass over a folded copy, taken only if the text contains them.
type automaton struct {
	rootNext [256]int32 // root transitions; 0 means none, because no child of the root is node 0

	edgeStart []int32 // node i has edges edgeByte[edgeStart[i]:edgeStart[i+1]], sorted by byte
	edgeByte  []byte
	edgeTo    []int32

	fail []int32
	// dict[i] is the nearest node on i's failure chain (not i itself) that ends a literal, or 0.
	dict []int32
	// outStart[i]:outStart[i+1] are the literals that end exactly at node i.
	outStart []int32
	outPat   []int32

	patterns int
}

var foldTable = func() (t [256]byte) {
	for i := range t {
		t[i] = byte(i)
		if i >= 'A' && i <= 'Z' {
			t[i] = byte(i) + 'a' - 'A'
		}
	}
	return
}()

type buildEdge struct {
	b  byte
	to int32
}

type buildNode struct {
	edges []buildEdge
	out   []int32
}

func (n *buildNode) child(b byte) int32 {
	for _, e := range n.edges {
		if e.b == b {
			return e.to
		}
	}
	return -1
}

// newAutomaton builds the matcher for lits, where literal i is reported as pattern i. A literal must not be empty and must be
// lower case; the caller guarantees both (it builds them from validated anchors).
func newAutomaton(lits []string) *automaton {
	nodes := make([]buildNode, 1, 1+len(lits)*4)
	for id, lit := range lits {
		cur := int32(0)
		for i := 0; i < len(lit); i++ {
			next := nodes[cur].child(lit[i])
			if next < 0 {
				next = int32(len(nodes))
				nodes = append(nodes, buildNode{})
				nodes[cur].edges = append(nodes[cur].edges, buildEdge{lit[i], next})
			}
			cur = next
		}
		nodes[cur].out = append(nodes[cur].out, int32(id))
	}
	n := len(nodes)
	a := &automaton{
		edgeStart: make([]int32, n+1),
		fail:      make([]int32, n),
		dict:      make([]int32, n),
		outStart:  make([]int32, n+1),
		patterns:  len(lits),
	}
	for i := range nodes {
		e := nodes[i].edges
		sort.Slice(e, func(x, y int) bool { return e[x].b < e[y].b })
	}
	// Failure links, breadth first: the failure of a child is found by walking the parent's failure chain until a node has an
	// edge on the same byte.
	queue := make([]int32, 0, n)
	for _, e := range nodes[0].edges {
		a.rootNext[e.b] = e.to
		queue = append(queue, e.to)
	}
	for h := 0; h < len(queue); h++ {
		u := queue[h]
		for _, e := range nodes[u].edges {
			v := e.to
			f := a.fail[u]
			for {
				if f == 0 {
					a.fail[v] = a.rootNext[e.b]
					if a.fail[v] == v {
						a.fail[v] = 0
					}
					break
				}
				if t := nodes[f].child(e.b); t >= 0 {
					a.fail[v] = t
					break
				}
				f = a.fail[f]
			}
			queue = append(queue, v)
		}
	}
	// Dictionary links: the next node down the failure chain that ends a literal, so a match at a node reports every literal
	// that is a suffix of it without walking the whole chain.
	for _, u := range queue {
		f := a.fail[u]
		if len(nodes[f].out) > 0 {
			a.dict[u] = f
		} else {
			a.dict[u] = a.dict[f]
		}
	}
	for i := range nodes {
		a.edgeStart[i+1] = a.edgeStart[i] + int32(len(nodes[i].edges))
		a.outStart[i+1] = a.outStart[i] + int32(len(nodes[i].out))
	}
	a.edgeByte = make([]byte, a.edgeStart[n])
	a.edgeTo = make([]int32, a.edgeStart[n])
	a.outPat = make([]int32, a.outStart[n])
	for i := range nodes {
		for j, e := range nodes[i].edges {
			a.edgeByte[int(a.edgeStart[i])+j] = e.b
			a.edgeTo[int(a.edgeStart[i])+j] = e.to
		}
		copy(a.outPat[a.outStart[i]:], nodes[i].out)
	}
	return a
}

func (a *automaton) next(s int32, c byte) int32 {
	for i, hi := a.edgeStart[s], a.edgeStart[s+1]; i < hi; i++ {
		switch b := a.edgeByte[i]; {
		case b == c:
			return a.edgeTo[i]
		case b > c:
			return -1
		}
	}
	return -1
}

// scan appends to out the pattern identifiers found in text that have not been seen under stamp yet, and marks them in seen so
// that they are not reported twice for the same stamp. A stamp names one unit of work (one text of one request); the caller
// makes it unique per unit.
func (a *automaton) scan(text string, stamp uint32, seen []uint32, out []int32) []int32 {
	out, high := a.scanFolded(text, stamp, seen, out)
	if high && hasFoldingNonASCII(text) {
		out, _ = a.scanFolded(foldNonASCII(text), stamp, seen, out)
	}
	return out
}

func (a *automaton) scanFolded(text string, stamp uint32, seen []uint32, out []int32) ([]int32, bool) {
	var s int32
	high := false
	for i := 0; i < len(text); i++ {
		c := text[i]
		if c >= 0x80 {
			high = true
		}
		c = foldTable[c]
		if s == 0 {
			s = a.rootNext[c]
			if s == 0 {
				continue
			}
		} else {
			for {
				if t := a.next(s, c); t >= 0 {
					s = t
					break
				}
				s = a.fail[s]
				if s == 0 {
					s = a.rootNext[c]
					break
				}
			}
			if s == 0 {
				continue
			}
		}
		o := s
		if a.outStart[o] == a.outStart[o+1] {
			o = a.dict[o]
		}
		for ; o != 0; o = a.dict[o] {
			for _, p := range a.outPat[a.outStart[o]:a.outStart[o+1]] {
				if seen[p] != stamp {
					seen[p] = stamp
					out = append(out, p)
				}
			}
		}
	}
	return out, high
}

// hasFoldingNonASCII reports whether text holds U+212A (Kelvin sign) or U+017F (long s), the only characters outside ASCII that
// Unicode simple case folding makes equal to an ASCII letter.
func hasFoldingNonASCII(text string) bool {
	return strings.Contains(text, "K") || strings.Contains(text, "ſ")
}

// foldNonASCII replaces those two characters by the letters they fold to.
func foldNonASCII(text string) string {
	return strings.NewReplacer("K", "k", "ſ", "s").Replace(text)
}
