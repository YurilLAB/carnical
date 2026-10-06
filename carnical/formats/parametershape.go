// SPDX-License-Identifier: Apache-2.0

package formats

import "strings"

// A trie bounds storage by the decoded names, without making a copy of every
// prefix. Both parameter orderings are checked. Repeated explicit arrays remain
// valid; plain duplicates have their own independently configurable rule.
type parameterNode struct {
	spelling string
	scalar   bool
	children map[string]*parameterNode
}

// Fold ASCII only. Forms may explicitly use a single-byte charset, so UTF-8
// replacement or Unicode folding would merge distinct valid byte names.
func parameterSegment(s string, mangle bool) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] = c + ('a' - 'A')
		}
		if mangle && (c == '.' || c == ' ') {
			b[i] = '_'
		}
	}
	return string(b)
}

func ambiguousParameter(roots map[string]*parameterNode, name string) bool {
	root, rest, nested := strings.Cut(name, "[")
	canonical := parameterSegment(root, true)
	spelling := parameterSegment(root, false)
	n := roots[canonical]
	bad := false
	if n == nil {
		n = &parameterNode{spelling: spelling}
		roots[canonical] = n
	} else if n.spelling != spelling {
		bad = true // PHP mangles root dots/spaces to underscores; other parsers keep them.
	}
	for nested {
		segment, tail, closed := strings.Cut(rest, "]")
		if !closed || strings.Contains(segment, "[") || tail != "" && !strings.HasPrefix(tail, "[") {
			return true // malformed bracket syntax has parser-dependent interpretations
		}
		bad = bad || n.scalar
		if n.children == nil {
			n.children = make(map[string]*parameterNode)
		}
		key := parameterSegment(segment, false)
		child := n.children[key]
		if child == nil {
			child = &parameterNode{spelling: key}
			n.children[key] = child
		}
		n = child
		nested = tail != ""
		if nested {
			rest = tail[1:]
		}
	}
	bad = bad || len(n.children) > 0
	n.scalar = true
	return bad
}
