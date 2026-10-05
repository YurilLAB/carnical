// SPDX-License-Identifier: Apache-2.0

package importers

import (
	"encoding/json"
	"errors"
	"sort"
	"strings"

	"github.com/YurilLAB/coraza/carnical/vpatch"
)

// ExprKind says what an Expr node is.
type ExprKind int

// The kinds of Expr node.
const (
	ExprLeaf ExprKind = iota
	ExprAnd
	ExprOr
)

// Expr is a boolean tree of conditions as a source format states it: "and" and "or" nested. A signature is a conjunction (a main
// condition and Also), so an "or" becomes several signatures. Expand does that, within a bound.
type Expr struct {
	Kind ExprKind
	Cond vpatch.Condition
	Kids []Expr
}

// Leaf is an Expr that is one condition.
func Leaf(c vpatch.Condition) Expr { return Expr{Kind: ExprLeaf, Cond: c} }

// And is an Expr that holds when all of kids hold.
func And(kids ...Expr) Expr { return Expr{Kind: ExprAnd, Kids: kids} }

// Or is an Expr that holds when any of kids holds.
func Or(kids ...Expr) Expr { return Expr{Kind: ExprOr, Kids: kids} }

// Errors from Expand.
var (
	ErrTooManyAlternatives = errors.New("or expands to too many signatures")
	ErrTooManyConditions   = errors.New("too many conditions in one signature")
	ErrEmptyExpr           = errors.New("empty and/or")
	ErrExprTooDeep         = errors.New("and/or nested too deeply")
)

// Expand puts e in disjunctive normal form: a list of alternatives, each a list of conditions that must all hold. An "or" of n
// branches inside an "and" multiplies, so the number of alternatives is bounded by maxAlts and each alternative by maxConds; a
// tree that would exceed either is an error, not a partial answer. Identical conditions within an alternative, and identical
// alternatives, are removed.
func (e Expr) Expand(maxAlts, maxConds int) ([][]vpatch.Condition, error) {
	alts, err := expand(e, maxAlts, maxConds, 0)
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	var out [][]vpatch.Condition
	for _, a := range alts {
		a = dedupeConds(a)
		if len(a) > maxConds {
			return nil, ErrTooManyConditions
		}
		k := condsKey(a)
		if seen[k] {
			continue
		}
		seen[k] = true
		out = append(out, a)
	}
	return out, nil
}

const maxExprDepth = 64

func expand(e Expr, maxAlts, maxConds, depth int) ([][]vpatch.Condition, error) {
	if depth > maxExprDepth {
		return nil, ErrExprTooDeep
	}
	switch e.Kind {
	case ExprLeaf:
		return [][]vpatch.Condition{{e.Cond}}, nil
	case ExprOr:
		if len(e.Kids) == 0 {
			return nil, ErrEmptyExpr
		}
		var out [][]vpatch.Condition
		for _, k := range e.Kids {
			a, err := expand(k, maxAlts, maxConds, depth+1)
			if err != nil {
				return nil, err
			}
			out = append(out, a...)
			if len(out) > maxAlts {
				return nil, ErrTooManyAlternatives
			}
		}
		return out, nil
	case ExprAnd:
		if len(e.Kids) == 0 {
			return nil, ErrEmptyExpr
		}
		out := [][]vpatch.Condition{{}}
		for _, k := range e.Kids {
			a, err := expand(k, maxAlts, maxConds, depth+1)
			if err != nil {
				return nil, err
			}
			if len(out)*len(a) > maxAlts {
				return nil, ErrTooManyAlternatives
			}
			next := make([][]vpatch.Condition, 0, len(out)*len(a))
			for _, x := range out {
				for _, y := range a {
					if len(x)+len(y) > maxConds*2 { // dedupe may shrink it; this only stops runaway growth
						return nil, ErrTooManyConditions
					}
					c := make([]vpatch.Condition, 0, len(x)+len(y))
					c = append(c, x...)
					c = append(c, y...)
					next = append(next, c)
				}
			}
			out = next
		}
		return out, nil
	}
	return nil, ErrEmptyExpr
}

func condKey(c vpatch.Condition) string {
	b, _ := json.Marshal(c)
	return string(b)
}

func condsKey(cs []vpatch.Condition) string {
	var b strings.Builder
	for _, c := range cs {
		b.WriteString(condKey(c))
		b.WriteByte('\n')
	}
	return b.String()
}

func dedupeConds(cs []vpatch.Condition) []vpatch.Condition {
	seen := map[string]bool{}
	out := cs[:0:0]
	for _, c := range cs {
		k := condKey(c)
		if seen[k] {
			continue
		}
		seen[k] = true
		out = append(out, c)
	}
	return out
}

// rankCondition says how good a main condition c would be: lower is better. The engine indexes on the main condition, and most
// virtual patches name a path, so a literal test of the path comes first, then of the whole URI, then everything else, with the
// method and negated tests last (they match nearly every request).
func rankCondition(c vpatch.Condition) int {
	if c.Negate {
		return 90
	}
	literal := c.Operator == vpatch.OpEquals || c.Operator == vpatch.OpPrefix || c.Operator == vpatch.OpSuffix || c.Operator == vpatch.OpContains
	only := func(t string) bool {
		if len(c.Targets) == 0 {
			return false
		}
		for _, x := range c.Targets {
			if x != t {
				return false
			}
		}
		return true
	}
	switch {
	case only(vpatch.TargetPath) && literal:
		return 0
	case only(vpatch.TargetPath):
		return 1
	case only(vpatch.TargetURI) && literal:
		return 2
	case only(vpatch.TargetURI):
		return 3
	case only(vpatch.TargetMethod):
		return 80
	case literal:
		return 10
	}
	return 20
}

// Assemble splits a conjunction into the main condition and Also: the best-ranked condition (see rankCondition, the first one when
// several tie) is the main one and the others keep their order. conds must not be empty.
func Assemble(conds []vpatch.Condition) (vpatch.Condition, []vpatch.Condition) {
	best := 0
	for i := 1; i < len(conds); i++ {
		if rankCondition(conds[i]) < rankCondition(conds[best]) {
			best = i
		}
	}
	main := conds[best]
	var also []vpatch.Condition
	for i, c := range conds {
		if i != best {
			also = append(also, c)
		}
	}
	return main, also
}

// SortedKeys returns the keys of a map in order, so output never depends on map iteration order.
func SortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// ExistsGuard returns the condition "the target has a value", which a negated test of a named value must be paired with. SecLang and
// Suricata do not fire a negated test on something the request does not have (a "!@rx" on a header the request lacks is false), but
// the model's Negate holds when no value matches, and a missing value matches nothing. So "header X is not like this" is written
// "header X exists, and is not like this". ok is false for targets that always have a value (the method, the URI, the path) and for
// targets with many values, where the guard would not mean the same thing.
func ExistsGuard(targets []string) (c vpatch.Condition, ok bool) {
	if len(targets) == 0 {
		return c, false
	}
	pattern := "^"
	for _, t := range targets {
		switch {
		case t == vpatch.TargetBody:
			pattern = "(?s)."
		case strings.HasPrefix(t, "arg:"), strings.HasPrefix(t, "header:"), strings.HasPrefix(t, "cookie:"):
		default:
			return c, false
		}
	}
	return vpatch.Condition{Operator: vpatch.OpRegex, Pattern: pattern, Targets: append([]string(nil), targets...)}, true
}
