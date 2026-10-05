// SPDX-License-Identifier: Apache-2.0

package formats

import (
	"strconv"

	"github.com/YurilLAB/coraza/carnical/inspect"
)

// maxVerdicts is the most verdicts one request can produce. Each rule is reported once, so this only matters in monitor mode on a
// body that breaks many rules.
const maxVerdicts = 32

// finder turns what a parser finds into verdicts, applying the policy. A parser never decides what a finding costs: it reports it
// here and is told whether to stop. Keeping that in one place is what lets every rule be set to block, monitor or off.
//
// The text of a verdict is built from the rule's fixed sentence, one of the fixed details in details.go, and numbers. There is no
// way to pass a string from the request into it, so a message cannot quote the body, a key or a name.
type finder struct {
	in           *Inspector
	verdicts     []inspect.Verdict
	seen         [maxRules / 64]uint64
	blocked      bool
	mutationRule *rule // method safety applies to every GraphQL envelope, including explicitly permitted GET/HEAD bodies
	method       string
	urlGraphQL   bool     // the URL parameters identify this request as GraphQL
	urlOverride  bool     // reserved method-override metadata in URL parameters
	urlProtocol  bool     // GraphQL protocol parameters were present in the URL, independently of body fields
	graphql      gqlStats // selected-operation totals belong to this request, never the shared Inspector
	// line is the number of the NDJSON line being checked, 0 when none is.
	line int
}

func (f *finder) active(r *rule) bool { return f.in.act[r.idx] != Off }

// hit reports a finding at byte offset off (-1 if it has no position). It returns true if the request is now refused, which tells
// the parser to stop. A parser that cannot go on after the finding (a syntax error) stops whatever this returns.
func (f *finder) hit(r *rule, off int, d detail) bool {
	return f.record(r, d, -1, off)
}

// hitLimit is hit for a limit, which says what the limit is.
func (f *finder) hitLimit(r *rule, d detail, limit, off int) bool {
	return f.record(r, d, limit, off)
}

func (f *finder) record(r *rule, d detail, limit, off int) bool {
	act := f.in.act[r.idx]
	if act == Off {
		return false
	}
	block := act == Block
	if block {
		f.blocked = true
	}
	word, bit := r.idx/64, uint64(1)<<(uint(r.idx)%64)
	if f.seen[word]&bit != 0 || len(f.verdicts) >= maxVerdicts {
		return block
	}
	f.seen[word] |= bit
	msg := r.name + ": " + r.text
	if d != dNone {
		msg += ", " + detailText[d]
	}
	if limit >= 0 {
		msg += " (limit " + strconv.Itoa(limit) + ")"
	}
	if f.line > 0 {
		msg += " in line " + strconv.Itoa(f.line)
	}
	if off >= 0 {
		msg += " at byte " + strconv.Itoa(off)
	}
	f.verdicts = append(f.verdicts, inspect.Verdict{ID: r.id, Message: msg, Block: block, Status: r.status, Severity: r.severity})
	if block {
		f.in.counts[r.idx].blocked.Add(1)
	} else {
		f.in.counts[r.idx].monitored.Add(1)
	}
	return block
}
