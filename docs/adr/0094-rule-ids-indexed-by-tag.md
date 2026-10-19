# ADR-0094: Rule ids indexed by tag for ctl's removals by tag

- **Status:** proposed
- **Date:** 2026-10-19 (expected; update before merge)
- **Version:** unreleased (post-v3.8.1)
- **PR:** No PR opened (owner-authorized Carnical development)
- **Issue(s):** No linked issue
- **Deciders:** Pending maintainer review
- **Category:** Perf

## Context and Problem

`ctl:ruleRemoveByTag` and `ctl:ruleRemoveTargetByTag` found their rules by comparing the tag with
every tag of every rule in the WAF, each time the action ran. The Core Rule Set runs one of them on
almost every request: rule 941010 removes `REQUEST_FILENAME` from the rules tagged
`xss-perf-disable` whenever the file name holds only safe bytes. The CRS's exclusion packages and
local exclusions use `ruleRemoveByTag` too.

A CPU profile of Carnical under its load test put `ctlFn.Evaluate` at 3.0% of all CPU time, nearly
all of it in that scan.

## Decision Drivers

- The same rules are removed, in the same order, as before.
- Rules are not changed once transactions run, but the parser changes the rule group as it reads
  directives, and `SecRuleUpdateActionById` can add a tag to a rule that is already in it.
- No locking on the path transactions take.

## Considered Options

- **Keep the scan.** Correct, and repeated for every transaction although its answer never changes
  once the rules are loaded.
- **Build the index when the rules are loaded.** There is no single point where loading ends:
  `coraza.NewWAF`, the parser and tests that use `corazawaf.WAF` directly all add rules.
- **Build the index on first use, and drop it on every change.** `RuleGroup.RuleIDsByTag` builds a
  map from each tag to the ids of its rules, in the group's order, the first time it is asked.
  `Add`, the `Delete*` methods, `DiscardPendingChain`, `FindByID` (whose rule may be changed in
  place) and `RulesChanged` drop it. `SecRuleUpdateActionById` over a range of ids changes the rules
  `GetRules` returns in place, and calls `RulesChanged` after.

## Decision Outcome

Chosen: **build the index on first use, and drop it on every change**.

- The index is held in an `atomic.Pointer`. Transactions that find it missing at the same moment
  each build the same map, and whichever is stored last serves the rest.
- A rule that has a tag twice is listed once for it, as the scan matched it once.
- The `ctl` engine profile gives the rule it removes by tag a tag before the one it is removed by,
  so an index that kept only a rule's first tag fails there.

Measured with Carnical's load test corpus (40,000 requests, CPU profile over 20 seconds):

| | Before | After |
| --- | --- | --- |
| `ctlFn.Evaluate`, share of CPU | 3.00% | 0.65% |

Throughput moved within the run-to-run noise (about ±3%), with the same requests refused, the same
attacks passed and no errors.

## Technical Discussion

No substantive technical discussion recorded; this record accompanies the owner-authorized change
and no PR thread exists.

## Consequences

- **Positive:**
  - Removal by tag costs a map lookup and the removals themselves.
- **Negative / follow-up:**
  - The index holds one entry per tag of every rule for as long as the WAF lives.
  - A change to a rule's tags that does not go through the rule group would leave the index stale: a
    new path that changes the rules `GetRules` returns must call `RulesChanged`. Rules are immutable
    after compilation.

## References

- Related ADRs: ADR-0092
- Code: `internal/corazawaf/rulegroup.go` (`RuleIDsByTag`, `RulesChanged`), `internal/actions/ctl.go`,
  `internal/seclang/directives.go`, `testing/engine/ctl.go`
