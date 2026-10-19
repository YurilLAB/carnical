# ADR-0092: The RULE collection filled when it is read

- **Status:** proposed
- **Date:** 2026-10-19 (expected; update before merge)
- **Version:** unreleased (post-v3.8.1)
- **PR:** No PR opened (owner-authorized Carnical development)
- **Issue(s):** No linked issue
- **Deciders:** Pending maintainer review
- **Category:** Perf

## Context and Problem

`RULE` holds the metadata of the rule being evaluated: its id, message, revision, log data and
severity. `Rule.doEvaluate` set all five at the start of every rule's evaluation, and expanded the
rule's `msg` and `logdata` macros to do it, whether the rule matched or not. With the Core Rule Set
a request evaluates several hundred rules, and almost none of them match.

A CPU profile of Carnical under a mixed load of benign requests and attacks put this work at about
8% of the time spent in the engine. The Core Rule Set never reads `RULE`: it has no `%{rule.*}`
macro and no `RULE` target.

## Decision Drivers

- No change in what any rule sees in `RULE`, or in what is logged.
- Rule sets that do read `RULE` keep their behaviour exactly.
- No cost to the many rules that never match.

## Considered Options

- **Keep filling `RULE` for every rule.** This is correct, and pays for a message expansion that is
  thrown away in nearly every case.
- **Always fill `RULE` when it is first read.** The transaction remembers the rule being
  evaluated, and `RULE` is filled from it on its first read during that rule. For a `RULE` target
  this is the same moment as before. For a `%{rule.msg}` macro in an action, it is not: the message
  would be expanded after earlier actions of the same rule ran, and a `setvar` the message refers
  to could already have changed it.
- **Fill it when it is read, unless a rule may expand a `%{rule.*}` macro.** The WAF records whether
  any directive holds such a macro, and only then fills `RULE` at the start of every rule as before.

## Decision Outcome

Chosen: **fill it when it is read, unless a rule may expand a `%{rule.*}` macro**.

- `corazawaf.WAF.RuleCollectionRead` starts true, so a WAF built directly behaves as before.
  `coraza.NewWAF` clears it before the rules are parsed.
- The parser sets it again for any directive that contains `%{rule.` or `%{rule}`, matched case
  insensitively. A rule given to `WithRule` as a Go value sets it too, since its actions cannot be
  read.
- When it is false, `doEvaluate` records the rule, and the first read of `RULE` through
  `Transaction.Collection`, `TransactionVariables.Rule` or `TransactionVariables.All` fills it.
  The record is cleared when the transaction is reset.

`BenchmarkCRSSimpleGET` and `BenchmarkCRSSimplePOST` (`testing/coreruleset`, six runs each,
compared with benchstat):

| Benchmark | Time | Bytes | Allocations |
| --- | --- | --- | --- |
| SimpleGET | 2.657 ms → 2.435 ms (−8.4%) | 272.2 KiB → 233.5 KiB (−14.2%) | 5477 → 4403 (−19.6%) |
| SimplePOST | 3.557 ms → 3.234 ms (−9.1%) | 424.3 KiB → 382.3 KiB (−9.9%) | 7135 → 6025 (−15.6%) |

Through Carnical with its load test corpus (40,000 requests), the requests refused and the attacks
passed were the same as before, with no errors.

## Technical Discussion

No substantive technical discussion recorded; this record accompanies the owner-authorized change
and no PR thread exists.

## Consequences

- **Positive:**
  - Every rule that does not read `RULE` no longer expands its message and log data on each
    evaluation.
- **Negative / follow-up:**
  - A plugin that reads `RULE` from an action, in a rule set with no `%{rule.*}` macro, gets the
    message expanded when it reads it rather than when the rule started.
  - `testing/engine/macroexpansion.go` holds the case that tells the two timings apart, so a change
    to the parser hook that loses it fails there.

## References

- Related ADRs: ADR-0049, ADR-0050
- Code: `internal/corazawaf/rule.go` (`fillRuleCollection`), `internal/corazawaf/transaction.go`
  (`TransactionVariables.ruleCollection`), `internal/corazawaf/waf.go` (`RuleCollectionRead`),
  `internal/seclang/parser.go` (`ruleMacro`), `waf.go`
