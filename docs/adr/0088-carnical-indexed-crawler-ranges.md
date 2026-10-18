# ADR-0088: Indexed lookup of published crawler ranges

- **Status:** proposed
- **Date:** 2026-10-18 (expected; update before merge)
- **Version:** unreleased (post-v3.8.1)
- **PR:** No PR opened (owner-authorized Carnical development)
- **Issue(s):** No linked issue
- **Deciders:** Pending maintainer review
- **Category:** Perf

## Context and Problem

`-bots-ranges` gives the bot policy the address ranges engines publish for their crawlers
([ADR-0087](0087-carnical-bot-policy-and-counts.md)). A request that claims to be a crawler is
checked against its engine's ranges before DNS. `Verifier.Verify` did this by scanning every
range of the engine in turn, on every such request.

Every claim pays for that scan, including a flood of impostors claiming Amazonbot or Googlebot from
addresses whose refusal is already cached. Engines publish a few hundred to a few thousand ranges,
but a ranges file may hold up to 4 MiB, which is about 250,000 ranges written one a line.
Measured with `BenchmarkVerifyRanges` (`carnical/bots`, Go 1.26.9, a 4-vCPU Xeon at 2.1 GHz), one
cached impostor's request cost:

- 6.9 µs at 1,300 ranges, the size of Amazon's list;
- 104 µs at 20,000 ranges;
- 1.33 ms at 250,000 ranges.

At the largest size, impostors claiming a crawler at 1,000 requests a second take more than one
core for the scan alone.

## Decision Drivers

- The cost of a claim must not grow with the size of the list an operator supplies.
- No new dependency, and no change to what is verified.
- Lookups must be safe for concurrent use without a lock.

## Considered Options

- **Keep the linear scan** and lower the file limit. Real lists stay well under the limit, but a
  lower limit would refuse lists that are legitimately long, and every claim would still pay for
  the scan.
- **A radix tree (prefix trie)** per engine, or a dependency such as `bart`. It is fast, but needs
  either a dependency or a hand-written structure much larger than the problem.
- **Sorted, disjoint spans with binary search.** Each range becomes the span of addresses it
  covers. The spans are sorted, overlapping or touching spans are joined, and IPv4 and IPv6 are
  kept apart. A lookup is one binary search.

## Decision Outcome

Chosen: **sorted, disjoint spans with binary search**, because it makes a lookup logarithmic in
the list's size with a few dozen lines of standard library code. The `Verifier.Ranges` field
becomes `Verifier.SetRanges`, which builds the index once and swaps it in with one atomic pointer,
so lookups take no lock. [ADR-0089](0089-carnical-crawler-lists-kept-current.md) uses that to
replace the lists while the edge runs.

After, on the same machine and benchmark, from ranges that do not touch (so none are joined):

| Ranges | Impostor, before → after | Crawler, before → after |
| --- | --- | --- |
| 1,300 | 6.9 µs → 182 ns | 4.0 µs → 123 ns |
| 20,000 | 104 µs → 205 ns | 103 µs → 158 ns |
| 250,000 | 1.33 ms → 228 ns | 1.32 ms → 196 ns |

Neither version allocates on a lookup. Building the index for 250,000 ranges takes 140 ms at start
and about 6 MB more than the list itself. For the lists engines publish, both costs are negligible.

`TestVerify` gained rows for the boundaries an index can get wrong:

- the first and last address of a range;
- two ranges that touch, and the address past both;
- a range inside a wider one;
- a single address and its neighbours;
- the end of an IPv6 range;
- an IPv4 address that shares its bits with an IPv6 range.

Each of four deliberate faults made some of these rows fail:

- an exclusive end of a span;
- no sort;
- a wrong last address;
- a join that shortens a span.

## Technical Discussion

No substantive technical discussion recorded; this record accompanies the owner-authorized change
and no PR thread exists.

## Consequences

- **Positive:** a claimed crawler costs the same whatever the list's size, so a long list no
  longer lets impostors make each request expensive.
- **Negative / follow-up:** keeping the lists current is the subject of ADR-0089.

## References

- Related ADRs: ADR-0087, ADR-0089
- Code: `carnical/bots/verify.go` (`SetRanges`, `rangeSet`), `carnical/bots/bots_test.go`
  (`TestVerify`, `BenchmarkVerifyRanges`)
