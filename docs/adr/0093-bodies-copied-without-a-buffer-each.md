# ADR-0093: Request and response bodies copied without a buffer of their own

- **Status:** proposed
- **Date:** 2026-10-19 (expected; update before merge)
- **Version:** unreleased (post-v3.8.1)
- **PR:** No PR opened (owner-authorized Carnical development)
- **Issue(s):** No linked issue
- **Deciders:** Pending maintainer review
- **Category:** Perf

## Context and Problem

A request body was copied through two 32 KiB buffers that were thrown away afterwards:

- `ReadRequestBodyFrom` and `ReadResponseBodyFrom` call `io.CopyN` into the `BodyBuffer`. The
  limited reader `io.CopyN` wraps the source in has no `WriteTo`, and `BodyBuffer` has no
  `ReadFrom`, so `io.Copy` allocates a buffer for each body.
- The JSON, urlencoded and raw body processors, and `ProcessResponseBody` without a processor,
  copy the buffered body into a `strings.Builder` with `io.Copy`. The body buffer's reader has
  no `WriteTo` either, so this allocated a second buffer, and a body longer than one buffer grew
  the builder in steps.

An allocation profile of Carnical under its load test put these at 19% of all the bytes it
allocated, more than any other single site.

## Decision Drivers

- The body limits and their actions behave exactly as before.
- A buffer that is reused must never hand on bytes from an earlier body.
- TinyGo keeps building: pools go through `internal/sync`.

## Considered Options

- **`ReadFrom` on `BodyBuffer`.** It would read straight into the memory buffer, but it has to
  repeat the memory limit, the spill to a temporary file and the limit checks that `Write`
  already makes, in a second place.
- **A pooled buffer for the copy into `BodyBuffer`, and `WriteTo` on its reader.** The copy in
  keeps going through `Write`, so every check stays where it is. The copy out of memory becomes
  one `Write` of the bytes already held.

## Decision Outcome

Chosen: **a pooled buffer for the copy into `BodyBuffer`, and `WriteTo` on its reader**.

- `BodyBuffer.copyN` copies through a 32 KiB buffer taken from a pool and returned after the copy.
  `io.CopyBuffer` writes only the bytes each read returned, so what is left in a buffer from an
  earlier body is never written.
- `bodyBufferReader.WriteTo` writes the rest of a body held in memory in one write, from where any
  earlier read stopped. For a body in a temporary file it copies from a section of the file
  starting there.

`BenchmarkCRSSimplePOST` and `BenchmarkCRSLargePOST` (`testing/coreruleset`, six runs each,
compared with benchstat):

| Benchmark | Time | Bytes |
| --- | --- | --- |
| SimplePOST | 3.282 ms → 3.392 ms (no significant change) | 385.2 KiB → 350.6 KiB (−9.0%) |
| LargePOST | 174.6 ms → 157.5 ms (−9.8%) | 1132.9 KiB → 898.1 KiB (not significant, ±37%) |

## Technical Discussion

No substantive technical discussion recorded; this record accompanies the owner-authorized change
and no PR thread exists.

## Consequences

- **Positive:**
  - A body costs one allocation of its own size when a body processor reads it, not a 32 KiB
    buffer and a growing builder.
- **Negative / follow-up:**
  - Each pooled buffer is 32 KiB. The pool holds as many as there are bodies being copied at once,
    and the Go runtime frees unused ones at garbage collection.

## References

- Related ADRs: ADR-0092
- Code: `internal/corazawaf/body_buffer.go` (`copyN`, `bodyBufferReader.WriteTo`),
  `internal/corazawaf/transaction.go`
