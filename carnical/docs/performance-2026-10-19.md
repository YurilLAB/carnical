# Performance record: 19 October 2026

This record measures the engine and proxy changes made on `edge-crs` between `24d7ce37` (before)
and `d1df209e` (after), and the regression suites run alongside them. The local runs used a cloud
container (Linux 6.18.44, 4 CPUs, Go 1.26.9, no IPv6). The CI runs used GitHub's Ubuntu 24.04
runners. The counts belong to these runs.

Use the [documentation index](README.md#review-the-evidence) for the current guides and older
records.

## What changed

| Commit | Change | Record |
| --- | --- | --- |
| `8d2e9595` | `RULE` is filled when it is read, not at the start of every rule | [ADR-0092](../../docs/adr/0092-rule-collection-filled-when-read.md) |
| `c006798e` | Bodies are copied into the body buffer through pooled buffers, and read out of it in one write | [ADR-0093](../../docs/adr/0093-bodies-copied-without-a-buffer-each.md) |
| `3af347c1` | The reverse proxy reuses the buffers it copies responses through | — |
| `a48986ce` | A target with no exceptions skips the pass that compares keys with them | — |
| `d1df209e` | `ctl` finds rules by tag through an index | [ADR-0094](../../docs/adr/0094-rule-ids-indexed-by-tag.md) |

None of them changes which requests are refused or what is logged.

## Through Carnical

`tools/loadtest` with its corpus, `-count 40000 -variants -hardening -ddos off`, 16 clients, the
load generator and the WAF on the same 4 CPUs. Three runs of each build, alternated:

| Build | Requests/s | p50 | p95 | p99 | Benign refused | Attacks passed | Errors |
| --- | --- | --- | --- | --- | --- | --- | --- |
| Before, run 1 | 2,012 | 6.43 ms | 19.93 ms | 26.83 ms | 1,029 | 354 | 0 |
| After, run 1 | 2,312 | 5.54 ms | 17.34 ms | 23.85 ms | 1,029 | 354 | 0 |
| Before, run 2 | 2,024 | 6.40 ms | 19.74 ms | 26.06 ms | 1,029 | 354 | 0 |
| After, run 2 | 2,377 | 5.40 ms | 16.78 ms | 22.77 ms | 1,029 | 354 | 0 |
| Before, run 3 | 2,026 | 6.38 ms | 19.71 ms | 26.46 ms | 1,029 | 354 | 0 |
| After, run 3 | 2,377 | 5.37 ms | 16.84 ms | 23.01 ms | 1,029 | 354 | 0 |

On average 2,021 requests per second before and 2,355 after (+16.5%), with the median latency 15%
lower and the 99th percentile 12% lower. Every run refused the same benign requests and passed the
same attacks.

CPU profiles over 20 seconds of the same load (share of all CPU time):

| | Before | After |
| --- | --- | --- |
| `RULE` filled for each rule (message and log data expanded) | about 8% | only when read |
| `ctlFn.Evaluate` (removals by tag) | 3.00% | 0.65% |
| `strings.ToLower` | 4.55% | 3.41% |

An allocation profile before the changes put the two 32 KiB copy buffers each body went through at
19% of all bytes allocated, and the reverse proxy's response copy buffer at 7.5%.

## In the engine

`BenchmarkCRSSimpleGET` and `BenchmarkCRSSimplePOST` (`testing/coreruleset`), six runs each,
compared with benchstat, for the `RULE` change:

| Benchmark | Time | Allocations |
| --- | --- | --- |
| SimpleGET | 2.657 ms → 2.435 ms (−8.4%) | 5,477 → 4,403 (−19.6%) |
| SimplePOST | 3.557 ms → 3.234 ms (−9.1%) | 7,135 → 6,025 (−15.6%) |

For the body copies, SimplePOST allocates 9.0% fewer bytes, and `BenchmarkCRSLargePOST` takes 9.8%
less time. The exception pass saves 1.5% of allocations on both benchmarks. The timing of the last
two changes is within the benchmark's noise.

## The rx prefilter

`SecRxPreFilter` (ADR-0049, ADR-0050) skips an `@rx` regular expression when a literal it needs
is absent. It stays `Off` in Carnical, as upstream ships it, because upstream marks it experimental.
Measured with it on:

- Through Carnical, about 8% more requests per second, with the same requests refused and the same
  attacks passed.
- Every one of the Core Rule Set's 320 `@rx` patterns (300 plus 20 negated), each compiled with
  the `(?s)` and `(?sm)` flags the operator adds, against 24,967 inputs: the CRS's own test
  payloads, the waf-bypass and GoTestWAF payloads, and what 21 chains of the CRS's transformations
  make of each. That is 15,978,880 pattern and input pairs. The prefilter skipped 8,517,863 of
  them, and the regular expression matched none of those.
- A fuzz target over the same patterns, seeded with the same inputs, ran for 10 minutes: 621,221
  inputs, none skipped that the regular expression matched.
- The CRS regression suite passes under the `coraza.rule.rx_prefilter` build tag, which turns it on.

## Regression suites

| Suite | Result |
| --- | --- |
| `go run mage.go test` (default and `no_memoize`, CRS under four tag sets, `TestRx*`, `TestCaseSensitive*`) | pass, after each change |
| `go test ./...` under `multiphase_evaluation`, `rx_prefilter`, `case_sensitive_args_keys`, `no_fs_access`, `mandatory_rule_id_check` | pass |
| `go run mage.go coverage` (race detector) with no tags, and with all seven tags | pass |
| `GODEBUG=fips140=on` and `fips140=only`, `./...` and the CRS suite | pass |
| `go run mage.go lint`, `go run mage.go adr` | pass |
| Carnical `./proxy ./shield ./crs ./policy ./cmd/carnical` | pass, except the two IPv6 tests this container cannot run |
| CI: Regression Tests (15 tag sets and 2 FIPS modes), Lint, ADR on `edge-crs` | pass, first run on this branch |

Regression Tests, Lint and ADR ran only on `main` before `2e8f4df9`, so `edge-crs`, the default
branch, had no engine regression matrix in CI. They now run on every push to it. The matrix moved
to Go 1.26, which `go.mod` requires.

The TinyGo workflow now runs on `edge-crs` too, with TinyGo 0.43.0, the newest release. The pinned
0.40.1 could not build a module needing Go 1.26; 0.41.0 is the first that can.

## JSON bodies under TinyGo

Turning on the TinyGo workflow showed that the JSON body processor walked nested objects and arrays
by recursion, about 650 bytes of stack per level. A TinyGo WASI build, with its default 64 KiB
stack, stopped with `fatal error: stack overflow` on a body nested about 100 deep, well inside the
default `SecRequestBodyJsonDepthLimit` of 1024. Carnical itself is built with Go, whose stacks grow,
and was not affected.

The walk now keeps its place in each open container on a stack of its own (`json_iter.go`), using
gjson's own member parsing so that every body, valid or not, is read as before. Measured on a
TinyGo 0.43.0 WASI build run under Node 22, through `coraza.NewWAF` with the JSON processor:

| Nesting depth | Before | After |
| --- | --- | --- |
| 50 | read | read |
| 100 | stack overflow | read |
| 1,024 | stack overflow | read |
| 1,025 | stack overflow | refused at the depth limit |
| 20,000 | stack overflow | refused at the depth limit |

Checks of the new walk:

- A fuzz target comparing the arguments, the truncation flag and the error of the new walk with the
  recursive one, over random bodies and depth and argument limits, ran 6,496,736 inputs, and after
  a later change another 5 minutes, with no difference.
- `FuzzJSONIterMatchesForEach`, kept in the suite, compares every member the walk reads with what
  gjson's `ForEach` gives. It ran 5,204,764 inputs with no difference, and it fails if the walk
  skips a byte differently from `ForEach`.
- `tinygo test -short ./internal/...`, with and without `coraza.no_memoize`, passes.
- JSON parsing alone takes about 16% longer on `BenchmarkReadJSON` and `BenchmarkValidationOverhead`
  (geometric mean), with the same memory. Through Carnical the load test gave 2,248 and 2,310
  requests per second against 2,243 and 2,291 before, with the same requests refused, the same
  attacks passed and no errors.
