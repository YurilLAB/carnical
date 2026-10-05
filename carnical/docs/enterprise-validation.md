# Enterprise protection validation

This record distinguishes tests of the changed Carnical code from limitations of the local development environment. Validation runs on Windows with Go 1.26.6 against local TCP listeners and an actual HTTP origin, without sending test attacks to public hosts.

## GraphQL operation and protocol enforcement (2026-10-05)

- `go test ./formats -count=1` passes, including the live proxy/origin checks, documentation consistency, monitor/off behavior, and adversarial cost checks without race instrumentation.
- `go test -race ./formats -skip 'Test(YAMLAtItsDefaultCapIsBounded|AdversarialBodiesCostInProportionToTheirSize)' -count=1` passes. These two existing timing tests have fixed throughput thresholds unsuitable for race instrumentation; they pass in the normal run above.
- `go test ./proxy -count=1` passes; the broader run also passes the proxy package with race instrumentation.
- `go vet ./formats ./proxy` passes.
- `go run golang.org/x/vuln/cmd/govulncheck@latest ./formats ./proxy` reports no reachable vulnerabilities in the tested packages at the time of the run. This is dependency evidence, not proof that the firewall has no vulnerabilities.
- `go test ./formats -run '^$' -fuzz '^FuzzGraphQL$' -fuzztime=30s -parallel=2` passes: 177,313 executions with the final implementation. It exercises documents and URL parameters and includes the new regression inputs as seeds.

Live evidence: selected GET mutations return 403 and produce rule 5002310; ambiguous selections and repeated `operationName` return 400 and rule 5002308. The origin receives zero requests for these refusals. A selected GET query beside an unselected mutation returns 200 and reaches the origin. A named POST mutation is forwarded with its body unchanged. Unit cases additionally cover forms, escaped parameter names, JSON member order, extensions, and a GET body explicitly permitted by policy.

Review covered bounded operation-name storage, selection ambiguity, method propagation to all envelopes, monitor/off behavior, no request content in findings, and the inspector's existing nil-input recovery contract. An initial method initialization before the recovery handler violated that contract; the existing regression test caught it and the initialization now happens inside the protected region.

## Executable format policy and decoded-body guards (2026-10-05)

The compiled firewall executable is exercised by 26 cases in `TestRequestFormatsAtCLI` against a real local HTTP origin with CRS disabled, so format enforcement is demonstrated independently. Cases cover default monitor, explicit block/off, CLI precedence over policy monitor, GraphQL GET selection, JSON duplicate keys, XML external entities, custom depth, gzip decoding and corrected origin framing, corrupt gzip, startup errors, invalid/unknown limits, a directory in place of a policy, and the 1 MiB policy-file cap. Default logs are checked for absence of a marker in request content.

Security review added live reproductions for two pre-existing guard-ordering defects. Before the fix, a compressed 160,011-byte JSON body exceeded the 128 KiB non-upload limit but returned 200, and compressed multipart uploads with an executable filename or script content also returned 200. After the fix these return 413 and 403 respectively, with no origin request. The decompressed size guard also holds in format monitor mode; an ordinary compressed upload reaches the origin unchanged after decoding. The proxy now checks final bytes and final media type after inspector transformations.

- `go test -p 1 ./formats ./proxy ./cmd/carnical -count=1` passes with the final implementation.
- `go test -race -p 1 ./proxy ./cmd/carnical -count=1` and `go vet ./cmd/carnical ./proxy ./formats` pass.
- `govulncheck ./cmd/carnical` reports no vulnerabilities at the time of the run.
- A Linux/amd64 binary with `CGO_ENABLED=0` is cross-compiled as a build check; this does not verify Linux runtime confinement.

## Aggregate GraphQL request budgets (2026-10-05)

Field, alias and directive budgets now apply to the selected operations across an entire request, including JSON batches. Tests exercise exact boundaries, fragment amplification, custom limits, selected versus unused operations, and interleaved fragment definitions. Each request owns its counters.

The compiled executable's live suite now has 29 cases, including batch refusal without an origin request, monitor forwarding, and three repeated valid batches through the same process to verify that counters reset. Normal and race runs of `./formats ./cmd/carnical` pass, with only the two existing throughput tests excluded from the race run as described above. `go vet` passes for both packages. The final GraphQL fuzz run passes 196,898 executions in 30 seconds, and the existing GraphQL benchmark runs with a valid selected-operation envelope. The Linux/amd64 cross-build passes again.

Review checked operation-index alignment, saturating arithmetic, per-request state, fixed-content findings, and monitor/off semantics. These are syntax budgets; schema-aware resolver costs and persisted-query registries are not implemented.

## Strict format policy loading (2026-10-05)

New regression cases first reproduced successful startup with a `null` policy/limit, duplicate limits/rules, and case-aliased limits. After strict validation, all five fail before opening a listener. The executable suite now has 34 live cases and passes, along with the full normal format suite, scoped race checks and vet. Valid default and customized policies still round-trip and enforce their configured limits.

`FuzzParsePolicy` passes 16,770 executions in a 30-second run. It checks accepted policies are usable and stable under canonical serialization, and that appending contradictory duplicate settings forces refusal. Unit cases cover escaped duplicate names, nested duplicates, exact case, empty collections, null entries, raw invalid UTF-8, unexpected extreme nesting and both sides of the shared 1 MiB cap. Review confirmed recursion follows the finite policy schema, configuration reflection stays outside the request path, and startup continues to fail closed. Compatibility is intentionally stricter for ambiguous and nullable configuration files.

## API volume and bounded rate state (2026-10-05)

The compiled executable suite has 44 live cases and passes. Added cases demonstrate a shared API route budget with CRS/formats off, custom and segment-bounded prefixes, resistance to spoofed forwarding headers, separate verified-client quotas through an explicitly trusted proxy, separate API/login quotas and startup refusal for invalid limits/prefixes. Refusals produce no origin requests and 429 replies include `Retry-After: 60` and `Cache-Control: no-store`.

Live proxy cases additionally exercise encoded slash/backslash, repeated slash, matrix parameters, uppercase routes, a caller changing its original prefix/trusted-range slices, and full identity state. Full state produces 503 without an origin request. Deterministic clock tests check exact minute expiry and rejection not extending the window; 100 concurrent calls admit exactly the seven permitted attempts. Storage is capped at 50,000 active client/budget pairs and 200,000 events, and expired capacity is reclaimed. Clock reads and all counters share one lock.

Normal and race runs of `./proxy ./cmd/carnical` pass, with final focused normal/race tests for the path and trust-copy safeguards. Vet passes, the CLI vulnerability scan reports no vulnerabilities, and the Linux/amd64 cross-build passes. `FuzzSlidingRateBudget` passes 177,583 executions in 30 seconds against a simple independently scanned event-history reference, covering expiry, saturation and ring wraparound.

These quotas apply to one process, use IP identity, and reset on restart. They do not provide distributed or authenticated-principal rate accounting. Capacity exhaustion is an explicit refusal, trading admission availability for bounded enforcement.

## Environment and baseline limitations

`go test ./...` in the upstream module fails on existing Windows filesystem expectations and open audit/debug log handles (auditlog, operators, seclang, testing). The changed code is confined to Carnical's separate module; no upstream engine files are changed.

The broader Carnical race run encounters Windows audit-file recovery/truncation failures in the pre-existing, untracked `control` package. Those files are outside these commits. The first broad run also ran an intermediate implementation; its format failures were corrected and superseded by the passing scoped runs above.

That broad run also times out after ten minutes in the untracked virtual-patch brute-force comparison test (`TestIndexedMatchEqualsBruteForce`). It is not represented as a passing full-module race run.

`go run mage.go adr` rejects 60 pre-existing ADRs as lacking the exact technical-discussion section marker. The new ADRs 0061–0065 produce no diagnostics. The Windows checkout has CRLF in older documents, which the validator's exact marker comparison does not normalize. This check is not claimed to pass globally.

WSL's Ubuntu environment first reported a read-only home when creating the Go cache and subsequently failed to start. Linux confinement and the full Linux CI matrix have not been verified by these runs.
