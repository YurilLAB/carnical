# Protection validation record

This records the protection work tested on 5–6 October 2026, including local Windows/Go 1.26.6
conditions and failures encountered then. Counts and versions belong to those runs.
Later fixes and [security CI](https://github.com/YurilLAB/carnical/actions/runs/37900620871)
at revision `fc8f17a6` supersede the old baseline/CI failures; all 12 jobs passed on that revision.

Use the [documentation index](README.md#review-the-evidence) to find the current operational
guides and later validation records. Attacks here target isolated local origins.

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

## URL query protection (2026-10-05)

Five new live reproductions returned 200 before the change for malformed escapes, raw semicolons, NUL, invalid UTF-8 and prototype parameter names. They now return 400 with no origin request. The compiled executable suite has 56 passing cases, checking ordinary encoded values/arrays, unchanged origin request targets, monitored duplicates/semicolons, configurable duplicate blocking, query byte/count caps and continued JSON body enforcement after a monitored query cap.

The full normal format suite and scoped race suite pass, with the two existing throughput exclusions described above for race instrumentation. The CLI normal/race suites and vet pass. The existing form fuzz target now includes generic GET and POST query inputs and passes 58,427 executions in 30 seconds. Query rows participate in the common monitor/off negative controls and concurrent shared-inspector checks. Policy validation, default serialization and the complete rule documentation table also pass.

Review covered independent form/query rule selection, bounded scanning and capture, escaped names, parameter counts, fixed-content findings, all-method dispatch and body-inspection continuity. A query beyond a monitored/disabled scan budget is forwarded without complete query analysis; default enforcement refuses it. Application-specific parameter schemas and query/body name collisions remain outside this change.

## GraphQL safe-method bypass variants (2026-10-05)

Two HEAD mutations first returned 200 in the compiled executable, including a discovered endpoint. They now return 403 without reaching the origin. GET keeps its existing rule; HEAD, OPTIONS and TRACE use 5002314. The executable suite now has 68 cases, including escaped protocol names/operation text, fragment-based selection, a batch in an explicitly permitted HEAD body, ambiguous duplicate selection and related monitor forwarding. Findings are structural, rather than matches against one attack string.

The full normal format and executable suites pass. Scoped race checks, vet and the Linux/amd64 cross-build pass. GraphQL fuzzing passes 6,263 executions in 30 seconds, including safe-method envelopes; the run spends much of its time minimizing new inputs. Rows also cover comments, raw GraphQL, form envelopes, selected queries beside unselected mutations, ordinary preflights and independent GET policy overrides. All new refusal rows participate in monitor/off negative controls and concurrent shared-inspector checks. Findings use fixed messages with distinct method, selection and envelope rule identities.

Review confirms method metadata is initialized inside panic recovery, every inspected envelope shares the selected-operation check, and no request rewriting or method expansion occurs. Persisted queries and nonstandard origin method aliases still require origin-specific enforcement. Two obsolete limitations in the format documentation were corrected.

## Bypass telemetry and log privacy (2026-10-05)

A live Coraza rule with a request macro first reproduced a secret marker in a default finding's Message, even though URI/Data were omitted. The same test now confirms a fixed default summary and an expanded message only with explicit detailed logging. A panic carrying request content is refused with 503 and a fixed failure message; a subsequent valid request still reaches the origin. Inspector failure (5000040), rate-state exhaustion (5000041) and API quota (5000042) now have distinct IDs. Rule text uses rule_msg, leaving slog's msg key for the event instead of producing duplicate JSON keys.

The executable suite now has 74 cases. Added cases verify every repeated blocked/monitored bypass attempt has a finding with the correct enforcement outcome, changed per-rule totals reach the actual executable's JSON log, and neither individual findings nor aggregates contain the secret marker. One monitored HEAD body simultaneously triggers body-on-get, duplicate JSON and safe-method mutation findings; all three are independently asserted. Related encoded/form variants share the appropriate structural rule rather than relying on one attack string. Invalid reporting intervals fail before listening.

Normal format/proxy/executable tests and the scoped race suite pass, with the two existing timing-test exclusions described above. The final additional executable case passes normal and race checks. Twenty concurrent workers produce exactly 100 blocked or monitored findings, batches emit once per rule per request, disabled rules remain silent, and snapshot mutation cannot change inspector state. Reporter lifecycle tests verify final flushing, suppression of unchanged snapshots, disabled reporting and format mode off. Vet, the CLI dependency vulnerability scan and Linux/amd64 cross-build pass.

Review covered atomic counter storage sized only by the registry, independent snapshots, unchanged stop/reporting caps, reporter cancellation/joining, stable labels and the opt-in boundary for expanded messages/panic details. Counters describe emitted findings, reset with a new inspector and are local to one process. A forced kill cannot flush a final summary. Default Coraza summaries require rule-ID lookup; existing log consumers must adopt rule_msg and the API quota's corrected ID. These are monitoring boundaries, not evidence of production deployment or complete application authorization.

## Layered GraphQL transport protection (2026-10-05)

Fifteen additional live executable reproductions first returned 200: a HEAD mutation with its primary rule disabled, a PUT form operation, URL/body operation selection conflicts, a lowercase method token, URL/form/JSON method overrides, three discovered-endpoint body-only protocol envelopes, three protocol-name case aliases, and two batches hiding operations after an empty prefix or beyond retained elements. They now return 400 or 403 with no origin request. The executable suite has 100 cases, including valid GET queries/POST mutations, ordinary metadata/preflights, application `_method` fields inside variables, escaped/bracket aliases, extension-only HEAD requests, monitor forwarding and hard header refusals with CRS/formats off.

Rules 5002315, 5002316 and 5002317 provide independent method, mixed-envelope and metadata layers. The live suite verifies repeated fallback blocks increment 5002315 even with the mutation rule off; monitored mixed envelopes increment 5002316; repeated method metadata increments 5002317. A combined protocol alias/override HEAD request emits four separate findings (5002314, 5002315, 5002308 and 5002317), with monitored outcomes and per-rule totals. Default logs and aggregates exclude the secret marker. Blocking mode stops at its first refusal rather than claiming all latent findings were inspected.

Normal format/proxy/executable tests pass. Scoped race checks pass, excluding the same two existing format throughput tests noted above; those pass normally. CLI race checks instrument the test/reporter harness, while its live child executable is built normally. The final GraphQL fuzz run passes 12,989 executions with a 30-second budget. Vet, govulncheck of the CLI dependency graph, and the Linux/amd64 cross-build pass. No upstream engine files or unrelated untracked API-policy work are included.

Review covered decoded protocol aliases, bounded JSON/form capture, batch discovery across all scanned elements, request-local URL identification, body-only protocol fields, independent policy exceptions, mutation selection before coarse guards, per-rule deduplication, fixed log text and admission before hop-header stripping. The GET/POST restriction is an explicit local policy, since the HTTP draft permits additional server methods. Legacy HEAD/PUT transports and header tunneling can require integration changes. Custom override names/getters and document-free persisted-query operation types still need explicit endpoint/origin policy. Format enforcement requires `-formats-mode block`; default monitor mode intentionally forwards. Monitored/disabled batch caps still limit retained operation analysis.

## Enterprise package publication (2026-10-06)

The owner authorized publication of the previously untracked API guard, signed configuration, policy, control/feed API,
virtual-patch engine/importers and offline commands. Normal short checks pass across those packages. Normal policy/control
checks also pass, including real proxy requests and TLS listeners; the control authentication timing check and policy
paranoia measurement pass outside short mode. A short race run across all publication packages passes with a 15-minute
per-package timeout. The virtual-patch package took 890.6 seconds under the race detector, including its reduced short-mode
index-equivalence workload. This is not the unabridged, non-short index stress run.

Publication testing fixed Windows audit-log torn-tail repair and failed-append rollback. The Windows writer retains append
semantics, opens a checked writable repair handle, and closes after rollback failure. Scoped race regressions also verify
that repair cannot truncate a different file. A reopened audit test handle is now closed. Policy tests retain their custom
rule identity/severity checks while expecting the proxy's privacy-safe summary.

Live virtual-patch command checks exposed replay runs that could load zero scoped signatures and still report success.
Replay now accepts software scope and rejects empty active sets. Normal/race command rows cover matching, absent and wrong
scope. A real conversion loads two community-tier Jira fixture signatures, and an offline replay compares their indexed
and full answers over 468 benign and 247 attack samples with no difference. These two Jira signatures match none of that
generic corpus; this smoke check is not a detection-rate claim. An unsupported count-comparison fixture is explicitly
refused by conversion rather than approximated.

Vet, govulncheck over the Carnical module, and Linux/amd64 compilation with CGO disabled pass. The source scan finds no
deployment credentials; signing/TLS test material is generated locally or uses test vectors. Third-party test fixtures
retain their upstream notices and bytes, including whitespace; diff whitespace checks pass outside those fixture paths.
The packages remain integration APIs: production stores, UI/key provisioning, guarded discovery transport and installing
API/virtual-patch inspectors in a deployed site's proxy are separate deployment work.

## Environment and baseline limitations

The [live load report](loadtest-2026-10-06.md) records a final 500,000-request run with corrected URL/framing fidelity:
5,282.34 requests/second, p99 10.620 ms, zero transport/availability errors, 86.92% labelled-attack refusal and 2.34%
labelled-benign refusal. All 8,888 added bypass regression requests are refused before the counted origin. The report
preserves the 34 admitted attack templates and 11 refused benign templates, the precise standalone configuration and
the boundary between request admission and exploitation. It does not measure the uninstalled integration APIs.

The [extended live load report](loadtest-750k-2026-10-06.md) records 750,000 requests through the same WAF binary, retaining
all 731 original templates and adding 238 templates across six categories. The run achieves 5,657.82 requests/second with
p99 9.633 ms and zero transport/availability errors. It refuses 312,695 of 364,553 labelled attack requests (85.77%) and
11,608 of 385,447 labelled benign requests (3.01%). The original cohort retains the same outcomes; the new workload exposes
18 admitted HPP templates, 15 admitted XPath templates and four new benign refusals. All 10,062 bypass regression requests
are refused. The [organized inventory](loadtest-750k-admitted-2026-10-06.md) lists all 67 admitted attack templates with
wire targets and payload details. Vet and a 3,000-request race-instrumented harness pilot pass; the child WAF is built
normally. Post-run checks reconcile every case and aggregate, verify original-cohort outcomes and matching binary/corpus
hashes, and confirm child shutdown. This is admission evidence against a fixed origin, not exploitation or production
deployment validation.

The [variant load report](loadtest-750k-variants-2026-10-06.md) adds variants across all 22 attack categories and exercises
3,849 distinct attack requests and 1,778 distinct benign requests over 750,000 requests with an even class split. Attack
refusal is 81.42%, benign refusal is 3.76%, throughput is 4,855.09 requests/second and p99 latency is 11.091 ms, with zero
transport/availability errors. All original 969 templates retain their outcomes. No generated variant of a refused
measured parent is admitted; 90 variants of admitted parents are refused. New syntax candidates and variants of already
admitted inputs produce 716 admitted templates; the [inventory](loadtest-750k-variants-admitted-2026-10-06.md) preserves
their categories, parents, variation types and payloads. All 5,542 bypass regression requests, including variants, are
refused. Vet, final normal/race live pilots and the default-workload compatibility check pass. Post-run checks reconcile
every count, fingerprint total, category, original outcome and parent comparison. Review excludes renamed configuration
files whose attack interpretation would be lost and preserves duplicate JSON/form/query fields. The WAF pipeline is
unchanged; workload composition and weights differ, and admitted candidates still require unsafe application behavior.

`go test ./...` in the upstream module fails on existing Windows filesystem expectations and open audit/debug log handles (auditlog, operators, seclang, testing). The changed code is confined to Carnical's separate module; no upstream engine files are changed.

An earlier broader Carnical race run encountered Windows audit-file recovery/truncation failures in the then-untracked
`control` package. The publication fixes and passing control checks above supersede those failures. The first broad run
also ran an intermediate format implementation; its failures were corrected and superseded by the passing scoped runs.

That broad run also times out after ten minutes in the untracked virtual-patch brute-force comparison test (`TestIndexedMatchEqualsBruteForce`). It is not represented as a passing full-module race run.

`go run mage.go adr` rejects 60 pre-existing ADRs as lacking the exact technical-discussion section marker. The new ADRs
0061–0070 produce no diagnostics. The Windows checkout has CRLF in older documents, which the validator's exact marker
comparison does not normalize. This check is not claimed to pass globally.

WSL's Ubuntu environment first reported a read-only home when creating the Go cache and subsequently failed to start. Linux confinement and the full Linux CI matrix have not been verified by these runs.
