# Live WAF input hardening validation: 2026-10-06

The final standalone Carnical WAF refused **357,164 of 375,000 attack-labelled requests (95.24%)** in a 750,000-request live run. Every one of the **246 new adversarial templates** was refused, including deeper traversal encoding, nested XPath comments, parenthesized template arithmetic, obfuscated commands and XML attributes. **195 attack-labelled templates still reached the counted origin**; they are [organized by category](loadtest-hardening-admitted-2026-10-06.md) and require application/deployment context. This does not establish universal bypass resistance.

The same final executable and suite also ran a matched 750,000-request control with local signatures disabled. Both runs used the new parameter-shape checks. Local signatures refused **534 additional attack templates / 48,805 additional requests**, with identical benign outcomes. Compared by request fingerprint to the historical variant run, 521 of its 716 admitted attack templates are now refused; all 5,629 historical case IDs and request hashes are retained.

| Outcome | Matched control: local rules off | Final: local rules on |
| --- | ---: | ---: |
| Total measured requests | 750,000 | 750,000 |
| Attack requests refused | 308,359 / 375,000 (82.23%) | 357,164 / 375,000 (95.24%) |
| Attack requests at origin | 66,641 | 17,836 |
| Benign requests passed | 360,947 / 375,000 | 360,947 / 375,000 |
| Benign requests refused | 14,053 (3.75%) | 14,053 (3.75%) |
| Transport errors / unavailable responses | 0 / 0 | 0 / 0 |
| Admitted attack case IDs | 729 | 195 |

The complete [final JSON](loadtest-hardening-2026-10-06.json), [control JSON](loadtest-hardening-control-2026-10-06.json) and [initial bypass reproductions with final results](loadtest-hardening-bypass-evidence-2026-10-06.json) preserve measured outcomes. Earlier reports remain unchanged.

## What changed and what was challenged

Ten local SecLang rules supplement the signed, untouched CRS 4.30.0. They target XPath, command execution, server templates, serialized Java markers, encoded traversal and unsafe/ambiguous URL authorities across parsed arguments, XML text/attributes and cookies. Multiple transport/HTML/JavaScript decoding stages inspect values without changing forwarded input. Format rules additionally refuse mixed scalar/container names, malformed bracket syntax and root aliases. Default logs have fixed family labels and rule/transaction IDs; format totals retain blocked/monitored counts without request content.

After the initial local signatures were written, new probes admitted deeper traversal encodings, nested/comment-separated XPath and parenthesized template expressions (18 base request templates). Further XML probing admitted an attribute predicate. Broader structural patterns and XML attribute targets closed those admissions; the JSON reproduction record matches their request hashes to final refused outcomes. The existing strict XML text-split policy already refuses comment/CDATA fragmentation. These new probes were used during development, so final results are regression evidence rather than a blind evaluation.

Review also corrected a declared scalar's bracket-alias exemption in API validation and a single-byte form-name folding defect. Build-tag checks exposed score loss when multiphase evaluation ran a local signature before CRS initialization. Loading local rules immediately after CRS initialization preserves early scores; all three tested rule-evaluation build modes now pass. The two published full runs use the final corrected binary.

Operational logging exposed Windows socket-address collisions (errno 10048) during upstream connection creation. A bounded retry now creates a fresh socket only for that error, with three total attempts, cancellation checks and origin-policy validation on every dial. It never replays an established-connection failure and keeps body-bearing connections isolated. Regression cases cover a transient/persistent collision, policy failure, cancellation, EOF and connection reset. A live TCP regression deliberately reserves the initial source port, reproduces an actual OS bind failure and succeeds on the second fresh-port connection under the race detector. Retry events have their own operational ID (5000051), distinct from failed requests (5000050) and attack findings.

Optional `-api-spec` enforcement now accepts a local, bounded OpenAPI contract for supported scalar/array parameters and JSON bodies. It checks required/typed inputs, unknown names/properties and declared content types, including independent JSON validity/duplicate-key checks. It refuses enforcement startup for warnings or unsupported body/object-parameter contracts. Live tests demonstrate malicious host/userinfo/escaped-host refusal, scalar duplicate/alias refusal, required fields, unknown privileged properties and body-shape refusal, while declared repeated arrays and approved example URLs pass. See [configuration and limitations](input-hardening.md).

## Remaining admissions

| Category | Admitted case IDs | Requests at origin | Required context/control |
| --- | ---: | ---: | --- |
| hpp | 48 | 4,378 | Declare scalar versus array parameters; plain repeats remain monitored by default. |
| probe | 28 | 2,576 | Authenticate/restrict real diagnostic services and verify whether the probed files exist. |
| protocol | 1 | 92 | Verify the application ignores untrusted forwarding headers; the proxy strips untrusted identity claims. |
| rfi | 108 | 9,870 | Declare allowed fetch destinations; bind resource identifiers and enforce DNS/redirect/egress controls at the fetcher. |
| scanner | 2 | 184 | A user-agent name alone does not establish malicious application behavior. |
| wordpress | 8 | 736 | Enable the existing WordPress profile where applicable; patch plugins and integrate appropriate virtual patches. |

The generic benchmark has no API contract installed. No real 5Weeks1K OpenAPI definitions or allowed fetch destinations were available in the searched workspace. The supplied contract is explicitly an example, not an invented production policy. Ordinary remote URLs, repeated array values and diagnostic paths cannot all be denied generically while preserving legitimate behavior. Request admission to this inert origin proves neither code execution nor a successful fetch, authorization bypass or vulnerable plugin. Completing site-specific protections requires those actual contracts and application integration.

## Category outcomes

| Attack category | Unique attack templates | Refused requests | Origin requests |
| --- | ---: | ---: | ---: |
| hpp | 241 | 17,597 | 4,378 |
| java | 159 | 14,551 | 0 |
| ldap | 272 | 24,936 | 0 |
| lfi | 262 | 23,994 | 0 |
| nosql | 190 | 17,452 | 0 |
| php | 190 | 17,382 | 0 |
| probe | 183 | 14,236 | 2,576 |
| protocol | 56 | 5,045 | 92 |
| prototype | 176 | 16,051 | 0 |
| rce | 316 | 28,902 | 0 |
| regression | 57 | 5,244 | 0 |
| rfi | 120 | 1,104 | 9,870 |
| scanner | 36 | 3,128 | 184 |
| sqli | 313 | 28,692 | 0 |
| ssi | 290 | 26,591 | 0 |
| ssrf | 196 | 17,944 | 0 |
| ssti | 255 | 23,305 | 0 |
| upload | 42 | 3,864 | 0 |
| wordpress | 45 | 3,389 | 736 |
| xpath | 388 | 35,530 | 0 |
| xss | 274 | 25,099 | 0 |
| xxe | 34 | 3,128 | 0 |

All 246 new attack templates account for 22,437 refused requests. All 57 bypass-regression attack templates account for 5,244 refused requests. Category labels describe fixtures; an exploitable sink is a separate precondition.

## Detection telemetry

Local-rule log counts are observations, not distinct requests or successful exploit counts: multiple rules can match a request, and format refusals can happen before CRS. Default records expose rule ID, severity, transaction ID and fixed family label without payloads. Existing per-rule format totals independently track the new shape checks. The final JSON preserves the full log-rule histogram.

| Local rule | Logged findings |
| --- | ---: |
| 5006001 | 26,736 |
| 5006002 | 2,749 |
| 5006003 | 20,657 |
| 5006004 | 2,655 |
| 5006005 | 22,569 |
| 5006006 | 15,817 |
| 5006007 | 3,382 |
| 5006008 | 8,420 |
| 5006009 | 2,918 |
| 5006010 | 4,013 |


## Benign refusals and measurement boundaries

Both matched runs refused 70 benign-labelled case IDs / 14,053 requests. The local signature toggle changed no benign case outcome. The original 67 refused benign IDs persist, plus three new XML comment/CDATA/numeric-reference control IDs rejected by the existing strict text-split policy (5002213). This is valid XML syntax rejected by a defensive policy, and should be reviewed against real endpoint expectations. Full benign outcomes remain in the JSON; neither zero false positives nor blanket production suitability is claimed.

**Flood protection was explicitly disabled (`-ddos off`) for these unpaced payload measurements.** The production default remains on. With flood protection on, rapid connections from one loopback address caused resets; the separate 10,000-request negative run had 8,606 transport errors and correctly exited unsuccessfully. The harness now saves invalid evidence but exits with failure for any transport/availability error or request/origin-accounting discrepancy. Such traffic refusals are not credited as payload detections. The published runs have zero errors and independently counted origin requests equal to HTTP 200 responses for every case.

Three attempted control reruns produced six unavailable (502) responses each and were rejected by the harness. One overlapped CPU-intensive package tests; another did not, so CPU contention alone did not explain the failures. A format timing test failed during the overlap and passed when rerun separately. Operational telemetry in the third attempt identified all six failures as Winsock 10048 (address already in use). The [diagnostic evidence](loadtest-hardening-bypass-evidence-2026-10-06.json) preserves those fixed-label events and per-case statuses. The final published runs include bounded pre-connection collision retries and have zero unavailable responses. Their retry-event counts are in the full JSON; success does not guarantee availability on every host.

The host had 15,840 TIME_WAIT sockets in a diagnostic sample, consistent with substantial connection churn. That observation does not by itself establish general port exhaustion. [Microsoft documents error 10048](https://learn.microsoft.com/en-us/windows/win32/winsock/windows-sockets-error-codes-2) and [port-exhaustion diagnosis](https://learn.microsoft.com/en-us/troubleshoot/windows-client/networking/tcp-ip-port-exhaustion-troubleshooting). Invalid attempts are excluded from detection/throughput percentages, not counted as successful protection. No global Windows TCP settings or body-isolation safeguards were weakened to make the test pass.

Only the harness-owned loopback WAF and inert counted origin receive traffic. Payload URLs and Host headers do not become network destinations. The origin never evaluates scripts, interprets queries or fetches remote resources. The test includes actual CRS, format inspection, reverse proxy and response inspection, with the declared flood-policy exception. It does not validate Linux confinement at runtime, production application authorization or outbound fetch safety.

## Reproduction and provenance

The `hardening-v1` suite has 5,963 case IDs: 4,095 unique attack templates and 1,862 unique benign templates. Six benign IDs duplicate other wire templates (two historical, four new), giving 5,957 unique constructed requests. The added 51 attack seeds generate 195 additional attack variants; added nearby controls produce 88 benign case IDs / 84 unique requests. Variations include encoding, case/whitespace and query/form/JSON/XML channels, with deterministic class-alternating scheduling. This is a reusable varied corpus, not 750,000 unique exploit strings. Request hashes exclude tracking identifiers.

Build from `carnical/`, then run from the repository root with the owner's separate corpus:

```powershell
go build -o ../build/carnical.exe ./cmd/carnical
go build -o ../build/loadtest.exe ./tools/loadtest
# From repository root:
.\build\loadtest.exe -binary D:/Dev/coraza/build/carnical.exe -corpus D:/Dev/5Weeks1k/newsletter/content/waf/corpus -output D:/Dev/coraza/build/control.json -variants -hardening -count 750000 -concurrency 16 -ddos off -local-rules=false
.\build\loadtest.exe -binary D:/Dev/coraza/build/carnical.exe -corpus D:/Dev/5Weeks1k/newsletter/content/waf/corpus -output D:/Dev/coraza/build/final.json -variants -hardening -count 750000 -concurrency 16 -ddos off -local-rules=true
```

The binary was built from base commit `f7f65124` plus this hardening change before committing. Both JSON reports record identical binary SHA-256 `473aa0ae0e41c49b7e008ffcbd4083f18ca88885266c134b693569dea6c81176` and suite SHA-256 `93a86e48df503011bd08786a9965da9238f01799eea66c2ad34aa536206d38ec`. Compiler/runtime: go1.26.6; Windows, 12 logical CPUs, 16 clients, no pacing. Corpus hashes and exact WAF arguments are in the JSON. Raw WAF logs and executables remain ignored local build artifacts.

| Measurement | Control | Final |
| --- | ---: | ---: |
| Started / completed (UTC) | 2026-10-06T05:52:26Z / 2026-10-06T05:54:53Z | 2026-10-06T05:56:02Z / 2026-10-06T05:58:29Z |
| Elapsed | 147.808 s | 146.634 s |
| Requests/second | 5074.16 | 5114.78 |
| p50 / p95 / p99 | 2.677 / 6.903 / 10.330 ms | 2.635 / 6.945 / 10.395 ms |

Throughput describes these local runs, not an isolated performance comparison or production capacity estimate.

## Validation and review

- Normal tests passed for `crs`, `formats`, `proxy`, `cmd/carnical` and `apiguard`, including compiled CLI requests to real loopback servers and origin-refusal checks.
- Scoped race tests passed for those packages. Two existing format throughput-cost tests were excluded from race instrumentation and passed normally; this is not a claim that the whole module's race suite ran without exclusions.
- CRS tests passed with `coraza.no_memoize`, `coraza.rule.multiphase_evaluation` and `coraza.rule.no_regex_multiline`. Upstream engine code and signed CRS files were not edited.
- `FuzzForm` ran for 45 seconds with two workers: 5,733 executions and no failing input. Existing parser limits, monitor/off behavior and single-byte-name regression cases passed.
- `go vet` passed for changed packages and the load tester. `govulncheck ./cmd/carnical` reported no vulnerabilities; this checks known dependency vulnerabilities, not every possible defect.
- Linux amd64 cross-compilation passed; no Linux runtime claim is made.
- `git diff --check` passed. The ADR check has the same 60 pre-existing missing-Technical-Discussion errors in ADR-0001 through ADR-0060; ADR-0072 introduced no diagnostics. No unrelated historical ADRs were rewritten.

Source review checked bounded parsing, immutable shared rules, unknown-name handling, unsupported-contract refusal, score initialization order, mode/threshold behavior, safe default log labels, bounded pre-connection retries and policy checks, origin accounting and invalid-run failure. Finite tests and review reduce risk; application-specific contracts, query binding, guarded fetching and deployment tuning remain necessary.
