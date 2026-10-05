# Live WAF variant test: 750,000 requests, 2026-10-06

This run adds variants across **all 22 attack categories**, retaining the original 969 templates. It tests **3,849 distinct
attack requests** and **1,778 distinct benign requests** through the actual standalone Carnical executable, CRS, format
inspection and reverse proxy. Of 375,000 attack requests, **305,324 were refused (81.42%)** and **69,676 reached the counted
origin**. There were zero transport or availability errors. Of 375,000 benign requests, 14,110 were refused (3.76%).

The [organized inventory](loadtest-750k-variants-admitted-2026-10-06.md) lists **all 716 admitted attack templates**, their
categories, parent IDs, variation types, wire targets, bodies or relevant headers and origin counts. The
[complete JSON evidence](loadtest-750k-variants-2026-10-06.json) records every case's outcome, fingerprints, category totals,
runtime details and full synthetic request details for admitted attacks. The earlier
[fixed-template 750,000-request run](loadtest-750k-2026-10-06.md) is preserved separately.

| Outcome | Requests | Share within class |
| --- | ---: | ---: |
| Attack requests refused | 305,324 / 375,000 | 81.42% |
| Attack requests reaching origin | 69,676 / 375,000 | 18.58% |
| Benign requests reaching origin | 360,890 / 375,000 | 96.24% |
| Benign requests refused | 14,110 / 375,000 | 3.76% |
| Bypass regression requests, including variants, refused | 5,542 / 5,542 | 100% |

| Measurement | Result |
| --- | ---: |
| Concurrent clients | 16 |
| Elapsed measured time | 154.477 seconds |
| Throughput | 4,855.09 requests/second |
| Latency p50 / p95 / p99 | 2.765 / 7.290 / 11.091 ms |
| Transport errors / availability failures | 0 / 0 |

## How requests differ

The earlier run cycled through 969 fixed templates. This run retains those and adds **3,378 attack templates** and
**1,282 benign templates**, for 5,629 case IDs. Two original benign case IDs construct the same requests as other benign
IDs, leaving 5,627 distinct constructed requests overall. Generated requests are deduplicated after construction against
existing templates and each other. Random tracking IDs are excluded from fingerprints and do not count as variation.

The [variant generator](../tools/loadtest/variants.go) makes deterministic, reproducible changes:

- Query and form parameter names, values or both are percent-encoded, with uppercase/lowercase hex and alternate space
  encodings. Decoded names/values, order and duplicate occurrences are preserved. Raw semicolon and malformed-escape
  probes are not repaired and relabelled as attacks.
- JSON strings and keys use Unicode escapes, including surrogate pairs for supplementary characters; layout uses spaces
  or tabs. Duplicate keys survive transformation because JSON is not decoded through a map.
- XML scalar payloads use numeric character references. XXE fixtures vary entity names, quote style and media type.
- Probe, WordPress and protocol paths vary dot segments, repeated slashes and encoded dots. Their interpretation depends
  on the origin's path normalization; the WAF can reject these forms before application routing.
- Upload fixtures vary trailing extensions while keeping dangerous script content/extensions. Reserved configuration
  filenames such as `.htaccess` and `web.config` are not renamed into purported attacks: losing their configuration role
  would make that label misleading. This issue was caught and corrected before the final pilot and full run.
- Curated syntax changes include SQL case/whitespace/comments and boolean expressions; XSS tags, events and character
  references; traversal depths and encodings; shell separators and quoting; Java lookup schemes/serialized prefixes;
  alternate SSRF address forms; template expression spacing; LDAP attributes/booleans; XPath functions/unions; SSI quoting;
  nested NoSQL operators; parameter clashes; prototype paths; scanner versions; application paths and method tokens.

The run alternates attack and benign requests, cycling within each class, for an even 375,000/375,000 split. Each attack
template is sent **97 or 98 times** and each benign case ID 210 or 211 times. These are thousands of different templates,
not 750,000 unique attacks or freshly randomized payloads on every request. All templates are exercised. The class split
and category weights differ from the previous run, so aggregate percentages are not a direct measure of WAF improvement
or regression.

The syntax choices were checked against [OWASP SQL injection testing](https://wstg.owasp.org/v4.2/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05-Testing_for_SQL_Injection/),
[OWASP's XSS evasion guidance](https://cheatsheetseries.owasp.org/cheatsheets/XSS_Filter_Evasion_Cheat_Sheet.html),
[OWASP traversal guidance](https://community.owasp.org/attacks/Path_Traversal),
[OWASP path confusion testing](https://wstg.owasp.org/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management/13-Path_Confusion/)
and [XML syntax](https://www.w3.org/TR/xml/). They are request indicators for application-dependent attack methods.
Partial injection fragments require a compatible unsafe application sink; a static origin cannot verify those preconditions.
The earlier report records the primary guidance for the six previously added families.

## Findings and interpretation

Every one of the original 969 templates retains its previous admission/refusal outcome and response-status set.
**No generated variant of a refused measured parent reached the origin.** Ninety attack variants of admitted measured
parents were instead refused. These comparisons apply to generated variants with actual parent cases; curated new family
seeds have a conceptual `syntax-family` parent and are assessed independently.

The 716 admitted templates comprise the original 67 and 649 added templates. Most admissions are XPath, parameter
pollution, remote-resource inputs and command strings; the inventory orders categories by origin admissions and preserves
the exact variants. HPP duplicates remain intentionally monitored by default in query/form inspection, while endpoint
contracts determine whether duplicate values or array/scalar mixtures are unsafe. The tested URL and command strings need
an application-specific sink before admission constitutes an exploit.

Fourteen new LFI templates reach the origin with a `%252e`-style traversal string as the parsed input. Query/form transport
escaping adds a further visible encoding layer. Those candidates require **additional origin decoding** before `../` is
produced; they are not proof of traversal against a normally single-decoding origin. The generator's transport encodings
otherwise preserve the parsed seed rather than silently assuming additional decoding.

All tested SQLi, XSS, PHP, LDAP, NoSQL, SSI, prototype-pollution, hostile-upload and XXE attack templates, plus the bypass
regression cohort, are refused. This is coverage of the tested indicators, not complete protection for every possible
payload in those categories. Refusal includes parser and format policy enforcement as well as CRS signatures.

There are **67 refused benign templates**: 31 search, 20 prototype controls, 10 API and 6 form cases. These include the
15 original refusals and variants of benign text, editor HTML, restricted media types and uppercase prototype-like keys.
The table below lists every one. All new ordinary controls on the curated family's endpoints pass. Endpoint tuning still
needs the real API/application contracts; this benchmark does not weaken policies to improve its scores.

## Results across all attack categories

| Category | Attack templates | Added templates | Requests | Refused | Reached origin | Refusal rate |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| HTTP parameter pollution | 241 | 213 | 23,421 | 9,621 | 13,800 | 41.08% |
| Java attack indicators | 159 | 144 | 15,505 | 11,901 | 3,604 | 76.76% |
| LDAP injection | 272 | 232 | 26,448 | 26,448 | 0 | 100.00% |
| Local file inclusion | 234 | 209 | 22,844 | 21,483 | 1,361 | 94.04% |
| NoSQL injection | 190 | 154 | 18,474 | 18,474 | 0 | 100.00% |
| PHP injection | 190 | 176 | 18,522 | 18,522 | 0 | 100.00% |
| Application probes | 183 | 147 | 17,865 | 15,128 | 2,737 | 84.68% |
| Protocol/header probes | 56 | 50 | 5,443 | 5,345 | 98 | 98.20% |
| Prototype pollution | 176 | 149 | 17,107 | 17,107 | 0 | 100.00% |
| Command injection | 244 | 222 | 23,799 | 14,552 | 9,247 | 61.15% |
| Bypass regressions | 57 | 44 | 5,542 | 5,542 | 0 | 100.00% |
| Remote file inclusion | 120 | 114 | 11,694 | 1,176 | 10,518 | 10.06% |
| Scanner identifiers | 36 | 16 | 3,528 | 3,332 | 196 | 94.44% |
| SQL injection | 313 | 282 | 30,570 | 30,570 | 0 | 100.00% |
| Server-side includes | 290 | 250 | 28,191 | 28,191 | 0 | 100.00% |
| SSRF inputs | 196 | 182 | 19,120 | 13,861 | 5,259 | 72.49% |
| Template injection | 193 | 181 | 18,809 | 15,009 | 3,800 | 79.80% |
| Hostile uploads | 42 | 30 | 4,116 | 4,116 | 0 | 100.00% |
| WordPress paths | 45 | 40 | 4,375 | 3,591 | 784 | 82.08% |
| XPath injection | 304 | 264 | 29,552 | 11,280 | 18,272 | 38.17% |
| Cross-site scripting | 274 | 247 | 26,743 | 26,743 | 0 | 100.00% |
| XML external entities | 34 | 32 | 3,332 | 3,332 | 0 | 100.00% |

## Every refused benign template

| Case | Parent | Variation | Method | Wire target | Refused requests | Status |
| --- | --- | --- | --- | --- | ---: | --- |
| ` search/79 ` | (original) | (original) | GET | ` /?s=ls+command+linux ` | 211 | ` 403 ` |
| ` search/85 ` | (original) | (original) | GET | ` /?s=1+and+1+is+2 ` | 211 | ` 403 ` |
| ` search/99 ` | (original) | (original) | GET | ` /?s=mysql+backup+guide ` | 211 | ` 403 ` |
| ` search/110 ` | (original) | (original) | GET | ` /?s=null+and+void+meaning ` | 211 | ` 403 ` |
| ` search/115 ` | (original) | (original) | GET | ` /?s=base64+explained ` | 211 | ` 403 ` |
| ` search/164 ` | (original) | (original) | GET | ` /search/ls%20command%20linux ` | 211 | ` 403 ` |
| ` forms/226 ` | (original) | (original) | POST | ` /wp-admin/post.php ` | 211 | ` 403 ` |
| ` api/231 ` | (original) | (original) | POST | ` /graphql ` | 211 | ` 403 ` |
| ` api/242 ` | (original) | (original) | POST | ` /api/csp-report ` | 211 | ` 415 ` |
| ` api/243 ` | (original) | (original) | POST | ` /api/text ` | 211 | ` 403 ` |
| ` api/245 ` | (original) | (original) | POST | ` /xmlrpc.php ` | 211 | ` 400 ` |
| ` prototype/v08-query ` | (original) | (original) | GET | ` /api/settings?__PROTO__[loadtest]=1 ` | 211 | ` 400 ` |
| ` prototype/v08-form ` | (original) | (original) | POST | ` /api/settings ` | 211 | ` 400 ` |
| ` prototype/v09-json ` | (original) | (original) | POST | ` /api/settings ` | 211 | ` 400 ` |
| ` prototype/control-02 ` | (original) | (original) | POST | ` /api/settings ` | 211 | ` 403 ` |
| ` search/variant-00167 ` | ` search/79 ` | ` query-encoded-name ` | GET | ` /?%73=ls+command+linux ` | 211 | ` 403 ` |
| ` search/variant-00168 ` | ` search/79 ` | ` query-encoded-value ` | GET | ` /?s=%6C%73%20%63%6F%6D%6D%61%6E%64%20%6C%69%6E%75%78 ` | 211 | ` 403 ` |
| ` search/variant-00169 ` | ` search/79 ` | ` query-encoded-both ` | GET | ` /?%73=%6C%73%20%63%6F%6D%6D%61%6E%64%20%6C%69%6E%75%78 ` | 211 | ` 403 ` |
| ` search/variant-00170 ` | ` search/79 ` | ` query-lower-hex ` | GET | ` /?%73=%6c%73%20%63%6f%6d%6d%61%6e%64%20%6c%69%6e%75%78 ` | 211 | ` 403 ` |
| ` search/variant-00171 ` | ` search/79 ` | ` query-percent-space ` | GET | ` /?s=ls%20command%20linux ` | 211 | ` 403 ` |
| ` search/variant-00197 ` | ` search/85 ` | ` query-encoded-name ` | GET | ` /?%73=1+and+1+is+2 ` | 211 | ` 403 ` |
| ` search/variant-00198 ` | ` search/85 ` | ` query-encoded-value ` | GET | ` /?s=%31%20%61%6E%64%20%31%20%69%73%20%32 ` | 211 | ` 403 ` |
| ` search/variant-00199 ` | ` search/85 ` | ` query-encoded-both ` | GET | ` /?%73=%31%20%61%6E%64%20%31%20%69%73%20%32 ` | 211 | ` 403 ` |
| ` search/variant-00200 ` | ` search/85 ` | ` query-lower-hex ` | GET | ` /?%73=%31%20%61%6e%64%20%31%20%69%73%20%32 ` | 211 | ` 403 ` |
| ` search/variant-00201 ` | ` search/85 ` | ` query-percent-space ` | GET | ` /?s=1%20and%201%20is%202 ` | 211 | ` 403 ` |
| ` search/variant-00266 ` | ` search/99 ` | ` query-encoded-name ` | GET | ` /?%73=mysql+backup+guide ` | 211 | ` 403 ` |
| ` search/variant-00267 ` | ` search/99 ` | ` query-encoded-value ` | GET | ` /?s=%6D%79%73%71%6C%20%62%61%63%6B%75%70%20%67%75%69%64%65 ` | 211 | ` 403 ` |
| ` search/variant-00268 ` | ` search/99 ` | ` query-encoded-both ` | GET | ` /?%73=%6D%79%73%71%6C%20%62%61%63%6B%75%70%20%67%75%69%64%65 ` | 211 | ` 403 ` |
| ` search/variant-00269 ` | ` search/99 ` | ` query-lower-hex ` | GET | ` /?%73=%6d%79%73%71%6c%20%62%61%63%6b%75%70%20%67%75%69%64%65 ` | 211 | ` 403 ` |
| ` search/variant-00270 ` | ` search/99 ` | ` query-percent-space ` | GET | ` /?s=mysql%20backup%20guide ` | 211 | ` 403 ` |
| ` search/variant-00321 ` | ` search/110 ` | ` query-encoded-name ` | GET | ` /?%73=null+and+void+meaning ` | 211 | ` 403 ` |
| ` search/variant-00322 ` | ` search/110 ` | ` query-encoded-value ` | GET | ` /?s=%6E%75%6C%6C%20%61%6E%64%20%76%6F%69%64%20%6D%65%61%6E%69%6E%67 ` | 211 | ` 403 ` |
| ` search/variant-00323 ` | ` search/110 ` | ` query-encoded-both ` | GET | ` /?%73=%6E%75%6C%6C%20%61%6E%64%20%76%6F%69%64%20%6D%65%61%6E%69%6E%67 ` | 211 | ` 403 ` |
| ` search/variant-00324 ` | ` search/110 ` | ` query-lower-hex ` | GET | ` /?%73=%6e%75%6c%6c%20%61%6e%64%20%76%6f%69%64%20%6d%65%61%6e%69%6e%67 ` | 211 | ` 403 ` |
| ` search/variant-00325 ` | ` search/110 ` | ` query-percent-space ` | GET | ` /?s=null%20and%20void%20meaning ` | 211 | ` 403 ` |
| ` search/variant-00346 ` | ` search/115 ` | ` query-encoded-name ` | GET | ` /?%73=base64+explained ` | 211 | ` 403 ` |
| ` search/variant-00347 ` | ` search/115 ` | ` query-encoded-value ` | GET | ` /?s=%62%61%73%65%36%34%20%65%78%70%6C%61%69%6E%65%64 ` | 211 | ` 403 ` |
| ` search/variant-00348 ` | ` search/115 ` | ` query-encoded-both ` | GET | ` /?%73=%62%61%73%65%36%34%20%65%78%70%6C%61%69%6E%65%64 ` | 211 | ` 403 ` |
| ` search/variant-00349 ` | ` search/115 ` | ` query-lower-hex ` | GET | ` /?%73=%62%61%73%65%36%34%20%65%78%70%6c%61%69%6e%65%64 ` | 211 | ` 403 ` |
| ` search/variant-00350 ` | ` search/115 ` | ` query-percent-space ` | GET | ` /?s=base64%20explained ` | 211 | ` 403 ` |
| ` forms/variant-00739 ` | ` forms/226 ` | ` form-encoded-name ` | POST | ` /wp-admin/post.php ` | 210 | ` 403 ` |
| ` forms/variant-00740 ` | ` forms/226 ` | ` form-encoded-value ` | POST | ` /wp-admin/post.php ` | 210 | ` 403 ` |
| ` forms/variant-00741 ` | ` forms/226 ` | ` form-encoded-both ` | POST | ` /wp-admin/post.php ` | 210 | ` 403 ` |
| ` forms/variant-00742 ` | ` forms/226 ` | ` form-lower-hex ` | POST | ` /wp-admin/post.php ` | 210 | ` 403 ` |
| ` forms/variant-00743 ` | ` forms/226 ` | ` form-percent-space ` | POST | ` /wp-admin/post.php ` | 210 | ` 403 ` |
| ` api/variant-00756 ` | ` api/231 ` | ` json-unicode-strings ` | POST | ` /graphql ` | 210 | ` 403 ` |
| ` api/variant-00757 ` | ` api/231 ` | ` json-layout-20 ` | POST | ` /graphql ` | 210 | ` 403 ` |
| ` api/variant-00758 ` | ` api/231 ` | ` json-layout-09 ` | POST | ` /graphql ` | 210 | ` 403 ` |
| ` api/variant-00789 ` | ` api/242 ` | ` json-unicode-strings ` | POST | ` /api/csp-report ` | 210 | ` 415 ` |
| ` api/variant-00790 ` | ` api/242 ` | ` json-layout-20 ` | POST | ` /api/csp-report ` | 210 | ` 415 ` |
| ` api/variant-00791 ` | ` api/242 ` | ` json-layout-09 ` | POST | ` /api/csp-report ` | 210 | ` 415 ` |
| ` prototype/variant-02756 ` | ` prototype/v08-query ` | ` query-encoded-name ` | GET | ` /api/settings?%5F%5F%50%52%4F%54%4F%5F%5F%5B%6C%6F%61%64%74%65%73%74%5D=1 ` | 210 | ` 400 ` |
| ` prototype/variant-02757 ` | ` prototype/v08-query ` | ` query-encoded-value ` | GET | ` /api/settings?__PROTO__[loadtest]=%31 ` | 210 | ` 400 ` |
| ` prototype/variant-02758 ` | ` prototype/v08-query ` | ` query-encoded-both ` | GET | ` /api/settings?%5F%5F%50%52%4F%54%4F%5F%5F%5B%6C%6F%61%64%74%65%73%74%5D=%31 ` | 210 | ` 400 ` |
| ` prototype/variant-02759 ` | ` prototype/v08-query ` | ` query-lower-hex ` | GET | ` /api/settings?%5f%5f%50%52%4f%54%4f%5f%5f%5b%6c%6f%61%64%74%65%73%74%5d=%31 ` | 210 | ` 400 ` |
| ` prototype/variant-02760 ` | ` prototype/v08-query ` | ` query-percent-space ` | GET | ` /api/settings?__PROTO__%5Bloadtest%5D=1 ` | 210 | ` 400 ` |
| ` prototype/variant-02761 ` | ` prototype/v08-form ` | ` form-encoded-name ` | POST | ` /api/settings ` | 210 | ` 400 ` |
| ` prototype/variant-02762 ` | ` prototype/v08-form ` | ` form-encoded-value ` | POST | ` /api/settings ` | 210 | ` 400 ` |
| ` prototype/variant-02763 ` | ` prototype/v08-form ` | ` form-encoded-both ` | POST | ` /api/settings ` | 210 | ` 400 ` |
| ` prototype/variant-02764 ` | ` prototype/v08-form ` | ` form-lower-hex ` | POST | ` /api/settings ` | 210 | ` 400 ` |
| ` prototype/variant-02765 ` | ` prototype/v08-form ` | ` form-percent-space ` | POST | ` /api/settings ` | 210 | ` 400 ` |
| ` prototype/variant-02809 ` | ` prototype/v09-json ` | ` json-unicode-strings ` | POST | ` /api/settings ` | 210 | ` 400 ` |
| ` prototype/variant-02810 ` | ` prototype/v09-json ` | ` json-layout-20 ` | POST | ` /api/settings ` | 210 | ` 400 ` |
| ` prototype/variant-02811 ` | ` prototype/v09-json ` | ` json-layout-09 ` | POST | ` /api/settings ` | 210 | ` 400 ` |
| ` prototype/variant-02817 ` | ` prototype/control-02 ` | ` json-unicode-strings ` | POST | ` /api/settings ` | 210 | ` 403 ` |
| ` prototype/variant-02818 ` | ` prototype/control-02 ` | ` json-layout-20 ` | POST | ` /api/settings ` | 210 | ` 403 ` |
| ` prototype/variant-02819 ` | ` prototype/control-02 ` | ` json-layout-09 ` | POST | ` /api/settings ` | 210 | ` 403 ` |

## Configuration and validation

The same WAF binary as the earlier runs was used, SHA-256
`f880ae3b6ff1c223d9f6b04348175fa76f73cbc73c1f42f04fb87e3a82bb82d3`.
It embeds standalone revision `32061afd` with `vcs.modified=true`, as explained in the original report. CRS 4.30.0 uses
paranoia level 1 and inbound threshold 5; CRS and formats are in block mode, with response inspection enabled. API quotas
and the WordPress flag are disabled. OpenAPI/API guard and virtual-patch integration APIs are not installed. This change
extends the test harness and reports, without changing the measured WAF pipeline.

Windows, Go 1.26.6, 12 logical CPUs. The measured interval is 2026-10-05 18:04:34-18:07:09 UTC (2026-10-06 in Sydney).
The ordered suite SHA-256 is `5206320b7fca530e70cb71e088fd41ed96b47691caa31f7e64a967b98f422d52`.
The report JSON is copied byte-for-byte from the final output, SHA-256
`ad91e64b4df4346d073d299d46149c6e3484a7ff32112fd2220fcb740231272d`.

Normal and race-instrumented 30,000-request pilots pass with no transport/availability errors; the final race pilot uses
the same suite hash as this full run. Race instrumentation covers the load generator; the child WAF is built normally.
Vet and formatting/whitespace checks pass. A separate 731-request live run without `-variants` preserves the original
default workload and its outcomes. Post-run assertions reconcile all response counts, origin counts, per-category totals,
unique fingerprints, coverage of every template, all original outcomes and parent comparisons. Test child processes stop
after completion. Review covered label validity, mutable request copies, duplicate preservation, hash-based deduplication,
balanced scheduling, synchronized aggregation and loopback confinement.

All connections go to the harness's loopback WAF/origin; corpus Host fields and payload URLs never become destinations.
The counted origin returns fixed JSON and never executes commands, evaluates expressions, loads uploads or retrieves
resources. HTTP 200 plus an origin counter proves admission, not exploitation. Malformed/framing probes still use raw
local connections, preserving bytes; wire-target verification and URL-fragment fixes remain active. Availability failures
are never credited as detections. This short local HTTP/1.1 measurement does not establish production capacity, TLS-edge
behavior, distributed attack resistance, Linux confinement or security of the uninstalled integration APIs.

## Reproduce

From the repository root, supplying the owner's separately maintained corpus directory:

```text
go build -o build/carnical.exe ./carnical/cmd/carnical
go run ./carnical/tools/loadtest -binary D:/Dev/coraza/build/carnical.exe -corpus D:/Dev/5Weeks1k/newsletter/content/waf/corpus -output D:/Dev/coraza/build/loadtest-750k-variants.json -variants -count 750000 -concurrency 16
```

`-variants` implies the extended categories and selects alternating class scheduling. It refuses counts too small to
exercise every template. Omitting it preserves the original cyclic scheduling; `-extended` retains the previous expanded
fixed suite. Rebuilds can have different binary hashes due to source or VCS metadata; each report records its own hash.
Request fingerprints cover method, Host, verified target, explicit normalized headers and reconstructed body, excluding
the measurement ID and socket destination. They describe constructed HTTP content rather than complete TCP streams.

Raw WAF logs stay local and uncommitted. The evidence's 1,048,266 parsed log events and rule counts include readiness
traffic and can contain multiple events per request. They are an observed snapshot; forced child termination does not
guarantee a final flushed format-statistics summary. Full payload details in this report are synthetic test evidence,
not a change to the WAF's default logging privacy policy.
