# Request-format validation record

This preserves the recorded parser benchmarks, regression tests and source-mutation results.
Versions and counts refer to those runs; use the [security CI](https://github.com/YurilLAB/carnical/actions/workflows/security.yml)
for current checks and [format policy](formats.md) for operational settings.

## What it costs

**Measured** on an AMD Ryzen 5 5600X, Linux (WSL2), Go 1.26.6, one core, by `go test ./formats -run '^$' -bench .` on a body of about 100 KiB of ordinary content for each format (GraphQL 30 KiB; historical YAML baseline 30 KiB, current YAML benchmark 12 KiB to stay within the pair budget):

| Format | ns per byte | MB/s | Allocations per body |
|---|---|---|---|
| JSON | 2.5 to 3.2 | 310 to 410 | 12 |
| XML | 3.1 to 3.3 | 300 to 320 | 11 |
| NDJSON | 3.2 to 4.4 | 225 to 315 | 9 |
| multipart (20 fields and a 80 KiB file) | 0.12 to 0.15 | over 6,000 | 121 |
| urlencoded form | 8.4 to 12.8 | 78 to 120 | 3,476 (a map entry per parameter name, for duplicates) |
| gzip then JSON (per decompressed byte) | 5.1 to 6.0 | 165 to 200 | 50 |
| GraphQL (with fragments) | 13.8 to 15.0 | 67 to 72 | 6,167 |
| YAML | 139 to 165 | 6 to 7 | 73,600 |

The multipart figure is low because the content of a part is skipped with a substring search; what is read byte by byte is the headers.

The claim is that cost is linear in the size of the body and bounded, and it is tested rather than argued. `TestAdversarialBodiesCostInProportionToTheirSize` builds, for each format, the bodies that make a parser do the most work for their size (one key repeated, a thousand keys, an escaped key, sixty attributes on every element, the boundary inside every line, a million fields, aliases, fragments), with monitor mode and every count limit raised so that nothing stops the scan early, at 64 KiB and again at 256 KiB. Every one costs under 62 ns per byte, and four times the bytes takes about four times as long. A body of 1 MiB of the worst of them took 1.5 to 37 ms, with no parser using more memory than a small multiple of the keys or names that are open at that moment.

**YAML is the exception.** The goccy parser can perform quadratic copying while building block mappings or inserting omitted values into collections. A separate `yaml.max_collection_work` budget stops inspection before parsing more than 1024 structural work units (default and hard ceiling; a site can lower it). Each lexer token for a colon, explicit key marker, opening flow map, comma or block sequence entry counts once. This deliberately counts valued entries and flow sequences conservatively. Previously accepted wide documents can now trigger `yaml-limit`. Byte, node and depth caps remain in force. Monitor mode forwards and records the limit; with that rule off, the body passes silently after inspection stops, so later YAML findings are not assessed. The 250 ms cost assertion is unchanged and includes ordinary mappings, explicit keys and omitted-value collections at the work cap. YAML remains off unless a policy lists its media type.

Decompression reads at most the output limit plus one byte: a gzip stream that expands to 256 MiB (260 KiB on the wire) is stopped after 1 MiB with under 8 MiB allocated and in under a second (`TestDecompressionIsBoundedByTheLimitNotByTheInput`).

## Verified

All of it was run on Linux (WSL2, Ubuntu) and on Windows with Go 1.26.6; the race detector was run on Linux.

* **Table tests.** 641 rows in 9 tables (JSON 86, XML 107, form 54, multipart 73, GraphQL 106, NDJSON 31, compression 43, YAML 51, content type and mismatch 90), each accepted or refused with a named rule, including the known differentials (duplicate keys that differ in case, by escape and by the Kelvin sign; a UTF-16 JSON body; a BOM; JSON labelled `text/plain`; a DOCTYPE with an entity; a gzip bomb at a ratio of 1,000; a GraphQL batch of 50; an alias flood; a fragment cycle three deep through an inline fragment; a YAML anchor bomb and `!!python/object`; multipart with base64; a form with 5,000 parameters). `TestEveryRuleHasARefusalRow` fails if a rule has no row.
* **Every proper prefix of a valid body is refused** for JSON, XML, GraphQL, multipart, gzip and deflate (`prefix_test.go`, about 4,300 bodies): a parser that gave up at the end of its input without a report would accept a document cut in half.
* **Bodies the standard library writes are accepted** (`mime/multipart`, `net/url`, `encoding/json`, `encoding/xml`, `compress/gzip`), so the strictness is aimed at hand-made bodies and not at ordinary writers.
* **Negative controls.** `TestEveryRefusalDependsOnItsRule` runs every refusal row again with the rule it expects switched off and requires the same check to fail (487 rows): a row that still passes was being refused by something else and tests nothing about its rule. `TestMonitorModeRecordsTheSameFindingsAndRefusesNothing` runs every refusal row in monitor mode. `mutation/mutate.sh` breaks the source itself, one place at a time, and requires the tests to fail: see "Source mutation" below.
* **Fuzzing.** Ten Go fuzz targets (JSON, XML, GraphQL, NDJSON, compression, YAML, form, multipart, Content-Type and the whole dispatcher), each run for 30 seconds (3.1 million inputs in all, no failure), asserting that nothing panicked (an inspector that recovers a panic reports `internal-error`, which fails the target), that every verdict is in range with a plain message, and that a blocking verdict has an error status.
* **No quotation.** `TestVerdictsNeverQuoteTheRequest` puts a marker in a key, a value, an element name, an entity, a form name, a field, a multipart name, a filename, a transfer encoding, a Content-Type parameter and a YAML tag, and checks that no message repeats it. `TestEveryDetailHasText` and the type of `detail` make it impossible for a message to hold a string from the request.
* **Concurrency.** Every row of every table is run from 16 goroutines on one inspector, three times, under the race detector, and must give the answer it gives alone.
* **Through the proxy.** `e2e_test.go` starts the real proxy (`proxy.New`, with the rule set switched off so that it is not what is being tested) with a real application behind it. A gzip JSON body, sent with a length and in chunks, reaches the application decompressed with a correct `Content-Length`, no `Content-Encoding` and no `Transfer-Encoding`; 20 refused bodies (duplicate keys, a UTF-16 body, JSON as `text/plain`, a DOCTYPE with an entity, a gzip bomb, a batch of 50, introspection, base64 multipart, 5,000 parameters, an opaque type, YAML, a body with no type, a GET with a body) never reach the application and are recorded with the right identifier; 8 accepted bodies reach it byte for byte; monitor mode lets a body through and records it as not disruptive; with `AllowRequestEncoding` off the proxy still refuses gzip itself.

## Source mutation

`formats/mutation/mutate.sh` makes a copy of the package, breaks one place in it, runs the tests, and requires them to fail. It does this to every place in the parsers and the dispatcher that reports a refusal or decides one, with three operators: the call that reports a finding does nothing (`A`), the parser's own error reporter does nothing but the parse still stops (`B`), and the condition of an `if` that guards a report is replaced by `false`, which is what deleting the check would do (`C`). Run it on Linux (`formats/mutation/mutate.sh 6`; it takes about 45 minutes on a busy machine, and `ONLY=file` reruns a list of survivors).

**Measured**, 425 mutants:

| | Mutants |
|---|---|
| Killed by the tests | 393 |
| Did not compile (an `if` with an initialiser, which the operator cannot wrap) | 15 |
| Survived | 17 |

The first run killed 356 and left 54. Each survivor was read: 37 were real gaps in the tests (a truncated body accepted silently because a bounds guard that panics was recovered as `internal-error`, which still counted as a refusal; a colon, equals sign or quote replaced by another punctuation mark; empty variable definitions; a fragment with no `on`; a `%TAG` directive that no tag uses; node and depth limits that only the second pass of YAML reaches). They are now rows, a prefix test, and a check that no row ever reaches `internal-error`, and the mutants are killed. The 17 that remain are all equivalent, or cannot be reached:

* the same finding is made a few lines later by another check (the end-of-input check in a GraphQL list and selection set; the parse-time selection cap, which the field count repeats; a bare line feed after a boundary, which the walk reports again; a multipart header block that ends in the body, which the missing-newline check reports; `filename*` that is not a valid extended value, which the mismatch check reports under the same rule; an unterminated XML declaration, attribute value, CDATA section or empty name, each reported by the next check under the same rule; a YAML token cap, which the node limit repeats and which differs only in what it costs; a YAML parse error, which becomes a recovered panic and the same rule);
* a guard that is never reached (the end-of-input check at the top of the JSON value reader, which every caller makes first; the tag case in the YAML walker, because tags are refused as tokens);
* the recovery from a panic inside the YAML library, which needs the library to panic.


## 2026-10-10: Cost-test sampling

The cost tests now use Go's benchmark calibration instead of the lowest of three short samples. Each scaling fixture must grow by about four times its actual byte length. The fragment fixture keeps its 900-fragment chain and increases selections per fragment within the definition cap. Each trial starts with a collected heap and measures enough calls to include allocation and collection costs. The limits remain 400 ns per byte and at most 9 times the duration for a body with four times the bytes; YAML keeps its separate 250 ms limit.

With Go 1.26.9, the GraphQL alias case passed 18 native Linux measurements across one, two and eight CPUs. As negative controls, an injected quadratic workload failed the scaling check at 13.6 times the duration, while a costly linear workload failed the byte ceiling at 1,085 ns per byte. These controls validate the test; they are not production parser findings.

To inspect timings and allocations for the adversarial bodies, run from the repository root:

```sh
go -C carnical test ./formats -run '^$' -bench '^BenchmarkAdversarialBodies/' -benchmem -count=6
```
