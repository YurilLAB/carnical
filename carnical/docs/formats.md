# Strict request-body formats

Package `formats` (`carnical/formats`) reads the body formats a site's clients send, checks each one with a parser written for the purpose, refuses what no legitimate client sends, and hands the rest on. It is an `inspect.Inspector` and runs in the proxy after the proxy's own checks and before the rule set.

## Why

A firewall and the application behind it parse the same body with different parsers. Where the parsers differ (which of two equal JSON keys wins, whether a DOCTYPE is read, how a multipart body with no final boundary ends, whether a UTF-16 body is decoded, whether `;` separates form fields) an attacker writes the body that one reads as harmless and the other as an attack. The WAFFLED research (arxiv.org/abs/2503.10846) found 1,207 bypasses of five WAFs in exactly these differences, and `docs/attacks.md` lists the strict normaliser as the largest class not yet done.

This package does not try to predict what the application will do. It reads each format with a parser that accepts only what the RFC grammar allows, refuses what is ambiguous, and has a limit on everything an attacker can make large. If the firewall will not read a body two ways, there is no second way for the application to read it. It is not a replacement for the rule set: a body that passes here is well formed, not harmless.

## Using it

```go
pol := formats.Policy{Monitor: true} // start a site here: record, refuse nothing
if err := pol.Validate(); err != nil { /* refuse to start */ }
cfg.Inspectors = append(cfg.Inspectors, formats.New(pol))
cfg.AllowRequestEncoding = true // lets one gzip or deflate layer reach the inspector, which decompresses it
```

`formats.New(Policy) *Inspector` keeps nothing between requests, so one value serves any number of them at once. A policy that fails `Validate` is not a way to run with a weaker one: `New` still returns an inspector, and it refuses every request that has a body (5002990) and says why in `Err()`. `ParsePolicy` reads a policy written as JSON, refuses unknown fields and trailing data, and validates. `Rules()` lists every rule with its default, for a console.

Start every site with `"monitor": true`, read what is found for a few days, set the rules the site's own clients trip to `monitor` or `off`, then turn monitor mode off.

## What is refused

| Format | Refused |
|---|---|
| Content type | A type not on the list (default: form, multipart/form-data, JSON and `+json`, XML and `+xml`, GraphQL, NDJSON, `text/plain`); opaque binary types (octet-stream, msgpack, CBOR, protobuf, gRPC, Thrift, Avro, BSON) unless named in `allow_opaque`, and then only up to a size cap; a body with no Content-Type; a body on GET or HEAD; a Content-Type that does not follow the grammar, repeats a parameter or uses an RFC 2231 extended one; a charset that is not utf-8, us-ascii, iso-8859-1 or windows-1252 |
| JSON | Anything RFC 8259 does not allow; trailing data; a BOM; raw control characters; invalid UTF-8; an escaped NUL; a lone surrogate escape; a key given twice (after decoding escapes, ignoring case); `__proto__` and `constructor`/`prototype` keys; depth over 64; more than 50,000 values or 20,000 keys; a number or string over its length |
| XML (XML, SOAP, XML-RPC, `+xml`) | DOCTYPE, ENTITY and other declarations, external references, references to any entity but the five predefined ones, XInclude, XSLT, processing instructions, a declared encoding that is UTF-16/32, not accepted, or disagrees with the header or the bytes, text split by a comment or CDATA section, a repeated attribute, depth over 32 |
| GraphQL | Depth over 12, more than 500 fields, 20 aliases, 50 directives (all counted after fragments are expanded), a batch over 10, introspection, fragment cycles and fragments that are unknown or defined twice, a request whose `variables`, `operationName` or `extensions` are not the types the protocol gives them |
| NDJSON | Each line as JSON; more than 1,000 lines; a blank line between records |
| gzip, deflate | A second layer, any other encoding, a corrupt or truncated stream, a wrong checksum, anything after the stream (a second gzip member is anything after it), output over 1 MiB, a ratio over 100:1 |
| YAML (off unless allowed) | Any explicit tag, more than 4 anchors or 8 aliases, depth over 32, more than 10,000 nodes, a body over 32 KiB, more than one document (an empty one counts), a duplicate key |
| Form | A bad percent escape, an escaped or raw NUL or control character, `;` as a separator, invalid UTF-8, more than 1,000 parameters, over-long names and values, brackets nested over 8, `__proto__` names; duplicate names are recorded |
| Multipart | No boundary, an invalid or over-long boundary, more than 100 parts, a part header that does not follow the grammar, a repeated Content-Disposition or Content-Type, a `filename` and `filename*` that disagree, a nested multipart, a transfer encoding other than 7bit, 8bit or binary, a bare line feed, no closing boundary, data before the first or after the last boundary, a line that starts with the boundary and is not a delimiter, a part with no name |
| Mismatch | A body that starts like JSON, XML or multipart under a Content-Type that says form, `text/plain` or multipart (or none); a body declared as JSON or XML that does not start like it |

## Policy

All fields are optional; a field left out (or zero) takes its default. No limit can be switched off: a limit is a positive number below a fixed ceiling, because the point of every limit is that the cost of a request is bounded by its size.

| Field | Meaning |
|---|---|
| `monitor` | Record every finding and refuse nothing. |
| `rules` | `{"rule-name": "block" \| "monitor" \| "off"}`. An unknown name is an error, so a misspelt rule can never leave a protection quietly on its default. `policy-invalid` and `internal-error` cannot be changed: a body that could not be checked is never let through (except in monitor mode, which lets everything through). |
| `allowed_types` | `type/subtype`, `type/*` or `*+suffix`. Default as in the table above. YAML is added by listing `application/yaml`, `text/yaml`, `application/x-yaml`. |
| `allow_opaque`, `opaque_max_bytes` | Opaque types the site receives (a media type or a prefix ending in `*`) and their size cap (default 64 KiB). |
| `allowed_charsets` | Default `utf-8`, `us-ascii`, `iso-8859-1`, `windows-1252`. |
| `max_body_bytes` | Largest body after decompression (default 1 MiB). |
| `graphql_paths` | Exact paths that are GraphQL endpoints, in addition to any path with a segment called `graphql` or `graphiql`. |
| `json`, `xml`, `graphql`, `ndjson`, `encoding`, `yaml`, `form`, `multipart` | The limits of each parser. Each field is named, with its default, in the Go type (`policy.go`). |

### How GraphQL is found

A request to a GraphQL path must be a GraphQL request: its query must parse. A request anywhere else is treated as GraphQL only if its `query` parses as a GraphQL document, so a search form with a `query` field, or an Elasticsearch body whose `query` is an object, is left alone. The query is looked for in a JSON object, an array of them (a batch), an `application/graphql` body, a form, and the query string (`GET`, and any method on a GraphQL path). Positions in GraphQL messages are bytes of the decoded query text, not of the request.

## Decisions that are not obvious

* **Duplicate keys are compared after decoding escapes and with case folded** (a Unicode simple fold, so the Kelvin sign and the long s match `k` and `s`, as they do in Go's own decoder). Frameworks keep the first, the last, or merge, and some match keys without regard to case. The stricter comparison refuses every body any of them would read differently.
* **Form and multipart duplicate names are recorded, not refused**, by default (`form-duplicate-param`, `multipart-duplicate-name`): a group of checkboxes is a legitimate duplicate. Names ending in `[]` are never reported. A site that has no such field sets the rule to `block`.
* **A lone `filename*` is recorded, not refused.** RFC 7578 forbids it in form data and browsers never send it, but some HTTP libraries do. A `filename*` that disagrees with `filename` (the Coraza decoy) is refused.
* **A byte order mark is refused for every text format**, XML included. A .NET client that writes one sets `body-bom` to `monitor`.
* **`text/plain` is checked for a body that is a whole JSON or XML document** (it starts like one and ends like one): that is how a cross-site request carries JSON with no preflight. Plain prose that starts with a bracket is left alone. An HTML snippet posted as `text/plain` is refused as XML; a site that does this sets `mismatch-xml-body` to `monitor`.
* **Gzip's `x-gzip` alias, a second member, and `deflate` without a zlib header are refused** (`allow_raw_deflate` accepts the last). These are differences between servers, and the proxy only passes `gzip` and `deflate` through anyway.
* **The ratio limit does not apply under 4 KiB of output.** A few hundred bytes of repetitive JSON can compress past 100:1 and is not an attack. Above that, the limit applied is the smaller of the output cap and 100 times the compressed size.
* **Decompression reads at most the limit plus one byte.** The time and memory a compressed body can cost depend on the limit, not on what the stream claims to hold. The decompressed body may be larger than the proxy's `MaxFormBody` (128 KiB), which applies to what was sent: set `encoding.max_output` to 131072 on a site that has no upload so that the rule set never sees more than it would from an uncompressed request.
* **XML text split by a comment or CDATA section is refused.** Coraza hands the rules the text pieces of an element separately, so `sel<!-- -->ect` is not seen whole by them and is by the application (README, "Known limits"). One run of text, or one CDATA section alone, is accepted; `a<!-- -->b`, `a<![CDATA[b]]>` and two CDATA sections are not. This also refuses `hello <!-- note --> world`, which no request has a reason to send.
* **A refused or monitored finding never quotes the request.** A message is built from a rule's fixed sentence, one of a fixed list of phrases (`details.go`, an enumeration, so no string from the request can be passed) and numbers. A test puts a marker in every place content can reach and checks that no message repeats it.

## Verdicts

Identifiers 5002000 to 5002999. The table is the one the code holds; a test (`TestDocumentationMatchesRules`) fails if this table and `Rules()` differ in any column. A message looks like `json-duplicate-key: an object key given twice (compared after decoding escapes, ignoring case) at byte 17`, or `graphql-fields: a GraphQL query that selects more fields than the limit (limit 500)`, or, for NDJSON, `... in line 3 at byte 9`.

Default is what happens when the policy does not say. Status is what the visitor gets for a refusal.

| ID | Rule | Default | Status | Severity | Finds |
|---|---|---|---|---|---|
| 5002001 | `type-not-allowed` | block | 415 | high | the Content-Type is not one this site accepts |
| 5002002 | `type-opaque` | block | 415 | high | a binary body type that nothing can inspect |
| 5002003 | `opaque-too-large` | block | 413 | medium | a binary body larger than the site allows |
| 5002004 | `type-missing` | block | 415 | medium | a request body with no Content-Type |
| 5002005 | `type-malformed` | block | 400 | high | a Content-Type that does not follow the grammar |
| 5002006 | `charset-not-allowed` | block | 415 | high | a charset this site does not accept |
| 5002007 | `type-duplicate-param` | block | 400 | high | a Content-Type parameter given more than once |
| 5002008 | `type-duplicate-header` | block | 400 | high | more than one Content-Type header |
| 5002009 | `body-on-get` | block | 400 | medium | a request body on a GET or HEAD request |
| 5002010 | `body-too-large` | block | 413 | medium | a request body larger than the site allows |
| 5002020 | `body-wide-encoding` | block | 400 | high | a body in UTF-16 or UTF-32, which filters do not read |
| 5002021 | `body-invalid-utf8` | block | 400 | high | a body that is not valid UTF-8 |
| 5002022 | `body-control-char` | block | 400 | medium | a NUL or control character where the format allows none |
| 5002023 | `body-bom` | block | 400 | medium | a byte order mark at the start of the body |
| 5002040 | `mismatch-json-body` | block | 415 | high | a body that is JSON under a Content-Type that says it is not |
| 5002041 | `mismatch-xml-body` | block | 415 | high | a body that is XML under a Content-Type that says it is not |
| 5002042 | `mismatch-multipart-body` | block | 415 | high | a body that is multipart under a Content-Type that says it is not |
| 5002043 | `mismatch-declared-json` | block | 400 | high | a body declared as JSON that does not start like JSON |
| 5002044 | `mismatch-declared-xml` | block | 400 | high | a body declared as XML that does not start like XML |
| 5002070 | `encoding-unsupported` | block | 415 | high | a Content-Encoding other than one gzip or deflate layer |
| 5002071 | `encoding-layers` | block | 415 | high | more than one layer of Content-Encoding |
| 5002072 | `encoding-corrupt` | block | 400 | high | a compressed body that cannot be decompressed |
| 5002073 | `encoding-trailing-data` | block | 400 | high | data after the end of the compressed stream |
| 5002074 | `encoding-too-large` | block | 413 | high | a compressed body that expands past the size limit |
| 5002075 | `encoding-ratio` | block | 413 | high | a compressed body that expands far more than ordinary content does |
| 5002100 | `json-syntax` | block | 400 | high | JSON that does not follow RFC 8259 |
| 5002101 | `json-trailing-data` | block | 400 | high | data after the JSON value |
| 5002102 | `json-limit` | block | 400 | high | JSON over a size, depth or count limit |
| 5002103 | `json-duplicate-key` | block | 400 | high | an object key given twice (compared after decoding escapes, ignoring case) |
| 5002104 | `json-proto-key` | block | 400 | high | a key that pollutes an object prototype |
| 5002105 | `json-nul-escape` | block | 400 | medium | an escaped NUL character in a string |
| 5002106 | `json-surrogate` | block | 400 | high | an escaped surrogate that is not half of a valid pair |
| 5002200 | `xml-syntax` | block | 400 | high | XML that is not well formed |
| 5002201 | `xml-doctype` | block | 400 | high | a DOCTYPE declaration |
| 5002202 | `xml-entity-decl` | block | 400 | critical | an ENTITY or other markup declaration |
| 5002203 | `xml-external-ref` | block | 400 | critical | a reference to an external resource |
| 5002204 | `xml-entity-ref` | block | 400 | high | a reference to an entity that is not predefined, or an invalid character reference |
| 5002205 | `xml-xinclude` | block | 400 | critical | XInclude |
| 5002206 | `xml-xslt` | block | 400 | critical | an XSLT stylesheet namespace (xsl:include, xsl:import, document()) |
| 5002207 | `xml-pi` | block | 400 | high | a processing instruction other than the XML declaration |
| 5002208 | `xml-encoding-mismatch` | block | 400 | high | a declared encoding that disagrees with the Content-Type charset or the bytes |
| 5002209 | `xml-encoding-wide` | block | 400 | high | a declared UTF-16 or UTF-32 encoding on a body that is not |
| 5002210 | `xml-encoding-disallowed` | block | 400 | high | a declared encoding this site does not accept |
| 5002211 | `xml-limit` | block | 400 | high | XML over a size, depth or count limit |
| 5002212 | `xml-duplicate-attr` | block | 400 | high | an attribute given twice on one element |
| 5002213 | `xml-text-split` | block | 400 | high | text split by a comment or CDATA section |
| 5002300 | `graphql-syntax` | block | 400 | high | a GraphQL document that cannot be parsed |
| 5002301 | `graphql-depth` | block | 400 | high | a GraphQL query nested deeper than the limit |
| 5002302 | `graphql-fields` | block | 400 | high | a GraphQL query that selects more fields than the limit |
| 5002303 | `graphql-aliases` | block | 400 | high | a GraphQL query with more aliases than the limit |
| 5002304 | `graphql-directives` | block | 400 | high | a GraphQL query with more directives than the limit |
| 5002305 | `graphql-batch` | block | 400 | high | a GraphQL batch larger than the limit |
| 5002306 | `graphql-introspection` | block | 403 | high | a GraphQL introspection query |
| 5002307 | `graphql-fragment` | block | 400 | high | a GraphQL fragment that is cyclic, unknown or defined twice |
| 5002308 | `graphql-request-shape` | block | 400 | high | a GraphQL request whose parts are not the types the protocol uses |
| 5002309 | `graphql-limit` | block | 400 | high | a GraphQL document over a size or count limit |
| 5002400 | `ndjson-lines` | block | 400 | high | more lines than the limit |
| 5002401 | `ndjson-blank-line` | block | 400 | medium | a blank line between records |
| 5002500 | `yaml-syntax` | block | 400 | high | YAML that cannot be parsed |
| 5002501 | `yaml-tag` | block | 400 | critical | an explicit tag (a deserialisation attack) |
| 5002502 | `yaml-anchor` | block | 400 | high | more anchors or aliases than the limit (entity expansion) |
| 5002503 | `yaml-limit` | block | 400 | high | YAML over a size, depth or count limit |
| 5002504 | `yaml-multi-document` | block | 400 | high | more than one YAML document |
| 5002505 | `yaml-duplicate-key` | block | 400 | high | a mapping key given twice |
| 5002600 | `form-bad-escape` | block | 400 | high | a percent escape that is not two hex digits |
| 5002601 | `form-control-char` | block | 400 | high | a NUL or control character, escaped or raw |
| 5002602 | `form-duplicate-param` | monitor | 400 | medium | a parameter name given more than once |
| 5002603 | `form-limit` | block | 400 | high | a form over a count or length limit |
| 5002604 | `form-bracket-depth` | block | 400 | high | a parameter name with brackets nested deeper than the limit |
| 5002605 | `form-semicolon` | block | 400 | high | a semicolon used as a separator |
| 5002606 | `form-proto-key` | block | 400 | high | a parameter name that pollutes an object prototype |
| 5002700 | `multipart-no-boundary` | block | 400 | high | a multipart type with no boundary |
| 5002701 | `multipart-bad-boundary` | block | 400 | high | a boundary that RFC 2046 does not allow |
| 5002702 | `multipart-limit` | block | 400 | high | a multipart body over a part or header limit |
| 5002703 | `multipart-header` | block | 400 | high | a part header that does not follow the grammar |
| 5002704 | `multipart-duplicate-header` | block | 400 | high | a part header given twice |
| 5002705 | `multipart-duplicate-name` | monitor | 400 | medium | two parts with the same name |
| 5002706 | `multipart-filename-mismatch` | block | 400 | critical | a filename and a filename* that disagree |
| 5002707 | `multipart-filename-star` | monitor | 400 | medium | a filename* parameter, which RFC 7578 forbids |
| 5002708 | `multipart-nested` | block | 400 | high | a multipart part inside a part |
| 5002709 | `multipart-transfer-encoding` | block | 400 | high | a part transfer encoding that hides content from filters |
| 5002710 | `multipart-bare-lf` | block | 400 | high | a line ending that is not CRLF where the structure needs one |
| 5002711 | `multipart-no-close` | block | 400 | high | no closing boundary |
| 5002712 | `multipart-epilogue` | block | 400 | high | data after the closing boundary |
| 5002713 | `multipart-preamble` | block | 400 | high | data before the first boundary |
| 5002714 | `multipart-delimiter` | block | 400 | high | a boundary line that is not a clean delimiter |
| 5002715 | `multipart-disposition` | block | 400 | high | a missing or invalid Content-Disposition |
| 5002716 | `multipart-duplicate-param` | block | 400 | high | a Content-Disposition parameter given more than once |
| 5002990 | `policy-invalid` | block | 503 | critical | the formats policy is invalid, so bodies are refused |
| 5002991 | `internal-error` | block | 503 | critical | the body could not be checked |

`type-duplicate-header` is a second line of defence: the proxy already refuses a request with two Content-Type headers (5000005) before any inspector runs. `internal-error` is what a panic in a parser becomes (none was found; see the fuzzing below).

## How it is built

One file per format, each with its own parser, its limits and its fuzz target. The inspector (`inspector.go`) parses the Content-Type, decides by media type, decompresses if asked, and calls the format's check. A check reports a finding to the `finder`, which applies the policy (block, monitor or off) and says whether to stop; no parser decides what a finding costs. Each rule is reported once per request.

| File | What it is |
|---|---|
| `contenttype.go` | Content-Type and Content-Disposition grammar (RFC 9110): token, quoted string, duplicate and extended parameters. Not `mime.ParseMediaType`, which repairs what this refuses. |
| `jsonscan.go` | RFC 8259 tokenizing parser. Never builds a tree; its memory is the folded keys of the objects that are open. |
| `xmlscan.go` | One-pass XML scanner: names, attributes, references, declaration, encoding, DOCTYPE classification. |
| `graphql.go`, `graphqlreq.go` | Lexer, parser and fragment-expanding analyser; the envelope (JSON, batch, form, query string). |
| `ndjson.go`, `encoding.go`, `yaml.go`, `form.go`, `multipart.go`, `sniff.go` | As named. |

## What it costs

**Measured** on an AMD Ryzen 5 5600X, Linux (WSL2), Go 1.26.6, one core, by `go test ./formats -run '^$' -bench .` on a body of about 100 KiB of ordinary content for each format (GraphQL 30 KiB, YAML 30 KiB):

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

**YAML is the exception.** The library that reads it (goccy/go-yaml) is not linear: a document of many mapping keys costs about 75 ms at 32 KiB and far more per byte at larger sizes. It is bounded by the size cap (32 KiB by default; `TestYAMLAtItsDefaultCapIsBounded` holds the worst shapes to 250 ms at that size) and is off unless the policy lists a YAML type. It also allocates about 140 times the size of the body. The rule set costs about 6 ms per KiB of body, which is 200 ms for the same 32 KiB, so YAML parsing is of the same order, but a site that turns it on should keep `yaml.max_bytes` small.

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



## What is not done, and what to watch

* **Only GraphQL looks in the query string.** `a=1&a=2`, `%zz` and `;` in a query string are not checked: duplicate query parameters are too common to refuse, and the form rules would need their own settings for it.
* **No Unicode normalisation.** Keys are compared after escape decoding and case folding, not after NFC or NFKC, which a framework could apply.
* **XML is scanned, not validated.** There is no namespace resolution (a prefix bound to the XInclude or XSLT namespace is found by what it is bound to, so this holds), no attribute-value normalisation and no check of characters above the control range (U+FFFE, U+FFFF). The text-split rule may refuse mixed content with a comment in the middle of a sentence.
* **GraphQL is read for what it costs, not checked against a schema.** A syntax this parser does not know is refused on a GraphQL path: the nullability operators of the 2025 draft (`field!`, `field?` in a selection), and anything that is not an operation or fragment. Client directives such as `@defer` and `@stream` are ordinary directives and are counted.
* **YAML** follows the goccy parser, which is not the parser the application uses; differences between YAML parsers are the largest of any format here, and tags and anchors are refused because they are what is dangerous in all of them, not because the rest is equivalent.
* **A body that names a single-byte charset is refused for JSON, NDJSON, GraphQL and YAML if it has any byte above 127**, because those formats are UTF-8 and a parser that honours the header would read it differently.
* **A legitimate client may need a rule set to `monitor`**: a single-page application that posts JSON with no Content-Type header (the browser sends `text/plain`), a .NET client that writes a byte order mark in XML, an HTML snippet posted as plain text, a `curl --data @file` whose file ends in a line feed (a raw line feed in a form is refused).
* **The query-string check for GraphQL on GET reads `query` and `variables` only**; `extensions` and `operationName` are not looked at there.
* **Not run on a real forge or real traffic.** The rows come from the research and from what the standard library writes. Start every site in monitor mode.
