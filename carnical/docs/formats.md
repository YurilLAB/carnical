# Request formats and parsing policy

The format inspector checks body/query syntax, ambiguity and resource limits before CRS. It helps
reduce differences between WAF and application parsing. A well-formed request can still contain an
attack; format checks do not replace CRS or application validation.

Source: [policy](../formats/policy.go), [inspector](../formats/inspector.go), [rule
registry](../formats/rules.go).

## Why

Parsers can disagree about duplicate keys, XML declarations, encodings, form separators and
multipart boundaries. The inspector rejects specific ambiguous forms and bounds parser work.
Backend-specific behavior and unsupported formats still need separate review.

## Using it

| Option | Behavior |
| --- | --- |
| `-formats-mode monitor` | Default: report findings while forwarding; other proxy protections still enforce. |
| `-formats-mode block` | Enforce configured blocking findings after tuning legitimate traffic. |
| `-formats-mode off` | Disable the inspector; incompatible with a policy file or encoding opt-in. |
| `-formats-policy path.json` | Read a regular file, at most 1 MiB, before listening or confinement. |
| `-allow-request-encoding` | Allow one bounded gzip/deflate layer. Both CRS and origin receive decoded bytes. |

The CLI mode overrides the policy's `monitor` field. Per-rule overrides still apply. Proxy
`-max-body`/`-max-form-body` limits and format body/decompression limits all apply independently.

For library integration:

```go
pol := formats.Policy{Monitor: true} // start a site here: record, refuse nothing
if err := pol.Validate(); err != nil { /* refuse to start */ }
cfg.Inspectors = append(cfg.Inspectors, formats.New(pol))
cfg.AllowRequestEncoding = true // lets one gzip or deflate layer reach the inspector, which decompresses it
```

Request state is isolated; one inspector can serve concurrent requests. Counters are shared and
bounded. Validate policy before installation. An invalid policy is exposed by `Err()` and body
requests produce `policy-invalid` (5002990).

`ParsePolicy` accepts one JSON object of at most `formats.MaxPolicyBytes` (1 MiB). It rejects
unknown/trailing fields, invalid limits, nonexact names/case, duplicate members (including escaped
aliases), null values and invalid UTF-8. Omit optional settings or use an empty object/list; zero
numeric limits select defaults. Null does not reset a setting.

Start in monitoring, review legitimate traffic, tune individual rules, then enable blocking.
`Rules()` exposes the registry for management integrations.

## What is refused

| Format | Refused |
|---|---|
| Content type | A type not on the list (default: form, multipart/form-data, JSON and `+json`, XML and `+xml`, GraphQL, NDJSON, `text/plain`); opaque binary types (octet-stream, msgpack, CBOR, protobuf, gRPC, Thrift, Avro, BSON) unless named in `allow_opaque`, and then only up to a size cap; a body with no Content-Type; a body on GET or HEAD; a Content-Type that does not follow the grammar, repeats a parameter or uses an RFC 2231 extended one; a charset that is not utf-8, us-ascii, iso-8859-1 or windows-1252 |
| JSON | Anything RFC 8259 does not allow; trailing data; a BOM; raw control characters; invalid UTF-8; an escaped NUL; a lone surrogate escape; a key given twice (after decoding escapes, ignoring case); `__proto__` and `constructor`/`prototype` keys; depth over 64; more than 50,000 values or 20,000 keys; a number or string over its length |
| XML (XML, SOAP, XML-RPC, `+xml`) | DOCTYPE, ENTITY and other declarations, external references, references to any entity but the five predefined ones, XInclude, XSLT, processing instructions, a declared encoding that is UTF-16/32, not accepted, or disagrees with the header or the bytes, text split by a comment or CDATA section, a repeated attribute, depth over 32 |
| GraphQL | Depth over 12, more than 500 fields, 20 aliases, 50 directives (all counted after fragments are expanded), a batch over 10, introspection, fragment cycles and fragments that are unknown or defined twice, a request whose `variables`, `operationName` or `extensions` are not the types the protocol gives them |
| NDJSON | Each line as JSON; more than 1,000 lines; a blank line between records |
| gzip, deflate | A second layer, any other encoding, a corrupt or truncated stream, a wrong checksum, anything after the stream (a second gzip member is anything after it), output over 1 MiB, a ratio over 100:1 |
| YAML (off unless allowed) | Any explicit tag, more than 4 anchors or 8 aliases, depth over 32, more than 10,000 nodes or 1024 collection work units, a body over 32 KiB, more than one document (an empty one counts), a duplicate key |
| Form | A bad percent escape, an escaped or raw NUL or control character, `;` as a separator, invalid UTF-8, more than 1,000 parameters, over-long names and values, brackets nested over 8, `__proto__` names; duplicate names are recorded |
| URL query | The same parameter grammar checks on every method and endpoint, with independent query rules/limits; raw queries over 64 KiB; repeated parameters are monitored by default, with explicit `[]` arrays supported |
| Multipart | No boundary, an invalid or over-long boundary, more than 100 parts, a part header that does not follow the grammar, a repeated Content-Disposition or Content-Type, a `filename` and `filename*` that disagree, a nested multipart, a transfer encoding other than 7bit, 8bit or binary, a bare line feed, no closing boundary, data before the first or after the last boundary, a line that starts with the boundary and is not a delimiter, a part with no name |
| Mismatch | A body that starts like JSON, XML or multipart under a Content-Type that says form, `text/plain` or multipart (or none); a body declared as JSON or XML that does not start like it |

## Policy

All fields are optional; a field left out (or zero) takes its default. No limit can be switched off:
a limit is a positive number below a fixed ceiling, because the point of every limit is that the
cost of a request is bounded by its size.

| Field | Meaning |
|---|---|
| `monitor` | Record every finding and refuse nothing. |
| `rules` | `{"rule-name": "block" \| "monitor" \| "off"}`. An unknown name is an error, so a misspelt rule can never leave a protection quietly on its default. `policy-invalid` and `internal-error` cannot be changed: a body that could not be checked is never let through (except in monitor mode, which lets everything through). |
| `allowed_types` | `type/subtype`, `type/*` or `*+suffix`. Default as in the table above. YAML is added by listing `application/yaml`, `text/yaml`, `application/x-yaml`. |
| `allow_opaque`, `opaque_max_bytes` | Opaque types the site receives (a media type or a prefix ending in `*`) and their size cap (default 64 KiB). |
| `allowed_charsets` | Default `utf-8`, `us-ascii`, `iso-8859-1`, `windows-1252`. |
| `max_body_bytes` | Largest body after decompression (default 1 MiB). |
| `max_query_bytes` | Largest raw URL query scanned (default 64 KiB). The proxy's request-target/header cap also applies. |
| `graphql_paths` | Exact paths that are GraphQL endpoints, in addition to any path with a segment called `graphql` or `graphiql`. |
| `json`, `xml`, `graphql`, `ndjson`, `encoding`, `yaml`, `form`, `query`, `multipart` | The limits of each parser. `query` uses the same fields/defaults as `form` (1000 parameters, 256 name bytes, 65536 value bytes, bracket depth 8), applied independently to the URL. Each field is named, with its default, in the Go type (`policy.go`). |

Query names and values are percent-decoded once for validation and must be UTF-8. Valid encoded
separators remain values; raw semicolons are refused because parsers disagree about them. Duplicate
query names are compared after escape decoding and case folding; the default is monitoring, with
`query-duplicate-param: block` available for APIs that require singular parameters.

All four GraphQL protocol parameters still reject repetition independently. The query is never
rewritten. A query beyond its scan budget is refused in block mode; monitoring or disabling that
budget allows it without complete query analysis. Body inspection continues even when query analysis
stops at a monitored budget.

### How GraphQL is found

A request to a GraphQL path must be a GraphQL request: its query must parse. A request anywhere else
is treated as GraphQL only if its `query` parses as a GraphQL document, so a search form with a
`query` field, or an Elasticsearch body whose `query` is an object, is left alone.

The query is looked for in a JSON object, an array of them (a batch), an `application/graphql` body,
a form, and the URL query string on every method. When URL parameters identify GraphQL, body
envelope checks also apply to that request.

Positions in GraphQL messages are bytes of the decoded query text, not of the request.

## Compatibility choices

* **Duplicate keys are compared after decoding escapes and with case folded** (a Unicode simple fold, so the Kelvin sign and the long s match `k` and `s`, as they do in Go's own decoder). Frameworks keep the first, the last, or merge, and some match keys without regard to case. This comparison catches those duplicate-key ambiguities; it does not establish equivalence with every backend parser.
* **Form and multipart duplicate names are recorded, not refused**, by default (`form-duplicate-param`, `multipart-duplicate-name`): a group of checkboxes is a legitimate duplicate. Names ending in `[]` are never reported. A site that has no such field sets the rule to `block`.
* **A lone `filename*` is recorded, not refused.** RFC 7578 forbids it in form data and browsers never send it, but some HTTP libraries do. A `filename*` that disagrees with `filename` (the Coraza decoy) is refused.
* **A byte order mark is refused for every text format**, XML included. A .NET client that writes one sets `body-bom` to `monitor`.
* **`text/plain` is checked for a body that is a whole JSON or XML document** (it starts like one and ends like one): that is how a cross-site request carries JSON with no preflight. Plain prose that starts with a bracket is left alone. An HTML snippet posted as `text/plain` is refused as XML; a site that does this sets `mismatch-xml-body` to `monitor`.
* **Gzip's `x-gzip` alias, a second member, and `deflate` without a zlib header are refused** (`allow_raw_deflate` accepts the last). These are differences between servers, and the proxy only passes `gzip` and `deflate` through anyway.
* **The ratio limit does not apply under 4 KiB of output.** A few hundred bytes of repetitive JSON can compress past 100:1 and is not an attack. Above that, the limit applied is the smaller of the output cap and 100 times the compressed size.
* **Decompression reads at most the limit plus one byte.** The time and memory a compressed body can cost depend on the limit, not on what the stream claims to hold. The proxy also checks final decompressed bytes against `MaxFormBody` (128 KiB for non-uploads), independently of the format inspector's mode and output limit. Uploaded content and filenames are checked after decompression.
* **XML text split by a comment or CDATA section is refused.** Coraza hands the rules the text pieces of an element separately, so `sel<!-- -->ect` is not seen whole by them and is by the application (README, "Known limits"). One run of text, or one CDATA section alone, is accepted; `a<!-- -->b`, `a<![CDATA[b]]>` and two CDATA sections are not. This can also refuse legitimate mixed content such as `hello <!-- note --> world`; review the rule for sites that accept it.
* **A refused or monitored finding never quotes the request.** A message is built from a rule's fixed sentence, one of a fixed list of phrases (`details.go`, an enumeration, so no string from the request can be passed) and numbers. A test puts a marker in every place content can reach and checks that no message repeats it.

## Verdicts

Operation selection follows the [GraphQL execution
rules](https://spec.graphql.org/September2025/#sec-Executing-Operations): multiple operations
require a matching `operationName`, operation names must be unique, and an anonymous operation must
be alone. JSON member order does not affect selection. A selected mutation in a GET query string is
refused with 403, as permitted by the [GraphQL-over-HTTP
draft](https://http-spec.graphql.org/draft/#sec-GET); a selected query beside a mutation remains
valid.

All four protocol parameters (`query`, `variables`, `operationName`, `extensions`) are checked for
repetition in query strings and GraphQL forms. Nonempty GET/form `variables` and `extensions` must
be JSON objects or null. Empty optional parameters mean absent. Persisted queries without a document
remain supported; the proxy cannot establish their operation type without the application's
persisted-query registry, so the application must enforce method safety for them.

Selected mutations over `HEAD`, `OPTIONS` or `TRACE` also return 403, using
`graphql-safe-method-mutation`. These are [safe HTTP
methods](https://httpwg.org/specs/rfc9110.html#safe.methods), and frameworks such as [Express may
dispatch HEAD to GET handlers](https://expressjs.com/en/4x/api/router/#router-method). The check
applies to URL and body envelopes, including an explicitly permitted HEAD body. The existing GET
rule stays independently configurable. Ordinary OPTIONS preflights without GraphQL protocol
parameters pass.

A second, independent rule, `graphql-http-method`, permits GraphQL operations/protocol parameters
only over GET or POST. It blocks other methods with 403 even if a mutation rule is disabled, and
covers extension-only persisted-query requests on configured GraphQL paths. This is Carnical's
hardening policy: the [GraphQL-over-HTTP draft](https://http-spec.graphql.org/draft/#sec-Request)
permits servers to implement other methods. A legacy endpoint can disable this rule explicitly; the
safe-method mutation rule still applies. The default policy now refuses HEAD queries as well as
mutations.

`graphql-mixed-transport` refuses GraphQL protocol parameters split between URL and body with 400.
It covers JSON, form, raw GraphQL and batch envelopes, including a URL document paired with
body-only selection or variables on a discovered endpoint. Ordinary URL metadata such as `locale`
remains allowed.

`graphql-method-override` refuses top-level `_method` metadata in a GraphQL URL, form or JSON
envelope, including decoded escapes, case aliases and bracket forms; it does not reserve `_method`
inside `variables`. Framework middleware can [change the effective method from headers, query or
body fields](https://expressjs.com/en/resources/middleware/method-override/), so these findings
complement operation selection rather than matching one mutation string.

Custom override names/getters still require origin-specific policy.

Protocol-name case aliases such as `Query`, `QUERY` or `operationname` are recognized for inspection
and refused by `graphql-request-shape` when the request is GraphQL. This includes decoded names and
batch discovery. The original bytes are never normalized or rewritten for forwarding. Mutation and
transport checks still run, so an alias cannot hide an operation from those independent guards;
monitor mode reports the alias finding as well.

JSON batch discovery observes GraphQL query candidates in every root-array object, including objects
beyond the retained element budget. An empty/unrelated prefix cannot suppress discovery. The
existing batch cap still applies before operation analysis; monitor/off modes keep the bounded
retention limit and cannot fully analyze elements beyond it. Ordinary JSON batches without GraphQL
query candidates remain ordinary JSON.

The proxy also rejects mixed/lowercase HTTP method tokens (5000043) and `X-HTTP-Method-Override`,
`X-Method-Override`, `X-HTTP-Method` headers, including underscore aliases (5000044), with 400
regardless of CRS or format mode. Sites relying on header method tunneling must change that
integration. These proxy findings use the individual match log; format-rule counters include the
three new GraphQL rule identities. Enforce them with `-formats-mode block`; monitor mode
deliberately forwards and records findings.

These protections complement the depth, alias, field and batch limits used by commercial products
such as [F5 WAF for NGINX](https://docs.nginx.com/waf/policies/graphql-protection/) and [Fastly
Next-Gen
WAF](https://www.fastly.com/blog/introducing-graphql-inspection-for-the-fastly-next-gen-waf). They
do not validate GraphQL fields against a schema or replace application authorization.

Each HTTP request also has aggregate GraphQL budgets: `graphql.max_request_fields` defaults to 1000,
`max_request_aliases` to 40, and `max_request_directives` to 100. Totals include only the selected
operation of every document inspected in that request, after fragment expansion; unused operations
still undergo their individual limits.

A batch cannot multiply a permitted individual budget without being subject to these totals.
Counters reset for every request and use saturating arithmetic. These are conservative syntax
counts, not schema-weighted resolver cost or a bound on response size; pagination arguments and
authorization still require application controls.

Raise the request budgets for a known legitimate workload, or use monitor mode while tuning.

Identifiers 5002000 to 5002999. The table is the one the code holds; a test
(`TestDocumentationMatchesRules`) fails if this table and `Rules()` differ in any column. A message
looks like `json-duplicate-key: an object key given twice (compared after decoding escapes, ignoring
case) at byte 17`, or `graphql-fields: a GraphQL query that selects more fields than the limit
(limit 500)`, or, for NDJSON, `... in line 3 at byte 9`.

Default is what happens when the policy does not say. Status is what the visitor gets for a refusal.

<details>
<summary>Full rule reference: IDs, defaults, statuses and severities</summary>

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
| 5002310 | `graphql-get-mutation` | block | 403 | high | a GraphQL mutation selected for execution using GET |
| 5002311 | `graphql-request-fields` | block | 400 | high | a GraphQL request whose selected operations exceed the total field limit |
| 5002312 | `graphql-request-aliases` | block | 400 | high | a GraphQL request whose selected operations exceed the total alias limit |
| 5002313 | `graphql-request-directives` | block | 400 | high | a GraphQL request whose selected operations exceed the total directive limit |
| 5002314 | `graphql-safe-method-mutation` | block | 403 | high | a GraphQL mutation selected for execution using HEAD, OPTIONS or TRACE |
| 5002315 | `graphql-http-method` | block | 403 | high | a GraphQL operation transported using a method other than GET or POST |
| 5002316 | `graphql-mixed-transport` | block | 400 | high | GraphQL protocol parameters split between the URL and request body |
| 5002317 | `graphql-method-override` | block | 400 | high | method-override metadata in a GraphQL transport |
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
| 5002608 | `form-parameter-shape` | block | 400 | high | parameter names with conflicting scalar, container or normalized interpretations |
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
| 5002800 | `query-bad-escape` | block | 400 | high | a URL query percent escape that is not two hex digits |
| 5002801 | `query-control-char` | block | 400 | high | a NUL or control character in URL query parameters |
| 5002802 | `query-duplicate-param` | monitor | 400 | medium | a URL query parameter name given more than once |
| 5002803 | `query-limit` | block | 400 | high | URL query parameters over a count or length limit |
| 5002804 | `query-bracket-depth` | block | 400 | high | a URL query parameter name with brackets nested deeper than the limit |
| 5002805 | `query-semicolon` | block | 400 | high | an unescaped semicolon in URL query parameters |
| 5002806 | `query-proto-key` | block | 400 | high | a URL query parameter name that pollutes an object prototype |
| 5002807 | `query-invalid-utf8` | block | 400 | high | URL query parameters that are not valid UTF-8 |
| 5002808 | `query-too-large` | block | 414 | high | a raw URL query larger than the site allows |
| 5002809 | `query-parameter-shape` | block | 400 | high | URL parameter names with conflicting scalar, container or normalized interpretations |
| 5002990 | `policy-invalid` | block | 503 | critical | the formats policy is invalid, so bodies are refused |
| 5002991 | `internal-error` | block | 503 | critical | the body could not be checked |

</details>

`type-duplicate-header` is a second line of defence: the proxy already refuses a request with two
Content-Type headers (5000005) before any inspector runs. `internal-error` is what a panic in a
parser becomes (see the recorded fuzzing results in [validation](formats-validation.md#verified)).

## Monitoring and logs

Each emitted finding increments an atomic per-rule blocked or monitored counter. `Inspector.Stats()`
returns a fresh snapshot containing only stable rule IDs/names and counts. Storage is sized by the
rule registry, never by client identities or input strings. A rule is counted at most once per
request; a batch may trigger the same rule repeatedly, but the inspector emits it once.

Off rules are silent. Parsing still stops at the first blocking finding and the 32-verdict reporting
cap, so counts describe reported findings rather than all possible problems or unique requests.
Snapshot fields are independently atomic, not one transaction across all rules.

The executable logs changed `format protection totals` snapshots every minute by default.
`-formats-stats-interval` accepts `0` (disabled) or 100ms through 24h; a graceful stop flushes a
final changed snapshot. A forced process kill cannot flush. Counters reset when a new inspector is
constructed and do not aggregate across a fleet. Format mode off does not run this reporter.

For per-attempt events, `msg` is `rule matched`, `rule_msg` contains fixed rule text, and
`disruptive` distinguishes enforced from monitored findings. Log tests verify every repeated bypass
attempt is recorded with the correct outcome. Aggregate labels contain no URI, body, credentials or
client address. CRS expanded messages and inspector panic text are available only through the
explicit detailed-log setting; they are not safe summaries.

## How it is built

One file per format, each with its own parser, its limits and its fuzz target. The inspector
(`inspector.go`) parses the Content-Type, decides by media type, decompresses if asked, and calls
the format's check. A check reports a finding to the `finder`, which applies the policy (block,
monitor or off) and says whether to stop; no parser decides what a finding costs. Each rule is
reported once per request.

| File | What it is |
|---|---|
| `contenttype.go` | Content-Type and Content-Disposition grammar (RFC 9110): token, quoted string, duplicate and extended parameters. Not `mime.ParseMediaType`, which repairs what this refuses. |
| `jsonscan.go` | RFC 8259 tokenizing parser. Never builds a tree; its memory is the folded keys of the objects that are open. |
| `xmlscan.go` | One-pass XML scanner: names, attributes, references, declaration, encoding, DOCTYPE classification. |
| `graphql.go`, `graphqlreq.go` | Lexer, parser and fragment-expanding analyser; the envelope (JSON, batch, form, query string). |
| `ndjson.go`, `encoding.go`, `yaml.go`, `form.go`, `multipart.go`, `sniff.go` | As named. |

## What it costs

Body/decompression/work limits bound inspection. YAML needs an additional collection-work guard
because its underlying parser can copy quadratically. `yaml.max_collection_work` defaults to 1024
and cannot exceed that ceiling; it counts structural lexer work before parsing. Wide previously
accepted documents may now trigger `yaml-limit`. YAML remains opt-in.

Monitoring or disabling a work-limit rule permits forwarding after inspection stops; later findings
may therefore be absent. Decompression reads no more than its output limit plus one byte. See
[benchmarks and parser tests](formats-validation.md#what-it-costs) for measurements and conditions.

## Verified

Tests check rule-table consistency, refusal/monitor/off controls, valid standard-library output,
truncated input, concurrent use, logging privacy, decompression and live origin forwarding. The
[validation record](formats-validation.md#verified) keeps the recorded counts and environment.

## Source mutation

[Mutation results](formats-validation.md#source-mutation) describe deliberate source changes that
the tests detected, alongside equivalent/unreachable survivors.

## What is not done, and what to watch

* **Query validation checks grammar and budgets, without an application schema.** Duplicate parameters are monitored by default. Application-specific names/types and collisions between query and body parameters need separate policy.
* **No Unicode normalisation.** Keys are compared after escape decoding and case folding, not after NFC or NFKC, which a framework could apply.
* **XML is scanned, not validated.** There is no namespace resolution (a prefix bound to the XInclude or XSLT namespace is found by what it is bound to, so this holds), no attribute-value normalisation and no check of characters above the control range (U+FFFE, U+FFFF). The text-split rule may refuse mixed content with a comment in the middle of a sentence.
* **GraphQL is read for what it costs, not checked against a schema.** A syntax this parser does not know is refused on a GraphQL path: the nullability operators of the 2025 draft (`field!`, `field?` in a selection), and anything that is not an operation or fragment. Client directives such as `@defer` and `@stream` are ordinary directives and are counted.
* **YAML** follows the goccy parser, which is not the parser the application uses; differences between YAML parsers are the largest of any format here, and tags and anchors are refused because they are what is dangerous in all of them, not because the rest is equivalent.
* **A body that names a single-byte charset is refused for JSON, NDJSON, GraphQL and YAML if it has any byte above 127**, because those formats are UTF-8 and a parser that honours the header would read it differently.
* **A legitimate client may need a rule set to `monitor`**: a single-page application that posts JSON with no Content-Type header (the browser sends `text/plain`), a .NET client that writes a byte order mark in XML, an HTML snippet posted as plain text, a `curl --data @file` whose file ends in a line feed (a raw line feed in a form is refused).
* **Persisted GraphQL requests without a document cannot be classified as query or mutation** without access to the origin's persisted-query registry. Origin method safety remains necessary for them.
* **Not run on a real forge or real traffic.** The rows come from the research and from what the standard library writes. Start every site in monitor mode.
