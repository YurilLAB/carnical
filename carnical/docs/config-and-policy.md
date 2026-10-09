# Signed configuration and customer policy

The `config` package verifies signed per-tenant configuration. The `policy` package validates
customer settings and compiles them to proxy/CRS configuration and bounded SecLang rules. These are
integration libraries; `cmd/carnical` does not start a signed-policy service.

A configuration envelope carries the JSON policy document, not raw SecLang. Verification binds the
tenant, edge audience, sequence and validity window. Compilation applies the edge's own policy
validation. Keep signing keys outside the control service and implement a durable sequence store;
signed transport does not prevent a trusted signer from weakening allowed settings.

Use [verification order](#what-the-verifier-checks-in-this-order), [sequence
storage](#the-sequence-record), [policy fields](#the-document), [policy
comparison](#comparing-policies) and [integration example](#for-the-control-worker) for review.
Source: [config](../config/), [policy](../policy/).

## Part 1. The configuration channel (`config/`)

### What it stops

| Attacker | What they try | What stops it | Error the edge logs |
|---|---|---|---|
| A compromised control host | Make an edge enforce a policy of its choosing | It does not hold the signing key (the signer is a different user and host zone). An envelope it forges has a bad signature. | `bad_signature` |
| A compromised control host | Reuse a genuine envelope for another tenant | The tenant is inside the signed bytes. | `bad_signature` (field changed) or `wrong_tenant` (genuine, for a tenant this edge is not assigned) |
| A network attacker | Replay an old envelope, or one for another edge | The sequence must be higher than any accepted; the audience (the edge id) is signed. | `rollback`, `wrong_audience` |
| A network attacker | Hold back newer envelopes and replay an old one later | Validity windows are short (7 days at most by default), and the sequence record outlives restarts. | `expired`, `rollback` |
| Anyone who sees an envelope | Change the payload, the dates, the sequence, the key id | All of them are signed. | `bad_signature` |
| Anyone | Send a huge or malformed object to use up the edge | Size is checked before anything is parsed; the parser is strict and linear. | `oversize`, `malformed` |
| Someone who steals a signing key | Sign anything | Keys have dates, can be revoked in a signed key list, and the list's own sequence only rises, so an old list cannot bring a revoked key back. | `revoked_key`, `key_not_valid`, `unknown_key` |
| A power cut | Leave a half-written record that lowers the stored sequence | The record is written to a temporary file, flushed, renamed, and the directory flushed; a damaged record is an error, never a smaller number. | `store_corrupt` (nothing accepted for that tenant until an operator looks) |

### The envelope

| Field | Form | Notes |
|---|---|---|
| `v` | the number 1 | the layout version |
| `tenant` | 32 lower-case hexadecimal digits | the tenant id (T1) |
| `audience` | 1 to 63 of `a-z 0-9 . _ -`, starting with a letter or digit | the id of the edge it is for |
| `seq` | whole number from 1 to 2^53 - 1 | rises with every configuration for a tenant; 2^53 - 1 is the largest integer every JSON reader keeps exactly |
| `not_before`, `not_after` | `2026-10-05T00:00:00Z` (UTC, to the second, nothing else) | the same time form the release scheme uses |
| `key_id` | 16 lower-case hex digits | the first 8 bytes of SHA-256 of the 32-byte public key, as `newsletter/brief/waf/keys.py` computes it |
| `payload` | base64url, no padding, canonical | JSON, 1 byte to 2 MiB; the envelope does not look inside beyond "is JSON" |
| `sig` | base64url, no padding, canonical | the 64-byte Ed25519 signature over the signed bytes below |

Wire form: one JSON object with exactly these nine fields and nothing else, at most 4 MiB. Repeated
field names, nested values, any other field, white-space tricks around base64, invalid UTF-8,
anything after the closing brace, and non-canonical base64 (a spelling of the same bytes with a
spare bit set) are all refused as `malformed`.

`encoding/json` alone would take the last of two equal names; two readers that disagree about which
one counts is how signed data gets read differently from how it was checked, so the decoder reads
field by field.

### The signed bytes, byte by byte

```
"carnical-config-v1"            18 ASCII bytes, no length, no terminator: the domain
then these eight fields, in this order, each as a 4-byte big-endian length followed by the bytes:
  1  version     2 bytes, big-endian                  00 01
  2  tenant      the 32 ASCII characters
  3  audience    the ASCII characters
  4  sequence    8 bytes, big-endian
  5  not_before  8 bytes, big-endian two's complement, seconds since 1970-01-01T00:00:00Z
  6  not_after   8 bytes, as above
  7  key_id      the 16 ASCII characters
  8  payload     the payload bytes, exactly as they are
```

Every field has a length in front and the order never changes, so no byte can move from one field to
the next, and two different envelopes never give the same bytes. The domain at the front names what
is signed and the layout, so a signature made for anything else (a release manifest, a key list, a
later layout `carnical-config-v2`) is never valid here.

A test signs the release scheme's own bytes (`sfw-v1\nmanifest\n...`) and a key list with the same
key and shows neither verifies as an envelope.

**Test vector** (fixed keys: seed `0102...20` for the signing key, `4142...60` for the root; the
values below were produced by `config/testdata/vectors.py`, which builds the bytes with Python's
`struct` and the `cryptography` package and shares no code with the Go; `config/vectors_test.go`
checks the Go code against them byte for byte):

```
signing public key   79b5562e8fe654f94078b112e8a98ba7901f853ae695bed7e0e3910bad049664
key id               65b60673d6ed884b
tenant               00112233445566778899aabbccddeeff   audience edge-eu-1   seq 7
window               2026-10-05T00:00:00Z .. 2026-10-12T00:00:00Z   payload {"schema":1,"mode":"block"}

signed bytes (hex), with the fields apart:
63617 26e696361 6c2d636f6e6669672d7631                                  "carnical-config-v1"
00000002 0001                                                           version 1
00000020 3030313132323333343435353636373738383939616162626363646465656666   tenant (32 bytes)
00000009 656467652d65752d31                                             audience "edge-eu-1"
00000008 0000000000000007                                               sequence 7
00000008 000000006ac2e880                                               not_before 1791158400
00000008 000000006acc2300                                               not_after  1791763200
00000010 36356236303637336436656438383462                               key id (16 bytes)
0000001b 7b22736368656d61223a312c226d6f6465223a22626c6f636b227d         payload (27 bytes)

signature (hex)      e6b55a1cfe887953bd17578577050020cd8d1d287a9aaceb6f84d4f9fb2e9d6719fe3626798468dc28f46e310d0364e57f5c98b8c934c84cff2f884725e6ee03
```

The whole signed message, unbroken, is in `config/vectors_test.go` (`vecSignedHex`), together with
the wire form of the envelope and of a key list.

### The key list

How an edge learns which keys may sign configuration, so that a key can be rotated or revoked
without touching the edge's installation. It is the release scheme's `keys.json` idea (a short
document signed by a pinned root key, a sequence that only rises, dates, a revoked list; Ed25519;
key ids as above; at most 50 keys and 500 revoked ids; the root may not be listed as a signing key;
any fault refuses the whole file) with two deliberate differences:

- the signed bytes start with `carnical-keys-v1` and a listed key's role must be exactly `config`, so a release key list the same root signed (`sfw-v1`, role `manifest`) is **not** a valid Carnical key list, and the reverse. Without that, an old release list with a high sequence number could be handed to an edge to make it forget its signing keys;
- it is read with `config.VerifyKeySet` / `config.AcceptKeySet`, and its sequence is kept in the same record store, under `keyset-<root key id>`.

```
signed bytes: "carnical-keys-v1" (16 bytes), then as 4-byte-length fields: version (2 bytes, 00 01), root key id (16 ASCII), payload (the JSON, exact bytes)
wire form:    {"v":1,"key_id":"<root key id>","payload":"<base64url>","sig":"<base64url>"}
payload:      {"schema":1,"seq":3,"issued":"...Z","expires":"...Z",
               "keys":[{"id":"...","alg":"ed25519","pub":"<base64url, 32 bytes>","roles":["config"],"not_before":"...Z","not_after":"...Z"}],
               "revoked":["<16 hex>", ...]}
```

A list is refused (with the error that says why) for: a bad signature, a root that is not pinned, a
repeated name anywhere in the payload, an unknown field, a key whose id is not the hash of its key,
a role other than `config`, a key listed twice, a root key listed as a signing key, more than 50
keys or 500 revoked ids, a validity over 366 days, or dates in the wrong form.

`Apply` gives the verifier the keys, the revoked ids and the list's expiry; after the expiry no key
is believed until a newer list arrives (`key_list_expired`).

### What the Verifier checks, in this order

The order is the design: everything an envelope says about itself (audience, tenant, dates,
sequence) is judged **after** its signature, so a refusal that names one of those means the envelope
really was signed by a trusted key, and an unsigned flood cannot spend sequence numbers.

| # | Check | Error (`Reason()` code) |
|---|---|---|
| 1 | larger than 4 MiB | `oversize` |
| 2 | strict decode, field forms, payload is JSON | `malformed`, `unsupported_version` |
| 3 | a key list is loaded and has not expired | `unknown_key`, `key_list_expired` |
| 4 | the key id is not revoked | `revoked_key` |
| 5 | the key id is listed | `unknown_key` |
| 6 | now is inside the key's dates | `key_not_valid` |
| 7 | the Ed25519 signature | `bad_signature` |
| 8 | audience is this edge | `wrong_audience` |
| 9 | tenant is assigned to this edge | `wrong_tenant` |
| 10 | the window is not empty or over the maximum (7 days by default, 31 at most) | `invalid_window` |
| 11 | now is not before `not_before`, nor after `not_after`, give or take 2 minutes of clock skew | `not_yet_valid`, `expired` |
| 12 | `Accept` only: the sequence is higher than any accepted for the tenant, **recorded atomically with that check** | `rollback`, `store_corrupt`, store failure (`errors.Is(err, config.ErrStore)`) |

No error text repeats anything the sender wrote (no tenant, key id, sequence or payload byte), and
none carries the stored sequence: a test checks every refusal's text against the values that caused
it. Nothing here is secret, so nothing needs a constant-time comparison; the signature check is
`crypto/ed25519`'s.

Two entry points, and the difference matters:

- `Accept(raw, now)` is what an edge calls for a configuration that arrives. It verifies, then records the sequence in the same atomic step. Of any number of envelopes presented at once for one tenant, those accepted are exactly the ones that were higher than everything accepted before them, the highest of all always is, and no number is ever accepted twice. Nothing is recorded for an envelope that fails any other check.
- `Verify(raw, now)` does everything but record, and lets an envelope with the *same* sequence as the newest through, so an edge can re-check at start-up the envelope it is already running. Never apply a configuration that was only `Verify`'d.

The sequence is recorded **before** the edge applies the configuration. If applying then fails (a
payload that will not compile), that number is spent, and the control plane must sign the corrected
policy under a higher one. The alternative (record after applying) would let a crash between the two
replay the envelope.

### The sequence record

`config.SeqStore` is the interface (`Advance(stream, seq)` atomically records a higher number or
returns `rollback`; `Last(stream)`). `FileSeqStore` keeps one file per stream (a tenant id, or
`keyset-<id>`) in one directory (mode 0700, files 0600):

```
carnical-seq-v1\n<stream>\n<decimal sequence>\n<first 16 hex digits of SHA-256 of those three lines>\n
```

Write path: temporary file in the same directory, write, `fsync`, rename over the file, `fsync` of
the directory, and only then does `Advance` return. The checksum catches a cut, empty or altered
file; the stream name inside catches a file copied to another tenant's name.

**A damaged record is never read as "no record" or as a smaller number**: it is `store_corrupt`, and
nothing is accepted for that tenant until an operator, who knows the newest sequence the control
plane issued, calls `FileSeqStore.Reset(stream, seq)` (no code path that handles an envelope calls
it).

Stale temporary files are removed when the store is opened. Opening an existing store first rejects
directory symlinks and, on Unix, any group/other directory permissions; rejection does not clean up
files or change permissions. Windows deployments must restrict the directory with ACLs.

Relative directory paths are resolved when the store opens. Changing the process working directory
does not move the store or reset its replay protection. The directory owner and its parent path must
remain protected.

Honest limits: one process writes the directory (two writers could each read the same number and
both write a higher one); Windows cannot flush a directory, so the power-cut argument is for Linux;
a validly formed *older* record put back by someone who can write the directory is a rollback this
package cannot see (the directory must be the edge user's alone, `deploy/tmpfiles.d`); the clock is
the machine's, and a skewed clock widens or narrows the windows by its error.

### Using it

Signer service (holds the key; nothing else does):

```go
signer, _ := config.NewSigner(privateKey)                       // ed25519.PrivateKey, never in an edge
env, err := signer.Sign(tenantID, "edge-eu-1", seq, 48*time.Hour, policyJSON)   // policyJSON is policy.Encode(p)
raw, _ := env.Marshal()                                         // what travels
```

The control plane decides the next `seq` for a tenant (it is part of what the signer is asked to
sign) and re-signs before the window ends (daily, say).

Edge:

```go
store, _ := config.OpenFileSeqStore("/var/lib/carnical/seq")
v, _ := config.NewVerifier(config.VerifierConfig{Audience: "edge-eu-1", Tenants: assigned, Store: store})
ks, err := config.AcceptKeySet(keysJSON, pinnedRoots, now, store)   // a signed key list; refuse and keep the old one on error
ks.Apply(v)
env, err := v.Accept(raw, now)                                      // a refusal: log config.Reason(err), keep running the old configuration
p, err := policy.Decode(env.Payload)                                // strict again, with this edge's own code
c, err := policy.Compile(p)                                         // then build a new WAF off the request path and swap it in
```

At start-up an edge loads its persisted envelope with `Verify`, not `Accept`.

---

## Part 2. The customer policy (`policy/`)

### The document

`policy.Policy` is JSON. A field left out takes the value `policy.Default()` gives it, so a document
only names what differs; `{}` is the default policy. Unknown fields, repeated fields, `null` (except
for `threshold` and inside the two sections other packages own) and values of the wrong kind are
errors. Typed field names and rule-group names may use different casing, but aliases of the same
name cannot appear together. Property names inside `api` and `body_formats` remain case-sensitive.

| Field | Form | Limits / default |
|---|---|---|
| `schema` | 1 | |
| `revision` | whole number | the control plane's counter; **not** part of the content hash |
| `mode` | `block`, `monitor`, `off` | `block`. `off` runs no rules but the proxy's own checks (path, host, upload, WordPress) still run |
| `sensitivity` | `relaxed`, `normal`, `strict` | `normal`; the table below |
| `threshold` | null, or 1 to 1000 | replaces the preset's blocking score |
| `body.max_upload_bytes` | 1 KiB to 64 MiB | 1 MiB. Also the size of the largest upload (read whole into memory per request in flight, which is why 64 MiB is the ceiling) |
| `body.max_form_bytes` | 1 KiB to 1 MiB, at most the upload limit | 128 KiB. The rules cost time in proportion to a body; the evaluation budget cuts a request off long before 1 MiB is useful |
| `allowed_methods` | 1 to 20 of `[A-Z][A-Z-]{0,19}`, never `CONNECT` or `TRACE` | `GET HEAD OPTIONS POST` |
| `allowed_hosts` | 0 to 100 DNS names; empty means any name | none. No wildcards (the proxy compares exactly), no ports, punycode for non-ASCII |
| `rule_groups` | map from `sqli xss lfi rfi rce php ssrf java scanner protocol` to `on`, `log`, `off` | all on |
| `exclusions` | up to 100 of `{path, categories (1 to 10 groups), targets (0 to 8), note}` | none |
| `custom_rules` | up to 100 of `{id 1..9999, field, operator, value or values, case_sensitive, action, note}` | none |
| `allow_ips` | up to 500 addresses or CIDR ranges, none wider than /16 (IPv4) or /32 (IPv6) | none |
| `block_ips` | up to 5000, none wider than /8 or /16 | none |
| `allow_paths` | up to 200 path prefixes | none |
| `paths` | `allow_encoded_slash`, `allow_path_params` | both false |
| `uploads` | `allow_script_names`, `allow_script_content` | both false |
| `wordpress` | `enabled`, `allow_xmlrpc`, `login_per_minute` 1 to 600 | off, false, 10 |
| `responses` | `keep_banners`, `keep_caching`, `inspect` | all false. `inspect` is off because it buffers responses (latency) |
| `deny_headers` | up to 50 header names | none |
| `framework` | `deny_next_action` | false: a Next.js site that uses server actions needs the header, and nothing can tell from outside which sites do |
| `vpatch` | `tiers` (`verified community experimental`), `software` (up to 200 of `name` or `name@version`) | `["verified"]`, none |
| `api_mode` | `off learn monitor enforce` | `off` |
| `api`, `body_formats` | JSON objects owned by other packages | absent |
| `note` | free text, 1000 bytes | empty |

Limits that every document meets: 1 MiB total, 16 levels deep, 8192 bytes per string, 400,000
values; in the other packages' sections 256 KiB, 12 levels, 20,000 values, and field names of
printable ASCII without quote or backslash, at most 200 bytes.

Strings that reach a rule are held to a character set that means nothing to SecLang (below); free
text (notes) must be valid UTF-8 made of printable characters and spaces: no control, separator,
zero-width or direction-changing character, because that is how text is made to read as something it
is not.

`Decode` normalises and validates, so what it returns is canonical. **Normal form**: sets (methods,
hosts, header names, addresses, paths, categories, targets, tiers, software, the words of a `pm`
rule) sorted and de-duplicated; hosts, header names (with `_` written `-`), targets, fields, tiers
and software lower case; methods upper case; an address written in its shortest form with the host
bits of a range cleared (`10.1.2.3/8` is `10.0.0.0/8`, `::ffff:192.0.2.1` is `192.0.2.1/32`); rule
groups that are `on` left out; exclusions sorted, custom rules sorted by id; absent lists empty;
notes trimmed; the other packages' sections rewritten in canonical JSON.

`Encode` writes that, compactly, and `Hash` is the SHA-256 of it with the revision zeroed: two
policies that say the same thing have the same hash whatever the order or case of their lists, and a
change of revision alone is not a change.

### Sensitivity

| | blocking paranoia level | blocks at | outbound score |
|---|---|---|---|
| `relaxed` | 1 | 8 | 8 |
| `normal` | 1 | 5 | 4 |
| `strict` | 2 | 5 | 4 |

Rules score 5 (critical), 4 (error), 3 (warning) or 2 (notice). `relaxed` therefore needs a critical
rule and a warning together; `normal` is the Core Rule Set as published; `strict` adds the level 2
rules, which find more and flag more ordinary traffic (from the [historical corpus](proxy-reference.md#historical-paranoia-level-comparison): level 1
wrongly blocks 2.4% of 468 tricky ordinary requests and finds 82.6% of 247 attacks, level 2 8.3% and
86.2%, levels 3 and 4 block more than a site can use without weeks of tuning, so no preset uses
them).

A `threshold` replaces the second column and leaves the first. The detection paranoia level is left
equal to the blocking one: running the next level up only to log it would double the match log and
cost rule time for matches nobody blocked on.

Measured cost of the levels is under "What was run".

Real requests, through the proxy: `/x?id=1+order+by+10` (one critical rule) is stopped at normal and
strict and passes at relaxed; `/x?c=ZWNobyAnaGknOw==` (a level 2 rule) is stopped only at strict; a
request whose Host is an IP address (one warning, 3) passes everywhere and is stopped with
`threshold: 3`.

### Rule groups

A group is a **range of Core Rule Set rule ids**, not a tag (the tags cross the ranges: 934 carries
`attack-rce`, `attack-ssrf` and `attack-ssti`, 944 carries `attack-rce`, so a tag would put a Java
rule in the RCE group):

| group | ids | | group | ids |
|---|---|---|---|---|
| `sqli` | 942000-942999 | | `java` | 944000-944999 |
| `xss` | 941000-941999 | | `ssrf` (also the generic rules of 934) | 934000-934999 |
| `lfi` | 930000-930999 | | `scanner` | 913000-913999 |
| `rfi` | 931000-931999 | | `protocol` | 920000-922999 |
| `rce` | 932000-932999 | | `php` | 933000-933999 |

- **on**: nothing is generated.
- **off**: `SecRuleRemoveById <first>-<last>` after the rules are loaded.
- **log**: the rules run and record their matches, and add nothing to the score. The Core Rule Set cannot do this from outside (every rule adds its own score to `tx.inbound_anomaly_score_plN` and rule 949110 reads the sum), so each rule that is one condition gets a second `setvar` that takes its own back (`SecRuleUpdateActionById 942100 "setvar:'tx.inbound_anomaly_score_pl1=-%{tx.critical_anomaly_score}'"`). Which rule adds what is **read from the embedded rule set at first use**, so the table cannot drift from the rules, and a test reads the files again independently and requires the two to agree for every rule. A rule that needs several conditions (a chain: 920180, 920480 and 43 others) keeps its score in its last link, which an action added to the rule cannot reach (the engine runs a rule's own actions when its first link matches, so a compensation would also lower the score of a request whose later links did not match), so **in a group set to log those 45 rules are switched off instead** (no match, no score, no record). 30 of them are in `protocol`. `Compiled.Notes` says so for every group set to log; the UI should show it.

Verified against the real rule set, for each of the ten groups and each state: an attack that only
that group's rules see is stopped when the group is on, passes and is recorded (rule ids in the
group's range, no 949110) when it is on `log`, and passes with nothing recorded when it is off.

Two more tests: with sqli on `log` an XSS attack is still stopped, and with a blocking score of 8 a
SQL injection (5) and a request whose Host is an address (3) are stopped with sqli on, and pass with
sqli on `log` or `off` (the 5 is not counted).

### Exclusions

`{path, categories, targets}`: the rules of those groups are kept away from those parts of requests
whose path begins with `path` (case-sensitive; end a folder with `/`; characters
`A-Za-z0-9/_.~@:=+,-` only, no `//` or dot segment). One rule per exclusion and category:

```
SecRule REQUEST_FILENAME "@beginsWith /editor/" "id:1010100,phase:1,pass,nolog,t:none,ctl:ruleRemoveTargetById=942000-942999;ARGS:content,ctl:ruleRemoveTargetById=942000-942999;REQUEST_COOKIES"
SecRule REQUEST_FILENAME "@beginsWith /api/"    "id:1010004,phase:1,pass,nolog,t:none,ctl:ruleRemoveById=932000-932999"
```

With no targets the whole category is removed for the request; with targets only those parts are
taken out of what its rules look at, which is the Core Rule Set's own exclusion model. Targets:
`args argnames cookies cookienames headers body query path uri method filenames`, or `arg:NAME`,
`cookie:NAME`, `header:NAME` (names of letters, digits and `_ . - [ ]`, 64 at most; headers without
`_ . [ ]`; lower case, because the engine compares in lower case).

`arg:NAME` takes out the argument's value; its name is still seen unless `argnames` or `arg:` plus
the name under `argnames` is also excluded. Tested against the real rule set (17 requests): the
excluded argument on the excluded page passes; another argument, another page, a page that only
starts alike, the path in another case, and another group's attack are all still stopped.

### Custom rules, and why no input can write anything else

A custom rule is one field, one operator, a value, and `block` or `log` (`block` refuses the request
outright in block mode and is only recorded in monitor mode; there is no `allow` action, so nothing
here can switch the rules off). It compiles to exactly one `SecRule` with the id `1050000 + id`, a
fixed message `Custom rule <id>` (never the note, never request data), and a fixed list of actions:

```
SecRule ARGS "@rx (?i:a\x22b\x5cc\x20\x25\x7bx\x7d\x0ad)" "id:1050007,phase:2,deny,status:403,log,t:none,msg:'Custom rule 7',tag:'carnical-custom',severity:'CRITICAL'"
```

Fields: `method path uri query args argnames cookies cookienames headers body filenames host
useragent`, or `arg:NAME`, `cookie:NAME`, `header:NAME`. The rule runs in phase 1 when the field is
complete after the request headers (everything but `args`, `argnames`, `arg:`, `body`, `filenames`).
`uri` and `query` are matched after one round of URL decoding.

The text of a value reaches the engine inside `"@rx ..."`, where the quote, the backslash, the
percent sign (it opens a macro, `%{tx.score}`), white space and the backtick mean something to the
SecLang reader, and where the engine itself decides, from the backslash escapes in the text, whether
to match runes or raw bytes (`internal/operators/rx.go`: a `\x` escape above 0x7f makes it match
bytes).

So **the customer's text is never written into a rule**. Every operator becomes a regular
expression, built from a parsed tree:

- `contains equals beginsWith endsWith pm`: each character is written as itself if it is an ASCII letter or digit, as `\xHH` if it is any other ASCII character (so a quote, a backslash, a space, a percent sign, a newline and a NUL are the same plain thing: four characters), as itself if it is a printable character outside ASCII, and **refused** if it is anything else (a control, line or paragraph separator, zero-width or direction-changing character, non-breaking space, invalid UTF-8). `equals` is `\A...\z`, `beginsWith` `\A...`, `endsWith` `...\z`, `pm` an alternation; case is ignored with `(?i:...)` unless `case_sensitive`.
- `rx`: parsed as RE2 with the engine's own flags in front (`(?sm)`), refused if it does not parse, if its compiled size (worked out from the tree, without expanding it, so a hostile expression costs nothing to refuse: `((a{100}){100}){100}` is refused in microseconds and allocates almost nothing) is over 2,000 instructions, or if writing the tree back out does not parse to the same tree; then written in the library's canonical spelling with the five characters SecLang cares about (quote, apostrophe, percent sign, space, backtick) as `\x` escapes and the whole put in a group so the text never ends in a backslash. What RE2 cannot say (lookahead, back-references, possessive quantifiers, atomic groups) is refused; so is anything that would need `\x{...}` or an escape above 0x7f (invisible characters, and a negated class such as `[^\x00-\x7f]`, which is a range above 0x7f): those make the engine read the expression as raw bytes, or fail to build the whole WAF for every tenant on the edge.

After the line is made it is checked (`checkRuleLine`): one line, exactly four quotation marks, none
preceded by a backslash, no control, separator or backtick character, shorter than 32 KiB (the
parser reads lines with a 64 KiB limit and **stops without an error** at the first longer line,
which would silently drop every directive after it), starting `SecRule `, carrying the id it was
made for.

The text of the pattern is checked again on its own (`checkEmittable`). And `Validate` finishes by
writing the whole policy out, so **a policy that passes `Validate` always compiles**. The ids in the
reserved range 1000000 to 1099999:

| ids | what |
|---|---|
| 1010000 + 100 * exclusion + group | exclusions |
| 1020000 + n | allow-list address rules (100 ranges to a rule) |
| 1030000 + n | block-list address rules |
| 1040000 + n | allowed pages |
| 1050000 + id | custom rules |

What was run against the real engine (`seclang_test.go`): 8 operator and case combinations against
112 hostile values (newlines, quotes, backslashes in every position, `%{...}`, SecLang directives,
`Include`, backticks, NUL, DEL, line and paragraph separators, NEL, zero-width and direction
characters, invalid UTF-8, 256 bytes of quotes) and 15 probe inputs each: every one is either
refused for a documented reason or becomes exactly one rule that the engine reads as exactly one
rule, and that matches what an independent oracle (`regexp.QuoteMeta` and the standard library) says
the operator means.

67 regular expressions, valid and not, against 39 probes, the same way. A deliberately naive escaper
(the value pasted into the line) is shown to fail the same checks. Fuzzing: see the last section.

### Address lists and pages

`allow_ips`, `block_ips` become `@ipMatch` rules on `REMOTE_ADDR` (which the proxy sets from the
verified client address), 100 ranges to a rule so a line stays short; `allow_paths` become
`@beginsWith` rules on `REQUEST_FILENAME`. Order: allow list, block list, allowed pages, exclusions,
custom rules.

The allow list uses the `allow` action, which skips every later rule in every phase, so **an address
on both lists is allowed** (the console's order: allow, ban, block); the block list applies even on
an allowed page. In monitor mode the engine does not enforce `deny` and `allow`, so the block list
is only recorded.

`@ipMatch` silently skips an entry it cannot parse, which is why every entry is parsed and written
by `netip` here.

### What `Compile` returns

`policy.Compile(p)` validates, then returns `Compiled` with the fields of `proxy.Config` and
`crs.Settings` that a policy decides, under their own names: `AllowedHosts`, `Paths`, `DenyHeaders`
(with `next-action` added when the framework option asks), `WordPress`, `Uploads`, `Responses`,
`MaxFormBody`, `CRS` (mode, paranoia level, thresholds, `RequestBodyLimit`, `AllowedMethods`,
`InspectResponses`, and the generated SecLang in `Before` and `After`; `UploadDir` stays empty
because it is the operator's), plus the sections for components that are not in this package:
`VPatch`, `APIMode`, `API`, `BodyFormats`, and `Revision`, `Hash`, `Notes`.

`Compiled.ApplyTo(*proxy.Config)` sets those and leaves everything else (the upstream, the origin
guard, trusted proxies, the limits that belong to the machine, the operator's upload directory)
alone.

Mode: `block` is `SecRuleEngine On`, `monitor` is `DetectionOnly`, `off` is `Off`.

### Comparing policies

`Diff(old, new)` lists every difference in words with a stable code and the policy section;
`Weakens` returns the ones that lower protection; `Confirm` returns those and the ones that could
turn every visitor away (a block-list range wider than /16 for IPv4 or /32 for IPv6: `Change.Risk`,
`block_ip.wide`), which is what the UI asks the customer's password for.

Both policies are normalised first, so a change of order or case is not a difference; a note's text
never appears in a message.

An address list change counts by what is *covered*: adding an allow-list address a broader entry
already holds is not a weakening, narrowing an exclusion is not, and neither is a change that only
strengthens. An exclusion's `(path prefix, group, target)` triples are compared the same way (`args`
covers `arg:x`; a shorter path covers a longer one; the whole request covers any target).

| Code | Weakens | Meaning |
|---|---|---|
| `mode.lowered` / `mode.raised` | yes / no | block > monitor > off |
| `paranoia.lowered`, `threshold.raised` / `paranoia.raised`, `threshold.lowered` | yes / no | the *effective* level and score, preset and override together; any one dimension getting weaker is reported even if the other got stronger |
| `sensitivity.changed` | no | a different setting with the same effect |
| `rule_group.off`, `rule_group.log` / `rule_group.on` | yes / no | by the new state, weakening when it is lower than the old (log > off) |
| `exclusion.added` / `exclusion.removed` | yes / no | only when something new is not already covered |
| `custom_rule.removed` | when it blocked | |
| `custom_rule.relaxed` / `custom_rule.raised` | yes / no | block to log / log to block |
| `custom_rule.changed` | when it blocks | what a rule matches cannot be compared, so changing a blocking one counts as lowering protection |
| `custom_rule.added` | no | |
| `allow_ip.added`, `allow_path.added` | yes | not covered by what was there |
| `block_ip.removed` | yes | not covered by what remains |
| `allow_ip.removed`, `allow_path.removed`, `block_ip.added`, `block_ip.wide` (risk) | no | |
| `body.upload_limit_raised`, `body.form_limit_raised` | yes | |
| `method.added`, `host.added`, `hosts.opened` (list emptied: any name) | yes | `hosts.restricted` (list given to a site that had none) does not |
| `uploads.script_names_allowed`, `uploads.script_content_allowed`, `paths.encoded_slash_allowed`, `paths.path_params_allowed`, `wordpress.disabled`, `wordpress.xmlrpc_allowed`, `wordpress.login_rate_raised`, `responses.banners_kept`, `responses.caching_kept`, `responses.inspection_disabled`, `framework.next_action_allowed`, `deny_header.removed` | yes | and each one's opposite does not |
| `vpatch.tier_removed`, `vpatch.software_removed` | yes | declared software is what switches the patches about it on, so removing one switches them off |
| `api.mode_lowered` | yes | off < learn < monitor < enforce |
| `api.config_changed` | when the API mode is monitor or enforce | the settings are another package's, so a change cannot be judged here |
| `body_formats.config_changed` | yes | likewise |
| `note.changed` | no | |

(The task asks for "a custom allow rule added": a custom rule here has no allow action, by design,
so there is nothing of that kind to report. If one is ever added it must be added to this table and
to `diff.go`.)

### Reading the PHP console's export

`policy.FromConsoleExport(data)` reads `{"site_firewall_policy":1,...,"policy":{...}}`
(`PolicyTransfer.php`) or a bare `policy.json` (`schema` 1) and returns a valid policy and a list of
what could not be carried over and why, one plain line each. The fixtures in `policy/testdata/` were
written by the console's own code (`Policy::blank()`, `Policy::ruleFromForm`,
`PolicyTransfer::export` under PHP 8.3), including PHP's quirk of writing an empty map as `[]`.

| PHP setting | Here |
|---|---|
| `mode` | carried. **Unset** (null) means config.php's value, which this program cannot see; the PHP built-in default `monitor` is used and the list says so, because a new site here starts in `block` |
| `sensitivity`, `threshold` | `standard` is `normal`; `relaxed` and `strict` are carried as the nearest preset and **named as approximate**; a threshold is scaled by the sensitivity exactly as `Engine::sensitiveThreshold` does and carried as the override |
| `rule_groups` | the ten with a counterpart are carried; `upload`, `wordpress`, `cve`, `ssti`, `xxe`, `probe`, `other` have none (uploads and WordPress have sections of their own, `cve` is the virtual patches) and are named when they are not `on` |
| `disabled`, `overrides` | **not carried** and listed with their ids: single rules cannot be switched off here, and the rule set scores a rule by its severity, so a score between cannot be set exactly; a rule group or an exclusion is the nearest |
| `exclusions` | carried; categories with no group, and targets this model does not have (`uploads`) are dropped and named; **an exclusion that would lose all its targets is dropped, never widened to the whole request**; a path the strict character set refuses is dropped |
| `allow_ips`, `block_ips`, `allow_paths` | carried when valid; an entry that is not an address, is wider than the lists here take, or does not fit the path character set is named |
| `rules` | a rule that needs several conditions (`also`), a minimum length, a transformation other than URL-decoding and lower-casing, an operator other than `contains`, `rx`, `pm`, a pattern PCRE accepts and RE2 does not (possessive quantifier, lookaround), or an action other than block or log is left out and named. A rule that looks at several parts of the request becomes one rule for each part. A rule that blocks with a score **below the point at which the PHP firewall stops a request** adds to other matches there and cannot here, so it is carried as `log` and named |
| `block_oversize` | a request too big to inspect is always refused here; named when the export has it off |
| `outbound.inspect` | carried; `outbound.max_kb`, `contact`, `timezone`, `stats`, `log`, `reputation`, `ips` (automatic bans and the IDS/IPS points) named as not carried |
| anything else | named as unknown, not an error |

An export carrying every one of these (`console_export_tuned.json`) gives 33 lines. A document that
is not an export, is over 2 MiB, repeats a field or nests more than 32 levels is an error.

### For the control worker

The package-level functions are the interface; a thin adapter satisfies whatever interface
`control/` defines. Everything is safe for concurrent use and bounded by the document's size.

```go
p, err := policy.Decode(body)             // strict; *policy.Error (errors.Is(err, policy.ErrInvalid)) lists Problem{Path, Message}
changes := policy.Confirm(old, p)         // the UI asks for the password if len(changes) > 0; Weakens() is the weakening ones alone
hash := p.Hash()                          // identity of a revision; ignores Revision
b, _ := policy.Encode(p)                  // canonical JSON: this is the payload to give the signer
c, _ := policy.Compile(p)                 // control may compile too (to refuse a policy early), but the edge compiles its own
p2, skipped, err := policy.FromConsoleExport(export)
policy.RegisterSection(policy.SectionAPI, apiValidator)    // in the api package's init: validates "api" without editing this package
```

---

## What was run

Earlier local development notes recorded the following Linux checks (WSL2, Ubuntu, Go 1.26.6, 12
cores). These historical timings and fuzz counts were not repeated by the Windows publication run;
its independently verified checks follow below.

```
go test ./config/... ./policy/... -count=1                 # config 0.5 s, policy about 45 s (the engine tests build real WAFs)
go test -race ./config/... -count=3                        # 11 s
go test ./config -run '^$' -fuzz '^FuzzDecode$' -fuzztime 25s -fuzzminimizetime 0   # and FuzzKeySetPayload, FuzzVerifyKeySetWrapper, FuzzParseRecord
go test ./policy -run '^$' -fuzz '^FuzzDecode$' -fuzztime 45s -fuzzminimizetime 0    # and FuzzCanonRx, FuzzGeneratedDirectives, FuzzPolicyValues, FuzzFromConsoleExport
```

(`-fuzzminimizetime 0` because Go's fuzzer reports 0 executions a second while it minimises a new
input, which looked like a hang and was not: with minimising off, `config.FuzzDecode` runs 2.77
million executions in 30 s.)

Local publication checks on 2026-10-06: the config and policy suites pass on Windows with Go 1.26.6,
including real local proxy requests for custom policy rules. Custom rules retain their rule IDs and
fixed privacy-safe Coraza summaries; expanded request-bearing messages require explicit detailed
logging. This publication check does not repeat the earlier claimed Linux fuzz execution counts.

## What was not done, and what is risky

These packages provide integration APIs. The standalone proxy optionally installs explicit API
contracts with `-api-spec`; API discovery/learning, virtual-patch packs and signed-policy/control
listeners require separate integration. Real production stores, customer UI wiring, key
provisioning/rotation, distributed rollout and Linux confinement remain deployment work.

External signature/corpus equivalence tests skip when their separately supplied data is absent; do
not treat those skips as full-library coverage. No deployment credentials or deployment signing keys
are shipped with these sources; tests generate keys or use published test vectors.
