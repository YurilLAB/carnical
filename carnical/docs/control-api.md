# Control API and signed feed

The `control` package provides authenticated management endpoints, a Go client and an audit log.
`control/feed` provides a separate signed monitoring feed. Both need an integration service; the
standalone WAF does not start them.

Control requests require a verified client certificate and an Ed25519 request signature. The server
then checks tenant/scope authorization, replay state and write conditions. Weakening changes require
a signed recent step-up assertion from the UI. That assertion is not independent proof of a password
check if the UI host itself is compromised.

Start with [authentication layers](#2-the-layers), [credentials](#3-credentials), [request
signing](#4-signing-a-request), [endpoints](#6-endpoints) and [required
interfaces](#what-the-owner-has-to-connect). Source: [control package](../control/), [integration
interfaces](../control/ports.go), [feed handler](../control/feed/handler.go).

## 1. What this protects against

The UI (a separate application, "the UI") authenticates the human: password, TOTP, sessions. None of
that is this API's concern. After that the UI calls the control API for the customer. The API
assumes the UI host can be taken over, the network between them is hostile, and any request can be
copied, changed or sent again.

| Attacker | What they hold | What stops them |
|---|---|---|
| Someone on the network | Nothing, or a copy of requests in transit | TLS 1.3 only, so there is nothing to read; a request is signed over its method, target, body, time and nonce, so a changed one fails and a copied one is a repeat |
| A TLS-terminating proxy, or whoever stole only the UI's TLS key | A client certificate that the CA signed | The certificate alone is refused: every request also needs a signature from the credential's Ed25519 key, which the proxy does not have |
| Whoever stole only the UI's signing key | A way to sign | The signature alone is refused: the request must also come over a connection whose client certificate key is one the credential lists |
| A compromised UI host holding both | Everything the credential may do | The credential's own limits: its tenants, its scopes, its source addresses, its expiry. A weakening change still needs a step-up the UI cannot invent without the customer's password (see below, and the limit of that claim). It can be revoked at once. Every action is in the audit log |
| One customer's own session | A UI session for tenant A | The tenant in the path must be one the credential may act for; a credential for A can never read or write B, tested on every route |
| Someone replaying a captured request | A valid signed request | Nonces are remembered until the request would be refused for its age anyway; a full cache refuses new requests, it does not forget |
| Someone guessing credentials or hammering the API | Network access and a client certificate | Failures are slowed per source address; every refusal looks the same and takes the same time; the table that remembers failures has a size limit |
| Someone with write access to the log file | The file | A changed, deleted, inserted or moved line breaks the hash chain at that point. (Not: someone who can rewrite the whole file, see section 9) |

**Trust boundaries:**

* **A UI that lies about the step-up.** The step-up is the UI asserting "the customer typed their password at this time". The
  API checks that the assertion is recent and signed by the credential. It cannot check that the password was typed. A UI host
  that is fully controlled, with its signing key, can claim a step-up for every request. What the step-up does stop is a bug or
  a stolen *session* in the UI turning into a weakened firewall without a fresh password; and it records, in the audit log
  under the credential and acting user, every weakening that was claimed to have one.
* **The decision of what weakens a policy.** That is the validator's (`PolicyValidator`): this package asks it and obeys.
  A validator that misses a weakening change gives that change no step-up.
* **A compromised control host.** It holds the policy store and the audit log.
* **Denial of service from a client holding a valid certificate.** The API has global and per-credential in-flight limits
  and bounded memory, so it degrades by refusing; it cannot tell a flood from busy use.

## 2. The layers

Checks run in this order. Framing and source backoff precede body reading; authentication and
tenant/scope authorization precede store access.

1. **Transport** (`control.TLSConfig`). TLS 1.3 only; a client certificate is required and verified against the CA bundle;
   the server certificate and the CA bundle are reloaded from disk when their files change (modification time and size,
   looked at at most every two seconds, swapped as a whole, a bad file leaves the old one in force and is reported by
   `LastError`); session tickets are off, so no connection is resumed without presenting its certificate again and a restart
   leaves nothing valid; curve preferences are X25519MLKEM768 (the post-quantum hybrid), X25519, P-256.
2. **Credential** (`control.Credential`). One per UI deployment: an id, the SHA-256 fingerprints of the public keys of the
   client certificates it may use (the key, not the certificate, so a certificate can be renewed on the same key), an Ed25519
   public key it signs with, the tenants (a list, or "all" for the owner's own tooling), the scopes, optional source
   addresses, a not-after date, and a revoked flag. Authentication needs **both** the certificate and the signature.
3. **Authorisation.** Scope per route; tenant per route; a step-up for weakening changes; `If-Match` for writes;
   `Idempotency-Key` for publish.
4. **The endpoints** (section 6), each validating everything before it touches a store.
5. **The HTTP layer.** Only GET, PUT and POST; a request target of lower-case letters, digits and `/ : . -` (no percent
   encoding exists, so there is no second way to write a path); strict content type; a body limit; header limits; no CORS
   header ever; `Cache-Control: no-store`, `X-Content-Type-Options: nosniff`, `Content-Security-Policy: default-src 'none'`;
   uniform error bodies; a request id on every response and in every audit line; a recovered panic is a uniform 500.
6. **The audit log** (section 9).

### What is checked before the credential is looked at

In this order, each refusing with a fixed 4xx and a fixed message that never repeats input:

1. a global in-flight slot (503 if none);
2. the request target's characters and length, the headers (count, size, no proxy or override headers, no repeated header that
   carries meaning, no underscore in a name, no HTTP/1.0, no trailers), the route, the method, the query;
3. whether the connecting source address is waiting out earlier failures (429, before one byte of its body is read);
4. the content type and the body size (415, 413).

### Authentication: one path, whatever the outcome

`Server.authenticate` makes every check in the same order whatever the earlier ones found: header
form, credential lookup, client certificate, signature, time, revoked, expired, source address,
repeated nonce. The signature is verified once in every case (an unknown credential, a malformed
header and a bad signature all spend one Ed25519 verification, against a dummy key where there is no
real one), and only the audit log is told which check failed.

The caller gets `401 unauthenticated` with the same body and headers each time. Measured in
`TestFailurePathsTakeTheSameTime`: 13 kinds of failure, 2,000 attempts each, sent in turn so machine
noise falls on all alike, medians between 91.4 and 95.5 microseconds (a spread of 4 microseconds),
while a request refused before authentication takes 4.0 microseconds, so the comparison can see a
difference.

Failures are rate limited, and the two limits are deliberately different:

* **Per source address** (an IPv6 address counts as its /64): after 3 failures the source waits 1 second, then doubling to a
  maximum of 15 minutes. While it waits, even a perfectly good request from it is refused unread (`429 too_many_failures`).
* **Per credential id, as the request claimed it** (known or not, so this is not an oracle): from the same threshold a failing
  request for that id gets `429` instead of `401`, and the failure is not audited one by one. But **a request that
  authenticates is never refused because of this counter.** If it were, anyone holding a stolen client certificate could lock
  the real UI out of its own credential by failing on its behalf.

A refusal because the replay cache is full (`503 replay_cache_full`) is not the caller's failure and
counts against nobody.

## 3. Credentials

A credentials file is plain data; nothing in it is secret (the key is the public half).

```json
{
  "credentials": [
    {
      "id": "ui-prod",
      "label": "Customer UI, production",
      "cert_spki": ["<64 lower-case hex digits: SHA-256 of the client certificate's SubjectPublicKeyInfo>"],
      "signing_key": "<43 characters of base64url: the Ed25519 public key>",
      "tenants": ["<32 lower-case hex digits>"],
      "scopes": ["read", "write", "publish"],
      "sources": ["203.0.113.5", "198.51.100.0/24"],
      "not_after": "2027-01-01T00:00:00Z",
      "revoked": false
    }
  ]
}
```

`"tenants": "all"` is for the owner's own tooling and works only on a server started with
`AllowAllTenants`. The file is parsed strictly (no unknown field, no repeated key, no duplicate id)
and refused whole if any credential is wrong, so a typo cannot remove a restriction.
`control.OpenCredentialFile` re-reads it when it changes (at most once a second), keeps the last
good set if a new one does not parse, and writes a revocation back atomically with mode 0600.

The client certificate's fingerprint is `sha256(cert.RawSubjectPublicKeyInfo)`:

```
openssl x509 -in client.pem -noout -pubkey | openssl pkey -pubin -outform der | openssl dgst -sha256
```

| Scope | Allows |
|---|---|
| `read` | the GET endpoints and `policy:validate` for the credential's tenants |
| `write` | PUT policy, `policy:rollback`, register and verify hostnames |
| `publish` | publish |
| `admin` | list and revoke credentials; also needs a credential for all tenants and a server that allows them |
| `raw-addresses` | events with visitor addresses whole instead of cut to /24 and /48 |

Scopes do not imply each other. A credential that may publish but not read cannot read.

## 4. Signing a request

Every request except `/healthz` carries:

| Header | Value |
|---|---|
| `Authorization` | `Carnical-Sig cred=<id>, ts=<unix seconds>, nonce=<32 lower-case hex>, sig=<86 characters of base64url>` |
| `Carnical-Acting-User` | the id of the person the UI is acting for: 1 to 128 of `A-Z a-z 0-9 . _ @ : + -`, starting with a letter or digit |
| `Carnical-Stepup-At` | optional: Unix seconds at which the customer last re-entered their password |
| `If-Match` | for PUT policy and rollback: the revision the caller last read, as `"7"` |
| `Idempotency-Key` | for publish: 8 to 64 of `A-Z a-z 0-9 - _` |
| `Content-Type` | `application/json; charset=utf-8` when there is a body |

The Authorization header has exactly one spelling: those four fields, in that order, separated by a
comma and one space, the time without a leading zero, nothing else. `sig` is the 64-byte Ed25519
signature, base64url without padding.

### The signed text

Thirteen lines, joined with a single line feed (no line feed at the end), UTF-8:

```
 1  carnical-control-v1                         the prefix: this protocol and no other
 2  <METHOD>                                    GET, PUT or POST
 3  <host>                                      the Host header, lower-cased: where this request is for
 4  <request target>                            exactly as sent: path and query, no scheme, no host
 5  <hex SHA-256 of the body>                   of the bytes sent; of the empty string when there is no body
 6  <timestamp>                                 the ts in the Authorization header
 7  <nonce>                                     the nonce in the Authorization header
 8  <credential id>                             the cred in the Authorization header
 9  <tenant id, or ->                           the 32 hex digits after /v1/tenants/ in the target; - for other routes
10  <acting user>                               the Carnical-Acting-User header
11  <step-up time, or ->                        the Carnical-Stepup-At header; - when absent
12  <If-Match, or ->                            the header exactly as sent; - when absent
13  <Idempotency-Key, or ->                     the header exactly as sent; - when absent
```

Why these. Lines 2 to 5 pin what the request does and says; 6 and 7 make it one request in time; 8
and 9 say whose it is and for which tenant, so a request cannot be turned on another tenant (not
even one the credential may also use, which fails the signature, not the tenant check); 10 and 11
make the acting user and the step-up part of what was signed, so a proxy cannot add or strengthen
them; 12 and 13 stop a relay changing a write into one that overwrites a newer revision, or one
publish into another; line 3 stops a request captured at one server being sent to another that
trusts the same key.

The step-up is therefore not a header anyone can add: it is part of the signed request.

A value on lines 3 to 13 that has a line break, a control character, anything outside printable
ASCII (`0x21` to `0x7e`), is empty where it is required, or is a single `-` where `-` means absent,
makes the text impossible to build (`CanonicalString` returns an error), so no two different
requests can have the same text. This is what the fuzz target `FuzzCanonicalString` checks.

### How to sign (Python, with `cryptography`)

```python
import base64, hashlib, secrets, time
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

def sign(key: Ed25519PrivateKey, cred, method, host, target, body, user, tenant="", step_up=None, if_match="", idem=""):
    ts, nonce = int(time.time()), secrets.token_hex(16)
    text = "\n".join(["carnical-control-v1", method, host.lower(), target, hashlib.sha256(body).hexdigest(), str(ts), nonce,
                      cred, tenant or "-", user, str(step_up) if step_up else "-", if_match or "-", idem or "-"])
    sig = base64.urlsafe_b64encode(key.sign(text.encode())).rstrip(b"=").decode()
    return f"Carnical-Sig cred={cred}, ts={ts}, nonce={nonce}, sig={sig}"
```

The tenant is the 32 hex digits after `/v1/tenants/` in the target, or `-`. Send exactly the target
you signed: no re-encoding, no reordering of the query, no trailing slash.

### Test vector

Checked by two independent implementations: this package's Go code and Python's `cryptography`
library (`control/testdata/vector_check.py`) give the same signature. The key is the Ed25519 key
whose 32-byte seed is the bytes 0 to 31, so anyone can regenerate it.

```
seed (hex)        000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
public key        A6EHv_POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg            (base64url)

PUT https://control.example:8443/v1/tenants/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/policy
body              {"mode":"block","threshold":5}                        (30 bytes, no line break)
SHA-256 of body   4f4e113d1f639b7a12caa49ebb4fa90a9f69871d7e867d712d2118ba22a032f9
ts                1791201600
nonce             000102030405060708090a0b0c0d0e0f
credential        ui-prod
acting user       user-42
step-up           1791201500
If-Match          "7"
Idempotency-Key   (none)

signed text       carnical-control-v1
                  PUT
                  control.example:8443
                  /v1/tenants/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/policy
                  4f4e113d1f639b7a12caa49ebb4fa90a9f69871d7e867d712d2118ba22a032f9
                  1791201600
                  000102030405060708090a0b0c0d0e0f
                  ui-prod
                  aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
                  user-42
                  1791201500
                  "7"
                  -

signature (hex)   778c8187b7877c9155810da2c7b54912827bfc3414c5f72f1d361adc2dd3208795573da8c8c65cc0cb28bf77c2184fbb1faa883be87d1c669c23d6d9b63d4a07
signature (b64u)  d4yBh7eHfJFVgQ2ix7VJEoJ7_DQUxfcvHTYa3C3TIIeVVz2oyMZcwMsov3fCGE-7H6qIO-h9HGacI9bZtj1KBw
Authorization     Carnical-Sig cred=ui-prod, ts=1791201600, nonce=000102030405060708090a0b0c0d0e0f, sig=d4yBh7eHfJFVgQ2ix7VJEoJ7_DQUxfcvHTYa3C3TIIeVVz2oyMZcwMsov3fCGE-7H6qIO-h9HGacI9bZtj1KBw
```

The tests `TestCanonicalVector` and `TestDocumentationHasTheVector` fail if the code and this page
stop agreeing.

### Time and replay

A request is accepted if its `ts` is within 60 seconds of the server's clock (60 inclusive, 61
refused). Its nonce is then remembered, per credential, until the request could no longer be
accepted for its age (`ts + 61` seconds), and a second request with that nonce is refused whatever
else it says.

The cache holds at most 200,000 nonces, 50,000 for any one credential. When it is full it refuses
new requests with `503 replay_cache_full` and a `Retry-After`, because forgetting a nonce to make
room would allow a replay. A nonce is remembered only after the signature has been verified, so
nobody without a key can fill it.

Keep the UI host's clock right (NTP); a drift past a minute is refused as `401`.

## 5. Weakening changes and step-up

A policy write, or a rollback, for which `PolicyValidator.Validate` returns a non-empty `Weakening`
list is refused with `403 step_up_required` unless the request carries `Carnical-Stepup-At` (so it
is signed) within the last 5 minutes, at most 60 seconds in the future. The refusal names every
weakening change in the words the validator gave, so the UI can ask the customer:

```json
{"error": {"code": "step_up_required", "message": "this change reduces protection; ask the customer to confirm with their password, then send the time they did in Carnical-Stepup-At",
 "request_id": "req_...", "weakening": [{"code": "mode_lowered", "summary": "Attacks will be noted but let through instead of blocked."}]}}
```

The UI then asks for the password, and repeats the same write with the time of that check. A step-up
is not used up by a write: two writes inside five minutes can share one. A first policy is compared
with the defaults the validator knows, so a first policy that starts weaker than the default needs
one too.

A document the validator finds invalid is `422` whether or not there is a step-up. Publishing needs
none, because only the current revision can be published and a revision enters history only through
a write that passed this check.

## 6. Endpoints

Paths are under `/v1`. `{tenant}` is exactly 32 lower-case hex digits. Bodies are JSON in UTF-8 with
`Content-Type: application/json; charset=utf-8`, at most 256 KiB, one object, no repeated key,
nested at most 64 deep for a policy document and 16 for the API's own objects, no byte-order mark,
valid UTF-8.

The API's own request objects refuse fields they do not name, and a field must be spelled exactly
(Go's JSON reader would accept `REVISION`; this one does not). Policy documents are opaque apart
from that.

| Method and path | Scope | Needs | What it does |
|---|---|---|---|
| `GET /healthz` | none | a TLS client certificate only | `{"status":"ok"}` and nothing else. `control.HealthHandler()` is the same for a load balancer on a plain private listener |
| `GET /v1/tenants/{tenant}/policy` | read | | `{"revision", "updated", "document"}` and `ETag: "<revision>"`; 404 `no_policy` if there is none |
| `PUT /v1/tenants/{tenant}/policy` | write | `If-Match`; step-up if it weakens | the body is the document; validates, stores the next revision; `If-Match: "0"` creates the first; 412 if the revision moved (with the current one in `ETag`); 422 with `problems` if invalid; 403 `step_up_required` |
| `POST /v1/tenants/{tenant}/policy:validate` | read | | dry run: `{"valid", "problems", "weakening", "diff", "step_up_required"}`; writes nothing |
| `GET /v1/tenants/{tenant}/policy/history` | read | | `?limit=1..500&cursor=` newest first: revision, time, actor, credential, kind (`put` or `rollback`), the revision restored, and the weakening codes |
| `POST /v1/tenants/{tenant}/policy:rollback` | write | `If-Match`; step-up if it weakens | body `{"revision": N}`: stores revision N's content as a new revision; N must be an earlier revision; validated against the current rules |
| `POST /v1/tenants/{tenant}/publish` | publish | `Idempotency-Key` | body `{"revision": N}`, N must be the current revision (409 `revision_not_current`); calls the publisher; returns `{"sequence", "revision"}`. The same key with the same body returns the first answer and `Idempotent-Replay: true`; the same key with another body is 422; an unfinished one is 409 `in_progress`. Keys belong to one credential and tenant; unfinished claims are retained until completion or failure, and successful answers last 24 hours from completion (configurable) |
| `GET /v1/tenants/{tenant}/hosts` | read | | each hostname with its state (`pending` or `verified`), whether it is routable, and for a pending one the DNS challenge |
| `POST /v1/tenants/{tenant}/hosts` | write | | body `{"hostname": "..."}`; lower-cased; a public name only (no address, no wildcard, no port, no internal suffix). 201 with a challenge: a TXT record named `_carnical-challenge.<hostname>` with the value `carnical-verify=<32 hex>`. The same name again returns the same challenge |
| `POST /v1/tenants/{tenant}/hosts/{hostname}:verify` | write | | asks the `HostVerifier`; verified only if it says yes; at most one check per hostname per 10 seconds (429 `too_soon`). A pending claim does not stop another tenant claiming the same name; the first to prove it holds it, and the other's later check is refused |
| `GET /v1/tenants/{tenant}/status` | read | | health, last publish, each edge's acknowledged sequence |
| `GET /v1/tenants/{tenant}/events` | read | | `?limit&cursor`: events newest first, in the feed's vocabulary; addresses cut to /24 and /48 (also inside the free-text fields) unless the credential has `raw-addresses` |
| `GET /v1/tenants/{tenant}/traffic` | read | | `?limit&cursor`: one row per day |
| `GET /v1/credentials` | admin | all-tenants credential | every credential: id, label, tenants, scopes, sources, certificate fingerprints, expiry, revoked, and a short fingerprint of the signing key. Never a key |
| `POST /v1/credentials/{id}:revoke` | admin | all-tenants credential | revokes at once; the next request with it is refused. Revoking one that is revoked is not an error |

Pagination: `limit` is a whole number from 1 to 500 (default 100), no leading zero; `cursor` is 1 to
512 characters of `A-Z a-z 0-9 - _`, taken from `next_cursor` of the previous page, which is present
exactly when `has_more` is true.

The history cursor encodes a revision; the others are whatever the `EventSource` returned. A source
that returns more than was asked for, or says there is more with no valid cursor, is an internal
error, not a short or wrong page.

Errors are always `{"error": {"code", "message", "request_id"}}` (plus `problems` for
`invalid_policy` and `weakening` for `step_up_required`); the message is fixed text and never
contains anything from the request. The same request id is in the `X-Request-Id` header and in every
audit line for the request.

| Status | Code | When |
|---|---|---|
| 400 | `bad_request`, `invalid_json` | a malformed target, header, query or body |
| 401 | `unauthenticated` | any authentication failure, for any reason |
| 403 | `forbidden` | the scope or the tenant is not the credential's (the same answer for both) |
| 403 | `step_up_required` | a weakening change without a fresh step-up |
| 404 | `not_found`, `no_policy`, `host_not_found`, `revision_not_found`, `credential_not_found` | |
| 405 | `method_not_allowed` | with an `Allow` header |
| 409 | `revision_not_current`, `in_progress`, `hostname_unavailable` | |
| 412 | `precondition_failed` | `If-Match` is not the current revision; `ETag` says what is |
| 413, 415 | `payload_too_large`, `unsupported_media_type` | |
| 422 | `invalid_policy`, `invalid_revision`, `invalid_hostname`, `idempotency_key_reused` | |
| 428 | `precondition_required` | no `If-Match`, or no `Idempotency-Key` |
| 429 | `too_many_failures`, `too_many_requests`, `too_soon` | with `Retry-After` |
| 431 | `headers_too_large` | |
| 500 | `internal` | a store failed or the handler panicked; no text from the cause |
| 501 | `not_implemented` | the server was started without that store |
| 502, 503 | `verification_unavailable`; `overloaded`, `unavailable`, `replay_cache_full`, `audit_unavailable`, `idempotency_full` | with `Retry-After` |

## 7. The numbers

All in `control.Limits` (zero means the default).

| | Default |
|---|---|
| Body | 256 KiB |
| Header lines, total header size, one header value | 40, 16 KiB, 4096 bytes |
| Requests in flight, per credential | 128, 16 |
| Clock skew; step-up age | 60 s; 5 min |
| Replay cache, per credential | 200,000; 50,000 |
| Failures before a source or credential id waits; first wait, maximum; quiet time that starts it over; keys remembered | 3; 1 s, 15 min; 15 min; 50,000 |
| Idempotency keys: lifetime, total, per credential | 24 h, 50,000, 10,000 |
| Page size, default and maximum | 100, 500 |
| One store call | 10 s |
| `http.Server`: read header, read, write, idle | 5 s, 15 s, 30 s, 60 s; HTTP/2 at most 32 streams |

## 8. The Go client

`control.NewClient` makes calls with: TLS 1.3 only and mutual TLS (the certificate can come from
files and is read again when they change, so a renewed certificate needs no restart); optional
pinning of the server certificate's key (any of several SPKI fingerprints, **in addition to** the
normal chain and name checks, never instead); no proxy from the environment; no redirect ever
followed (a signed request is for one address; a 3xx is `ErrRedirect`); a size limit on the answer
(`ErrResponseTooLarge`, whether the length was declared or not); a timeout that covers connecting,
sending and reading the whole answer; a refusal to send a target the server would not accept or one
that Go would send differently from how it was signed.

`Client.Do` signs and sends; `GetPolicy`, `PutPolicy` and `Publish` are conveniences. An error
answer is an `*control.APIError` with the code, the request id, and the `problems` or `weakening`
lists.

## 9. The audit log

`control.FileAudit` appends one JSON object per line:

```
{"seq":12,"ts":"2026-10-05T12:00:00Z","prev":"<64 hex: SHA-256 of line 11 as written>","request_id":"req_...","credential":"ui-prod",
 "tenant":"<32 hex>","user":"user-42","action":"policy.put","rev_before":6,"rev_after":7,"changes":["mode_lowered"],
 "source":"203.0.113.5","outcome":"ok","detail":"step_up"}
```

* **What is logged.** Every authenticated request. A read has one line; a change has two (`started`, written *before* anything
  changes, and the outcome after). Every authentication failure has one line with the reason (`bad_signature`,
  `unknown_credential`, `certificate_mismatch`, `skew`, `replay`, ...: for the operator, never sent to the caller). A source
  that is waiting has one line for each wait, not one per blocked request. Outcomes: `ok`, `started`, `denied`, `invalid`,
  `conflict`, `error`, `auth_failed`, `refused`.
* **What is never logged**: request bodies, policy content, targets, query strings, header values, or any secret. Text fields
  are cut to bounded printable ASCII before they are written. The credential id of a failed request is the one it claimed,
  kept only if it has the form of an id.
* **Fail closed.** If the first line of a change cannot be written the change is not made (`503 audit_unavailable`). A read
  whose line cannot be written is not served. If a change's closing line cannot be written the change stands, the failure is
  counted (`Stats().AuditFailures`) and reported, and the next change is refused.
* **Durability.** Opened for appending only, mode 0600 (a log other users can read is refused at open), every line flushed to
  disk before a successful `Append` returns. A failed write attempts rollback; a rollback failure closes the log and
  rejects subsequent appends. Windows repair uses a separate read/write handle and checks that it identifies the same
  file before truncating; Windows operators must enforce access with filesystem ACLs. Only one process may write a log.
* **Verifying.** `control.VerifyChain(io.Reader)` reports the first line that does not belong. An edited line is reported at
  the line after it (the first whose `prev` no longer matches); a deleted, inserted, duplicated or swapped line at the first
  line out of place; a line that is not written in exactly the form `Append` writes (white space, an escaped character, a
  reordered field, an unknown field) at that line. `OpenFileAudit` runs it over the whole file and refuses a broken one; an
  unfinished last line (a crash during a write, never acknowledged) is cut off and reported by `Repaired()`.
* **What a chain cannot do.** It cannot show that the last lines were cut off, or that the last line was edited, and it
  cannot stop someone who can rewrite the whole file and recompute it. For that, copy `FileAudit.Head()` (the sequence number
  and hash of the last line) somewhere the log's own user cannot write, regularly, and check with `VerifyChainHead`. The tests
  show each of these cases: the chain alone misses them and the recorded head finds them.

## 10. Key rotation

| What | How, without a gap |
|---|---|
| **A UI signing key** | Make the new key pair. Add a second credential with the new public key and the same certificates, tenants and scopes (`ui-prod-2`). Switch the UI to it. Revoke the old one (`POST /v1/credentials/ui-prod:revoke`) once nothing uses it. (One credential has one signing key on purpose: two keys in one credential would make a stolen old key as good as the new.) |
| **A UI client certificate, same key** | Issue a new certificate for the same key. Nothing changes in the credential, because it lists the key's fingerprint. The client reloads it from disk. |
| **A UI client certificate, new key** | Add the new key's fingerprint to the credential's `cert_spki` next to the old (the file is re-read within a second), switch the UI, then remove the old one. A credential may list up to 16. |
| **The server certificate** | Replace the files; the next connection uses it with no restart. Clients that pin should pin two keys (the current and the next) so a planned change does not need a coordinated deploy. |
| **The client CA** | Put the new CA's certificate in the bundle next to the old, issue client certificates from it, then remove the old CA from the bundle. Removal takes effect at the next connection. |
| **A credential's lifetime** | Every credential has a `not_after`. A credential past it is refused. Set it to the time the key is due to be replaced. |
| **Revoking in an emergency** | `POST /v1/credentials/{id}:revoke`, or `"revoked": true` in the file, or remove the file's entry: effective on the very next request. |

## 11. The feed

The owner console already reads a signed pull feed (version 1) from each protected site; the hosted
Carnical serves the same one, one path and one key per site, so the console, the fleet reader and
the monthly reports work unchanged (`docs/backend-compat.md` section 1).

```
GET <path>/feed?since=<cursor>&days=<n>
Authorization: SFW1 key=<16 hex>, ts=<unix>, nonce=<32 hex>, sig=<64 hex>
sig = lower-case hex HMAC-SHA256(32-byte secret, "SFW1\nGET\n" + the request target exactly as sent + "\n" + ts + "\n" + nonce)
```

`feed.New(feed.Config{...})` makes a `Handler` for **one site**: the site id is set when it is made
and is the `id` in every answer, and nothing in a request chooses a site. Mount it at
`Handler.Path()` (default `/feed`; it must end in `/feed`). Keys come from a `feed.KeyStore`; a key
belongs to one site, and one for another site is "unknown key". Data comes from a `feed.EventSource`
(below).

* **Verification** is the PHP console's: 405 for a method other than GET; 401 for a missing or malformed header, an unknown or
  revoked key, a time more than 300 seconds off, a wrong signature (constant time), or a nonce seen in the last 600 seconds;
  403 for a scope not allowed; 429 with `Retry-After` past 60 requests an hour for one key; 404 when the feed is off, the path
  is another, or the request did not arrive over TLS. Only correctly signed requests are remembered or counted, so nobody
  without a secret can use up a key's hour or fill the memory.
* **The frame**: `feed:1`, `generated`, `site`, `scopes`, `addresses: "cut"|"whole"`, `cursor` and `more` **always** (the
  reader requires both even without the events scope; the PHP console omits them and so reads as "not a feed"), then one
  section per scope.
* **Everything is checked against the reader's own limits before it is sent**, because the reader refuses a whole answer for a
  wrong frame and drops a whole event for one wrong field: event kinds and severities, times as `YYYY-MM-DDTHH:MM:SSZ`, text cut
  to the reader's lengths by character, an empty address left out rather than sent as `""`, empty maps as `{}`, at most 2000
  events newest first. An event or day the reader would refuse is left out and counted in `health.notes`. The answer never
  passes 6 MiB (the reader gives up at 8): events are cut at that size and `more` is set, with the cursor of the last event
  sent, so none is lost. This budget covers every scope and includes JSON escaping of cursors and text. Traffic sources
  must return at most the requested number of days. If the other sections alone exceed the budget, the handler returns
  a generic 500 before writing any data; request fewer days or fewer scopes instead of silently losing traffic figures.
* **Privacy.** With `addresses: "cut"` an IPv4 address becomes a.b.c.0 and an IPv6 address its /48 (an IPv4 address inside IPv6
  is the IPv4 address), in events, bans, offenders and marks. Free-text fields that carry our own explanations (`why`, `what`,
  `detail`, `msg`) are scanned for addresses and those are cut too. That scan is best effort; the address fields are exact.
* **Proof of compatibility** (`feed/compat_test.go`, skipped when Python or the reader is missing) uses the real reader:
  `feed.authorization` and `feed.request_path` sign requests the handler accepts; `feed.parse` accepts every byte the handler
  sends, with nothing left out (the same tests show it does refuse a missing cursor, an empty address and an empty map as a
  list, so "nothing left out" means something); `fleet.pull_site`, the console's own pull, run against the handler
  over HTTP, follows `more` across pages, stores every event once, pins the site id and reads the answer again as "nothing new";
  `feed.refusal` turns each of our 401, 403, 404 and 429 into the right state. The shared test vector (secret bytes 1 to 32,
  target `/feed?since=abc&days=7`, ts 1791014400, nonce `0123456789abcdef0123456789abcdef`, signature
  `987bb305649ec1e529c083e5e197dc2dce0a01d8ed8e4a10f0650381391feac0`) is reproduced by `TestTheSharedVector` and by the reader's
  own code.

## What the owner has to connect

Everything is an interface in `control/ports.go` (the feed's is in `feed/handler.go`). A nil store
makes the routes that need it answer `501 not_implemented`; the server still authenticates first.

| Interface | What it must do |
|---|---|
| `CredentialStore` | `OpenCredentialFile` is one; or implement `Lookup`, `List`, `Revoke` over a database. Lookup is called on every request, so a revocation must be visible at once; return copies |
| `Auditor` | `OpenFileAudit` is the implementation to use. Required |
| `PolicyStore` | One revisioned, opaque JSON document per tenant. `Put(tenant, body, expect, meta)` must be atomic with the revision check and return `ErrConflict` if the current revision is not `expect` (0 means none yet); revisions rise by one and are never reused. It must only ever touch the named tenant's data. `History` is newest first for revisions below `before` |
| `PolicyValidator` | The one place that knows what a document means, so the one place that knows what weakens it. Return `Problems` for a document that cannot be accepted, `Weakening` for the changes (against the current document; `nil` current means none yet) that reduce protection, each with a `Summary` in plain words for the customer, and `Diff`. Pure: no side effects. Do not repeat the customer's content verbatim in a message |
| `Publisher` | Turn the current revision into a signed configuration for the edges (`segmentation.md` T5) and return its sequence number. Concurrent attempts for the same idempotency key are rejected, and a successful answer is replayed within its retention period. Failed calls release the key for retry. Claims are local to one server process; coordinate durable idempotency in the publisher when multiple control servers share it |
| `StatusSource` | health, last publish, each edge's acknowledged sequence |
| `EventSource` (control) | `Events` and `Traffic` for a tenant, newest first, a page at a time, with opaque cursors of 1 to 512 characters of `A-Z a-z 0-9 - _`. It must return at most `Limit` items |
| `HostRegistry` | `Add` records a pending claim with the token the server made and returns the existing record for the same tenant and name; `ErrHostTaken` only when another tenant has **verified** it; `MarkVerified`; `MarkChecked`. **The edge must route a hostname only when its record says verified, and only to the tenant that holds it.** A nil registry disables the three host routes |
| `HostVerifier` | `Verify(hostname, name, value)`: look up the TXT record `name` and say whether it contains `value`. Use a resolver the owner trusts (ideally validating), and bound its own time. Re-check verified hosts on a schedule; that is the owner's job (`segmentation.md` T9) |
| `feed.EventSource` | One call per section, always for the one site the handler was made for. `Events` returns events oldest first with, for each, the cursor that stands after it, so the handler can send fewer than it was given. Anything it returns that the reader would refuse is left out and counted |
| `feed.KeyStore` | `feed.MemoryKeys` is one; `feed.GenerateKey` makes a key and the 43-character text the owner pastes into the console |

Wiring, in outline:

```go
audit, _ := control.OpenFileAudit("/var/lib/carnical/control/audit.log", nil)   // keep audit.Head() somewhere else, too
creds, _ := control.OpenCredentialFile("/etc/carnical/control/credentials.json", nil)
srv, _ := control.NewServer(control.Config{Credentials: creds, Audit: audit, Policies: ..., Validator: ..., Publisher: ...,
    Status: ..., Events: ..., Hosts: ..., Verifier: ..., AllowAllTenants: false})
tlsr, _ := control.NewTLSReloader(control.TLSOptions{CertFile: "...", KeyFile: "...", ClientCAFile: "..."})
hs := srv.HTTPServer(tlsr.Config())
ln, _ := net.Listen("tcp", "10.0.0.5:8443")
log.Fatal(hs.ServeTLS(ln, "", ""))
```

Serve the owner's own tooling (the credentials routes, all-tenants credentials) on a **separate
listener** with `AllowAllTenants: true`, bound to the owner's tunnel, not on the one the UI uses.

## What was verified, and what was not

Run on Linux (WSL, Go 1.26.6), with `-race`:

* Table tests with positive and negative rows for every behaviour above (about 1,700 cases in `control`, 400 in `feed`);
  authentication tampering with every signed field (57 rows), the route table walked so that every route has its scope and
  tenant checks tested (a route with no test case fails the walk), 41 audit tampering rows, the TLS handshakes over real
  sockets, and an end-to-end run over a real TLS listener with the Go client on HTTP/1.1 and HTTP/2.
* Fuzz targets: the signature header parser, the signed-text builder, the JSON checks and envelopes, the target and routing,
  the whole handler, the credentials file, the audit verifier, and the feed's parsers, the address cut and the event encoder.
* Mutation checks (`.attack/control/mutate.py`): each security property broken in a copy of the source and the tests shown to
  fail. The result is in the report that came with this change.
* The signature test vector, against a second implementation. The feed against the real Python reader.

Publication checks on 2026-10-06 also run the control tests on Windows. Audit repair uses a checked
writable handle because Windows append-only handles cannot truncate; repair failure closes the audit
log. Normal append writes preserve append-only semantics. These checks cover local stores and TLS
test listeners, not a deployed control service. File modes do not represent Windows ACL enforcement.

**Not verified.** The real stores (nothing here has run against them). A browser or the real UI.
Load beyond the tests' concurrency. Constant-time behaviour below the level of a measurement:
`hmac.Equal`, `subtle.ConstantTimeCompare` and Go's Ed25519 are used for secrets, and the timing
test measures what a caller can see, not cache effects. The deployment under the sandbox and
firewall rules in `hardening.md`.
