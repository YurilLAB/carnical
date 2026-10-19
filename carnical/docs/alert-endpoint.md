# Alert endpoint

Carnical can tell your own HTTPS endpoint, while an attack goes on, what is being attacked and how:
the ports and protocols, how many requests and addresses, what kind of attack it is and what
Carnical is doing about it. Nothing is sent unless an endpoint is set (`-alert-endpoint`, or the
"Attack alerts" step of `carnical setup`).

Messages are few and small: one when an attack starts, at most one a minute while it goes on, and
one when it ends. They are about the attacks flood protection finds, so with `-ddos off` none are
sent (start-up warns of it). They are sent by one goroutine from a queue of 32, one at a time and at least half
a second apart, over one kept-alive connection, so alerting costs next to nothing when the machine
is short of resources, and a slow or dead endpoint costs one goroutine and a few kilobytes.

## Setting it up

`carnical setup` asks, in step 5, for the endpoint's URL (blank for none), for the private
addresses it may be at if it is not public, and for a signing secret file. Leave the secret blank
and setup makes a new one when it saves, in a protected file next to the encryption key, and says
where; give that secret to the receiving end. The URL, the allowance and the secret's path are kept
in the site file's encrypted settings.

On the command line:

| Flag | Default | Meaning |
| --- | --- | --- |
| `-alert-endpoint` | none | HTTPS URL that is sent the messages. Plain `http://` only to a loopback address, for a relay on the same machine. ASCII only (a name in its punycode form), with no user name, password, fragment or IPv6 zone. |
| `-alert-endpoint-secret-file` | none | Required with an endpoint. The first line is the secret, 32 to 1,024 printable characters (`openssl rand -hex 32` makes one). The file must not be readable by everyone or writable by its group. |
| `-alert-endpoint-allow` | none | Private addresses or ranges the endpoint may be at, as `-origin-allow` for the origin. |
| `-alert-endpoint-ca-file` | system | CA bundle for the endpoint's certificate. |

With `-confine`, the endpoint's port must be in `-confine-connect` (443 is there by default). The
shipped [nftables policy](../deploy/nftables/carnical.nft) lets the edge user open TCP 80 and 443
only: use port 443, or add the endpoint's port to `edge_out`.

## What a message holds

A JSON object, at most 16 KiB:

```json
{
  "version": 1,
  "id": "9f2c41d8a0b7e6f5c4d3b2a1908f7e6d",
  "event": "attack_start",
  "severity": "critical",
  "at": "2026-10-19T01:00:03Z",
  "site": "example.com",
  "text": "DDoS attack detected on example.com (request_flood, one_client_tool): 4370 requests/s at peak, usually 40, to tcp/443, from about 1031 addresses in 5 networks; mitigation on",
  "attack": {
    "mode": "on",
    "started": "2026-10-19T01:00:03Z",
    "kinds": ["request_flood", "one_client_tool", "one_target", "many_new_addresses"],
    "ports": [{"protocol": "tcp", "port": 443, "requests": 43670, "connections": 1065}],
    "rate": 4370, "peak_rate": 4370, "baseline_rate": 40,
    "requests": 43670, "addresses": 1031, "networks": 5,
    "tls": 43670, "plain": 0, "http1": 1200, "http2": 42470,
    "top_origins": [{"label": "BR AS28573", "requests": 9120}],
    "clusters": [{"kind": "fingerprint", "label": "GET HTTP/2 python-requests/2.32.3", "share": 0.954, "addresses": 973}],
    "reasons": ["about 4,370 requests a second, the usual is 40"],
    "refused": 0, "challenged": 0, "banned": 0,
    "window": true
  }
}
```

| Field | Meaning |
| --- | --- |
| `event` | `attack_start`, `attack_update` or `attack_end` |
| `severity` | `critical` for a start, `warning` for an update, `info` for an end |
| `text` | One line for a person, a chat or a pager |
| `attack.kinds` | What the attack is: see [the attack record](ddos.md#what-the-attack-record-says) |
| `attack.ports` | The local TCP ports attacked, the most requested first, with the requests and connections each received; `other_ports` counts any further ports |
| `attack.window` | `true` on a start: the counts are those of the ten seconds that showed the attack, as nothing of the attack itself has been counted yet |
| `attack.ended` | On `attack_end` |
| `attack.stopped` | On `attack_end`: Carnical stopped while the attack went on, so its record ends there and not the attack |
| `dropped` | Messages before this one that the queue had no room for |

Every string is Carnical's own text, a number, or a label Carnical made and bounded: a client
fingerprint, a path template, a country or network. Labels made from what clients sent have
control characters escaped and `<` and `>` replaced by `‹` and `›`, so a chat that reads markup
cannot be made to ping a channel. No message holds a query string, a body, a header value, a
cookie, an address of a visitor or matched data.

When the queue is full, an update waiting gives its place to a start or an end, and a newer update
of the same attack replaces one still waiting: the endpoint gets the latest.

## Checking a message

Each POST carries:

| Header | Meaning |
| --- | --- |
| `X-Carnical-Event` | The event |
| `X-Carnical-Delivery` | A copy of the message's `id` for logs (not signed: deduplicate on the body's `id`); a retry carries the same one |
| `X-Carnical-Timestamp` | Unix seconds when this attempt was signed |
| `X-Carnical-Signature` | `v1=` and the hex HMAC-SHA256, keyed with the shared secret, of the timestamp, a full stop and the body |

A receiver must check the signature with a constant-time compare, refuse a timestamp more than five
minutes from its own clock, and drop a message whose `id` (in the signed body; the
`X-Carnical-Delivery` header is a copy for logs and is not signed) it has already seen. In Python:

```python
import hashlib, hmac, time

def valid(secret: bytes, headers, body: bytes) -> bool:
    ts = headers.get("X-Carnical-Timestamp", "")
    sig = headers.get("X-Carnical-Signature", "")
    if not (ts.isascii() and ts.isdigit() and len(ts) <= 12) or not sig.isascii() or not sig.startswith("v1="):
        return False
    if abs(time.time() - int(ts)) > 300:
        return False
    want = hmac.new(secret, ts.encode() + b"." + body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(sig[3:].encode(), want.encode())
```

Then parse the body and drop it if its `id` was seen in the last ten minutes.

In Go, `notify.Verify(secret, timestamp, signature, body, time.Now(), 5*time.Minute)` does the same.
The secret is the text of the file's first line, not its decoding.

## How the endpoint is protected

- Carnical posts only to the one URL configured, and follows no redirect: a 3xx is a failure.
- Every connection goes through the origin guard's dialer, which checks the address the connection
  is really about to use, after the name has been resolved: a name that points, or later moves, to
  a private, local or cloud metadata address gets no connection unless `-alert-endpoint-allow`
  lists it. No proxy from the environment is used.
- TLS 1.2 or later, with the certificate checked against the system's CAs or
  `-alert-endpoint-ca-file`. Plain HTTP is refused except to loopback.
- The URL, its token and the secret never appear in a log line, an error or the setup transcript;
  a failed delivery is logged as its reason only (`the address is not allowed`, `the endpoint's
  certificate is not trusted`, `timed out`, `TLS failed`, `could not connect`, or the status), at
  most once every 30 seconds.
- An attacker cannot make Carnical flood the endpoint: messages come from attacks, not requests;
  there is at most one update a minute per attack, one post at a time, at least half a second apart,
  and at most three attempts each (retried only after no reply, 408, 429 or 5xx, after one and three
  seconds; never for a refused address or a certificate that is not trusted, which no attempt can
  change).
- Each attempt is bounded by a five-second timeout, and the reply is read to 4 KiB at most. A kept
  HTTP/2 connection is pinged after 30 seconds without a frame, so one to an endpoint that went
  silent is replaced. At shutdown an attack going on has its record closed (`attack_end` with
  `stopped`), and what is waiting is sent for at most two seconds, then dropped and counted.

## Verified

`go test ./notify` covers the URL and secret rules, signing and verifying (a changed body, a
changed timestamp, another secret and a stale timestamp are refused), delivery with one kept-alive
connection, retries only for failures that may pass, a refused redirect, the queue's priorities,
an endpoint that never answers (shutdown stays within its wait), and failure lines that hold neither
URL nor secret. `go test ./cmd/carnical -run 'TestAlertEndpoint|TestRequestFormatsAtCLI'` covers the
flags, the setup step and the saved secret. On Linux, `go test ./proxy -run
TestAFloodFromAThousandAddressesThroughTheProxy` sends a real flood from a thousand addresses
through the proxy and checks that the signed `attack_start` that reaches a TLS endpoint names the
attacked port, the protocol, the kinds and the spread.
