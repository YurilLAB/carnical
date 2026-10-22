# Alert endpoint

Carnical can tell your own HTTPS endpoint each [intrusion alert](#intrusion-alerts) it writes to
the log and, while an attack goes on, what is being attacked and how: the ports and protocols, how
many requests and addresses, what kind of attack it is and what Carnical is doing about it. Nothing
is sent unless an endpoint is set (`-alert-endpoint`, or the "Attack alerts" step of
`carnical setup`).

Messages are few and small. The intrusion alerts go as the log's lines, many to a message, one
message a second (two when more wait than one holds). An attack flood protection finds is told in
one message when it starts, at most one a minute while it goes on, and one when it ends; with
`-netwatch-state`, so are the [network floods](#network-floods) the kernel's packet guards drop.
With `-alerts off`, `-ddos off` and no `-netwatch-state` nothing is sent (start-up warns of it).
They are sent by one goroutine from a queue of 32, one at a time and at least half a second apart,
over one kept-alive connection, so alerting costs next to nothing when the machine is short of
resources, and a slow or dead endpoint costs one goroutine and a few kilobytes.

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
to public addresses only: use port 443, or add the endpoint's port to `edge_out`. It drops every
connection the edge opens to this machine or a private address before it looks at the port, so on
that deployment a relay on the same machine, or an endpoint `-alert-endpoint-allow` allows, is
never reached. Letting the edge reach one takes an accept ahead of those drops, which the host
audit reports as a rule that lets traffic past them: send the alerts to a public HTTPS endpoint
instead.

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
| `event` | `attack_start`, `attack_update` or `attack_end` (and `intrusions`, `network_attack_*`, below) |
| `severity` | `critical` for a start, `warning` for an update, `info` for an end |
| `text` | One line for a person, a chat or a pager |
| `attack.kinds` | What the attack is: see [the attack record](ddos.md#what-the-attack-record-says) |
| `attack.ports` | The local TCP ports attacked (the first four seen), the most requested first, with the requests and connections each received; `other_ports` counts any further ports |
| `attack.window` | `true` on a start: the counts are those of the ten seconds that showed the attack, as nothing of the attack itself has been counted yet |
| `attack.ended` | On `attack_end` |
| `attack.stopped` | On `attack_end`: Carnical stopped while the attack went on, so its record ends there and not the attack |
| `dropped` | Messages before this one that the queue had no room for |

Every string is Carnical's own text, a number, or a label Carnical made and bounded: a client
fingerprint, a path template, a country or network. Two of them hold what clients sent: a client
fingerprint is the method, the protocol and the first 72 bytes of the `User-Agent`, and a path
template is the path with its identifiers taken out (numbers, and segments over 40 characters or
of 16 and more that hold a digit), at most six segments in 96 bytes, so a word or a name in a path
is kept. Labels made from what clients sent have control characters escaped and `<` and `>`
replaced by `‹` and `›`, so a chat that reads markup cannot be made to ping a channel. No message
holds a query string, a body, another header, a cookie or matched data, and only an intrusion
alert holds a visitor's address, as its log line does.

When the queue is full, an update or a message of intrusion alerts waiting gives its place to a
start or an end, and a newer update of the same attack replaces one still waiting: the endpoint
gets the latest.

## Intrusion alerts

Every [intrusion alert](proxy-reference.md#intrusion-alerts) written to the log is sent as that
line, without its `time` and `level`: the same fields under the same names. They are `intrusion
blocked`, `intrusion detected`, `inspection incomplete`, `alert repeated`, `suspected intrusion`,
`alerts dropped` and the [repeat offender](ddos.md#repeat-offenders) lines (`source blocked`,
`source would be blocked`, `source block ended`, `auto-block table full`). The `intrusion totals`
and `intrusion summary` reports stay in the log. As the endpoint is sent the lines written to the
log, the log's limits come first: one line per source, signature and action in
`-alert-repeat-window`, at most `-alert-rate` lines a second, and `-alert-min-risk`,
`-alert-suppress` and `-alert-exclude-sources` apply. With `-alerts off` none are sent.

```json
{
  "version": 1,
  "id": "4be0d27c95a1e3f8076b2d9c1a5e8f34",
  "event": "intrusions",
  "severity": "critical",
  "at": "2026-10-22T09:15:02Z",
  "site": "example.com",
  "text": "3 intrusion alerts on example.com: 1 blocked, 1 detected, 1 repeated",
  "intrusions": [
    {"msg": "intrusion blocked", "alert_id": "8d1f3a7c2b9e4f60", "layer": "crs", "sig": "crs-942100",
     "sig_name": "SQL injection (libinjection)", "rules": [942100, 949110], "category": ["sqli"],
     "risk": "high", "severity_raw": "CRITICAL", "action": "blocked", "mode": "block", "status": 403,
     "score": 10, "threshold": 5, "src": "203.0.113.9", "src_key": "203.0.113.9", "method": "GET",
     "host": "example.com", "path": "/search", "count": 1},
    {"msg": "intrusion detected", "alert_id": "2c90e1b4a7d35f18", "layer": "crs", "sig": "crs-5006102",
     "sig_name": "Script on another host in a body parameter", "rules": [5006102], "category": ["rfi"],
     "risk": "low", "severity_raw": "CRITICAL", "action": "detected", "mode": "detect", "status": 0,
     "src": "198.51.100.23", "src_key": "198.51.100.23", "method": "POST", "host": "example.com",
     "path": "/contact", "count": 1},
    {"msg": "alert repeated", "alert_id": "8d1f3a7c2b9e4f60", "layer": "crs", "sig": "crs-942100",
     "sig_name": "SQL injection (libinjection)", "rules": [942100, 949110], "category": ["sqli"],
     "risk": "high", "severity_raw": "CRITICAL", "action": "blocked", "mode": "block", "score": 10,
     "threshold": 5, "src": "203.0.113.9", "src_key": "203.0.113.9", "method": "GET",
     "host": "example.com", "path": "/search", "first": "2026-10-22T09:14:02Z",
     "last": "2026-10-22T09:14:43Z", "count": 14}
  ]
}
```

| Field | Meaning |
| --- | --- |
| `severity` | `critical` when an alert is high risk, a suspected intrusion or a source blocked; `warning` when one is medium risk or alerts were dropped or not sent; `info` otherwise |
| `intrusions` | The alerts, in the order they were written to the log, each as its line; see [intrusion alerts](proxy-reference.md#intrusion-alerts) for the fields |
| `intrusions_dropped` | Alerts before these that were not sent: more than 256 waited, or the queue had no room for their message |

A message holds at most 50 alerts and 16 KiB; while more wait, a second follows within the same
second. When 256 wait, a medium or high risk alert takes the place of the oldest lower one, and any
other is not sent; the next message counts them in `intrusions_dropped`. The alerts are in the log
either way.

Each alert names the visitor's address as `-alert-source` says: `full` (the default), `prefix`
(its /24 or /48) or `off`, and the path as `-alert-path` says. Use `-alert-source prefix` or `off`
when the endpoint is not to hold visitors' addresses. At shutdown the alerts written as the alerts
close (the repeats still being counted and the last requests') are sent before the endpoint stops,
within its two seconds; `alert endpoint closed` counts the alerts that were not sent in
`intrusions_not_sent`.

## Network floods

With `-netwatch-state /run/carnical/netwatch/state.json`, the edge also sends what
[`carnical-netwatch`](network-protection.md#telling-of-a-flood) finds: floods the kernel drops
before the proxy sees them. The events are `network_attack_start`, `network_attack_update` and
`network_attack_end`, with the same severities, signing and limits as the others, and a `network`
record in place of `attack`. This one is from the end-to-end check in
[network protection](network-protection.md#telling-of-a-flood), a real flood dropped by the real
policy (the counts by port and by kind are read a moment apart, so they differ a little):

```json
{
  "version": 1,
  "id": "52f06c0bf1505d74bc88d68819a6d721",
  "event": "network_attack_start",
  "severity": "critical",
  "at": "2026-10-19T02:10:13.16894475Z",
  "site": "example.com",
  "text": "Network flood detected on example.com (udp_flood, udp_reflection): 97801 packets/s dropped at peak, usually 2, to udp/53 udp/27015, reflected from udp/123; the packet guards drop it",
  "network": {
    "started": "2026-10-19T02:10:13.155319188Z",
    "kinds": [{"kind": "udp_flood", "packets": 77968, "bytes": 27684724},
              {"kind": "udp_reflection", "packets": 19800, "bytes": 10206348}],
    "ports": [{"protocol": "udp", "port": 53, "packets": 54600, "bytes": 12994800},
              {"protocol": "udp", "port": 27015, "packets": 23400, "bytes": 14695200}],
    "source_ports": [{"protocol": "udp", "port": 123, "packets": 19500, "bytes": 10062000}],
    "packet_rate": 97801, "peak_packet_rate": 97801, "byte_rate": 37903710, "peak_byte_rate": 37903710,
    "baseline_packet_rate": 2, "packets": 97768, "bytes": 37891072
  }
}
```

| Field | Meaning |
| --- | --- |
| `network.kinds` | `udp_flood`, `udp_reflection`, `syn_flood`, `malformed_tcp` or `icmp_flood`, each with at least a tenth of the packets, the most first |
| `network.ports` | The destination ports, the most first, with at least a hundredth of the packets each |
| `network.other_ports`, `network.random_ports` | The UDP flood's packets to any other port; `random_ports` when they were at least half of it, a flood with no port to name |
| `network.ports_full` | More ports were hit than the watch counts (2,048 at a time), so the port a flood is aimed at may be missing |
| `network.source_ports` | For reflection, the services the replies came from |
| `network.packet_rate`, `byte_rate` | Dropped now, a second; `peak_` the highest, `baseline_packet_rate` the usual before it |
| `network.packets`, `bytes` | Dropped during the attack |
| `network.ended`, `network.stopped` | On `network_attack_end`; `stopped` when the watch stopped while it went on |

The record holds counts, ports and kinds only. The edge refuses a state file with an unknown kind,
event or field, more entries than the watch writes, or one over 64 KiB, one that is not root's or
that others may write, and logs that it could not read it, at most once a minute, without its
content. The file's directory belongs to root, which the host audit checks, so a process that has
taken over the edge cannot make up a flood or hide one.

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
- An attacker cannot make Carnical flood the endpoint: attack messages come from attacks, not
  requests, at most one update a minute per attack; intrusion alerts are the log's deduplicated,
  rate-limited lines, at most two messages a second of at most 50 each, and 256 waiting; there is
  one post at a time, at least half a second apart, and at most three attempts each (retried only after no reply, 408, 429 or 5xx, after one and three
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
an endpoint that never answers (shutdown stays within its wait), failure lines that hold neither
URL nor secret, and the intrusion alerts' batching, size limits, priorities, text and severity.
`go test ./alert -run TestSinks` checks that an alert sent is its log line, field for field.
`go test ./cmd/carnical -run 'TestAlertEndpoint|TestRequestFormatsAtCLI'` covers the flags, the
setup step, the saved secret, and that the alerts written to the log, including the repeats
written at shutdown, reach a TLS endpoint as those lines, with the source as `-alert-source` says. On Linux, `go test ./proxy -run
TestAFloodFromAThousandAddressesThroughTheProxy` sends a real flood from a thousand addresses
through the proxy and checks that the signed `attack_start` that reaches a TLS endpoint names the
attacked port, the protocol, the kinds and the spread.
