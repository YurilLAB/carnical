# L3 and L4 network protection

Carnical combines kernel packet filtering with admission checks on accepted TCP connections. The Go listener checks run
when flood protection is enabled (the CLI default); the kernel layer requires installing the Linux deployment policy.

| Layer | Protection | Default budget / monitoring |
|---|---|---|
| Before connection tracking | SYN packets to the local public TCP endpoint, after IP reassembly | 10,000/s across IPv4 and IPv6, burst 20,000; `edge_syn_global_drop` |
| Before connection tracking | Per-source SYN budget, including IPv6 address rotation within a /64 | 100/s per IPv4 address or IPv6 /64, burst 200; `edge_syn_source_drop` |
| Before connection tracking | Configured high-volume CDN/load-balancer peers | 5,000/s per IPv4 address or IPv6 /64, burst 10,000; separate bounded meters, `edge_syn_peer_admitted` and `edge_syn_peer_drop`. No aggregate exemption or fallback to an ordinary bucket. |
| Before connection tracking | Bounded SYN meter storage | 65,536 keys per family; idle keys expire after 60 seconds. A full set refuses new keys until capacity is reclaimed; existing keys retain their own budget. |
| Before connection tracking | Invalid SYN+FIN/SYN+RST, null/FIN-only/Xmas flags, impossible TCP sources and UDP to port 443 | `edge_bad_tcp`, `edge_bad_source`, `edge_udp_drop`; ECN SYN flags and valid data-in-SYN are preserved. |
| Host input | Echo-request floods, including repeated established ICMP identifiers | 20/s combined IPv4/IPv6, burst 40; `edge_echo_admitted`, `edge_echo_drop`. Path-MTU/error messages and valid IPv6 discovery use separate rules. |
| Accepted TCP connections | Concurrent capacity reservation and live subnet counts | Shared global cap, reserved capacity for known clients, per-/24 or /48 caps. Address-history eviction cannot reset live counts; trusted proxy peers share the global cap. See [flood protection](ddos.md). |

The packet guard is scoped to locally addressed port 443. Loopback and forwarded traffic follow the existing deployment
policies. UDP/443 is closed because Carnical does not serve QUIC. IPv6 discovery requires hop limit 255, with router
advertisements also requiring a link-local source. Linux rejects some impossible IPv6 sources before nftables runs, so
their drops do not appear in the policy counters.

## Installing and tuning

Follow the [deployment guide](../deploy/README.md). Create the service users, replace the example management addresses and
resolver, and tune the SYN budgets in [carnical.nft](../deploy/nftables/carnical.nft) for the deployment before loading it:

```sh
sudo nft -c -f carnical/deploy/nftables/carnical.nft
sudo nft -f carnical/deploy/nftables/carnical.nft
sudo nft list counters inet carnical
sudo nft list set inet carnical syn4
sudo nft list set inet carnical syn6
```

Kernel limits do not learn traffic levels. Tune for shared NAT, CDN and load-balancer peers: a trusted application peer
still consumes the kernel's source and aggregate budgets unless assigned a separate finite peer budget below.
Ensure the configured public port matches the listener.
Keep management access available while installing the existing default-drop host policy. Loading this file affects
the host's networking; running the test below affects only disposable namespaces.

Early refusals increment counters without a log message per packet. General input refusals count in `input_denied`;
`input_logged` measures the log budget (5/minute, burst 5). Egress refusals retain their existing log prefixes with a
10/minute, burst-10 budget per refusal chain. Every refusal chain drops unconditionally after its conditional log rule,
so exhausting logging capacity cannot admit traffic. `egress_private_drop`, `egress_imds_drop`, `egress_edge_drop` and
`egress_internal_drop` count those refusals. Export these counter deltas into the deployment's monitoring.
Loading the base file directly retains named counters/meters. Use rendered profiles when changing sizes, timeouts, peer ranges
or meter rates: they replace this table atomically so old state cannot keep obsolete budgets or revoked peers alive. Capture
counter deltas before a replacement; counters and meters reset. Other nftables tables are unaffected.

## Choosing a budget

The renderer prints a complete policy for review. It never invokes nftables or loads rules. Profiles are starting budgets
per edge, not measured server capacities. Tune from peak **new TCP connections/SYN packets**, including retries, rather than
HTTP request counts: keep-alive and HTTP/2 carry many requests over one connection.

| Budget | Small | Standard (base file) | Large |
|---|---:|---:|---:|
| Aggregate SYN/s / burst | 1,000 / 2,000 | 10,000 / 20,000 | 100,000 / 200,000 |
| Ordinary address or IPv6 /64 SYN/s / burst | 50 / 100 | 100 / 200 | 1,000 / 2,000 |
| Configured peer address or IPv6 /64 SYN/s / burst | 500 / 1,000 | 5,000 / 10,000 | 20,000 / 40,000 |
| Ordinary meter keys per family | 8,192 | 65,536 | 262,144 |
| Peer meter keys per family | 1,024 | 4,096 | 4,096 |
| Meter idle timeout (seconds) | 30 | 60 | 60 |
| Echo/s / burst (IPv4+IPv6 together) | 20 / 40 | 20 / 40 | 100 / 200 |

Edit the management addresses and resolver in the source policy first. Then render a root-owned deployment file, replacing
the example peer addresses with verified network peers; leave `--peer` out for a direct edge:

```sh
python3 carnical/deploy/nftables/render_policy.py --profile small > network.nft
python3 carnical/deploy/nftables/render_policy.py --profile large \
  --peer 192.0.2.20 --peer 2001:db8:20::/64 --port 443 > network.nft
sudo nft -c -f network.nft
sudo nft -f network.nft
```

The renderer requires nftables 1.0.9 or later and kernel support for `destroy`; the check command verifies support before
installation. Load the whole file in one `nft -f` transaction. A large-to-small reload removes old peer entries and old meter
budgets; splitting replacement into separate delete/add shell commands would lose that atomicity.

`--set NAME=INTEGER` overrides a budget in the table: `syn_global_rate`, `syn_global_burst`, `syn_source_rate`,
`syn_source_burst`, `syn_peer_rate`, `syn_peer_burst`, `syn_meter_size`, `syn_peer_meter_size`, `syn_meter_ttl` (seconds),
`echo_rate` and `echo_burst`. Each must be in 1..1,048,576. Invalid ports, noncanonical/scoped CIDRs, all-address peer ranges
and unknown/duplicate budget names are rejected before any policy is emitted. Port 22 is reserved for the existing management
SSH allowlist; it cannot be selected as the public edge port. For example, a measured shared NAT may need
`--set syn_source_rate=500 --set syn_source_burst=1000` without being designated a proxy peer.

Peer ranges change only the packet budget. They do not trust forwarded HTTP headers or bypass request inspection; configure
`-trusted-proxies` separately for actual forwarding proxies. Source addresses alone do not authenticate packets. Keep peer
ranges narrow and administrator-owned, and retain upstream anti-spoofing measures. Malformed packets from a peer still drop.

The Go shield caps both initial and learned connections at 80% of the process's soft descriptor limit. Tune
`-ddos-max-conns`, request floors, upstream concurrency and evaluation concurrency to memory, CPU and TLS capacity.
The supplied systemd edge unit also has `MemoryMax=2G` and `LimitNOFILE=65536`; review these for the host. Measure SYN backlog,
accept queue and connection-tracking pressure. SYN cookies are a fallback against attacks, not a substitute for adequate
legitimate capacity. Scale multiple edges when one server's measured capacity is insufficient; budgets are local to each node.

## Validation

Run from the repository root on Linux with Go, nftables and iproute2:

```sh
cd carnical
go test -race ./shield
go test -race ./proxy -run TestAFloodFromAThousandAddressesThroughTheProxy -count=1 -v
CGO_ENABLED=0 go build -o ../build/carnical-network-linux ./cmd/carnical
cd ..
sudo python3 .github/security/test_network_policy.py --binary build/carnical-network-linux
```

The packet test creates two disposable network namespaces joined by a veth, runs the actual Carnical executable and
an isolated origin, loads the policy and sends only traffic inside that network. Fixture numeric UIDs avoid creating
host accounts. Source-flood tests use the production budgets; aggregate-limit and set-capacity tests reduce only the
thresholds/size/expiry to exercise exhaustion without a large flood. The script refuses to load rules into the host's
network namespace. The security workflow runs these checks in a separate required job and preserves their logs.

Local validation on Linux 6.18.33.2 with nftables 1.1.6:

- The full shield suite passed with race detection. The new regression failed on the previous code when request-history
  churn reset a network's occupied capacity; it passes with the fix, including concurrent listeners and trusted peers.
- Through the running proxy's distributed-flood test, all 160/160 regular visitor requests after detection were served;
  19/21,437 flood requests reached the origin. The monitor-only control admitted 22,531/22,531, with 180/180 visitor
  requests served. These are local test observations, not production throughput guarantees.
- Live IPv4/IPv6 ordinary HTTP reached the origin and SQL injection received 403. Valid ECN SYN packets passed; malformed
  TCP, UDP/443 and impossible sources were refused. Both families' fragmented SYN+FIN traffic was refused after reassembly,
  with fragmented ordinary SYN packets as positive controls.
- 512 SYN packets from one IPv4 source and 512 changing IPv6 addresses within one /64 exhausted their source budgets.
  Another IPv6 /64 retained its budget. Aggregate exhaustion across different addresses and full sets in both families
  refused new traffic; existing keys continued working, and expiry eventually reclaimed capacity.
- A 256-packet IPv6 echo flood using the same ICMP identifier remained limited after connection tracking recognized it.
  IPv6 discovery remained accepted at hop limit 255 and refused at 254. A separate 128-packet closed-port flood verified
  bounded refusal logging, and an ordinary IPv6 HTTP request still succeeded after the tests.
- The echo regression also failed with the previous established-before-echo rule ordering: only the first request reached
  the echo guard. Service-UID tests refused 16 connection attempts each to private, metadata, SMTP and internal destinations,
  including attempts beyond the log burst, with permitted origin-port connections as a positive control.

These checks cover the connection and packet layers described here. They do not establish upstream bandwidth protection,
SYN-proxy behaviour, production TLS capacity or the security of every application rule. The guard runs after IP reassembly,
so kernel fragment-queue resources remain a separate concern. Floods that fill the uplink require provider-side mitigation.
Existing repository-wide security findings remain tracked in [the findings report](../../docs/security-findings.md).
The new ADR passes the repository's validator in isolation; the whole ADR collection still fails on 60 older records
missing the required technical-discussion section.

The hosted Ubuntu 24.04 [L3/L4 job](https://github.com/YurilLAB/coraza/actions/runs/37479256414/job/112322767126) passed its
full race suite, live flood and packet checks. Its mitigated flood served 180/180 regular visitor requests and admitted
19/22,571 flood requests after detection; the monitor control admitted 20,495/20,495. The broader runtime job also exposed
a test timing issue where a correct reset arrived during `Dial`, before the test could check refusal. The test now accepts
that explicit reset only for intentionally refused connections, and passed ten consecutive race-enabled runs locally.
The overall security workflow remains failing on the existing sandbox forbidden-bind probe and unchanged Linux gosec
results (147 findings). No blanket waiver or reduced security gate was added.

### Small and large deployment tests (2026-10-07)

The expanded existing namespace test uses the renderer's production small/large profiles, the running Carnical binary,
the kernel policy and the Go connection shield. Request floors and upstream/evaluation concurrency are explicitly sized for
the test's shared client addresses. It tests keep-alive and new TLS connections; it does not establish that default request
floors will serve an arbitrary busy NAT without tuning. Packets vary source addresses, IPv6 addresses within a /64, source
ports, TCP sequences and flags. All traffic stays inside the two disposable namespaces.

| Live workload | Ordinary requests served | Hostile HTTP blocked | Observation |
|---|---:|---:|---|
| Small profile, IPv4/IPv6, four workers per family in ordinary traffic, eight during flood | 960/960 | 50/50 SQL injection probes | 6,000 varied packets over three seconds; no ordinary HTTP failures |
| Large profile, IPv4/IPv6, 32 workers per family in ordinary traffic, 64 during flood | 20,000/20,000 | 50/50 SQL injection probes | 100,000 varied packets over eight seconds; no ordinary HTTP failures |
| Verified HTTPS with kernel policy, shield and CRS enabled, 16 workers | 1,000/1,000 | 50/50 SQL injection probes | Certificate chain and IP SAN verified; both address families |

In the recorded plain-HTTP run, the small profile dropped 2,000 malformed SYN+FIN packets, 2,000 UDP/443 packets and
1,751 excess SYNs; 249 syntactically valid SYNs remained within its budget. The large profile dropped 33,334 malformed
packets, 33,333 UDP/443 packets and 23,396 excess SYNs; 9,937 valid SYNs remained within its budget. All generated flood
packets were accounted for by the admission/drop counters. A SYN within budget is allowed to attempt a connection; it is
not evidence that an HTTP attack reached the application. No SQL injection probe reached the origin.

The large profile's ordinary batches completed in about 3.6 seconds each (roughly 1,400 requests/s locally), and the mixed
flood batch in about seven seconds. Its p99 request latency rose from 10–14 ms in that recorded ordinary run to about
1,027 ms during the flood. The [controlled investigation below](#investigating-the-one-second-tail) subsequently reproduced
that delay without a flood and traced it to the test origin's accept queue and connection churn. The original comparison
also doubled client concurrency during the flood. These results establish service continuity in this workload, not a latency
guarantee. Kernel backlog pressure, TLS capacity, connection tracking, origin performance
and upstream bandwidth still need measurement on the intended server. A 100,000/s configured SYN budget is not a claim of
100,000/s tested server capacity. This lab does not emulate a multi-node massive website or realistic internet latency.

Additional checks passed:

- 128 concurrent attempts at small limits and 4,096 at large limits across eight listeners, with direct and trusted peers.
  Large direct traffic admitted exactly 1,639 sockets (the unreserved share of 2,048); trusted peers admitted 2,048. Closing
  every admitted socket reclaimed capacity. Three consecutive race-enabled runs passed.
- A simulated soft descriptor limit of 64 kept startup connections to 41 ordinary or 51 trusted/grown connections, rather
  than admitting all 128. The same regression failed with the previous production code, proving the low-resource fix.
- Ordinary source bursts and larger configured-peer bursts had no packet-budget refusals in both profiles. Peer rate
  exhaustion, full peer meters and aggregate exhaustion refused excess traffic without granting an ordinary fallback bucket.
  Exhaustion fixtures reduce thresholds/size to verify behaviour cheaply; production-profile burst tests retain their budgets.
- Large-to-small replacement immediately revoked the peer's larger budget. Changing the public port to 9443 preserved the
  IPv4/IPv6 guards and closed the old port. An unrelated table and counter survived profile replacements.
- The full Linux shield suite passed with race detection (153.7 seconds), and Windows shield/CLI tests and Go vet passed.
  The busy-site simulation served 99.91% of returning requests at a learned baseline of 1,184 requests/s, with 11.3x address
  and 3.8x network scaling, and did not label a tripling of ordinary traffic an attack. The live distributed-flood rerun served
  180/180 visitors and admitted 19/22,155 flood requests after detection; the monitor control admitted 21,548/21,548.

GitHub's existing required L3/L4 job runs these profile, TLS, reload and malformed-packet checks on every relevant push and
keeps the detailed logs. Repository-wide findings and the sandbox/YAML timing failures remain separate unresolved checks.
The hosted Ubuntu 24.04 [scaling job for commit 65b9acde](https://github.com/YurilLAB/coraza/actions/runs/37493305231/job/112371316359)
passed the full race suite, live distributed flood, both deployment profiles, verified TLS, port changes and reload checks.

### Investigating the one-second tail

The existing namespace test now records connection setup (including TLS when enabled), request writes, response headers,
body reads, reused-connection latency, accepted origin connections, handled origin requests and TCP counter deltas in both namespaces. Its percentiles
use the nearest-rank definition. Flood and no-flood controls use the same number of workers. `flood_requests` counts requests
started while the packet generator was active; a fast HTTP batch can finish before the eight-second packet stream finishes.
Counter snapshots cover the HTTP batch, while final nft counters account for the complete packet stream.

Three live repetitions of four origin configurations used the same Carnical binary, CRS, shield limits and large packet
profile. Each configuration served 10,000 requests at 64 workers without a flood and another 10,000 during a 100,000-packet
stream. The final repetition measured:

| Origin configuration | No-flood p99 | Flood p99 | Origin connections, no flood / flood | Listen overflows, no flood / flood |
|---|---:|---:|---:|---:|
| Original HTTP/1.0, queue 5 | 1,026 ms | 1,026 ms | 10,000 / 10,000 | 326 / 318 |
| HTTP/1.0, queue 256 only | 44 ms | 45 ms | 10,000 / 10,000 | 0 / 0 |
| HTTP/1.1 with Content-Length, queue 256 | 52 ms | 52 ms | 69 / 0 | 0 / 0 |
| Same persistent origin with TCP_NODELAY | 46 ms | 84 ms | 44 / 19 | 0 / 0 |

The original response-header wait accounted for almost the entire second; client-to-edge SYN retransmissions were zero.
The server namespace recorded 183/225 SYN retransmissions in the no-flood/flood original-origin batches and none after
changing only its queue. Together with the reproduced no-flood delay and unchanged WAF, this identifies an overloaded
origin accept queue as the cause in this lab. Linux's documented initial SYN retransmission timeout is one second.
The original HTTP/1.0 origin closed each connection, forcing a new upstream handshake for every request. Carnical already
uses a persistent Go transport, but an origin that closes connections prevents reuse. The fixture now supplies valid
HTTP/1.1 response framing, a bounded queue of 256 and TCP_NODELAY. Persistent origin connections removed most handshakes;
TCP_NODELAY reduced the final run's 10,000-request flood batch from 7.28 to 3.26 seconds. The persistent TCP_NODELAY fixture's
flood p99 ranged from 46 to 84 ms across the three repetitions; it was 47 ms in the second. This change improves the test
origin and its deployment guidance; it does not change WAF rules or relax flood budgets.

All 240,000 ordinary requests across the three control repetitions succeeded. The last two repetitions also blocked 400/400
SQL injection probes before any origin connection was opened; the final repetition explicitly counted zero handled origin
requests for those probes. The full profile suite additionally checks a no-flood control
at eight workers for small deployments and 64 for large, verified HTTPS during another 100,000-packet flood, zero listen
overflows, zero client SYN retransmissions, bounded upstream connection creation and p99 below 500 ms. That threshold is a
laboratory regression check, not a production SLA. Both the profile suite and four-origin controls run in the existing
GitHub L3/L4 job and retain their logs. Each of two local full-suite runs served 36,440/36,440 ordinary batch requests,
blocked 150/150 SQL probes and accounted for 206,000 varied flood packets. Large matched-concurrency p99 was 44.6–45.2 ms
without flood and 45.6–46.2 ms during flood; small was 7.1–7.8 / 4.3–8.0 ms. The 4,000-request HTTPS flood batches used
16 workers paced at 20 ms, verified the certificate chain and IP SAN, and measured p99 4.5–5.8 ms.
All 4,000 requests in each HTTPS flood batch started during packet generation, with no
transport failures, listen overflows or client SYN retransmissions. The paced HTTPS result is not directly comparable to
the unpaced 64-worker HTTP result. Reproduce the controls on Linux with:

```sh
sudo python3 .github/security/test_network_policy.py --binary build/carnical-network-linux --latency-investigation
```

The first hosted run passed the full profile/TLS suite (large p99 69 ms with and without flood), but the deliberately
undersized queue-five control delivered only 9,999/10,000 requests to the origin. The diagnostic now prints every control's
status, error, latency and backend counts before checking it. Failures in that intentionally overloaded baseline remain
visible as measurements; all queue-256 configurations retain strict checks for 10,000 successful backend responses, zero
transport errors and zero listen overflows. SQL probes must still be blocked without reaching the backend in every control.
Live fault checks forced one real origin-side TCP reset: the broken baseline recorded a 502 and 9,999 handled requests
and continued through every corrected configuration. Injecting the same reset into a queue-256 configuration made its
strict response check fail, verifying that corrected-configuration failures are not accepted as baseline observations.

For an actual deployment, enable correctly framed persistent responses at the origin, size its accept queue and workers
against measured upstream concurrency, and compare `ss -lnt` queue occupancy with TCP counter deltas under matched traffic.
Track origin connection creation, visitor latency and named nft admission/refusal counters together. `ListenDrops` is a
namespace-wide counter and also rises from incomplete attacking SYNs; it does not by itself show that visitors were dropped.
Measure edge handshakes separately from origin waits before changing packet budgets. A larger queue only absorbs bursts;
it cannot increase a saturated origin's processing capacity. Keep evaluation, upstream and connection limits within the
server's resource budget. These local results do not measure internet-scale volumetric attacks or multi-node capacity.

## References

- [Netfilter hook ordering](https://wiki.nftables.org/wiki-nftables/index.php/Netfilter_hooks): raw priority -300 follows
  defragmentation and precedes connection tracking.
- [nftables dynamic-set documentation](https://netfilter.org/projects/nftables/manpage.html#_set_statement) and
  [meters](https://wiki.nftables.org/wiki-nftables/index.php/Meters): bounded, expiring keys and per-key rate limits.
- [RFC 4890](https://www.rfc-editor.org/rfc/rfc4890): IPv6 error and discovery traffic must be treated deliberately when filtering.
- [nftables scripting](https://wiki.nftables.org/wiki-nftables/index.php/Scripting): load a generated policy in one atomic transaction.
- [nftables 1.0.9 changes](https://www.netfilter.org/projects/nftables/files/changes-nftables-1.0.9.txt): destroy command support and kernel feature checks.
- [Linux TCP capacity settings](https://kernel.org/doc/html/latest/networking/ip-sysctl.html): SYN backlog limits and the purpose of SYN-cookie fallback.
- [Python HTTP response framing](https://docs.python.org/3.14/library/http.server.html#http.server.BaseHTTPRequestHandler.protocol_version)
  and [server queues](https://docs.python.org/3.14/library/socketserver.html#socketserver.BaseServer.request_queue_size):
  the fixture's HTTP/1.0 and queue defaults, and the Content-Length requirement for persistent responses.
- [Go HTTP transport](https://pkg.go.dev/net/http#Transport): persistent connection pooling.
- [Process descriptor limits](https://man7.org/linux/man-pages/man2/getrlimit.2.html): the soft limit constrains descriptors a process can open.
- [Linux IPv6 input implementation](https://github.com/torvalds/linux/blob/v6.18/net/ipv6/ip6_input.c): early rejection of
  multicast sources and loopback addresses on non-loopback interfaces.
