# L3 and L4 network protection

Carnical combines kernel packet filtering with admission checks on accepted TCP connections. The Go
listener checks run when flood protection is enabled (the CLI default); the kernel layer requires
installing the Linux deployment policy.

| Layer | Protection | Default budget / monitoring |
|---|---|---|
| Before connection tracking | SYN packets to the local public TCP endpoint, after IP reassembly | 10,000/s across IPv4 and IPv6, burst 20,000; `edge_syn_global_drop` |
| Before connection tracking | Per-source SYN budget, including IPv6 address rotation within a /64 | 100/s per IPv4 address or IPv6 /64, burst 200; `edge_syn_source_drop` |
| Before connection tracking | Configured high-volume CDN/load-balancer peers | 5,000/s per IPv4 address or IPv6 /64, burst 10,000; separate bounded meters, `edge_syn_peer_admitted` and `edge_syn_peer_drop`. No aggregate exemption or fallback to an ordinary bucket. |
| Before connection tracking | Bounded SYN meter storage | 65,536 keys per family; idle keys expire after 60 seconds. A full set refuses new keys until capacity is reclaimed; existing keys retain their own budget. |
| Before connection tracking | Invalid SYN+FIN/SYN+RST, null/FIN-only/Xmas flags, impossible TCP sources and UDP to port 443 | `edge_bad_tcp`, `edge_bad_source`, `edge_udp_drop`; ECN SYN flags and valid data-in-SYN are preserved. |
| Host input | Echo-request floods, including repeated established ICMP identifiers | 20/s combined IPv4/IPv6, burst 40; `edge_echo_admitted`, `edge_echo_drop`. Path-MTU/error messages and valid IPv6 discovery use separate rules. |
| Accepted TCP connections | Concurrent capacity reservation and live subnet counts | Shared global cap, reserved capacity for known clients, per-/24 or /48 caps. Address-history eviction cannot reset live counts; trusted proxy peers share the global cap. See [flood protection](ddos.md). |

The packet guard is scoped to locally addressed port 443. Loopback and forwarded traffic follow the
existing deployment policies. UDP/443 is closed because Carnical does not serve QUIC. IPv6 discovery
requires hop limit 255, with router advertisements also requiring a link-local source. Linux rejects
some impossible IPv6 sources before nftables runs, so their drops do not appear in the policy
counters.

## Installing and tuning

Follow the [deployment guide](../deploy/README.md). Create the service users, replace the example
management addresses and resolver, and tune the SYN budgets in
[carnical.nft](../deploy/nftables/carnical.nft) for the deployment before loading it:

```sh
sudo nft -c -f carnical/deploy/nftables/carnical.nft
sudo nft -f carnical/deploy/nftables/carnical.nft
sudo nft list counters inet carnical
sudo nft list set inet carnical syn4
sudo nft list set inet carnical syn6
```

Kernel limits do not learn traffic levels. Tune for shared NAT, CDN and load-balancer peers: a
trusted application peer still consumes the kernel's source and aggregate budgets unless assigned a
separate finite peer budget below. Ensure the configured public port matches the listener. Keep
management access available while installing the existing default-drop host policy. Loading this
file affects the host's networking; running the test below affects only disposable namespaces.

Early refusals increment counters without a log message per packet. General input refusals count in
`input_denied`; `input_logged` measures the log budget (5/minute, burst 5). Egress refusals retain
their existing log prefixes with a 10/minute, burst-10 budget per refusal chain. Every refusal chain
drops unconditionally after its conditional log rule, so exhausting logging capacity cannot admit
traffic.

`egress_private_drop`, `egress_imds_drop`, `egress_edge_drop` and `egress_internal_drop` count those
refusals. Export these counter deltas into the deployment's monitoring. Loading the base file
directly retains named counters/meters. Use rendered profiles when changing sizes, timeouts, peer
ranges or meter rates: they replace this table atomically so old state cannot keep obsolete budgets
or revoked peers alive.

Capture counter deltas before a replacement; counters and meters reset. Other nftables tables are
unaffected.

## Choosing a budget

The renderer prints a complete policy for review. It never invokes nftables or loads rules. Profiles
are starting budgets per edge, not measured server capacities. Tune from peak **new TCP
connections/SYN packets**, including retries, rather than HTTP request counts: keep-alive and HTTP/2
carry many requests over one connection.

| Budget | Small | Standard (base file) | Large |
|---|---:|---:|---:|
| Aggregate SYN/s / burst | 1,000 / 2,000 | 10,000 / 20,000 | 100,000 / 200,000 |
| Ordinary address or IPv6 /64 SYN/s / burst | 50 / 100 | 100 / 200 | 1,000 / 2,000 |
| Configured peer address or IPv6 /64 SYN/s / burst | 500 / 1,000 | 5,000 / 10,000 | 20,000 / 40,000 |
| Ordinary meter keys per family | 8,192 | 65,536 | 262,144 |
| Peer meter keys per family | 1,024 | 4,096 | 4,096 |
| Meter idle timeout (seconds) | 30 | 60 | 60 |
| Echo/s / burst (IPv4+IPv6 together) | 20 / 40 | 20 / 40 | 100 / 200 |

Edit the management addresses and resolver in the source policy first. Then render a root-owned
deployment file, replacing the example peer addresses with verified network peers; leave `--peer`
out for a direct edge:

```sh
python3 carnical/deploy/nftables/render_policy.py --profile small > network.nft
python3 carnical/deploy/nftables/render_policy.py --profile large \
  --peer 192.0.2.20 --peer 2001:db8:20::/64 --port 443 > network.nft
sudo nft -c -f network.nft
sudo nft -f network.nft
```

The renderer requires nftables 1.0.9 or later and kernel support for `destroy`; the check command
verifies support before installation. Load the whole file in one `nft -f` transaction. A
large-to-small reload removes old peer entries and old meter budgets; splitting replacement into
separate delete/add shell commands would lose that atomicity.

`--set NAME=INTEGER` overrides a budget in the table: `syn_global_rate`, `syn_global_burst`,
`syn_source_rate`, `syn_source_burst`, `syn_peer_rate`, `syn_peer_burst`, `syn_meter_size`,
`syn_peer_meter_size`, `syn_meter_ttl` (seconds), `echo_rate` and `echo_burst`. Each must be in
1..1,048,576. Invalid ports, noncanonical/scoped CIDRs, all-address peer ranges and
unknown/duplicate budget names are rejected before any policy is emitted.

Port 22 is reserved for the existing management SSH allowlist; it cannot be selected as the public
edge port. For example, a measured shared NAT may need `--set syn_source_rate=500 --set
syn_source_burst=1000` without being designated a proxy peer.

Peer ranges change only the packet budget. They do not trust forwarded HTTP headers or bypass
request inspection; configure `-trusted-proxies` separately for actual forwarding proxies. Source
addresses alone do not authenticate packets. Keep peer ranges narrow and administrator-owned, and
retain upstream anti-spoofing measures. Malformed packets from a peer still drop.

The Go shield caps both initial and learned connections at 80% of the process's soft descriptor
limit. Tune `-ddos-max-conns`, request floors, upstream concurrency and evaluation concurrency to
memory, CPU and TLS capacity. The supplied systemd edge unit also has `MemoryMax=2G` and
`LimitNOFILE=65536`; review these for the host.

Measure SYN backlog, accept queue and connection-tracking pressure. SYN cookies are a fallback
against attacks, not a substitute for adequate legitimate capacity. Scale multiple edges when one
server's measured capacity is insufficient; budgets are local to each node.

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

The packet test creates disposable network namespaces, an isolated origin and the actual WAF. It
refuses to load rules into the host namespace. Production source budgets are tested;
aggregate/capacity fixtures use reduced thresholds to reach exhaustion safely. CI preserves the logs
in the L3/L4 job.

See the [validation record](network-validation.md) for exact counts and controls. These tests do not
establish upstream bandwidth protection, production TLS capacity or a SYN proxy. Fragment-queue
resources remain a kernel concern because guards run after reassembly.

### Small and large deployment tests (2026-10-07)

See [profile tests](network-validation.md#small-and-large-deployment-tests-2026-10-07).

### Investigating the one-second tail

The earlier one-second delay was reproduced in an undersized test origin even without a flood.
Compare matched-concurrency runs, origin accept queues and TCP counters before raising edge budgets.
The [latency investigation](network-validation.md#investigating-the-one-second-tail) retains the
measurements and controls.
