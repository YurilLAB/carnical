# L3 and L4 network protection

Carnical combines kernel packet filtering with admission checks on accepted TCP connections. The Go listener checks run
when flood protection is enabled (the CLI default); the kernel layer requires installing the Linux deployment policy.

| Layer | Protection | Default budget / monitoring |
|---|---|---|
| Before connection tracking | SYN packets to the local public TCP endpoint, after IP reassembly | 10,000/s across IPv4 and IPv6, burst 20,000; `edge_syn_global_drop` |
| Before connection tracking | Per-source SYN budget, including IPv6 address rotation within a /64 | 100/s per IPv4 address or IPv6 /64, burst 200; `edge_syn_source_drop` |
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
still consumes the kernel's source and aggregate budgets. Ensure the configured public port matches the listener.
Keep management access available while installing the existing default-drop host policy. Loading this file affects
the host's networking; running the test below affects only disposable namespaces.

Early refusals increment counters without a log message per packet. General input refusals count in `input_denied`;
`input_logged` measures the log budget (5/minute, burst 5). Egress refusals retain their existing log prefixes with a
10/minute, burst-10 budget per refusal chain. Every refusal chain drops unconditionally after its conditional log rule,
so exhausting logging capacity cannot admit traffic. `egress_private_drop`, `egress_imds_drop`, `egress_edge_drop` and
`egress_internal_drop` count those refusals. Export these counter deltas into the deployment's monitoring.
Normal policy reloads retain named counters/meters; removing the table resets their state.

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

## References

- [Netfilter hook ordering](https://wiki.nftables.org/wiki-nftables/index.php/Netfilter_hooks): raw priority -300 follows
  defragmentation and precedes connection tracking.
- [nftables dynamic-set documentation](https://netfilter.org/projects/nftables/manpage.html#_set_statement) and
  [meters](https://wiki.nftables.org/wiki-nftables/index.php/Meters): bounded, expiring keys and per-key rate limits.
- [RFC 4890](https://www.rfc-editor.org/rfc/rfc4890): IPv6 error and discovery traffic must be treated deliberately when filtering.
- [Linux IPv6 input implementation](https://github.com/torvalds/linux/blob/v6.18/net/ipv6/ip6_input.c): early rejection of
  multicast sources and loopback addresses on non-loopback interfaces.
