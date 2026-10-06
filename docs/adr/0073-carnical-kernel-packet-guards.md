# ADR-0073: Carnical kernel packet guards

- **Status:** proposed
- **Date:** 2026-10-07 (expected; update before merge)
- **Version:** unreleased (post-v3.8.1)
- **PR:** No PR opened (owner-authorized Carnical development)
- **Issue(s):** No linked issue
- **Deciders:** Pending maintainer review
- **Category:** Feature

## Context and Problem

The owner requested more L3/L4 protection. The listener shield acts after TCP acceptance; the existing host policy allowed
all TCP traffic to the public port without a SYN budget before connection tracking. Echo limits could also be bypassed by
the established-connection accept rule, and placing log statements before their rate limit produced excessive logging.

## Decision Drivers

- Refuse excess SYN traffic before connection tracking allocates state.
- Bound per-source memory and prevent IPv6 address rotation from obtaining unlimited budgets.
- Keep valid TCP/ECN, IP reassembly and IPv6 discovery working.
- Observe refusals through counters without logging a line per flooded packet.
- Run live tests without modifying the host network policy.

## Considered Options

- Listener protection alone: too late to protect connection tracking against excess SYN packets.
- SYN proxy or XDP filtering: useful additional deployment choices, with separate compatibility and operational requirements.
- Extend the existing nftables policy with bounded meters and an aggregate budget at raw prerouting priority.

## Decision Outcome

Chosen: extend the existing Linux policy at priority -300, after defragmentation and before connection tracking. Positive
admission through bounded, expiring source meters is followed by an unconditional refusal, including when the set is full.
IPv6 sources share a /64 budget. The aggregate budget has no source exemption. Invalid TCP flag combinations and UDP/443
are refused separately, with named counters. Echo requests enter their own rate-limit chain before established traffic is
accepted; IPv6 control traffic has separate rules. Logging is conditional and refusal remains unconditional.

The kernel policy remains an explicit deployment step. The Go listener's capacity-accounting fixes require no Coraza API
change. A dedicated security job tests real packets, race detection and the running WAF in disposable network namespaces.

The proposed policy also supports rendered small/standard/large budgets, a configurable public port and separate bounded
meters for explicitly configured high-volume proxy peers. Every peer still consumes the aggregate budget and passes the
malformed-packet checks. Peer exhaustion cannot fall back to an ordinary source bucket. Rendering validates numeric values
and canonical peer CIDRs without loading rules. A rendered policy atomically replaces only this table, resetting its meters
and counters so profile changes and peer revocation apply immediately. The listener's initial floor also respects the process
file-descriptor ceiling. Live scaling, IPv4/IPv6, TLS, peer exhaustion and reload regressions run in the existing CI test home.

## Technical Discussion

No substantive technical discussion recorded; this record accompanies the owner-authorized change.

## Consequences

- Kernel budgets must be tuned for shared NAT/CDN peers and do not follow the shield's learned baseline.
- Profile values describe configured admission budgets, not certified throughput; deployment still needs capacity measurement.
- Rendered profiles require nftables 1.0.9 or later and kernel support for `destroy`; collect counter deltas before replacement.
- A full meter set refuses new sources until capacity is reclaimed; existing sources keep their budget.
- Packet filtering on the host cannot prevent an upstream link from being saturated or protect all fragment-queue resources.

## References

- ADR-0071: Carnical flood protection
- [Network protection and validation](../../carnical/docs/network-protection.md)
- [Netfilter hook ordering](https://wiki.nftables.org/wiki-nftables/index.php/Netfilter_hooks)
- [nftables set statements](https://netfilter.org/projects/nftables/manpage.html#_set_statement)
- [RFC 4890](https://www.rfc-editor.org/rfc/rfc4890)
