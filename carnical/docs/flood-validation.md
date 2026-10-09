# Flood validation record

These results use the recorded simulation/live fixtures. They explain the detector's tested
behavior and previous fixes; they are not production capacity guarantees.
For current settings, see [flood protection and IDS](ddos.md).

Measured (`TestASiteWithMuchTrafficIsNotLimitedAsIfItWereSmall`): a site serving 1,200 requests a second, half of its returning
visitors behind four shared addresses of about 120 requests a second each. The per-address limit rose 11.3x and the per-network
limit 3.8x, and 99.9% of returning visitors were served. With the limits fixed (control) 71% were. An attack of 8,000 requests a
second from 25,000 addresses on that site was detected after 8 s, 0.30% of it reached the application, and 100% of returning and
new visitors were served. A sudden tripling of real traffic was not flagged.

The adjustment is bounded, so it cannot be turned into an opening: one address that sends a lot for a long time raises its own
limit by at most 20x, a rise is learnt at most twice per step, and nothing is learnt during an attack.

The 80% file-descriptor ceiling applies to the initial connection floor as well as later growth. A small process with a soft
limit of 1,024 therefore admits at most 819 shield connections before the reserved share, even with the default 20,000 floor.
This ceiling leaves some descriptor headroom; it is not a memory or CPU budget. Set `-ddos-max-conns` lower when necessary,
and measure origin sockets, TLS handshakes, rule evaluation and memory use before raising it on a large edge. Kernel packet
budgets are configured separately; see [deployment profiles and live scaling tests](network-protection.md#choosing-a-budget).

## Measured

Simulation (`shield/sim_test.go`, simulated clock, the real `Admit`/`Done`, an application that can serve 200 requests a
second, 32 requests a second of ordinary traffic from 400 returning and many new visitors with six browsers):

| Scenario | Detected after | Attack admitted after detection | Returning visitors served | New visitors served |
|---|---|---|---|---|
| 20,000 addresses in 30 countries, 5,000 req/s, cache-busting `/` | 4 s | 0.10% | 100% | 100% |
| Same, `-ddos monitor` (control) | 4 s | — (not mitigated) | 3.1% | 3.1% |
| 30,000 addresses copying a real Chrome browser exactly, 3,000 req/s to `/search` | 4 s | 0.17% | 100% | 100% |
| Low and slow: 10,000 addresses, one request each every 20 s | 5 s | 1.0% | 100% | 100% |
| Busy site (1,200 req/s, half its returning visitors behind 4 shared addresses): 8,000 req/s from 25,000 addresses | 8 s | 0.30% | 100% | 100% |
| Busy site, real traffic suddenly 3x (negative control) | never flagged | — | 100% | 100% |
| Flash crowd of real people, 10x the visits (negative control) | never (stays "elevated") | — | — | 100% |
| A crowd to one article whose assets are on another host | treated as an attack | — | 100% | 100% (through the check) |

The attack record estimated the first botnet at 20,421 addresses (true 20,000) in 106 country/network labels.

Live (`proxy/shield_linux_test.go`, Linux): the real proxy and listener, 1,000 bot addresses (127.1.x.y; Linux routes all of
127/8 to loopback) sending about 500 requests a second, 20 regular visitors. Detected 3.0 s after the flood began; after
detection 180 of 180 visitor requests were served and 17 of 21,751 flood requests reached the application (0.08%). With
`-ddos monitor` (control) all 22,767 flood requests reached it.

Two flaws were found later, by testing a busy site and a site whose traffic is one app calling one endpoint, and are fixed. The
detector had a fixed floor of 50 requests a second and a baseline that started at zero, so a bursty busy site was declared under
attack in its first seconds, the baseline froze, and the attack could not end because the traffic never fell (reproduced:
1,197 of 1,200 seconds "in attack", baseline stuck at 7 requests a second). Now there is a learning period, an evidence-based way
out (an attack that shows none of the evidence that declared it for 5 minutes ends even if traffic has not fallen), and the
limits above. The test removes all four safeguards at once and fails; with them it passes.

The first live run found a hole the simulation did not: with a one-second reputation age, bots earned "known" standing in the
2.5 seconds before detection, and 85% of the flood got through. Standing is now learnt only while traffic is ordinary, and
during an attack only standing earned at least `KnownMinAge` before the attack began counts.


## 2026-10-10: Reproducible cardinality checks

`TestHLLEstimatesWithinAFewPercent` now uses deterministic SHA-256 hash fixtures for 50, 5,000 and 200,000 distinct inputs, retaining the 8% error limit. Production address hashing still uses its random process seed. HyperLogLog has [statistical estimation error](https://algo.inria.fr/flajolet/Publications/FlFuGaMe07.pdf), so a fresh random seed cannot guarantee the same error on every test run. A 100-seed diagnostic produced three estimates outside 8%.

The same test also checks register-index and rank boundaries, duplicate address hashing, merge preservation, reset and finite estimates. Manual negative controls disabled register updates, removed the rank sentinel, or returned NaN; each was rejected. The live flood and detector tests continue to exercise production address hashing.
