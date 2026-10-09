# Flood protection (`shield`)

Coraza and the Core Rule Set judge one request at a time, so they cannot see a flood. The shield (`carnical/shield`) sees the
traffic as a whole. It is on by default in `cmd/carnical` (`-ddos on`). `-ddos monitor` detects and logs attacks without
applying attack-specific mitigation; baseline per-address, per-network and connection capacity limits still apply.
`-ddos off` removes the shield. For payload-detection benchmarks, use `off` so single-source load generation does not
exhaust connection or request budgets; test flood mitigation separately with realistic client populations.

## Where it acts

| Point | What it does | Rule IDs |
|---|---|---|
| Connection accepted (`Shield.Listener`) | Per-address connection rate (20/s, bursts of 60; a quarter of that for strangers during an attack). At most 1,024 connections per /24 (IPv4) or /48 (IPv6). At most 20,000 connections, with a fifth kept back for known clients. When connections run short, idle keep-alive connections of unknown clients are closed first. Banned addresses are reset at once. A refused connection is reset (RST), so it leaves no TIME_WAIT. | connection refusals are counted, not logged one by one |
| Socket (Linux) | `TCP_DEFER_ACCEPT` (10 s): delays handing silent connections to the proxy until data arrives or the kernel timeout expires; server read deadlines are still required. `TCP_USER_TIMEOUT` (30 s): a client that stops acknowledging data (slow read, zero window) is dropped by the kernel. | |
| Request, before any other check (`Shield.Admit`) | At least 50 requests a second per address (bursts of 200) and 500 per /24 or /48, at all times; these rise automatically to follow the site's own busiest addresses and networks (see "Limits that follow your traffic"). During an attack: requests that look like the attack share 5 a second in total; clients the shield does not know share the site's usual rate; known clients and browsers that passed the check go on as normal. Addresses refused 30 times during an attack are banned for 10 minutes. | 5004001 address rate, 5004002 network rate, 5004003 attack cluster, 5004004 unknown-client budget, 5004005 check shown, 5004006/5004007 check failed/passed, 5004008 banned |
| Response (`Shield.Done`) | Status and time from the application: how clients become known, and how the detector sees the application struggling. | |

A refusal is 429 (rate) or 503 with `Retry-After`, `Cache-Control: no-store` and `Connection: close`. The shield never writes
a log line per refused request (in a flood that is a second flood, into the log); it writes a few lines per attack.

Connection capacity is reserved atomically across every listener that shares a `Shield`. Live counts per /24 or /48 are
kept separately from the bounded request-history tables, so churn through many addresses cannot reset them. Closing the
last socket removes the network's live entry; these entries are bounded by admitted sockets. Trusted CDN/load-balancer
peers bypass source and subnet limits and may use the reserved share, but still share the global connection cap. Refusals
remain available as `Snapshot.ConnsRefused`, without one log entry per socket. Non-finite rates and scaling settings are
rejected at configuration time. `Snapshot.WriteErrors` counts failed shield response body writes, and
`Snapshot.SocketOptionErrors` counts failures to apply optional TCP settings (including reset linger). A failure does not
turn a refusal into admission. Socket tuning is best effort; server read/write deadlines remain required.

## IDS signals

The shield also reports observation-only signals independently of flood mitigation:

- IP/network connection admission pressure: at least half of incoming TCP connections are refused by the admission guards.
- Early TCP closes: at least three quarters of closed nontrusted connections never reached HTTP activity (Go's StateActive).
- Rejected HTTP probes: at least half of shield-admitted requests receive a 4xx from a later WAF or policy check. Origin 4xx responses and gateway 5xx failures are excluded.

Each signal also needs at least Detector.MinAttackRate observations per second (default 20), averaged over ten seconds. Snapshot.IDSReasons and its connection/rejection rates expose current evidence; EarlyCloses and SecurityRejections count totals. The CLI logs ids_signal events at most once every 30 seconds per shield, including in monitor mode. Events contain aggregate reasons, without request bodies or paths. They indicate activity to investigate; they never change attack state or add bans. Normal short-lived connections and application errors remain allowed by these signals.

The connection signals observe accepted TCP sockets and admission refusals. Raw IP packets, incomplete SYN handshakes, UDP and link saturation remain the domain of the [Linux packet guards](network-protection.md) and provider-side protection. HTTP checks before shield admission and pre-parser failures are outside the rejection counter.

## Detecting an attack from many addresses and countries

A botnet of home routers, cameras and phones sends from tens of thousands of addresses, each slower than any per-address
limit. Per-address limits do not see it. The detector looks, every second, at the last ten seconds against a baseline (a
moving average with a 10-minute time constant, learnt only while traffic is ordinary):

| Signal | Attack looks like | People look like |
|---|---|---|
| Volume | above the site's own normal: the largest of 4x its moving average, its average plus 8 standard deviations of its own recent rates, and a floor of 20 requests a second (the floor only matters to small sites) | same, during a newsletter or a shared post |
| Fingerprint concentration (client program, header set, TLS settings) | one fingerprint is suddenly most of the traffic, from many addresses | the usual mix of browsers |
| Target concentration (path with numbers, IDs and query values removed) | one target, often with random query strings to get past caches | spread over pages and assets |
| New addresses | most requests from addresses never seen before | some |
| Engagement | a new address asks for one thing and nothing else | a page, then its CSS, scripts and images |
| Application health | errors or slow answers | — |

The average is a moving average with a 10-minute time constant, updated only while traffic is ordinary and never by more than
double in one step, so an attack cannot teach the detector that it is normal, and a site's daily rise and fall is followed. The
standard deviation is the site's own, measured between ten-second rates that do not overlap, so a steady rise is not mistaken for
noise: on a steady site the threshold is 4.0x the average, on a bursty one (measured: bursts of 5 seconds at 10x every 37
seconds) it is 6.8x. Nothing is declared in the first 60 seconds after start (`MinHistory`), and until the 5-minute learning period is over
only a rise of 10x counts.

Volume alone is "elevated" (logged, nothing done). Volume with a concentrated fingerprint from at least 20 addresses, or a
concentrated target from new addresses that do not behave like browsers, or an application in trouble with traffic from new
places, held for 3 seconds, is an attack. An attack lasts at least a minute and ends after 30 quiet seconds.

## Limits that follow your traffic

A fixed limit is right for a small site and wrong for a busy one: a company or a mobile carrier puts thousands of people behind
one address, and a limit of 50 requests a second per address, sensible for one person, refuses them. So each limit is a floor,
raised while traffic is ordinary to 4 times the moving average of the busiest address's (or network's) request rate, at most 20
times the configured limit:

| Limit | Floor | Follows | Ceiling |
|---|---|---|---|
| Requests per address, and new connections per address | 50 a second (bursts of 200), 20 connections a second | the busiest address's average rate | 20x |
| Requests per /24 or /48, and connections per /24 or /48 | 500 a second, 1,024 connections | the busiest network's average rate | 20x |
| Connections at once | 20,000 | twice the average number open | 250,000, and 80% of the process's file-descriptor limit (raise `LimitNOFILE` in the unit before expecting more than 52,000) |
| Look-alike requests during an attack | 5 a second in total | 2% of the site's usual rate | |

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

## Who still gets through during an attack

- **Known clients:** 5 successful requests spread over at least a minute, while traffic was ordinary. A standing earned in the
  minute before the attack began does not count, so bots cannot earn it in the seconds before detection.
- **Browsers that pass a check:** an unknown browser that falls outside the budget gets a small page that finds a SHA-256
  answer in JavaScript (17 leading zero bits, about a second on a phone) and earns a cookie bound to its address and browser for
  30 minutes. Nothing is stored on the server. The page's JavaScript is tested against Go's SHA-256.
- **Everyone else** shares a budget equal to the site's usual rate. API clients are never shown the page; they get 503 with
  `Retry-After`.

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

## What it cannot do

- **Floods bigger than the network link** fill the link before they reach this machine. Only the hosting provider's network
  (its DDoS protection) or an upstream scrubbing service can stop those. Ask the provider what volumetric protection the
  server's network has.
- **Packet floods below TCP** are handled separately by the [Linux deployment policy](network-protection.md): bounded SYN
  budgets before connection tracking, malformed TCP filtering and UDP/443 refusal. SYN cookies are also configured in
  `deploy/sysctl/90-carnical.conf`. These layers require deployment; the Go listener alone does not install kernel rules.
- **A patient botnet** that uses the site normally for minutes before attacking can earn known standing. Per-address limits
  still apply to it, and 30 refusals during an attack remove the standing.
- **A restart during an attack** relearns the baseline from the attack, and for the first 60 seconds nothing is declared an
  attack (only the per-address limits apply); for the next four minutes only a 10x rise counts. Give `-ddos-baseline-rate` (the
  site's usual requests a second) to start from a known value. Saving the baseline across restarts is not done.
- **Assets on another host:** a crowd to one page is then indistinguishable from a single-target flood and is treated as an
  attack; people get through by the check (measured above), at the cost of a one-second page.
- State is per process: several edges each keep their own.

## Flags

| Flag | Default | |
|---|---|---|
| `-ddos` | `on` | `on`, `monitor` or `off` |
| `-ddos-rate`, `-ddos-burst` | 50, 200 | the least requests per address allows; raised automatically on a busy site, up to 20x |
| `-ddos-max-conns` | 20000 | the least connections at once allows (a fifth reserved for known clients); raised with the site's average, up to 250,000 |
| `-ddos-challenge` | true | the browser check during an attack |
| `-ddos-baseline-rate` | 0 (learn) | the usual requests a second |
| `-ddos-ranges` | none | an ip2asn-style table (from iptoasn.com, public domain) so attack logs name countries and networks |

Load tests from one address (such as `tools/loadtest`) need `-ddos off` or a higher `-ddos-rate`.
