# Flood protection and IDS

The Shield watches traffic across requests and limits connection/request pressure before expensive
processing. It is enabled by default in the standalone proxy.

| Mode | Behavior |
| --- | --- |
| `-ddos on` | Detect floods and apply mitigation, alongside baseline connection/request limits. |
| `-ddos monitor` | Detect and log floods; baseline limits still enforce (429), but attack-specific mitigation does not: no attack budgets, challenges or bans. |
| `-ddos off` | Remove Shield. Use this for isolated payload benchmarks, then test flood behavior separately. |

Source: [Shield](../shield/shield.go), [listener](../shield/listener.go),
[detector](../shield/detect.go), [CLI wiring](../cmd/carnical/shield.go).

## Where it acts

| Stage | Protection |
| --- | --- |
| TCP admission | Per-address connection rate, live subnet counts, a global cap and reserved capacity for known clients. |
| Socket tuning on Linux | `TCP_DEFER_ACCEPT` (10s) delays handing silent connections to the proxy; `TCP_USER_TIMEOUT` (30s) limits stalled acknowledgements. Server deadlines still apply. |
| Request admission | Per-address and subnet budgets; during an attack, shared budgets for known clients, matching traffic and unknown clients. |
| Response observation | Status and timing inform the detector and client reputation. |

Connections are reserved atomically across listeners sharing a Shield. Live subnet counts are
separate from request-history tables, so address-history eviction cannot reset occupied capacity.
The last socket closes its subnet entry. Trusted proxy peers may use the reserved share and bypass
source/subnet limits, but still share the global cap.

Refused connections are reset. HTTP refusals return 429 or 503 with `Retry-After`, `Cache-Control:
no-store` and `Connection: close`, except on a trusted proxy's connection, which carries other
visitors' requests and stays open unless the refused request is HTTP/1 with a body still to read
(`Shield.ConnContext`, set by `Edge.Server`). Logs are bounded
rather than written for each Shield refusal. A failed reset/socket option does not turn a refusal
into admission.

| Monitoring field | Meaning |
| --- | --- |
| `Snapshot.ConnsRefused` | Refused connections. |
| `Snapshot.WriteErrors` | Failed Shield response writes. |
| `Snapshot.SocketOptionErrors` | Failed optional socket settings, including reset linger. |

## IDS signals

These alerts report patterns for investigation. They do not change attack state or add bans.

| Signal | Threshold |
| --- | --- |
| Connection admission pressure | At least 50% of incoming TCP connections are refused. |
| Early TCP closes | At least 75% of closed nontrusted connections never reached HTTP `StateActive`. |
| HTTP security rejections | At least 50% of Shield-admitted requests receive a later WAF/policy 4xx. Origin 4xx, gateway 5xx and 408 (a client too slow to send its request) responses are excluded. |

Each signal also needs `Detector.MinAttackRate` observations per second (default 20), averaged over
ten seconds. `Snapshot.IDSReasons` and the rate fields expose current evidence; `EarlyCloses` and
`SecurityRejections` hold totals. The CLI emits `ids_signal` at most once every 30 seconds per
Shield, including in monitor mode, with aggregate reasons and no request paths/bodies.

TCP signals cover accepted sockets and admission refusals. Raw packets, incomplete SYN handshakes,
UDP and link saturation need [kernel packet guards](network-protection.md) or provider protection.
HTTP checks before Shield admission and pre-parser failures are outside the rejection counter.

## Detecting an attack from many addresses and countries

Every second, the detector compares a ten-second window with the site's ordinary traffic. It
combines volume with fingerprint/target concentration, new addresses, engagement and origin health.
Volume alone is logged as elevated traffic; it does not declare an attack.

The volume threshold is the largest of four times the baseline, baseline plus eight standard
deviations, and 20 requests/second. The baseline has a ten-minute time constant, updates whenever no
attack has been declared (elevated volume without attack evidence included) and grows by at most two
times per step. Deviation is measured from nonoverlapping ten-second windows.

An attack needs elevated volume plus supporting evidence held for three seconds:

- A concentrated fingerprint from at least 20 addresses.
- A concentrated target from new addresses without normal browser engagement.
- An unhealthy application with traffic from new places. A request its client abandoned, or whose
  response the proxy ended to free an upstream place, is not counted as an application error.

A flood of connections that carry no requests is enough on its own, held for three seconds likewise
and without a rise in requests: connections arrive at four times their usual rate (and at least 20 a
second) and at three times the request rate, from at least 20 more addresses than usually open
connections and at least twice as many. Connections the per-address limits refuse count towards the rate but add only their one
address, so a single host that opens connections as fast as it can is held by its own connection
limits and never puts the whole site into attack mode. An attack does not end while such a flood
goes on.

An attack lasts at least one minute and ends after 30 quiet seconds. It can also end after five
minutes without the evidence that triggered it. The first 60 seconds are a history period; during
the remaining five-minute learning period, only a tenfold rise qualifies. Set `-ddos-baseline-rate`
when restarting into a flood; learned baseline state is not persisted.

## Limits that follow your traffic

The limits of an address, and of a network, grow to follow that address's or network's own traffic,
so that many visitors behind one company or carrier address are not limited as if they were one
person. Each has a moving average of the requests a second that the application answered well for
it (a status under 400, from the application and not from the proxy), kept in every second that is
not an attack's and with the weight the warmed-up baseline gives a second; its request limit is
four times that average when that is more than the configured floor, up to the ceiling, and its
connection limits rise by the same factor. What one address has earned raises no other address's
limit, and an address that is refused, or answered with errors, earns nothing. The average neither
grows nor fades during an attack, fades when the address stops sending, and is taken away by a ban.
A sudden rise counts for at most twice the average, from the first second after every start, so a
higher limit takes minutes of ordinary use to earn, whether or not `-ddos-baseline-rate` is set.
After a restart an address with many visitors behind it is therefore held to its configured limit
for a while: in the busy-site simulation, shared addresses that need 2.4 times the floor take about
20 minutes to earn it. Nonfinite rates/scaling settings are rejected during configuration.

An address raises its own limit by using it, so the ceiling is the real limit of an address that is
patient. Measured with one address that takes everything it is given, on a site the detector knows
and right after a start without a baseline alike: it is still at its configured limit after 5
minutes, at twice it after about 15, at ten times after 30, and at the default ceiling of 20 times
after 40. `-ddos-max-raise` sets the ceiling, from 1 to 100; with 1 every address and network stays
at its configured limit, which suits a site whose visitors do not come in numbers from behind one
address.

IPv6 clients are counted by /64 and their networks by /48, as IPv4 clients are by address and /24,
in the limits and in the detector alike: new addresses, the number of different addresses, the
addresses behind a fingerprint or opening connections, and an attack's record all count one /64
once, so one host cannot look like a botnet by changing the last 64 bits of its address. A
/48 is the largest block one site is given and what a provider divides among some hundreds of home
lines, which is what a /24 is to IPv4; a network tier at /56 would hand the holder of one /48 256
network budgets, and at /64 as many as it has clients.

| Limit | Default floor | Growth ceiling |
| --- | --- | --- |
| Requests per address | 50/s, burst 200 | 20 times the configured floor. |
| New connections per address | 20/s, burst 60 | 20 times the configured floor. During an attack, unknown clients get one quarter of the normal rate. |
| Requests per IPv4 /24 or IPv6 /48 | 500/s | 20 times the configured floor. |
| Connections per /24 or /48 | 1,024 | 20 times the configured floor. |
| Total connections | 20,000; one fifth reserved | Follows twice average occupancy, up to 250,000 and 80% of the process's soft descriptor limit. |
| Matching traffic during an attack | 5 requests/s in total | Follows 2% of the site's usual rate. |

The descriptor ceiling applies at startup too: a soft limit of 1,024 permits at most 819 Shield
connections before the reserved share. It leaves descriptor headroom but is not a CPU/memory budget.
Tune `-ddos-max-conns`, origin sockets, TLS and evaluation concurrency from measurements. Kernel
packet budgets are [configured separately](network-protection.md#choosing-a-budget).

## Clients that stop reading

At most `-max-upstream` requests (default 256) are at the application at once, and a request keeps its place until its
response has been written to the client. A client that opens requests for large responses and then reads nothing (an HTTP/2
stream window of zero, or a full TCP window) would hold those places until the write timeout (120 seconds by default), and
every other visitor would be told the site is busy. Reproduced: with the places all held this way, another client got 503
for as long as the client kept it up.

Now, when no place is free, the response whose write has been stuck the longest, and for at least five seconds, is ended and
its place goes to the waiting request at once, and its request to the application is cancelled at the same moment, so the
application never has more requests than places. A slow client is left alone while there are places to spare. An HTTP/1
connection is dropped at that moment, without the TLS goodbye a client that is not reading would never take and without
what the kernel had still to send it, so the client sees a reset and nothing of the connection is left; an HTTP/2 stream
is reset and its connection stays for the client's other requests. At most an eighth of the places can be ending at once; a
request that finds none to take gets the usual 503. Each case is logged as rule 5000052. The limits are fixed, and what they
cost a legitimate client is a download cut short when it had stopped taking data for five seconds while the whole site was
at its limit.

## Who still gets through during an attack

- **Known clients** earned five successful requests over at least a minute of ordinary traffic.
  Standing earned in the minute before an attack does not count, and a trusted proxy peer earns none
  for its address (or its /64, which other clients may share). This is reputation, not authentication:
  known clients share a budget of twice the site's usual rate (at least 50 requests/second), and beyond
  it are treated like any other client.
- **Browser challenges** let an unknown browser outside the budget solve a JavaScript SHA-256
  puzzle (17 leading zero bits) for a cookie tied to its address/browser for 30 minutes.
- **Other clients** share a budget equal to the site's usual rate. API clients receive 503 and
  `Retry-After` rather than a challenge page.

An address refused 30 times during an attack (429 for its own or its network's limit, 503 for an
attack budget) is banned for ten minutes, and again after another 30 refusals if it carries on once
the ban runs out. Being shown the challenge counts as a tenth of a refusal: the many people behind
one address are each shown it about once, while a bot that loads pages at 20 a second is shown it
300 times in 15 seconds. A right answer takes back one challenge shown, so people who are shown it
and answer it add nothing to the count; the page names an empty icon, so their browsers ask for no
`/favicon.ico`, which an attack budget would refuse. One answer can be sent many times, so answers take back no
more than the address was shown, and never a refusal; a bot behind an address whose people answer
is counted for what it is shown beyond their answers. An IPv6 address is counted and banned with its
/64; a trusted proxy peer is never refused for a ban, even one on a /64 it shares. In monitor mode nothing is banned: an address over
its own limit is refused with 429 as at any other time. When the address table is full, an entry
without standing is forgotten first; a ban or a known client's standing goes only when every entry
in the sample of 32 has one. Rule IDs are 5004001
(address rate), 5004002 (network rate), 5004003 (attack cluster), 5004004 (unknown-client budget),
5004005 (challenge shown), 5004006/5004007 (failed/passed) and 5004008 (ban).

## Measured

See [flood validation](flood-validation.md) for simulation and live results, including controls and
previous defects. Those results measure their recorded workload, not production capacity.

## What it cannot do

- A saturated uplink needs provider-side mitigation; traffic fills it before reaching the host.
- The Go listener does not install packet rules. [Linux SYN/UDP guards](network-protection.md)
  and deployment SYN cookies must be installed separately.
- A patient botnet can earn reputation by behaving normally before attacking. The known-client
  budget caps what that standing lets through; beyond it the bots are challenged or refused like
  strangers, and an address banned for repeated refusals loses its standing. Known clients share one budget, so a botnet with
  standing can use it up; returning visitors are then challenged like anyone else, and an API client that cannot answer a challenge
  is refused.
- Standing and a higher limit go to an address, not to a person, and patience earns both: an
  address that is answered well for tens of minutes earns up to 20 times the floor for itself (not
  for any other address), and one that asks for a few pages over a minute is known. Nothing told
  by an address can tell a patient bot from a visitor; what either earns is bounded by the ceiling
  (`-ddos-max-raise`, which can be 1) and the known-client budget, and is lost with a ban.
- A single-page crowd with assets on another host may resemble a targeted flood and trigger challenges.
- A crowd of returning visitors taken for an attack shares the known-client budget (twice the usual rate, at least 50 requests a second):
  beyond it they are challenged like anyone else. A browser that answers the challenge is served; a client that cannot (an API
  client) is refused, and 30 refusals ban its address for ten minutes. A site whose regulars arrive in crowds can raise the budget
  with `-ddos-known-factor` and `-ddos-known-rate`.
- State belongs to each process. Plan [replica behavior](availability-and-deployment.md#state-and-replica-contracts).

## Flags

| Flag | Default | Meaning |
| --- | --- | --- |
| `-ddos` | `on` | `on`, `monitor` or `off`. |
| `-ddos-rate`, `-ddos-burst` | 50, 200 | Per-address request floors, with bounded automatic growth. |
| `-ddos-max-raise` | 20 | The most times its configured limit an address, or a network, may earn by its own well-answered requests (1 to 100). 1 keeps the limits fixed. |
| `-ddos-max-conns` | 20000 | Global connection floor, with bounded automatic growth and reserved capacity. |
| `-ddos-known-factor`, `-ddos-known-rate` | 2, 50 | During an attack, the budget returning visitors with standing share: this many times the usual request rate, and at least this many a second. Raise them on a site whose regulars come in crowds. |
| `-ddos-challenge` | true | Enable browser challenges during an attack. |
| `-ddos-baseline-rate` | 0 | Learn the baseline; a positive value seeds the site's usual requests/second. |
| `-ddos-ranges` | None | ip2asn-style country/network labels for attack logs. |

Single-address load tests need `-ddos off` or a suitable request floor to avoid measuring their own
quota exhaustion. Flood tests need realistic client populations.
