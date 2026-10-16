# Flood protection and IDS

The Shield watches traffic across requests and limits connection/request pressure before expensive
processing. It is enabled by default in the standalone proxy.

| Mode | Behavior |
| --- | --- |
| `-ddos on` | Detect floods and apply mitigation, alongside baseline connection/request limits. |
| `-ddos monitor` | Detect and log floods; baseline limits still enforce (429), but attack-specific mitigation does not: no attack budgets, challenges or bans. |
| `-ddos off` | Remove Shield. Use this for isolated payload benchmarks, then test flood behavior separately. |

`on` and `monitor` take a [strength](#strengths) after a comma, as in `-ddos monitor,strict`; a
strength alone, as in `-ddos strict`, means `on`. The figures on this page are those of `normal`,
the default.

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

Refused connections are reset. HTTP refusals carry `Retry-After`: on a 429 for an address's or a
network's own limit it is the seconds until the next request fits that limit (1 to 3600); on the
403 of a ban, the seconds left on the ban; on a 503 for an attack's shared budget it is 5, an
estimate, as on the challenge page. The 403 for a wrong answer to the challenge has none, since a
browser may try again at once. Refusals, that 403 among them, also carry `Cache-Control: no-store`
and `Connection: close`, except on a trusted proxy's connection, which carries other
visitors' requests and stays open unless the refused request is HTTP/1 with a body still to read
(`Shield.ConnContext`, set by `Edge.Server`). The challenge page is not a refusal and leaves the
connection open. Logs are bounded
rather than written for each Shield refusal. A failed reset/socket option does not turn a refusal
into admission.

| Monitoring field | Meaning |
| --- | --- |
| `Snapshot.ConnsRefused` | Refused connections. |
| `Snapshot.WriteErrors` | Failed Shield response writes. |
| `Snapshot.SocketOptionErrors` | Failed optional socket settings, including reset linger. |
| `Snapshot.DroppedEvents` | Events not given to `Config.OnEvent`: those found while 256 were already waiting for it, and those found after `Shield.Close`. |

`Config.OnEvent` is called on the Shield's own goroutine once a second, in order, and never while a
request or connection waits on it: a log writer that stalls delays later events, never admission.
`Shield.Close` hands it the events still waiting, so those found in the last second are not lost.

## IDS signals

These alerts report patterns for investigation. They do not change attack state or add bans.

| Signal (code) | Threshold |
| --- | --- |
| Connection admission pressure (`conn_pressure`) | At least 50% of incoming TCP connections are refused. |
| Early TCP closes (`early_close`) | At least 75% of closed nontrusted connections never reached HTTP `StateActive`. |
| HTTP security rejections (`rejections`) | At least 50% of Shield-admitted requests receive a later WAF/policy 4xx. Requests the Shield refused or challenged are not in the share. Origin 4xx, gateway 5xx and 408 (a client too slow to send its request) responses are excluded. |
| Addresses held over their own limit (`held`) | Requests refused by an address's or a network's own rate limit (429), with no ratio: a scanner that sends faster than its limit is reported even when other traffic is busy. |

Each signal also needs `Detector.MinAttackRate` observations per second (default 20), averaged over
ten seconds. `Snapshot.IDSReasons` and the rate fields expose current evidence; `EarlyCloses` and
`SecurityRejections` hold totals. An `ids_signal` event carries every current reason, the code of
each in `Event.Codes`, and `Event.Mode` (`on` or `monitor`), with aggregate reasons and no request
paths/bodies, including in monitor mode. Each signal is paced on its own: an event is sent when one
of the current signals was not reported in the last 30 seconds, so a new signal is reported at once
and one that goes on is reported again every 30 seconds. Once every signal has been gone for 30
seconds an `ids_clear` event names the codes reported since the last one; a signal that crosses its
threshold back and forth is not reported each time.

TCP signals cover accepted sockets and admission refusals. Raw packets, incomplete SYN handshakes,
UDP and link saturation need [kernel packet guards](network-protection.md) or provider protection.
HTTP checks before Shield admission and pre-parser failures are outside the rejection counter.

## Detecting an attack from many addresses and countries

Every second, the detector compares a ten-second window with the site's ordinary traffic. It
combines volume with fingerprint/target concentration, new addresses, engagement and origin health.
Volume alone is logged as elevated traffic; it does not declare an attack. The `elevated` event is
sent once until the state is reported back to normal: a `normal` event follows `elevated` or
`attack_end` once the state has stayed normal for ten seconds, so a rate that hovers at the
threshold is reported as one rise.

The volume threshold is the largest of four times the baseline, baseline plus eight standard
deviations, and 20 requests/second. The baseline has a ten-minute time constant, updates whenever no
attack has been declared (elevated volume without attack evidence included) and grows by at most two
times per step. Deviation is measured from nonoverlapping ten-second windows. The usual fingerprints
and targets are learned only from seconds under the threshold, so a flood that runs over it for a
while before there is evidence does not teach the baseline its look.

The baseline is held back while the application is failing compared with its own error ratio over
about an hour (a six-times-slower average): in those seconds the usual error ratio and latency can
only fall, the usual fingerprints, targets and addresses are not learned, and the usual rate can
rise only as far as the requests the application answers well rise from when it began to fail. An
application that fails whatever the load (a broken dependency) still answers more as more people
come, so the site's own growth is followed; a flood that is more than the application can answer is
not. Latency does not
count for this: it is measured until the response has been sent, so a few clients that read slowly
could otherwise hold the baseline still while the site's own traffic grows, until that growth was
taken for an attack. Requests whose clients gave up after waiting long do count as failures (see
the evidence below).
A flood that grows slowly enough to stay under the threshold is therefore not
learned as the site's usual once it makes the application fail (or wait), and is declared when it reaches four
times the rate from before. The same applies to a real rise in visitors that the application cannot
keep up with: past four times the usual rate, with the application failing and the traffic coming
from many more addresses, it is treated as an attack, and known visitors and browsers that answer
the challenge are still served. An application that stays worse for hours is taken as it is in time.
Clients do not earn standing in those seconds either.

What a slow flood grew to while the application kept up has been learned, though, and the attack's
budgets are sized from that usual rate, so the slower the flood, the less of it the mitigation holds
off. In the simulation, on an application that serves 200 requests a second, a flood that doubles
every four minutes is declared at about 390 a second and visitors are served in full; one that
doubles every eight minutes is declared at about 560 a second with a usual rate of 146, about 115 of
it the flood's, and a third of the flood is still let in, so visitors are served about 65%.

An attack needs elevated volume plus supporting evidence held for three seconds:

- A concentrated fingerprint from at least 20 addresses.
- A concentrated target from new addresses without normal browser engagement.
- An unhealthy application with traffic from new places. A request its client abandoned, or whose
  response the proxy ended to free an upstream place, is not counted as an application error unless
  the client had waited at least a second and four times the application's usual latency: an
  application that queues what it cannot serve, instead of failing it, shows its overload only so,
  since clients give up long before the upstream time-out (30 seconds by default), while clients that hang up at
  once cannot make a healthy application look as if it were failing.

A flood of connections that carry no requests is enough on its own, held for three seconds likewise
and without a rise in requests: connections arrive at four times their usual rate (and at least 20 a
second) and at three times the request rate, from at least 20 more addresses than usually open
connections and at least twice as many. Connections the per-address limits refuse count towards the rate but add only their one
address, so a single host that opens connections as fast as it can is held by its own connection
limits and never puts the whole site into attack mode. An attack does not end while such a flood
goes on.

An attack lasts at least one minute and ends after 30 quiet seconds. It can also end after five
minutes without the evidence that triggered it. The mitigation counts as such evidence while the
rate is still over the threshold of the baseline from before the attack, at least half the requests
are refused or shown the challenge, and fewer than half as many of them as before the attack come
with a client fingerprint that was at least 0.2% of the usual requests (when the baseline knew no
fingerprint, as after a restart into the flood with `-ddos-baseline-rate`, the last condition is
left out). A flood that only showed harm, which the mitigation
takes away, is then held for as long as it goes on, while the site's own clients, who still look as
they did, never hold an attack: when they grow past the old threshold after a flood has ended (a
night's attack followed by the day's peak), the attack ends after the five minutes even though the
attack's limits refuse much of their traffic. A flood that copies the site's own mix of clients is
told from them only by the evidence above. What an address's or a network's own limit refuses is
left out of both the rate and the refusals for this, since it is held whether there is an attack or
not: one address sending more than its limit does not hold the attack. So are the refusals of banned
addresses, unless they come from at least 20 addresses in ten seconds: the bans of a botnet hold the
attack, the ban of a single address does not. The first 60 seconds are a history period; during
the remaining five-minute learning period, only a tenfold rise qualifies. Set `-ddos-baseline-rate`
when restarting into a flood; learned baseline state is not persisted. The flag seeds the rate only
and skips its learning period: the usual fingerprints, targets, addresses and application health
are still learned over their own five minutes, from seconds under the volume threshold, so a surge
of the site's own clients soon after a restart is not taken for an attack and a flood running at
the restart is not learned as the site's usual look.

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
attack budget, 403 for a wrong answer to the challenge) is banned for ten minutes, and again after
another 30 refusals if it carries on once the ban runs out. Being shown the challenge counts as a
tenth of a refusal: the many people behind one address are each shown it about once, while a bot
that loads pages at 20 a second is shown it 300 times in 15 seconds. A right answer takes back one
challenge shown, so people who are shown it and answer it add nothing to the count; the page names an
empty icon, so their browsers ask for no `/favicon.ico`, which an attack budget would refuse. One
answer can be sent many times, so answers take back no more than the address was shown, and never a refusal
or a wrong answer; a bot behind an address whose people answer is counted for what it is shown
beyond their answers. An IPv6 address is counted and banned with its /64; a trusted proxy peer is
never refused for a ban, even one on a /64 it shares.
In monitor mode nothing is banned: an address over its own limit is refused with 429 as at any other
time. The shield remembers at most 262,144 addresses and 65,536 networks (/24 or /48): with the
address table full they hold about 55 MB of live heap, and about 70 MB when the addresses are spread
over enough networks to fill the network table too. With Go's default garbage collector setting
(`GOGC=100`) the heap in use grows to about twice that (about 105 MB and 130 MB measured), which is the
figure to size a memory limit from. When the address table is full, an entry
without standing is forgotten first; a ban or a known client's standing goes only when every entry
in the sample of 32 has one. Rule IDs are 5004001
(address rate), 5004002 (network rate), 5004003 (attack cluster), 5004004 (unknown-client budget),
5004005 (challenge shown), 5004006/5004007 (failed/passed) and 5004008 (ban).

## Strengths

| Setting | `relaxed` | `normal` (default) | `strict` |
| --- | --- | --- | --- |
| Per-address rate and burst (`-ddos-rate`, `-ddos-burst`) | 100/s, 400 | 50/s, 200 | 20/s, 80 |
| Per-network rate | 1,000/s | 500/s | 500/s |
| Highest raise of a limit (`-ddos-max-raise`) | 50x | 20x | 10x |
| Known clients during an attack (`-ddos-known-factor`, `-ddos-known-rate`) | 2x, 50/s | 2x, 50/s | 2x, 50/s |
| Strangers during an attack (factor, at least) | 2x, 20/s | 1x, 10/s | 0.5x, 5/s |
| New connections per address (rate, burst) | 40/s, 120 | 20/s, 60 | 10/s, 30 |
| Ban after, for | 60 refusals, 5 min | 30, 10 min | 15, 30 min |
| Attack threshold (rate factor, sigmas, seconds to confirm, floor) | 6x, 10, 5 s, 50/s | 4x, 8, 3 s, 20/s | 3x, 6, 2 s, 10/s |

`strict` is for a small site or one that is often attacked; in a crowd taken for an attack, an
address many people share, such as a carrier's, can be banned for 30 minutes. `relaxed` is for an
API or a site with many visitors behind a carrier's addresses. The number of connections and the
challenge's difficulty are the same at every strength. The [simulations](flood-validation.md#2026-10-16-three-strengths-of-protection)
measure each one.

A setting comes from, first to last:

1. a `-ddos-*` flag on the command line;
2. the same flag in the site file's `flags`, such as `"ddos-rate": 60`;
3. the strength;
4. the built-in default.

A flag that is not given leaves the strength's value, and so does a 0 for `-ddos-rate`,
`-ddos-burst`, `-ddos-max-conns`, `-ddos-known-factor` and `-ddos-known-rate`. A rate given
alone brings a burst of at least a tenth of it and a network rate of at least ten times it, and a
burst raises its network's to at least ten times it, so `-ddos-rate 5000` is all a busy API needs.
A `-ddos-max-conns` above 250,000 raises the most the connection limit can grow to with it.
`-ddos` on the command line replaces the site file's as a whole: `-ddos monitor` over a site's
`"ddos": "strict"` is `monitor,normal`. The start-up log (and `-check`) says which applies:
`"ddos"` is the mode, `"ddos_strength"` the strength and `"ddos_overrides"` the flags that change
its settings. With `-ddos off`, `-ddos-ranges` is refused, as it needs `-ddos on` or `monitor`; the
other `-ddos-*` flags change nothing, and the log warns that they were given.

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
| `-ddos` | `on` | `on`, `monitor` or `off`, with a strength `relaxed`, `normal` or `strict` (`-ddos strict`, `-ddos monitor,strict`). |
| `-ddos-rate`, `-ddos-burst` | The strength's | Per-address request floors, with bounded automatic growth: 0.01 to 1,000,000 a second, and 1 to 10,000,000 requests at least a tenth of the rate. |
| `-ddos-max-raise` | The strength's | The most times its configured limit an address, or a network, may earn by its own well-answered requests (1 to 100). 1 keeps the limits fixed. |
| `-ddos-max-conns` | 20000 | Global connection floor, with bounded automatic growth and reserved capacity (16 to 10,000,000, still at most 80% of the process's file-descriptor limit). |
| `-ddos-known-factor`, `-ddos-known-rate` | 2, 50 | During an attack, the budget returning visitors with standing share: this many times the usual request rate (0.01 to 1,000), and at least this many a second (0.01 to 1,000,000). Raise them on a site whose regulars come in crowds. |
| `-ddos-challenge` | true | Enable browser challenges during an attack. |
| `-ddos-baseline-rate` | 0 | Learn the baseline; a value from 0.01 to 10,000,000 seeds the site's usual requests/second. |
| `-ddos-ranges` | None | ip2asn-style country/network labels for attack logs. |

A value outside its range is refused at start-up with the flag's name and range, with `-ddos off`
too; a negative one is never taken for the default.

Single-address load tests need `-ddos off` or a suitable request floor to avoid measuring their own
quota exhaustion. Flood tests need realistic client populations.
