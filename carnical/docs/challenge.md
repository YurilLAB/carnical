# Person check

Carnical has a place for a check that a visitor is a person, such as an "I'm not a robot" page: package `challenge`
and `proxy.Config.Challenge`. Carnical does not include such a check. Without one, nothing on this page applies and
the proxy works as before.

## Where the check is called

The proxy calls the check at two points of a request:

| Point | When | If the check does not answer |
| --- | --- | --- |
| `challenge.Admission` | During an attack, the [flood shield](ddos.md) would show its challenge to a page load, or refuse a stranger over the attack's budget | The shield's own answer stands: its challenge page, or 503 |
| `challenge.Request` | The request passed the shield, the [bot policy](bots.md) and the request policy (host, path, headers, rate rules); its body has not been read yet | The request goes on to be inspected and forwarded |

A request the check answers goes no further. It is never forwarded to the application. A check that writes anything
has answered, even if it says it did not.

These are never offered to the check, and are refused as before:

- an address the shield has banned, or an address or network over its own rate;
- a kind of client the bot policy refuses (at both points);
- at the request point, anything the request policy refuses. At admission the request policy has not run yet: a
  request the check lets go on still faces it, and the check's answer is all such a request gets.

## What the check is told

`challenge.Signals` says what the other layers found:

| Field | What it is |
| --- | --- |
| `Point` | `Admission` or `Request` |
| `Client` | The visitor's address, through [trusted proxies](proxy-reference.md) |
| `Kind` | What kind of client the request says it is, as the bot policy reads it (`person`, `tool`, `disguised`, ...). At admission the bot policy has not run yet, so it is what the request's headers say, without the search engine check |
| `Watched` | The bot policy reports this kind as one it would refuse (`-bots-monitor`) |
| `Attack` | The shield is defending against an attack now |
| `Known` | The shield knows the address from ordinary use before the attack: requests the application answered well. The check's own answers earn no standing |
| `Strikes` | Refusals the address has had in the current attack |
| `Relayed` | A trusted proxy relayed the request; its address carries other visitors too |

## What the check reports

Before it writes an answer that carries a decision, the check calls `report` once with a `challenge.Outcome`. A
second report, or one after `Serve` has returned, is ignored.

| Verdict | What the proxy does |
| --- | --- |
| `Shown` | Nothing: showing the check is not a finding about the visitor |
| `Passed` | With a shield, sets the shield's clearance cookie (`carnical_clr`), so that this browser, from this address, is admitted through an attack as one that answered the shield's challenge. During an attack, the address is forgiven one showing of the shield's challenge, and at admission the refusal of the answer itself, which the check stood in for. No other refusal is forgiven |
| `Refused` | An alert, rule 5007001 (`challenge-5007001`), with the score and the check's reason. At the request point it is also a log line. At admission it has no line of its own, since a flood can bring many: the shield has already counted the refusal it would have made |

The reason is the check's own short text. The alert keeps up to 64 bytes of it: letters, digits, spaces and
`-+:,.`. Answer a refusal with a 4xx status, so that the shield counts it at the request point as it counts the
proxy's other refusals.

## What the proxy does to the check's answers

- Every answer is sent with `Cache-Control: no-store` and `X-Content-Type-Options: nosniff`: it is about one visitor.
- At admission, an answer in place of the shield's refusal closes the connection, as the refusal would have, unless
  a trusted proxy relayed it.
- The check reads the request body through the site's own body limit (`-max-form-body`, or `-max-body` for a file
  upload). It should read the body only for a request it answers.

## What the site says back

A check that is also a `challenge.Responder` sees the header of each response the application gives, before the
proxy forwards it and before the proxy's response hardening, with the request as the visitor sent it. That is how a
site can tell the check that a visitor proved to be a person, for example by signing in with a second factor, so that
the check can learn from it. The check should remove such a header, which is not meant for the visitor.

## Writing a check

```go
type gate struct{}

func (gate) Serve(w http.ResponseWriter, r *http.Request, s challenge.Signals, report func(challenge.Outcome)) bool {
	if !needsCheck(r, s) {
		return false // let it go on
	}
	// ... show the page, or judge its answer ...
	report(challenge.Outcome{Verdict: challenge.Passed, Score: 4})
	w.WriteHeader(http.StatusOK)
	return true
}

cfg.Challenge = gate{}
```

`Serve` runs for every request that reaches a point, on the request's goroutine, so it must be quick for the
requests it lets go on. During an attack, the check's answers are held to the shield's per-address and per-network
rates. Over the attack's budget, though, they are offered to the check rather than refused, so the check must bound
its own work, for example by limiting answers per network.
