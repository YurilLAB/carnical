# ADR-0095: A hook for a person check in the Carnical proxy

- **Status:** proposed
- **Date:** 2026-10-19 (expected; update before merge)
- **Version:** unreleased (post-v3.8.1)
- **PR:** No PR opened (owner-authorized Carnical development)
- **Issue(s):** No linked issue
- **Deciders:** Pending maintainer review
- **Category:** Feature

## Context and Problem

Carnical can tell a visitor is suspicious in several places. The bot policy reads what kind of client sent a
request (ADR-0087), the flood shield knows when the site is under attack and which addresses it knows from ordinary
use, and the proxy sees every request before the application does. But the only way it can ask a visitor to prove
they are a person is the shield's own work challenge, during an attack, for page loads. That challenge proves a browser
ran some JavaScript, not that a person is behind it. The owner asked for a check of the "I'm not a robot" kind to be
built on those parts, with the check itself kept outside this repository.

## Decision Drivers

- The check is not part of Carnical: the proxy must call it without knowing how it works, and must work as before
  without one.
- Nothing a layer refuses today may reach the check instead. A ban, an address or network over its own rate, a kind
  of client the bot policy refuses and a request the request policy refuses are refused as before.
- What the other layers know should reach the check, so that it can be stricter with a visitor they doubt, and what
  the check decides should reach them: a refusal is an alert, and a person it accepts should not be held back by the
  shield for the rest of an attack.
- No request data in alerts beyond what the proxy already allows.

## Considered Options

- **A middleware the integrator puts in front of the proxy.** Needs no change here, but it runs before the shield and
  the bot policy, so it knows nothing of what they found, and the shield goes on refusing the people it accepted.
- **A hook at two points of the proxy (chosen).** A `challenge.Gate` in `proxy.Config`, offered the requests the
  shield would challenge or refuse as strangers over an attack's budget, and every request that passed the shield,
  the bot policy and the request policy. It is told what those layers found, and reports what it decided.
- **A hook only in place of the shield's challenge.** Simpler, but a site that wants the check outside an attack
  (a login page, a visitor the bot policy watches) could not have it.

## Decision Outcome

Chosen: **a hook at two points**, because it is the only option where the check both hears from the other layers and
is heard by them, while every existing refusal stands.

- Package `challenge` defines `Gate`, `Signals` (the point, the visitor's address, the bot policy's kind and whether
  it watches it, the shield's attack state, the address's standing and its strikes in the attack, and whether a
  trusted proxy relayed it), `Outcome` and `Verdict` (shown, passed, refused).
- At admission, the proxy offers the check a decision for which `shield.Decision.Wants` is true: the shield's
  challenge, or a stranger refused over an attack's budget, which a person behind a busy address can be, unless the
  bot policy refuses the kind of client the request says it is (or, where it refuses fakes, the request claims to be
  a search engine's crawler, which only its DNS check could confirm). If the check does not answer, the shield's own
  answer stands. An answer there in place of a refusal closes the connection, as the refusal would have.
- After the request policy, before the body is read, every request is offered. A request the check answers goes no
  further; it is never forwarded, and a check that wrote anything has answered. Its answers are never cached, and it
  reads the body through the site's own body limit.
- A refusal is alerted as rule 5007001 (signature `challenge-5007001`, in a new range 5007000 to 5007999). At the
  request point its log line carries the score and the check's reason, kept to 64 bytes of a plain alphabet. At
  admission it has no log line of its own, as the shield's refusals have none, and adds nothing to the shield's
  counts: the shield counted what it would have done, the refusal of a stranger or, for a page load, the challenge
  shown.
- A person the check accepts gets the shield's clearance cookie, as a right answer to the shield's challenge does
  (`Shield.Vouch`). During an attack the address is forgiven one showing of the challenge, and what the shield charged
  for that very request when the check stood in for it (its refusal, or the challenge shown to a page load), and
  nothing else: an address that passes the check while it floods is still banned for the rest.
- The shield's standing is earned only by what the application answered, so the check's own answers earn none.
- `Shield.Standing` reads what the shield holds about an address without adding to its tables.
- A check that is also a `challenge.Responder` sees the header of each response the application gives before it is
  forwarded and hardened, with the request as the visitor sent it, so that a site can tell it in a header that a
  visitor proved to be a person.

## Technical Discussion

No substantive technical discussion recorded: the change was made for the owner, without a pull request. An
independent security review of the change before it was committed found that forgiving any refusal on a pass let a
flooding address escape its ban, and that the check's own answers earned the shield's standing; both were changed as
described above.

## Consequences

The hook's resource containment is enforced per edge: `MaxChallenges` limits simultaneous callbacks across all
three hooks without queuing, and `ChallengeBudget` supplies a cooperative deadline for each call. Busy or expired
checks fail closed. Calls remain synchronous and retain their place until they actually return, so ignoring
cancellation cannot create detached work outside the concurrency bound. A deadline does not forcibly preempt CPU
or every body read; the integrator still needs internal limits or process isolation. Derived callback contexts
are not used for subsequent origin responses or upgraded connections.

- **Positive:** a person check can be added to any site without forking the proxy, sees what the bot policy and the
  shield found, and its accepted visitors get through an attack as people who answered the shield's challenge do.
- **Positive:** nothing changes without a check configured; with one, every existing refusal is kept.
- **Negative / follow-up:** a check's answer requests are held to the shield's per-address and per-network rates but,
  over an attack's budget, are offered to the check rather than refused; the check must bound its own work, for
  example by limiting answers per network. A check that answers a request with a 2xx status is not counted by
  the shield as a refusal at the request point, so a check should answer a refusal with a 4xx status.

## References

- Related ADRs: ADR-0084 (alerts), ADR-0085 (repeat offenders), ADR-0087 (bot policy)
- Code: `carnical/challenge`, `carnical/proxy/challenge.go`, `carnical/shield/challenge.go`
- Documentation: `carnical/docs/challenge.md`
