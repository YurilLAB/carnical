# ADR-0096: PHP2Shell checked on the request and the response in the Carnical proxy

- **Status:** proposed
- **Date:** 2026-10-21 (expected; update before merge)
- **Version:** unreleased (post-v3.8.1)
- **PR:** No PR opened (owner-authorized Carnical development)
- **Issue(s):** No linked issue
- **Deciders:** Pending maintainer review
- **Category:** Feature

## Context and Problem

PHP2Shell (CVE-2026-109618, CVE-2026-109619) covers memory-safety failures during out-of-memory and fatal-error
handling and request-state cleanup in PHP. Some demonstrated paths use session upload progress and read worker
memory back through a session cookie; other paths need neither indicator. PHP's fix was released the day the owner
asked for Carnical to block the attack;
many sites behind it will run an unfixed PHP for a while. Cloudflare said that blocking it took more than request
rules: its managed rules look at the request and at the application's response. The owner asked for the same, with
the attack named PHP2Shell in the logs.

## Decision Drivers

- Hold without the rule set: the proxy's own checks run whatever the rule set's mode, as the upload checks do.
- Read the request as PHP reads it. The proxy already refuses multipart bodies that Go, the rules and PHP read
  differently; a check on a field's name must find the name wherever PHP would.
- Catch the leak itself, so that a request the request check does not recognise still gets nothing back.
- Few false positives, and an off switch for each check.
- No request data in alerts beyond what the proxy already allows.

## Considered Options

- **A virtual patch.** The vpatch layer matches requests only, runs in monitor mode by default and ships no
  signatures; nothing would change until an operator loaded and enabled a pack, and the response could not be held.
- **A local rule of the rule set.** Request-side only unless response inspection is on, which is off by default
  because it buffers responses; and the rules read a part's name as Go's parser does, not as PHP does.
- **A request check in the proxy.** Refuses the field the published exploit needs, but nothing else.
- **A request check and a response check in the proxy (chosen).**

## Decision Outcome

Chosen: **a request check and a response check in the proxy**, to cover the demonstrated default upload-progress
trigger and malformed session-cookie leak without a rule pack or response inspection. This does not cover every
fatal-error producer, stale-state consumer or memory-disclosure channel; only the fixed PHP runtime does.

- A multipart body with PHP's session upload progress field (`PHP_SESSION_UPLOAD_PROGRESS`) is refused with 403 as
  rule 5000013, before the other upload checks, so its line names the attack. The name is looked for in everything
  a parser could read as a part's headers (the same blocks the NUL check reads), read as PHP reads a header line (the
  rest of a line after a NUL dropped), with quotes, backslashes and white space taken out and letters in lower case:
  a superset of what PHP takes for the field. `UploadPolicy.AllowUploadProgress` (`-allow-upload-progress`,
  `uploads.allow_upload_progress`) turns it off.
- A response that sets `PHPSESSID`, or a name in `ResponsePolicy.SessionCookies` (`-session-cookies`,
  `responses.session_cookies`, up to 16 cookie names), to anything but a session id PHP could have made (empty, or up
  to 256 letters, digits, `-` and `,`, the last sent as `%2C`) is withheld before its headers are copied and answered
  403 as rule 5000080. It is not marked as the application's answer, so the shield counts it as a refusal of the
  visitor's. `ResponsePolicy.AllowBadSessionIDs` (`-allow-bad-session-ids`, `responses.allow_bad_session_ids`) turns
  it off.
- Both messages start with `PHP2Shell:`, as do their catalog names; both are in the `php` category, the response's
  in `data-leak` too, and both are high risk and count 4 toward a repeat offender's ban (ADR-0085), as an upload
  refusal does.
- 403 rather than the 502 of a WebSocket handshake the application did not switch: the response is withheld because
  the exchange is an attack, and a 4xx is what the shield counts against the visitor.

## Technical Discussion

No substantive technical discussion recorded: the change was made for the owner, without a pull request.

## Consequences

- **Positive:** sites using the default upload-progress name refuse that trigger and withhold recognized malformed
  session-cookie values, with the rule set on, in detection mode or off.
- **Positive:** a source that keeps trying is banned by the repeat-offender policy.
- **Negative:** a site that uses PHP's upload progress has to turn the request check off, and one whose session ids
  hold other characters (its own session handler's, or ids set with `session_id()`), or a non-PHP application that
  names its own cookie `PHPSESSID`, has to turn the response check off.
- **Negative / follow-up:** a session id carried in URLs (`session.use_trans_sid`) and an upload progress field
  renamed in `php.ini` are not checked. The checks are a stopgap; only a fixed PHP removes the bugs.

## References

- Related ADRs: ADR-0084 (alerts), ADR-0085 (repeat offenders)
- Code: `carnical/proxy/php2shell.go`, `carnical/proxy/proxy.go`
- Documentation: `carnical/docs/proxy-reference.md#php2shell`
- PHP advisories: [out-of-memory handling](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w),
  [stale global state](https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp)
