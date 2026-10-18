# ADR-0091: The block editor's saves on a site marked as WordPress

- **Status:** proposed
- **Date:** 2026-10-18 (expected; update before merge)
- **Version:** unreleased (post-v3.8.1)
- **PR:** No PR opened (owner-authorized Carnical development)
- **Issue(s):** No linked issue
- **Deciders:** Pending maintainer review
- **Category:** Feature

## Context and Problem

`-wordpress` is meant to protect a WordPress site without breaking it, but no post could be saved
in the block editor behind it. Two things refused every save, whatever the post said:

- **The method override.** WordPress's JavaScript (`wp.apiFetch`) sends PUT, PATCH and DELETE as a
  POST with `X-HTTP-Method-Override`, and WordPress's REST server runs the method named.
  - The proxy refused the header on every request (rule 5000044), because a server that honours it
    runs a method the edge did not check.
  - CRS rule 920450 also restricts the header.
- **The block markup.** The editor saves content as block markup, which is written as HTML comments
  (`<!-- wp:paragraph -->`). CRS rule 941180 refuses `<!--` in any argument.

A real WordPress 6.8 behind Carnical with `-wordpress` showed both:

- **Pretty links:** the draft, publish, update and trash requests were all refused.
- **Plain links (`?rest_route=`):** the same requests were refused.

The site's policy could exclude the content field. Even then, the header stayed refused by the
proxy, which no exclusion reaches.

## Decision Drivers

- `-wordpress` alone lets the editor save ordinary posts.
- The header is accepted only where WordPress reads it, and only for what its JavaScript sends.
- The application must get exactly the method the edge checked.
- No rule is taken off more than one field, on one API.

## Considered Options

- **Leave the header refused and tell sites to fix it.** A site cannot fix it: WordPress core sends
  the header, and nothing in WordPress turns that off.
- **Accept the header wherever `-wordpress` is set.** This is simple, but any page then accepts a
  method tunnelled past the method checks.
- **Accept only WordPress's REST API's use of the header, and take rule 941180 off its content.**

## Decision Outcome

Chosen: **accept only the REST API's use of the header, and take rule 941180 off its content.**

With `-wordpress`, the proxy lets `X-HTTP-Method-Override` through only when all of these hold:

- the request is a POST with one value of the header;
- the value is PUT, PATCH or DELETE, in any case;
- the request goes to `/wp-json/` (in any directory), or to the site's root or `index.php` with
  `rest_route`.

The header is then forwarded once, as `X-HTTP-Method-Override` with the upper-case method that was
checked. Every other spelling and repeat is dropped. Anywhere else, and for `X-Method-Override` and
`X-HTTP-Method`, rule 5000044 still refuses it.

The rule set gets `crs.Settings.WordPress`, which the proxy sets:

- On such a POST, rule 920450 reads its list of restricted headers without
  `X-HTTP-Method-Override`. Every other restricted header stays on it.
- Rule 941180 is kept off `json.content` on REST requests for `/wp/v2/`. Every other rule still
  reads that field, and rule 941180 still reads every other field.

Measured on WordPress 6.8 with `-wordpress` and no policy, using the editor's own `wp.apiFetch`:

- **Before:** with pretty links and with plain links alike, draft, publish, update and trash were
  all refused.
- **After:** all four saved, and no rule matched.

## Technical Discussion

No substantive technical discussion recorded; this record accompanies the owner-authorized change
and no PR thread exists.

## Consequences

- **Positive:** the block editor works on a site marked as WordPress, with no exclusions.
- **Negative / follow-up:**
  - A plugin that sends the header to an API other than WordPress's REST API is still refused.
  - Posts whose content quotes commands, SQL or scripts still match other rules. They need the
    site's own exclusions, as before.
  - At paranoia level 2 and above, block markup matches more rules, such as 941181, 941320 and
    942440.

## References

- Related ADRs: ADR-0090
- Code: `carnical/proxy/policy.go` (`wordPressOverride`), `carnical/proxy/proxy.go`,
  `carnical/crs/lists.go`, `carnical/crs/crs.go` (`Settings.WordPress`)
- Guides: `carnical/docs/proxy-reference.md`, `carnical/docs/formats.md`
