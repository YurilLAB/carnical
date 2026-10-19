# ADR-0090: Content types and file extensions the site adds to the Core Rule Set's policy

- **Status:** proposed
- **Date:** 2026-10-18 (expected; update before merge)
- **Version:** unreleased (post-v3.8.1)
- **PR:** No PR opened (owner-authorized Carnical development)
- **Issue(s):** No linked issue
- **Deciders:** Pending maintainer review
- **Category:** Feature

## Context and Problem

The Core Rule Set refuses a request whose content type is not on its list (rule 920420), and a
request for a file whose extension is on its list of restricted ones (rule 920440). Both lists are
the CRS's HTTP policy, and `crs-setup.conf` documents them as the site's to tune (its rules 900220
and 900240), as it does the list of methods that `-allowed-methods` already sets.

Carnical offered no way to change them. With a real Gitea behind Carnical, `git clone` and
`git push` failed on rule 920420 (`application/x-git-upload-pack-request` and
`application/x-git-receive-pack-request`), and every page that shows a `.sh` or `.sql` file failed
on rule 920440. An exclusion cannot help: 920420 reads the `Content-Type` header and 920440 the
file name, neither of which is a target an exclusion takes, and turning off the `protocol` group
loses much more than these two checks.

Allowing git's types showed a second problem. Coraza reads a body that no processor claims as a
form (`internal/corazawaf/transaction.go` says so in a TODO), so the binary pack that `git push`
sends was refused as malformed arguments (rules 920250 and 920270). ModSecurity keeps such a body
whole in `REQUEST_BODY` instead.

## Decision Drivers

- The Core Rule Set stays unmodified.
- A site can widen only these two lists, one entry at a time, and nothing else through them.
- What is written into a rule cannot end the rule or start another one.
- A release of the CRS that changes its lists must not be undone by a copy kept in Carnical.

## Considered Options

- **Exclusions for rules 920420 and 920440.** This would take each rule away from the paths it is
  excluded on, so every type, or every restricted extension, would pass there. It also cannot be
  scoped to a code host's paths, which differ for every repository.
- **Raw SecLang in the policy.** This could set anything, including switching the rules off. The
  policy is written to keep untrusted input from writing SecLang, so this is ruled out.
- **Two lists, as `crs-setup.conf` describes them.** `-allowed-content-types` and the policy's
  `allowed_content_types` add types to the CRS list. `-allowed-extensions` and
  `allowed_extensions` take extensions off the CRS list.

## Decision Outcome

Chosen: **two lists, as `crs-setup.conf` describes them.**

- Each list is read from the embedded `REQUEST-901-INITIALIZATION.conf` and then changed, so a new
  release's defaults carry through.
- A content type is a lower-case `type/subtype` with no parameters (64 characters on each side).
  An extension must be one the CRS restricts. Each list has at most 32 entries.
- An added type that no processor claims is parsed as XML or JSON when its suffix is `+xml` or
  `+json` (RFC 6839). Any other is read whole into `REQUEST_BODY` (Coraza's `RAW` processor), as
  ModSecurity reads it. Types the engine already parses as JSON or XML keep their processor.
- A flag replaces the policy's list, as `-allowed-methods` does.

Measured on a real Gitea 1.24, in block mode:

- **Before:** clone, push and pull failed, and `.sh` and `.sql` pages were refused.
- **With both git types allowed:** clone, push and pull worked.
- **With `.sh,.sql` allowed:** those pages were served.

## Technical Discussion

No substantive technical discussion recorded; this record accompanies the owner-authorized change
and no PR thread exists.

## Consequences

- **Positive:**
  - A code host, or any site with its own request types, can run in block mode without switching
    off the protocol rules.
  - A binary body of an allowed type is no longer refused as malformed arguments.
- **Negative / follow-up:**
  - A body of an added type that is not `+xml` or `+json` is not split into arguments, so only
    the few rules that read `REQUEST_BODY` see into it. The guides say to add only what the site
    needs.
  - Rule 930130 still refuses a clone URL that ends in `.git` (`.git/` in the path is how an
    exposed repository is found). Gitea, GitLab and GitHub take the same URL without `.git`.

## References

- Related ADRs: ADR-0062
- Code: `carnical/crs/lists.go`, `carnical/crs/crs.go` (`Settings.AllowedContentTypes`,
  `Settings.AllowedExtensions`), `carnical/policy/validate.go` (`validateCRSLists`)
- Guides: `carnical/docs/proxy-reference.md`, `carnical/docs/config-and-policy.md`,
  `carnical/docs/formats.md`
