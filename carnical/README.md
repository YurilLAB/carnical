# Carnical: OWASP CRS on Coraza, as a reverse proxy

Carnical is our web application firewall. This folder is our additions to the private copy of [OWASP Coraza](https://github.com/corazawaf/coraza). Nothing upstream is
rewritten: Coraza is the engine and the OWASP Core Rule Set (CRS) is the rule set. `carnical/` is its own Go module
(`github.com/YurilLAB/coraza/carnical`), so upstream releases merge without conflicts.

| Folder | What it is |
|---|---|
| `crs/` | The CRS embedded in the binary, with proof of where it came from, and typed settings (mode, paranoia level, thresholds, body limit, allowed methods, exclusions) turned into the directives that configure it. |
| `proxy/` | A reverse proxy: every request goes through Coraza and the CRS, clean ones are forwarded to one upstream. |
| `cmd/carnical/` | The program: `carnical -upstream http://127.0.0.1:8081 -mode block`. |
| `tools/update-crs/` | Fetches a CRS release, checks its GPG signature against the CRS project's pinned key, and replaces the embedded copy. |
| `audit/`, `cmd/carnical-audit/` | The segmentation checks: the walls between zones and between customers, run a few times a day. `carnical-audit -zones zones.json`. |
| `docs/backend-integration.md` | What it takes to connect this to our backend and web UI. |
| `docs/segmentation.md` | Zones, who may talk to whom, how customers are kept apart, and the checks and their schedule. Read this next. |
| `docs/backend-compat.md` | The contracts the existing backend expects (feed, events, policy, updates, advice) and the defects in it that matter for hosting. |

## Versions

- Coraza: v3.8.1 (branch `foundation` is the pinned upstream tag; our branch is `edge-crs`).
- OWASP CRS: 4.30.0, release signed by key `3600 6F0E 0BA1 6783 2158 8211 38EE ACA1 AB8A 6E72`. `crs/provenance.json` holds the
  archive hash, the signature hash and the hash of every embedded file; a test fails if any file differs.

## Run it

```
go run ./cmd/carnical -upstream http://127.0.0.1:8081 -listen :8080            # detect: log what the rules find, block nothing
go run ./cmd/carnical -upstream http://127.0.0.1:8081 -mode block              # block at the anomaly threshold
go run ./cmd/carnical -version                                                  # which CRS is embedded
```

Start every new site in `detect`, read the log for a few days, add exclusions for what is wrongly flagged, then switch to `block`.
Options: `-paranoia 1..4`, `-inbound-threshold`, `-max-body`, `-allowed-methods`, `-inspect-responses`, `-trusted-proxies`,
`-tls-cert`/`-tls-key`, `-upstream-host`, `-max-upstream`, `-log-details`. Run `-h` for all of them.

Paranoia levels on the 715-request corpus from the earlier research (468 deliberately tricky benign requests, 247 attacks):

| Level | Benign requests wrongly blocked | Attacks detected |
|---|---|---|
| 1 (default) | 2.4% | 82.6% |
| 2 | 8.3% | 86.2% |
| 3 | 13.7% | 83.8% (measured before upload bodies were replayed correctly, so a little low) |
| 4 | 35.3% | 85.0% (same) |

Level 1 is right for a new site; level 2 only after the site's exclusions are tuned. Levels 3 and 4 block too much ordinary traffic
to use without heavy tuning.

## What the proxy adds around Coraza

These come from bugs found in our own earlier gateway, where what the firewall inspected and what the application received could differ.

- The request target is forwarded exactly as it was inspected; one Go would re-encode (such as `/a%2fb|`) is refused.
- Proxy and identity headers are removed with `_` and `-` treated alike (`X_Original_URL` is `X-Original-URL` to PHP, CGI and IIS), and rebuilt from the verified client address.
- Trailers are not forwarded, protocol upgrades (WebSocket, h2c) are refused, and `CONNECT` is refused.
- A request takes an upstream place only after its body has been read, so a stalled upload cannot use them up.
- The visitor's address comes from `X-Forwarded-For` only when the connection is from a trusted proxy, read from the right; a `/0` trusted range is refused.
- A customer's origin is not trusted: connections to loopback, private, link-local and cloud-metadata addresses, and to this machine's own addresses, are refused at the moment they are made, on the address actually used (`-origin-allow` names ranges an operator permits).
- Rule matches are logged with the rule's id, severity and fixed message; the client address, URI and matched data (which hold what the visitor sent) only with `-log-details`.

## Known limits

- The CRS has no rule for XML external entities, and Coraza's XML processor hands rules the text pieces of an element separately, so a keyword split by an empty CDATA section is not seen whole.
- Uploaded file contents, trailers (dropped, so never forwarded) and SQL in a URL path segment are not inspected; CRS is generic and does not carry CVE-specific virtual patches for WordPress plugins.
- A body of hostile input costs CPU in proportion to its size (several seconds for 1 MiB of adversarial text). Keep `-max-body` as small as the site allows.
- Developing on Windows: run the tests under WSL or Linux. Coraza's own suite has Windows-only failures, and one of them (`normalisePath`, fixed in our copy) silently disabled the CRS's OS-file rule on Windows.

## Updating the CRS

```
GPG=$(command -v gpg) go run ./tools/update-crs -version 4.31.0
go test ./crs
```

The tool downloads over https from github.com only, refuses anything whose signature is not from the pinned key (checked with a
throwaway keyring, not yours), extracts only expected regular files, and writes nothing if any check fails.

## Our changes to upstream files

- `go.work`: one line adding `./carnical`.
- `internal/transformations/normalise_path.go`: `path.Clean` instead of `filepath.Clean`, so the transformation gives the same result on every OS.

## Licence

Coraza and the CRS are Apache-2.0 (the CRS licence is kept in `crs/owasp_crs/LICENSE`). The licence for code we add in `carnical/` is not
decided yet.
