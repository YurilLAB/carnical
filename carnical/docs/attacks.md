# Modern web attacks, and what Carnical does about each

Research done 2026-10-05 for what is exploited or prominently published from 2023 to 2026, set against what the Core Rule Set already covers and what a reverse proxy in front of an unpatched site can actually stop. **Measured** marks what was run here; **researched** marks a claim taken from the cited source and not run; the source URLs are the ones the research opened. CVE ids for 2026 are beyond what I know first-hand, so check them against a vendor tracker before relying on one.

The short version: a proxy owns the protocol layer completely (smuggling, HTTP/2 floods, path ambiguity, Host, its own CPU), helps partly where an exploit has a recognisable request shape (React Server Components, uploads, PHP and Node injection), and cannot fix authorisation logic, in-application SSRF, JWT or GraphQL abuse or race conditions. Patchstack's 2026 report measured hosting-level defences blocking 12% of the WordPress vulnerabilities that were exploited: a WAF is one layer, not the fix.

## Done in Carnical (each has a test; each protection test runs with the rule set off, so it does not depend on a rule)

| Class | What Carnical does | Evidence |
|---|---|---|
| **CPU exhaustion of the WAF itself.** Rules cost about 6 ms of CPU per KiB of body | A budget per evaluation phase (2 s) that stops the engine mid-evaluation, a cap on requests being evaluated at once, a 128 KiB cap on bodies that are not uploads, and a distinct 503 | **Measured**: 300 KiB of plain text takes 1.8 s on one core, 85% of it in Go's regexp matcher; with a 5 ms budget the request is refused after 48 ms. Disabling the engine's context check makes the test fail. Small change to upstream `internal/corazawaf` |
| **Request smuggling and desync** | Go re-serialises every request, so TE.TE, obfuscated headers and HTTP/2-to-1 downgrade do not pass through; a request with a body never shares its connection to the application with the next one (the CL.0 and 0.CL attacks need a reused connection); `Expect` is not forwarded | **Measured**: nine classic shapes with an attack hidden in a body; none reaches the application as an uninspected request. Closing after a bodied request is checked by counting the application's connections |
| **Interim responses hide the real response from response inspection** (found by the Coraza survey and then confirmed) | 1xx responses from the application are dropped before the engine sees them | **Measured**: before the fix a `103 Early Hints` made the engine treat it as the final response, so a database-error page reached the visitor; after, it is blocked like the same page sent without the 103 |
| **Path and URL parser differentials** (Apache confusion attacks, encoded slashes, `;` parameters, dot segments, double decoding, `/%77p-admin/`) | A path that needs interpreting is refused: encoded `/ \ ? # % NUL` and control characters, unnecessary escapes of plain characters, dot segments, semicolons, backslashes. Relaxations exist for applications that need them | **Measured**: 35-row table. CRS only covers some of these in decoded form |
| **Framework control headers** (Next.js `x-middleware-subrequest`, `x-invoke-*`, `x-matched-path`, method-override headers) | Removed from every forwarded request regardless of the rule set (the rule set blocks a few of them in blocking mode only, so detect mode or a raised threshold lets them through). `-deny-headers` refuses a header outright, for example `Next-Action` on a site with no server actions | **Measured**, including the underscore spelling and a header named in `Connection` |
| **Host-header and virtual-host attacks** | `-hosts` lists the names a site answers to; anything else gets 421 | **Measured** |
| **Compressed request bodies** (an application that unpacks them receives what nothing inspected) | `Content-Encoding` other than identity is refused (415) | **Measured** |
| **Web shell uploads** (most exploited WordPress plugins were taken this way) | Refused: script extensions anywhere in the name (`shell.php`, `shell.php.jpg`, `.phtml`, `.php5`, `.jsp`, trailing dot or space, `;` trick, NTFS stream, NUL, RFC 5987 encoded names), server configuration files (`.htaccess`, `web.config`), and any file part containing a PHP, ASP or JSP opening tag, however far into the file | **Measured**: 25-row table including the benign controls. The rule set checks a file's name but not what is inside |
| **Scripts run from directories WordPress only writes data to** | `-wordpress`: `.php`, `.phtml`, `.phar` under uploads, cache, upgrade, backup directories are refused (403) before the application runs them; `xmlrpc.php` off by default; login attempts limited per address | **Measured** |
| **Web cache deception and cached private pages** | A response that sets a cookie and has no `Cache-Control` gets `private, no-store`; HTML served at a stylesheet's address is not cacheable | **Measured** |
| **Content-type sniffing** (an uploaded file run as a script by the browser), **software banners** | `X-Content-Type-Options: nosniff` added; `X-Powered-By`, `Server`, `X-AspNet-Version` removed | **Measured** |
| **Connection floods and slow clients** | A cap on connections per address (128), HTTP/2 limited to 100 concurrent streams and 16 KiB frames, a write timeout; cleartext HTTP/2 is not enabled | **Measured** that the server advertises 100 streams |
| **A malformed request the engine could not process** returned an empty 200 | 400 or 413 | **Measured** |
| **Rules that run programs or change the process** (`@inspectFile`, `exec`, `setenv`, `@rbl`) | Replaced with versions that refuse to compile | **Measured** |
| **Uploads written to the machine's shared temp directory** (the engine always writes file parts to disk, contrary to what a comment here said) | `-upload-dir` | **Measured**: the control run finds the file in the shared directory, the configured run finds it in its own and removes it afterwards |
| **Old Go release with known vulnerabilities** | The module and workspace require go1.26.6 | **Measured**: `govulncheck` on go1.26.4 found seven that reach a proxy (an HTTP/2 cleartext check, quadratic URL path resolution, XML recursion among them); on go1.26.6 it reports none |

## Covered by the Core Rule Set, in whole or part (not changed)

| Class | CRS rules | Gap |
|---|---|---|
| React Server Components / Flight RCE (React2Shell, CVE-2025-55182 and follow-ups) | 934100, 934130 | Signature-chasing leaves gaps; patching stays mandatory. For a site with no server actions, `-deny-headers Next-Action` |
| Prototype pollution, Node injection | 934130 | A JSON-key check after escape decoding is not done |
| PHP object injection, Java deserialisation | 933170, 944120/200/210 | Wrapped or base64 gadgets evade it |
| SSRF (the application's own) | 934110, 934120, 934190 | Rebinding and redirects need the application or the host. The proxy's own outbound leg is checked at the connected address (`proxy/origin.go`) |
| SQL injection, XSS, LFI, RFI, command injection, SSTI | 942, 941, 930, 931, 932, 934200 | Normal CRS limits; paranoia level 1 by default |
| Log4Shell-style JNDI | 944150 to 944152 | Java-centred |
| Multipart, JSON, XML parser differentials (the WAFFLED research found 1,207 bypasses across five WAFs) | 920xxx, and fixes in Coraza 3.8 | This copy has the 2026 fixes that were found (JSON key collisions, Content-Type duplicates, multipart charset, `filename*` decoy, JSON depth). A strict re-serialising normaliser would close the class; it is the largest item not done |

## Not stoppable by a proxy

State this plainly to customers. These need the application or the host:

- **Broken access control, BOLA, mass assignment, privilege escalation by missing checks.** More than half of 2025's WordPress vulnerabilities (Patchstack). The request is well formed; only the application knows it should be refused.
- **JWT, OAuth and SSO flaws; GraphQL batching, aliasing, depth and introspection.** The limits belong in the GraphQL server.
- **Race conditions** (single-packet attacks). State changes must be atomic in the application.
- **Path-class framework bypasses** that do not depend on a header (for example the Next.js `/_next/data/` routes that skip middleware). Authorise in the data layer.
- **Zip-slip, polyglots, re-encoded images.** The host must not execute uploaded files.
- **SSRF through the application's own fetches.** Egress policy on the host (`hardening.md`).
- **Bandwidth floods.** Upstream or the host's provider.

## Not worth building (researched)

Hand-written payload regexes for each new RSC exploit beyond 934100; response-body inspection by default (CPU, a past Coraza response-JSON denial of service, low yield); paranoia level 2 or higher by default for WordPress (the CRS documentation says weeks of tuning, and the measured false positives here rise from 2.4% to 8.3%); an HTTP/3 listener (net/http has none and the QUIC libraries keep issuing CVEs); proxy-side GraphQL cost or JWT checks; archive inspection; race throttling.

## Next, in order of benefit per hour (from the research; not done)

1. A strict normaliser for multipart, JSON and XML bodies: exactly one Content-Type, allow-listed types and charsets, NUL and control characters refused, duplicate JSON keys (case-folded) refused, a depth cap (about 12 h; the largest remaining class).
2. A virtual-patch pack: path, `action=` and REST-namespace matchers for specific plugin advisories, fed from public advisories and scoped to the plugins a site has installed (about 24 h, then about an hour per advisory).
3. On Next.js sites: refuse the reserved `nxtP` and `nxtI` query keys.
4. A block page that carries the incident id the owner's Desk and the feed already use.
5. An unauthenticated-privilege-field guard for WordPress registration forms (heuristic: the cookie can be forged).

## Sources opened by the research

Go and HTTP/2: golang/go issues 63417 and 77440 and release notes; GHSA-4v7x-pqxf-cx7m (CONTINUATION flood, CVE-2023-45288); CERT VU#767506 (MadeYouReset); haproxy.com blog on CVE-2026-49975; Red Hat CVE-2026-56853 (h2c ReadHeaderTimeout). Smuggling: portswigger.net/research/http1-must-die; CVE-2025-22871 (bare LF). Path confusion: blog.orange.tw confusion attacks; GHSA-q9f5-625g-xm39 (Coraza `//`); spring.io CVE-2024-38819; Rapid7 on Tomcat CVE-2025-24813. Frameworks: Vercel postmortem on CVE-2025-29927; Akamai on the March 2025 Next.js bypass; zeropath on CVE-2026-44574 and 44573; react.dev advisories of 3 and 11 December 2025; Zscaler, Elastic and Wiz write-ups of React2Shell; raven.io on why a WAF rule patch leaves exposure. Parsers: arxiv.org/abs/2503.10846 (WAFFLED); coreruleset.org on CVE-2026-21876; GHSA-5gj4-9gm7-2fx2, GHSA-w253-m66g-rx24, GHSA-3wr7-993q-jrff (Coraza). WordPress: Patchstack, State of WordPress Security in 2026; Qualys on CVE-2023-3460; securityaffairs on CVE-2025-3102. General: PortSwigger Web Security Academy and the OWASP cheat sheets for SSRF, cache deception, host header, JWT, GraphQL, file upload.
