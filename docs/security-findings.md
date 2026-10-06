# Security findings review — 6 October 2026

This review is in progress. The initial hosted scan reported 183 Linux and 145
Windows findings (mostly overlapping). A scanner finding is evidence to review,
not proof of an exploitable vulnerability. Unreviewed findings remain enabled and
continue to fail the security gate; there is no blanket baseline or rule exclusion.

## Confirmed defects and fixes

| Finding | Verification | Change |
| --- | --- | --- |
| G115, audit-log part parsing | U+0142 and U+0145 narrowed to valid ASCII part letters | Validate bytes against the ASCII part set; test both parsing and modification |
| G115, configured file modes | Signed octal parsing accepted negative values before conversion to an unsigned mode | Parse unsigned 32-bit values; reject negative and overflowing modes in the directive table |
| G302, debug logs | Newly created debug logs requested mode 0666 and could contain request data | Create with 0600; verify Unix permission bits. Existing files retain their permissions and Windows uses its ACL model |
| G104, writable-directory probe | Close/removal failures were discarded | Return joined cleanup errors |
| G104, signature converter output | A failed stdout write still returned success | Return a failing exit status; independently test delivered and broken output |
| G104, temporary signature/sequence files | Failure cleanup hid additional close/removal failures | Preserve the original error and join cleanup errors |
| G114, HTTP example | Default server had no header/body/write/idle timeouts | Configure explicit timeouts and report response write failures |

## Defensive correctness improvements

These were not demonstrated as remotely exploitable bypasses. They strengthen
bounds and preserve intended behavior:

- Reject regex scalar escapes above U+10FFFF or in the surrogate range before
  narrowing to a rune. Importer regression cases cover overflow and surrogates.
- Normalize negative code points to U+FFFD instead of letting them alias bytes.
- Sort incident label counters using unsigned comparisons, without subtraction
  through a platform-sized signed integer. Exercise a maximum uint32 counter.
- Encode Landlock's packed kernel structure using native-endian byte stores,
  removing two unsafe dereferences, and check the descriptor range.
- Check seccomp program length before indexing and narrowing to the kernel ABI.
  Real Linux sandbox tests exercise kernel enforcement, not just compilation.

## Verified, narrowly scoped scanner exceptions

Only the following reviewed code sites received inline exceptions:

- MD5/SHA-1 imports and constructors implement the required SecLang normalization
  transforms. They do not authenticate data or verify signatures. The existing
  FIPS rejection behavior remains tested.
- `RandomString` generates transaction correlation IDs, not credentials.
- `inspectFile` executes an administrator-configured executable, passes the
  request value as one argument without a shell, and retains its timeout.

Other path, unsafe, cleanup, cookie, and integer-conversion findings remain in
the scanner output until their bounds and trust boundaries are reviewed.

## Dependency findings

The CRS test harness used x/crypto v0.55.0. Upgrade it to v0.57.0, along with
the dependency versions selected by Go. This removes the affected versions
for [GO-2026-6354](https://pkg.go.dev/vuln/GO-2026-6354) and
[GO-2026-6355](https://pkg.go.dev/vuln/GO-2026-6355). This test module and the
workspace now require Go 1.26; CI uses Go 1.26.6.

[GO-2026-5932](https://pkg.go.dev/vuln/GO-2026-5932) concerns the unmaintained
`golang.org/x/crypto/openpgp` packages and has no fixed version. x/crypto remains
needed by the harness dependency graph, but OpenPGP is absent from its package
and test graph on both Linux and Windows. A manifest-local exception expires
on 5 November 2026. CI fails if OpenPGP or a subpackage is imported, or if Go
cannot generate the dependency inventory. Other modules and advisories remain
fully scanned. The exception uses OSV's documented
[directory scope and expiration](https://google.github.io/osv-scanner/configuration/).

## Live validation and limits

The local Windows run sends 10,000 requests through a newly built Carnical
process and an independently counted inert loopback origin. It exercises 2,972
attack templates and 347 benign templates, including varied encodings and
held-out syntax. Flood mitigation is disabled to isolate content protections.

- 5,000 attack requests: 4,714 refused; 286 reached the origin.
- 5,000 benign requests: 4,672 admitted; 328 refused.
- Zero transport errors and unavailable responses.
- Admissions were confined to HPP, RFI, probe and WordPress categories. These
  include application-dependent cases; admission is not proof of exploitation.
  Their request-level evidence is retained for further investigation.
- Benign refusals occur in prototype and XPath controls and remain unresolved.

CI retains the full JSON report, gates the 17 supported injection/structural
categories, and checks ordinary search and JSON controls. This gate does not
claim the whole corpus is solved. Unit tests cover all pure Go application
modules, and root evaluation modes are tested separately. Linux tests run with
CGO disabled for the real confinement implementation.

Local validation includes the complete Linux Coraza suite, changed Carnical
suites on Windows, real Linux sandbox/config/importer/CLI tests, dependency
scanning, actionlint, and scanner-installer tests. The broader Windows Coraza
suite also reports file-locking and embedded-path failures; these are recorded
separately from the passing changed directive cases. Hosted results and
remaining finding counts are recorded after the push.

Policy tests now explicitly isolate CRS groups from independent supplemental
rules. Earlier failures expected an attack to pass when its CRS group was off
or logging, while a supplemental rule correctly refused it. Production defaults
retain supplemental enforcement; the live CI run exercises both layers.

The post-fix local scan reports 147 Linux and 112 Windows findings with no
package-loading errors (Linux: root 20, Carnical 127; Windows: root 20,
Carnical 92; HTTP example zero on both). Remaining findings are not waived.
