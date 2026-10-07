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
| G115, confinement probe ports | Closed ephemeral listeners could return the same allowed and forbidden port; deriving a second port with `+1` also lacked range checks | Reserve three distinct listeners together, validate nonzero 16-bit port arguments, and use a separately allocated HTTP port |
| G112, confinement probe HTTP server | The probe's server lacked a header timeout | Set explicit header, read, write and idle timeouts |

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
- Enforce a conservative YAML mapping-node bound before the parser builds its
  tree. Each mapping separator requires at least two nodes. The tree walk still
  counts all nodes, and the existing byte, depth and node limits stay unchanged.

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

## CI follow-up — 7 October 2026

The YAML cost test now keeps every adversarial body below the actual 32 KiB
cap; previously several shapes were rejected for size before parsing. Its
250 ms ceiling remains unchanged. The repeated short-key case dropped from
86 ms to 3.9 ms locally with `GOMAXPROCS=2`. All nine cost shapes passed,
including a 9,999-node mapping below the node cap (56 ms locally). A separate
running CLI blocked 60 varied block, flow and quoted-key mapping payloads under
rule 5002503, while forwarding 60 valid YAML controls unchanged. Duplicate-key
detection and flood mitigation were disabled in this
isolated check, proving the node limit holds independently. No attack reached
the counted inert origin.
Raising the node limit to 20,000 admitted all 60 identical mapping payloads
unchanged, confirming valid YAML and preserving the administrator's configured
limit rather than imposing an unconditional mapping ban.

The confinement probe passed twice on a real Linux kernel, including its
unconfined control and deliberately weakened Landlock and seccomp controls.
The weakened Landlock check now verifies forbidden bind and connect behavior
on supported kernels. An independent 50,000-pair socket experiment reproduced
five allowed/forbidden collisions with the old close-before-selection pattern.

All Carnical packages were checked on Linux. The configuration and control
tests were repeated on an executable Linux tmpfs because the Windows-mounted
temporary directory does not preserve their required Unix permissions.
Windows CLI tests, format race tests, 70,792 YAML fuzz executions, vet,
workflow validation and a fresh 10,000-request live mixed-traffic run also
passed. The mixed run retains the
previously documented context-dependent admissions and benign refusals; all
supported injection categories passed their existing CI gate.

The follow-up scan reports 140 Linux and 112 Windows findings, with no package
loading errors: seven fewer Linux findings, no new exceptions. Remaining
findings still fail the security gate. Runtime CI now preserves unit-test
output even if a failure prevents the live WAF test from running.

The fresh dependency audit also found two advisories affecting the standalone
HTTP example's old Coraza v3.3.3 dependency:
[GHSA-6r3q-mjv7-xr8m](https://github.com/advisories/GHSA-6r3q-mjv7-xr8m)
(argument-limit bypass) and
[GHSA-prpw-wwv7-xjjr](https://github.com/advisories/GHSA-prpw-wwv7-xjjr)
(native audit-log injection). The example now selects v3.8.1, which includes
both upstream fixes. With `GOWORK=off`, its tests and build passed. The running
standalone example blocked 100 varied parameter floods, passed a valid request
at the configured argument limit, and escaped forged audit boundaries in the
native log. The log-forgery request was accepted; its attempted forged log
records were neutralized. OSV re-scanned all five module manifests with no
actionable findings. The existing scoped OpenPGP exception is unchanged.

The workspace dependency versions require Go 1.26. Module manifests and sums
now match that minimum and the versions selected by workspace synchronization.
The full `go run mage.go check` passed, including lint, alternate evaluation
modes, race-tested HTTP example and CRS integration tests.

### Hosted-kernel and flood-comparison follow-up

The first follow-up hosted run confirmed that distinct ports alone did not
resolve the forbidden bind failure. Multipath TCP sockets can bypass Landlock
TCP bind/connect restrictions, as documented by the
[Landlock maintainers](https://github.com/landlock-lsm/linux/issues/54).
Seccomp now returns `EPROTONOSUPPORT` for IPv4 and IPv6 MPTCP socket creation.
Go falls back to ordinary TCP, where Landlock enforces the port policy; the
fix does not depend on `GODEBUG` or an application choosing the right protocol.
The real probe explicitly requests MPTCP for allowed and forbidden dial/listen
operations and checks raw MPTCP socket creation. Its weakened-seccomp control
requires the raw-socket denial to fail on kernels where the unconfined control
can create MPTCP sockets.

The filter tests cover IPv4/IPv6, socket flags, high argument bits and both
execution-policy modes, alongside ordinary TCP and UDP controls. Repeated real
Linux sandbox runs, the final strengthened control run and vet passed. The
local WSL kernel lacks MPTCP support, so the hosted kernel is needed to confirm
the positive raw-MPTCP control as well as the denial. The follow-up Linux scan
has the same 120 Carnical findings and no package-loading errors or new exceptions.

The hosted flood comparison reported five extra origin requests after the tiny
accept-queue control had timed out nine requests. Shared origin counters allowed
delayed work to contaminate later measurements. Each comparison now creates an
independent origin server and counters; the exact request-count assertions remain in place.
The complete isolated live network suite passed for IPv4/IPv6, TLS, varied
packet floods, reloads and injection blocking. All four latency comparisons
also passed: 80,000 HTTP requests, 200 blocked SQL-injection probes and 400,000
varied flood packets. The intentionally tiny accept queue reproduced a roughly
1,025 ms flood p99; the persistent origin with a 256-entry queue and TCP_NODELAY
measured 44 ms locally. These are fixture comparisons, not a new production
performance guarantee.

The unconfined ptrace probe now uses `PTRACE_SEIZE`, which
[does not stop its target](https://man7.org/linux/man-pages/man2/ptrace.2.html),
instead of `PTRACE_ATTACH`. A successful attach under a privileged
test account could otherwise leave the probe parent stopped.
The sandbox suite also passed as root inside private mount, network and PID
namespaces, confirming the privileged control completes without changing the
host namespace.

## Audit reporting follow-up — 7 October 2026

The latest preceding hosted run passed runtime/live-WAF, CrowdSec, network,
dependency, secrets and workflow checks. Its Linux and Windows security jobs
failed on 140 and 112 gosec findings respectively.

The audit command could report success after requested log or status writes
failed. Its deterministic status temporary file also overwrote another writer's
file. An independent source review found two additional monitoring defects:
failed console output still returned success, and aliased log/status paths
replaced the requested log history. These are reproduced reporting-correctness
defects, without a demonstrated remote exploitation route.

The shared report boundary now propagates serialization, write, sync, close
and rename errors to exit 1. A console/log failure makes a successfully written
status unhealthy without changing check counts. Unique mode-0600 temporary
files avoid reusing another writer's name and are removed on failure. Aliased
outputs are rejected before the status replacement; output directories must
remain under operator control. Concurrent hostile directory changes are not
covered. Watch mode retries and can recover after an output failure.

The delay flag promises unpredictable scheduling; it now samples with
[crypto/rand.Int](https://pkg.go.dev/crypto/rand#Int), preserving the existing
zero-to-jitter exclusive upper bound. Negative jitter and nonpositive watch
intervals return usage exit 2 instead of silently disabling delay or looping.

Regression tests reproduced the original defects before the fix and pass on
native Windows and real Linux. Live Windows command comparisons verify exit
codes, preserved JSONL history, status health and watch recovery using an inert
loopback listener. Linux uses `/dev/full` as a genuine failed-write control.
Focused vet and both target-platform gosec scans pass for the audit command.
The complete root/application rescan has no package-loading errors and reports
135 Linux and 107 Windows findings: five fewer on each target. One reviewed
G304 exception is limited to the operator-selected CLI log path; no tenant or
HTTP request input selects it. Remaining findings still fail the security gate.

## Audit formatter and writer validation — 7 October 2026

A live OCSF check reproduced a nil-pointer panic when a matched rule was logged
with H (trailer) but without K (rule details), including the default audit-parts
configuration when OCSF is selected. The panic terminated that HTTP connection
and omitted its audit record. The server remained running; no content-filter
bypass or process-wide denial of service was demonstrated. The source trace
also shows transaction cleanup was skipped in that deferred middleware call.

Native Message.Data now represents absent details as a true nil. Both consuming
formatters skip absent detailed data; OCSF retains the H-only error message
through the existing trailer interface. Full-K enrichment and JSON serialization
of native messages remain unchanged. This does not claim safety for arbitrary
third-party plugin getters returning a typed nil. Independent source investigation
and patch review covered the native optional-state paths and direct consumers.

OCSF now rejects numeric values outside its signed 32-bit representation instead
of wrapping them. It converts Go timezone seconds to minutes and enforces the
[OCSF 1.2 offset range](https://raw.githubusercontent.com/ocsf/ocsf-schema/v1.2.0/dictionary.json).
Normal values, unknown zeros and representable connector values are preserved.
These numeric defects were reproduced as logging correctness issues, without
a demonstrated remote input route to oversized connector values.

Serial and concurrent writers now return genuine output failures from log.Output.
Closed-file controls previously returned success and now fail. Two writer-init
tests now use a guaranteed missing parent below a temporary directory instead
of assuming the root directory is unwritable; both passed on Windows and Linux.

Regression tests reproduced the optional-data panic, numeric wrapping, timezone
unit mismatch and hidden write errors before the fixes. The complete auditlog
suite and audit-command suite pass on native Windows and real Linux. A running
WAF using OCSF and H without K blocked 50 varied requests, admitted 50 valid
controls and wrote 100 parseable records without panic; denied records retain
trailer messages and a configured UTC+11 offset appears as 660 minutes. Request
phase interruptions still leave the response code unknown in engine audit data;
the Denied action and observed HTTP 403 are validated separately.

Focused vet and gosec scans for both targets pass without new exceptions.
Four additional G115 findings are resolved on each platform. CI now requires
these audit suites on native Ubuntu and Windows, plus race checks on Ubuntu.
Local race execution is unavailable because this environment has no C compiler;
its result is validated by the hosted job after push. Other scanner findings
remain enabled. The preceding hosted run passed all runtime/live, network,
CrowdSec, dependency, secrets and workflow jobs, while both gosec targets still
failed on the remaining inventory.

## Native Windows rule loading and logger regression checks — 7 October 2026

The full native Windows engine suite reproduced failures loading embedded rules,
nested includes and absolute operator data files. Rule paths now use the io/fs
slash-separated namespace. Native separators and drive-qualified absolute paths
are handled by the default OS filesystem adapter; custom filesystem names retain
literal backslashes. Tests retain include-recursion limits, reject out-of-root
reads and preserve filesystem error identities instead of matching OS-specific
error text. See [Go's filesystem path contract](https://pkg.go.dev/io/fs#ValidPath).

Lazy audit-writer initialization now records success through the existing checked
initializer, preventing repeated initialization from abandoning open log handles.
Failed initialization remains retryable. Tests explicitly close their audit/debug
outputs before removing temporary directories. WAF cache disposal semantics for
in-flight transactions remain unchanged.

The complete engine suite passes on native Windows and Linux. CI runs the complete engine suite on both native runner platforms,
with focused race checks on Ubuntu. Other unreviewed scanner findings still fail
the required gate.

## YAML collection parser-work budget — 7 October 2026

The Ubuntu runtime job reproduced a 24,995-byte, 4,999-pair YAML body costing
250.968 ms. Source review found quadratic block-mapping suffix copying in
goccy/go-yaml v1.19.2. Independent review also identified omitted-value explicit
keys, shorthand flow maps and block sequences that bypass a colon-only counter
and can trigger suffix copying or repeated implicit-null insertion. Regression
tests reproduced the initial counter accepting 1025 explicit keys.

YAML `max_collection_work` now defaults to 1024, with the same policy ceiling.
It counts colon tokens, explicit key markers, opening flow maps, commas and block
sequence entries before parsing, regardless of the finding's rule action. This
conservatively bounds collection work and reports the actual work-unit budget.
Existing byte/node/depth/tag/alias checks remain in force. Wide collections may
now be refused. Monitor and rule-off modes retain forwarding semantics and stop
further YAML inspection at the budget.

On the same Windows machine the original body measured about 60 ms before and
2.45 ms after the initial bound; these are local measurements, not a production
latency guarantee. The 250 ms assertion remains unchanged. The real proxy tests
check ordinary and omitted-value variants, block/monitor/off behavior, exact
forwarded bytes, logged findings and independent origin request counts. See
[ADR-0075](adr/0075-carnical-yaml-parser-work-budget.md).

## Core scanner review and HTTP validation — 7 October 2026

The original seven remaining core G115 findings are resolved with explicit
byte bounds while preserving low-byte normalization. Unicode output uses the
signed formatting API for nonnegative runes, avoiding another narrowing path.
The regex prefilter no longer wraps shift distances above 255; regression cases
cover 255–512-byte literals, both case modes and every offset from 0 to 512.
Live HTTP checks on Windows and Linux blocked eight encoded/long-literal inputs
and admitted four ordinary controls, with independently counted origin requests.

The HTTP E2E runner now closes response bodies even when reading fails, preserves
read/close errors, and retains expected phase-3 body-abort behavior. A live
truncated response previously produced an error containing a nil cause; its
regression now exposes the actual unexpected EOF. Health checks validate URLs,
keep one control header across retries and enforce a 15-second context deadline
through body reads. A live stalled-body control confirms that deadline.

Five core code sites have narrowly scoped, reviewed exceptions: OSFS Open/ReadFile
load configured rules/data using native filesystem semantics; SecDebugLog opens
the administrator-selected destination with private creation permissions; the
existing zero-copy string helper transfers fresh buffers that callers never
mutate; and transformation-cache identity retains a typed pointer without
dereferencing it. Restricted RootFS implementations remain the sandbox boundary
for rule loading. The unused internal ReadFirstFile helper was removed after
confirming that no tracked module calls it. No scanner rule or required job was
disabled.

The complete native core suites pass on Windows and Linux, root lint reports
zero issues, and four evaluation/build-tag variants pass. The fresh core Gosec
scan reports zero findings and no package-loading errors on both targets. The
application inventory remains 115 Linux and 87 Windows findings, which continue
to fail the aggregate security gate. Local race execution still lacks a C
compiler; the hosted Ubuntu job supplies that check.

The ADR validator now normalizes Windows CRLF before inspecting sections. The
previous checker rejected 60 existing records on Windows; all 75 records now
pass on Windows and Linux, including the indexed YAML work-budget decision.

## Virtual-patch conversion publication — 7 October 2026

The pack converter now exclusively creates a private temporary file in the
operator-selected output directory and validates it through that same open
handle before publication. Failure cleanup preserves serialization, validation,
close and removal errors; failed reporting returns an error after publication.
The output directory must remain operator-controlled. Converted packs now use
0600 on Unix; installations using a separate service account must explicitly
grant it read access. Windows continues to use filesystem ACLs.

Regression controls reproduced loss of a neighbouring file and an input using
the previous temporary filename before the fix. A second control reproduced
a large valid legacy feed replacing a working pack with an output above the
64 MiB reader cap. Both defects no longer reproduce. JSON/YAML round trips,
existing-target replacement, input preservation, rename failure cleanup and
closed report output are covered in the existing command suite.

Independent source investigation and candidate review were completed; the
review's publication-before-validation defect was confirmed before correction.
The converter and virtual-patch short suites pass on Windows and Linux, and
focused vet passes. Actual converter processes on both platforms preserve
neighbouring/input files, load both output formats, support in-place conversion
and leave no temporary pack files. Linux checks private modes and an actual
failed-output sink. No new scanner exceptions were added.

The application rescan has 111 Linux and 83 Windows findings, four fewer per
target, with no package-loading errors. The core remains at zero. The hosted
run at commit 32f18269 passed both native suites, runtime/tag/live WAF tests,
Ubuntu race checks, CrowdSec, L3/L4, dependencies, secrets and workflow
validation. Application scanner findings still fail the security gate.

## Virtual-patch result-cache capacity — 7 October 2026

A public Go constructor call with ResultCache set to the largest positive integer
was isolated in its own process and confirmed to remain in the rounding loop.
The same path completed for ordinary and disabled capacities. No in-tree HTTP,
policy or control entry point supplies this option.

Positive capacities now cap at 1,048,576 entries (8 MiB) before rounding, with
a load-report warning for oversized requests. Default and negative/off behavior
are preserved. The original trigger and large power-of-two and just-over-ceiling
controls now complete. This bounds the result table per engine, not signature
allocations or multiple engines. Evictions can increase regex work and cause
earlier work-limit findings; see ADR-0076 and the integration guide.

Independent source investigation and candidate review found no remaining
capacity-boundary defect. Existing options tests cover the ceiling, rounding,
integer extrema, repeated loads, collisions and blocking/benign decisions.
The short virtual-patch suite passes on Windows and Linux; options tests also
execute on native Windows/386. Vet and all 76 ADR records pass. A full running
proxy with embedded CRS and the inspector handled 400 varied requests on each
platform: 200 refused, 200 admitted, and exactly 200 observed at the origin.

The application inventory is now 110 Linux and 82 Windows findings, with no
package-loading errors and no new scanner exceptions. The hosted run at
49a82bbe passed every native/runtime/integration and supply-chain job; the
remaining application findings keep both Gosec jobs and the aggregate gate red.

## Virtual-patch regex reload identity — 7 October 2026

A default-cache engine previously reused a regex non-match after a replacement
regex at the same condition index should match. Cache-disabled controls produced
the correct answer. Both full-proxy reproductions forwarded the first newly
blocked path after warming 50 non-matches, confirmed by origin request counts.
The indexed and brute-force APIs shared this defect; brute force was not used
as the independent oracle.

Each immutable snapshot now owns a fresh hash seed for cached regex results.
In-flight requests keep their original snapshot identity, so late old results
can evict a current slot but cannot deterministically alias a replacement rule.
The existing per-engine capped atomic table remains shared; compiled expressions
remain reusable. Each load starts cold for result caching and can increase
regex work. The table retains its pre-existing probabilistic fingerprint design.

Focused regressions failed before the change for stale false/true answers,
changed flags, one-slot late writes and exchanged true/false regex positions
during concurrent reloads. They now pass. The existing equivalence test contains
self-contained reload checks; external dataset absence skips only its dataset
subtest. Windows and Linux short suites for the engine, importers and pack CLI
pass, as do focused vet and workflow validation. Independent investigation and
candidate review found no surviving reload identity defect.

Live full-WAF checks on each platform send 300 varied requests through regex
replacement, reversal and flag changes: 100 refused and 200 forwarded, with
exactly 200 origin requests. Focused race checks were added to the hosted Ubuntu
job because local execution lacks a C compiler. Hosted run [37614453568](https://github.com/YurilLAB/carnical/actions/runs/37614453568)
passed the new race check and both native suites, runtime/tag/live WAF tests, CrowdSec, L3/L4, dependencies,
secrets and workflow validation. The application Gosec inventory still fails both scanner jobs and the aggregate gate.
No scanner exception was added for the reload fix.

## Batched application triage — 7–8 October 2026

This batch was validated locally before publication. Fresh application
scans contain zero Linux and zero Windows reports, with no package-loading errors,
down from 100 unique reports at the start of this batch. Reports were either
fixed or given a narrow, source-verified explanation; this does not mean 100
exploitable vulnerabilities were discovered or fixed. The core and API guard
remain clean. Required scanner rules and jobs remain enabled.

The signature converter now preserves its exclusive temporary file's private
permissions for signatures, conversion reports and legacy comparisons, including
replacement of an existing public output. All three sinks previously became 0644
on Unix; the regression reproduced this for new, private and public existing
files. They now remain 0600. A separate Unix account could open a public control
in the same traversable directory but was denied all three private outputs.
Owner conversion/comparison still succeeds, produces readable JSON and cleans up
failed publication. Independent source investigation and candidate review found
no surviving permission-boundary defect. Windows privacy remains an ACL and
operator-controlled directory responsibility.

Narrowing operations now expose existing bounds or retain the original value
in a suitably typed variable: API client fingerprints, percent-escape decoding,
Latin-1 corpus bytes, octal regex escapes, Bloom positions and literal masks.
API configuration boundary rows exercise New and SetConfig. The unused weak-key
fallback in the API limiter was removed: the supported Go 1.26 crypto/rand.Read
contract already fills the key or terminates the process, so that fallback was
not a demonstrated reachable entropy bypass. See [Go's crypto/rand contract](https://pkg.go.dev/crypto/rand#Read).

Seccomp assembly rejects offsets outside their serialized widths before casting;
existing program-length limits remain enforced. Boundary regressions cover
255/256 conditional offsets, larger unconditional jumps, missing/backwards
labels and 32-bit overflow. Real Linux confinement tests, unconfined controls
and deliberately weakened layers pass. The program limit agrees with
[the Linux kernel seccomp implementation](https://github.com/torvalds/linux/blob/master/kernel/seccomp.c).
The sandbox package builds for Linux/ARM64. No sandbox layer was removed.

The request runner preserves request-body, response-body and socket cleanup
errors. An incomplete readiness response cannot count as ready, and a failed
measured exchange cannot count as a completed refusal. Local HTTP regressions
cover normal responses, truncated bodies, request read/close failures, malformed
framing and corpus targets resembling external authorities. Reviewed exceptions
are limited to validated private configuration, infallible hash writes, fixed
procfs paths and offline operator-selected file/process/destination boundaries.
Reviewed public CRS asset permissions remain readable; private verification files
remain private. Existing Landlock/seccomp pointer bindings were checked against
fixed kernel ABI layouts and [Go's syscall pointer rules](https://pkg.go.dev/unsafe#Pointer);
no new unsafe binding was added. Authenticated clearance cookies remain usable
on plain HTTP, and direct TLS cookies are Secure; untrusted forwarding headers
do not change that decision. No broad scanner exclusion or baseline was introduced.

The confinement checker previously returned success when its JSON report was
sent to /dev/full. It now returns status 2 with an error; the live regression
passes while ordinary confined/unconfined reports remain valid. Fixture creation
errors are also returned before probes run. Its FlagSets already use ExitOnError;
the corresponding annotations document that existing failure behavior.

The sequence-store constructor now checks its private-directory requirement
before cleanup. Existing group/other permissions and directory symlinks are
rejected without changing permissions or removing files. Independent review
identified trailing-separator/dot spellings that initially passed the check;
those regressions failed before path normalization and now pass. The full
configuration suite passes on both platforms, including restart, corruption,
interrupted writes and concurrent signed-envelope acceptance. Windows ACLs,
trusted parent paths and continued ownership remain deployment responsibilities;
this library is not automatically installed by the standalone WAF. A proposed
cross-user tampering proof was blocked by automatic security review and was not
run; validation used ordinary filesystem-permission regressions.

The virtual-patch builder checks index widths, cumulative offsets, sentinel sizes
and flattened transform-table dimensions before narrowing or overflowing native
integers. A further independent review identified unchecked per-request class-mask
multiplication and backing-byte size on 32-bit hosts. The builder now rejects
those dimensions before publication; arithmetic boundary rows and actual matching
with 81 transform classes spanning two mask words pass on Windows, Linux and
Windows/386. No large allocation was attempted. A fresh candidate review found no surviving
index defect after that correction. A whole-batch representation
failure retains the prior active snapshot
and is reported with an empty-ID rejection. Native Windows/Linux matching suites
and 32-bit Windows boundary checks pass; actual billion-entry allocations were
not attempted, and these checks are not a general compilation memory cap. Live
reload checks through the full WAF pass on both platforms: 100 refused probes
and 200 admitted controls per platform, with exactly 200 origin requests.

Shield response-write and optional TCP-setting failures are now visible in
Snapshot.WriteErrors and Snapshot.SocketOptionErrors. Failure-path tests keep
refusal statuses, successful responses and HEAD requests correct, and a closed
Linux TCP listener produces the expected socket-option error count. Native
Windows/Linux shield suites pass. Thread-status reads also propagate scanner
and file-close errors instead of silently returning a partial status.

The complete Carnical module suites and full vet pass on native Windows and Linux.
After the final mask-size change, the complete virtual-patch short suites, its
importers and pack CLI passed again on both platforms, along with full vet.
All four CI-scanned modules have zero Gosec findings and no package-loading errors
for both target operating systems. Workflow validation, installer boundary tests
and all 76 ADR records pass. Local race execution remains unavailable without a C
compiler; the held batch still needs the hosted race jobs after publication.

An initial Linux
format timing assertion failed while builds/scans/tests were running together;
the complete format suite passed when rerun in isolation without relaxing its
thresholds. Each platform then completed 10,000 varied full-WAF requests with
zero transport errors or unavailable responses, and both reports pass the actual
CI supported-injection/control validator. Each run forwarded 4,672/5,000 benign
labels and refused 4,714/5,000 attack labels; 286 attack-labelled admissions and
328 benign-labelled refusals remain in the context-dependent corpus for triage.
They are not erased or presented as complete attack coverage. The final source
was rebuilt and rerun on 8 October with the same totals and passing validators.
The remaining labels are organized below; exploitation still depends on the
application and its configuration.

| Category | Attack-labelled requests reaching origin | Benign-labelled requests refused |
| --- | ---: | ---: |
| HTTP parameter pollution | 96 | 0 |
| Probe paths | 12 | 0 |
| Remote file inclusion | 168 | 0 |
| WordPress paths | 10 | 0 |
| Prototype pollution | 0 | 284 |
| XPath | 0 | 44 |

These counts are per platform and do not turn corpus labels into confirmed
bypasses or false positives. The final reload test also passed on each platform
with 100 refused probes, 200 admitted controls and 200 observed origin requests.

Single-source runs with shield on or monitor exhausted its baseline connection
budgets and were rejected as invalid payload measurements (9,217/9,412 transport
errors on Windows). Monitor disables attack-specific mitigation but retains
baseline limits; CLI help and flood documentation now make that distinction
explicit. The payload runs use the same ddos-off setting as hosted CI; separate
live kernel tests validate confinement. At publication, the last hosted run still
has two Gosec jobs and their aggregate gate failing; the committed batch requires
a new hosted run, including its race and integration checks.
