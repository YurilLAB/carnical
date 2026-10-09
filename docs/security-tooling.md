# Automated security review

The [Carnical repository](https://github.com/YurilLAB/carnical) uses one tool per review category.

| Category | Tool | Coverage |
| --- | --- | --- |
| Core source security, including Go-specific checks | [gosec](https://github.com/securego/gosec), v2.29.0 | Go AST/SSA and taint checks, targeting Linux and Windows |
| Dependency vulnerabilities | [OSV-Scanner](https://google.github.io/osv-scanner/usage/), v2.6.0 | All five tracked Go manifests; Go call analysis and all advisory results |
| Committed secrets | [Gitleaks CLI](https://github.com/gitleaks/gitleaks), v8.30.1 | Complete Git history, with redacted findings |
| Workflow validation | [actionlint](https://github.com/rhysd/actionlint), v1.7.12 | Actions syntax, expressions, and shellcheck on the Linux runner |
| Updating dependencies/actions | [Dependabot](https://docs.github.com/en/code-security/dependabot/working-with-dependabot/dependabot-options-reference) | Weekly reviewable PRs targeting `edge-crs`; no automatic merges |

The inherited CodeQL workflow was replaced while the repository was private and
lacked GitHub Code Security entitlement. The current workflow retains gosec as
the core scanner, with one tool per category. Semgrep CE was evaluated locally:
v1.179.0 reported partial parsing of the valid `hashOf[T ~string | ~[]byte]`
function in `carnical/apiguard/learn.go`. Choosing gosec also avoids overlapping
core scanners on this Go project. SonarQube and Bearer are alternatives to core
analysis rather than additional required services.

Scanners run within the checkout. No source is uploaded to a scanner SaaS/AI
service. OSV queries vulnerability/package services; release and Go module
downloads, GitHub artifacts, and Actions caches still use the network. Scanner
subscriptions are not required; Actions minutes/artifact storage remain
subject to the account's GitHub limits.

## Runs and reports

`.github/workflows/security.yml` runs on pushes to `edge-crs`/`main`, every PR,
Monday at 06:15 UTC, and manual dispatch. There are no path filters. Each category
has a time limit, read-only repository permissions, and checkout credential
persistence disabled. Actions are pinned to commit SHAs.
The runner is pinned to Ubuntu 24.04 to avoid an unreviewed distribution upgrade.

**Security review required** fails if any category fails, is cancelled, or is
skipped. Findings are not suppressed with `-no-fail`, a vulnerability ignore
list, or a code baseline. Reports survive failed scans for seven days. Open the
Actions run for the result table and gosec/Gitleaks SARIF or OSV JSON artifacts;
GitHub's private Security dashboard is not required. This workflow does not
change branch protection. Configure **Security review required** as a required
branch check when that feature is available for the repository.

gosec scans the root engine, `carnical`, the HTTP example, and the CRS harness
separately, with Linux and Windows target builds. Its default excludes `_test.go`;
the CRS harness currently has only tests, so no production files are scanned
there. The optional CGO `testing/modsecurity` comparison harness is included in
dependency auditing. Additional build tags are outside this static scan. Runtime,
fuzz, and live WAF tests remain separate validation.

OSV uses explicit manifest paths so untracked research, upstream downloads, and
`build/` do not become project dependencies. `--all-vulns` retains and fails on
module advisories even when call analysis marks them uncalled. Findings and
uncalled classifications are not proof of exploitable WAF vulnerabilities.
Processing/network failures also fail the check.

## Secret fixtures

`.gitleaks.toml` extends the default rules. Each exception requires both an exact
file path and an exact synthetic value, restricted to the matching rule. No
complete directory, report, or history is exempted. Verified fixtures are:

- Two fixed benchmark/example JWTs that are not provisioned credentials.
- A public signing-domain label, deterministic feed test key, and public signature vector.
- RFC WebSocket sample nonces and the old `SECRETMARK-4711` response-redaction marker.
- The exact shell template generating random non-key honeytoken bytes.
- Fifteen synthetic token variants in four historical load-test JSON reports.

A new credential in those report files still fails. Verify provenance and run
a positive control before adding another fixture exception. Actual exposed
credentials require revocation/rotation rather than an exception.

## Local commands

From the repository root, with Python 3.12+ and Go 1.26.9:

```shell
python .github/security/install.py gosec
python .github/security/install.py osv-scanner
python .github/security/install.py gitleaks
python .github/security/install.py actionlint
python .github/security/test_install.py
```

The installer supports x64 Linux/Windows. Hashes in `.github/security/tools.json`
are verified before installation. Downloads are limited to 64 MiB, extracted
executables to 128 MiB. Only the named executable is extracted; tar symlinks are
rejected and destination replacement is atomic. Update versions and hashes
together after checking the upstream release manifest. Dependabot maintains
Actions/module versions; scanner pins in `tools.json` need manual review.

On Linux use the workflow's scan commands. On PowerShell use `.exe` suffixes and
quote native arguments containing dots:

```powershell
$env:GOOS = 'linux' # repeat with windows
$env:CGO_ENABLED = '0'
build/security-tools/gosec.exe '-exclude-dir=.attack' '-exclude-dir=build' ./...
# Repeat in carnical, examples/http-server, testing/coreruleset with the absolute scanner path.
build/security-tools/osv-scanner.exe scan source --call-analysis=go --all-vulns --lockfile=go.mod --lockfile=carnical/go.mod --lockfile=examples/http-server/go.mod --lockfile=testing/coreruleset/go.mod --lockfile=testing/modsecurity/go.mod
build/security-tools/gitleaks.exe git . --config=.gitleaks.toml --redact
build/security-tools/actionlint.exe -shellcheck= -pyflakes=
```

## Initial validation: 2026-10-06

All four Windows releases were installed with verified hashes through the new
helper. Its regression test covers raw/zip/tar installation, checksum tampering,
tar symlinks, oversized members, and ignoring an unrelated archive path.
actionlint passes locally with shellcheck/pyflakes disabled because they are not
installed on Windows; the GitHub run additionally uses shellcheck.

Gitleaks scanned 1,671 commits and approximately 78.02 MB. The initial 490 matches
were grouped and verified as the exact fixtures above. Full-history scanning
passes with those narrow exceptions. Positive controls confirm new generic
credentials fail, including in an excepted report path. Other positive controls
confirm gosec reports MD5 use with G401, OSV blocks vulnerable `x/net v0.17.0`,
and actionlint rejects an unknown expression. They failed for real findings,
rather than installation/processing errors.

The initial project scans are **not clean**:

| Scan | Result |
| --- | --- |
| Root engine, Linux and Windows | 36 gosec findings per platform |
| Carnical, Linux / Windows | 145 / 107 gosec findings |
| HTTP example, Linux | 2 gosec findings |
| CRS harness | No non-test Go files for default gosec analysis |
| Dependencies | 3 module advisories in `testing/coreruleset/go.mod` |

The examined root/Carnical/example scans have no package-loading errors.
Existing findings include integer narrowing, compatibility hashes, unsafe/syscall
operations, configurable file/command paths, ignored errors, and HTTP/cookie
defaults. They remain unsuppressed for review and are not all confirmed bugs.
Do not silently baseline them to obtain a green check.

OSV reports [GO-2026-6354](https://pkg.go.dev/vuln/GO-2026-6354) and
[GO-2026-6355](https://pkg.go.dev/vuln/GO-2026-6355), fixed in `x/crypto v0.56.0`,
and [GO-2026-5932](https://pkg.go.dev/vuln/GO-2026-5932), concerning unmaintained
OpenPGP. All were marked uncalled locally, but the inventory check still fails.
The test-module pin is `v0.55.0`. An upgrade requires checking its Go minimum
and test-harness compatibility. The OpenPGP advisory has no fixed version and
needs a package-level usage review. This tooling change does not hide findings
or alter runtime/dependency versions.

The first [hosted validation run](https://github.com/YurilLAB/carnical/actions/runs/37423931304)
at commit `806f67f9` reproduced the local results: 183 Linux and 145 Windows gosec
findings, and the same three dependency advisories. All eight gosec SARIF reports
and the OSV inventory were downloaded and inspected. Secret detection, workflow
validation including shellcheck, and installer regression tests passed. Findings
failed the source/dependency jobs and the aggregate check; artifact uploads
succeeded. The subsequent workflow maintenance change pins `upload-artifact`
v7.0.1 to remove the deprecated Node 20 action warning. These results validate
the tooling and its failure behavior, not a clean security audit of the code.
