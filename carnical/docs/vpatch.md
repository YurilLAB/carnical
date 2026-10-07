# Virtual-patch integration and offline tools

`vpatch` compiles signatures into an immutable, atomically replaced request matcher. The engine implements
`inspect.Inspector`; the integrator installs it in the site's proxy and supplies a signature pack. The standalone
`cmd/carnical` executable does not install it automatically. External signature libraries are not shipped here.

```go
engine := vpatch.New(vpatch.Options{
    Mode: vpatch.ModeBlock,
    Tiers: []string{vpatch.TierVerified},
    BlockOnWorkLimit: true,
})
report := engine.Load(signatures)
// Inspect report before using the engine: invalid signatures are rejected individually.
```

The default mode is monitor and the default tier is verified. Community and experimental rules require an explicit tier
selection; experimental matches cannot block unless `ExperimentalMayBlock` is also enabled. Review imported rules against
real benign traffic before enabling them. `Scope` selects software tags and `Exclude` suppresses ID prefixes, allowing
integrations already running CRS to omit duplicated CRS signatures.

Regular expressions, transformation views, extracted values, output verdicts and per-request matching work are bounded.
The default regex-input work allowance is 4 MiB and the default verdict cap is 16. Work exhaustion reports rule 5100001;
`BlockOnWorkLimit` makes it refuse requests in block mode. `Stats()` exposes request, match, refusal and limit totals.
Callers must still provide bounded request bodies and preserve the proxy's inspected/forwarded request contract.

The `importers` packages convert supported CrowdSec AppSec rules, Suricata/Snort HTTP rules, nuclei templates and a SecLang
subset. Input is parsed, never executed. Conversion reports record unsupported constructs, constraints lost by conversion
and tier changes. A converted signature is not evidence that the originating scanner's entire test was reproduced. Keep
upstream licensing and notices when distributing rule data; the small checked-in test fixtures retain their notices.

From the `carnical` module:

```text
go run ./cmd/carnical-sigs convert -format crowdsec -in rule.yaml -out signatures.jsonl -report conversion.json
go run ./cmd/carnical-vpatch -h
```

`carnical-vpatch` supplies pack compilation, inspection and corpus replay commands. Its help documents the accepted input
formats and tier flags. These tools read local files; they do not send scanner requests to an external site.
`convert` writes through an exclusive temporary file in the selected output directory. Converted packs are created with
private permissions (0600 on Unix; Windows uses filesystem ACLs). Use an operator-controlled directory and explicitly grant
read access to a separate service account when installing a pack. The converter validates the temporary pack through its
open handle before publication; a serialization, validation or rename failure preserves the previous output. A failed report
write returns an error even if the valid pack has already been published.
For replay, supply `-scope jira` (or the site's other software tags) to activate scoped rules. A replay that loads no
signatures fails with an error instead of reporting empty detection and index-equivalence results as a successful check.

Publication validation on 2026-10-06 includes normal short package checks, importer tests, command tests, vet, a dependency
vulnerability scan and Linux/amd64 compilation. Dataset-backed tests require separately supplied files: set
`CARNICAL_VPATCH_DATA` to a directory with `legacy.jsonl` and `samples.jsonl`, and `CARNICAL_VPATCH_CORPUS` to the corpus
directory. Missing datasets cause explicit skips. The short index-equivalence workload is reduced from the full workload;
the final validation record distinguishes normal equivalence checks from scoped race checks.
