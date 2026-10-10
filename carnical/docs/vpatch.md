# Virtual patches and offline tools

`vpatch` compiles signatures into an immutable, atomically replaced request matcher. The engine
implements `inspect.Inspector`; the integrator installs it in the site's proxy and supplies a
signature pack. The standalone `cmd/carnical` executable does not install it automatically. External
signature libraries are not shipped here.

```go
engine := vpatch.New(vpatch.Options{
    Mode: vpatch.ModeBlock,
    Tiers: []string{vpatch.TierVerified},
    BlockOnWorkLimit: true,
})
report := engine.Load(signatures)
// Inspect report before using the engine: invalid signatures are rejected individually.
```

The default mode is monitor and the default tier is verified. Community and experimental rules
require an explicit tier selection; experimental matches cannot block unless `ExperimentalMayBlock`
is also enabled. Review imported rules against real benign traffic before enabling them. `Scope`
selects software tags and `Exclude` suppresses ID prefixes, allowing integrations already running
CRS to omit duplicated CRS signatures.

## Loading and index limits

Compiled indexes use checked 32-bit indices and offsets, including cumulative literal-table offsets
and flattened transformation views. Per-request class-mask dimensions and their uint64 backing bytes
must also fit native integer arithmetic; 32-bit deployments can therefore reject a rule set that
fits on 64-bit hosts.

If an entire index cannot fit, `Load` retains the previous active snapshot and reports a rejection
with an empty ID; the report's loaded counts describe that retained snapshot. This representation
check is not a general memory budget for signature compilation.

## Request work limits

Regular expressions, transformation views, extracted values, output verdicts and per-request
matching work are bounded. The default regex-input work allowance is 12 MiB and the default verdict
cap is 16. A byte given to an expression is charged by what the expression costs: once for most,
and about once per 16 NFA threads its large counted repeats can keep alive (`x{0,990}` some 60
times), charged before it runs, so a value that would take more than is left is not run. No request
of the equivalence corpus, padded attack variants included, runs out at the default allowance.

Go's regular expressions have no DFA, so an alternation whose branches stay alive together costs
its whole program on every byte, which the charge for counted repeats does not see. Two more bounds
cover that: an expression may compile to at most 8,000 instructions (the largest in the shipped
feeds is about 6,500), and a request has a time budget for expressions, `MaxEvalTime` (two seconds
by default, as the proxy gives each phase of rule evaluation; negative switches it off). Once it has
passed no further expression runs, so a request takes at most its budget plus one run. The largest
shipped expressions take some 40 ms on a hostile 128 KiB value; one built to keep 8,000 instructions
alive can take a few seconds. Work exhaustion and the time budget both report rule
5100001; `BlockOnWorkLimit` makes it refuse requests in block mode. `Stats()` exposes request,
match, refusal and limit totals. Callers must still provide bounded request bodies and preserve the
proxy's inspected/forwarded request contract.

Form and JSON bodies are read whole into arguments (at most 1,024); a value longer than 64 KiB, in
any target, is matched as its first and last 64 KiB. Multipart parts are read to their end on the
same terms. A multipart body with more than 64 parts, or longer than 8 MiB, is also offered raw to
`body` signatures, since the parts that were not read still reach the application. A part is a file
only when its `filename` parameter is set.

## Result cache

The regex result cache defaults to 32,768 entries (256 KiB). A negative `ResultCache` disables it;
positive capacities round up to a power of two, with a per-engine ceiling of 1,048,576 entries (8
MiB). Oversized requests use the ceiling and produce a `LoadReport.Warnings` entry.

Evictions can cause repeated regex work and earlier work-limit findings, so size the work allowance
for uncached traffic and review load warnings. The ceiling does not bound the memory used by loaded
signatures. Each successful load uses a fresh snapshot-specific cache identity, so old regex answers
cannot deterministically carry over to replacement rules, even when an older request finishes later.

Loads start cold for regex result caching; compiled expressions can still be reused. The table
retains its existing keyed fingerprint design.

## Import and conversion

The `importers` packages convert supported CrowdSec AppSec rules, Suricata/Snort HTTP rules, nuclei
templates and a SecLang subset. Input is parsed, never executed. Conversion reports record
unsupported constructs, constraints lost by conversion and tier changes. A converted signature is
not evidence that the originating scanner's entire test was reproduced. Keep upstream licensing and
notices when distributing rule data; the small checked-in test fixtures retain their notices.

From the `carnical` module:

```text
go run ./cmd/carnical-sigs convert -format crowdsec -in rule.yaml -out signatures.jsonl -report conversion.json
go run ./cmd/carnical-vpatch -h
```

Conversion reports and legacy comparison reports can contain private patterns/metadata and are
private too. Use an operator-controlled directory and explicitly grant any service-account access.

`carnical-vpatch` supplies pack compilation, inspection and corpus replay commands. Its help
documents the accepted input formats and tier flags. These tools read local files; they do not send
scanner requests to an external site. `convert` writes through an exclusive temporary file in the
selected output directory.

Converted packs are created with private permissions (0600 on Unix; Windows uses filesystem ACLs).
Use an operator-controlled directory and explicitly grant read access to a separate service account
when installing a pack. The converter validates the temporary pack through its open handle before
publication; a serialization, validation or rename failure preserves the previous output.

A failed report write returns an error even if the valid pack has already been published. For
replay, supply `-scope jira` (or the site's other software tags) to activate scoped rules. A replay
that loads no signatures fails with an error instead of reporting empty detection and
index-equivalence results as a successful check.

## Validation and datasets

Publication validation on 2026-10-06 includes normal short package checks, importer tests, command
tests, vet, a dependency vulnerability scan and Linux/amd64 compilation. Dataset-backed tests
require separately supplied files: set `CARNICAL_VPATCH_DATA` to a directory with `legacy.jsonl` and
`samples.jsonl`, and `CARNICAL_VPATCH_CORPUS` to the corpus directory. Missing datasets cause
explicit skips. The short index-equivalence workload is reduced from the full workload; the final
validation record distinguishes normal equivalence checks from scoped race checks.
