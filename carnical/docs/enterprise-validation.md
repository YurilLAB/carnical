# Enterprise protection validation

This record distinguishes tests of the changed Carnical code from limitations of the local development environment. Validation runs on Windows with Go 1.26.6 against local TCP listeners and an actual HTTP origin, without sending test attacks to public hosts.

## GraphQL operation and protocol enforcement (2026-10-05)

- `go test ./formats -count=1` passes, including the live proxy/origin checks, documentation consistency, monitor/off behavior, and adversarial cost checks without race instrumentation.
- `go test -race ./formats -skip 'Test(YAMLAtItsDefaultCapIsBounded|AdversarialBodiesCostInProportionToTheirSize)' -count=1` passes. These two existing timing tests have fixed throughput thresholds unsuitable for race instrumentation; they pass in the normal run above.
- `go test ./proxy -count=1` passes; the broader run also passes the proxy package with race instrumentation.
- `go vet ./formats ./proxy` passes.
- `go run golang.org/x/vuln/cmd/govulncheck@latest ./formats ./proxy` reports no reachable vulnerabilities in the tested packages at the time of the run. This is dependency evidence, not proof that the firewall has no vulnerabilities.
- `go test ./formats -run '^$' -fuzz '^FuzzGraphQL$' -fuzztime=30s -parallel=2` passes: 177,313 executions with the final implementation. It exercises documents and URL parameters and includes the new regression inputs as seeds.

Live evidence: selected GET mutations return 403 and produce rule 5002310; ambiguous selections and repeated `operationName` return 400 and rule 5002308. The origin receives zero requests for these refusals. A selected GET query beside an unselected mutation returns 200 and reaches the origin. A named POST mutation is forwarded with its body unchanged. Unit cases additionally cover forms, escaped parameter names, JSON member order, extensions, and a GET body explicitly permitted by policy.

Review covered bounded operation-name storage, selection ambiguity, method propagation to all envelopes, monitor/off behavior, no request content in findings, and the inspector's existing nil-input recovery contract. An initial method initialization before the recovery handler violated that contract; the existing regression test caught it and the initialization now happens inside the protected region.

## Environment and baseline limitations

`go test ./...` in the upstream module fails on existing Windows filesystem expectations and open audit/debug log handles (auditlog, operators, seclang, testing). The changed code is confined to Carnical's separate module; no upstream engine files are changed.

The broader Carnical race run encounters Windows audit-file recovery/truncation failures in the pre-existing, untracked `control` package. Those files are outside these commits. The first broad run also ran an intermediate implementation; its format failures were corrected and superseded by the passing scoped runs above.

`go run mage.go adr` rejects 60 pre-existing ADRs as lacking the exact technical-discussion section marker. The new ADR-0061 produces no diagnostic. The Windows checkout has CRLF in older documents, which the validator's exact marker comparison does not normalize. This check is not claimed to pass globally.

WSL's Ubuntu environment first reported a read-only home when creating the Go cache and subsequently failed to start. Linux confinement and the full Linux CI matrix have not been verified by these runs.
