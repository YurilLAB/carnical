# Coraza engine integration

Carnical builds on the Coraza engine and keeps its upstream Go import path. Use this reference when
embedding the engine or reviewing changes in this fork. For the standalone proxy, start with the
[operator guide](../carnical/README.md).

## Coraza Core Usage

Embed Coraza to add WAF middleware to a Go application or web server. The engine retains
`github.com/corazawaf/coraza/v3`; this workspace builds against the local engine.

```go
package main

import (
	"fmt"

	"github.com/corazawaf/coraza/v3"
)

func main() {
	// Initialize the WAF and parse the SecLang rules.
	waf, err := coraza.NewWAF(coraza.NewWAFConfig().
		WithDirectives(`SecRule REMOTE_ADDR "@rx .*" "id:1,phase:1,deny,status:403"`))
	// Check for rule parsing errors.
	if err != nil {
		fmt.Println(err)
		return
	}

	// Create a transaction and set its connection details.
	tx := waf.NewTransaction()
	defer func() {
		tx.ProcessLogging()
		tx.Close()
	}()
	tx.ProcessConnection("127.0.0.1", 8080, "127.0.0.1", 12345)

	// Process the request headers phase, which may return an interruption.
	if it := tx.ProcessRequestHeaders(); it != nil {
		fmt.Printf("Transaction was interrupted with status %d\n", it.Status)
	}
}

```

[HTTP server example](../examples/http-server/) provides an example to practice with Coraza.

## Build tags

See the [build-tag reference](../README.md#build-tags).

## FIPS mode

Coraza supports running under Go's [FIPS 140-3 mode](https://go.dev/doc/security/fips140) enabled.
Detection of FIPS mode is performed at runtime, so no build tag is required and default builds are
unchanged.

`t:md5` and `t:sha1` are unavailable whenever FIPS mode is on, that is under all of
`GODEBUG=fips140=on`, `=debug` and `=only`. Coraza applies the restriction uniformly so that
behaviour does not vary across FIPS modes. Both transformations stay **registered**, so rule sets
referencing them, including the CRS, still load unchanged.

The restriction applies at evaluation time: the transformation errors, the engine logs a warning and
keeps the untransformed value. The chain is **not** aborted and the rule is **not** skipped. For
example, `t:sha1,t:hexEncode` becomes effectively `t:hexEncode` over the raw input and the rule may
match *differently* rather than simply not matching.

Review any rule depending on these before deploying in FIPS mode.

## E2E Testing

From the repository root, run the local HTTP integration tool against your own WAF and test origin:

```shell
go run ./http/e2e/cmd/httpe2e --proxy-hostport localhost:8080 --httpbin-hostport localhost:8081
```

or as a library by importing:

```go
"github.com/corazawaf/coraza/v3/http/e2e"
```

As a reference for library usage, see [`testing/e2e/e2e_test.go`](../testing/e2e/e2e_test.go).
Expected directives that have to be loaded and available flags can be found in
[`http/e2e/cmd/httpe2e/main.go`](../http/e2e/cmd/httpe2e/main.go).

## Development

Coraza only requires Go for development. You can run `mage.go` to issue development commands.

See the list of commands

```
$ go run mage.go -l
Targets:
  check        runs lint and tests.
  coverage     runs tests with coverage and race detector enabled.
  doc          runs godoc, access at http://localhost:6060.
  format       formats code in this repository.
  fuzz         runs fuzz tests.
  lint         verifies code quality.
  precommit    installs a git hook to run check when committing.
  test         runs all tests.
```

For example, to format your code before submission, run

```shell
go run mage.go format
```

## Changes in this fork


- `go.work`: includes `./carnical` and pins Go 1.26.9, including the October 2026 HTTP/2 security fixes. Builds also use `golang.org/x/net` v0.60.0.
- `internal/corazawaf/rulegroup.go`, `rule.go`, `transaction.go`: rule evaluation stops when the transaction's context is done, and a blocking engine refuses the transaction (503). Nothing in the engine looked at the context before, so a request that was expensive to inspect could not be cut short. The proxy gives each evaluation phase a budget through it (`proxy/deadline.go`). A test in `rulegroup_test.go` covers the three cases.
- `internal/transformations/normalise_path.go`: `path.Clean` instead of `filepath.Clean`, so the transformation gives the same result on every OS.
- Further engine hardening validates audit-log part names and file modes, restricts new debug-log permissions and reports cleanup failures. See the [security findings review](security-findings.md) for confirmed fixes and remaining work.
