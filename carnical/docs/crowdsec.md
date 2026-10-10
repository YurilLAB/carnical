# CrowdSec IP decisions

Carnical reads IP/CIDR ban decisions directly from CrowdSec's Local API (LAPI). IPv4, IPv6 and
IPv4-mapped visitors are supported. Each HTTP request, including requests on existing keep-alive
connections, checks its verified client address before body inspection, flood admission or CRS
evaluation. The integration is independent of the CRS, format and flood modes.

This is an optional LAPI v1 **ban** integration, validated against CrowdSec 1.8.1. It does not
implement CrowdSec captcha, custom remediation, AppSec forwarding, usage-metrics submission or
CrowdSec hub certification. Simulated decisions and unsupported actions/scopes are skipped and
counted in the latest refresh log. The existing AppSec YAML importer in `vpatch/importers/crowdsec/`
is separate.

Start with [connection setup](#connect), then review [outage
behavior](#updates-outages-and-monitoring) and [live validation](#validate-and-remove). Source:
[CrowdSec client](../crowdsec/), [proxy integration](../proxy/proxy.go).

## Connect

Install and run CrowdSec separately. On its server, register a dedicated bouncer for **each Carnical
process**. Do not share this key with the firewall bouncer or another Carnical replica: the stream
cursor is stored per bouncer in LAPI.

```sh
# For the supplied systemd user; adapt the group for another deployment.
sudo install -d -o root -g carnical-edge -m 0750 /etc/carnical-crowdsec
sudo sh -c 'umask 077; cscli bouncers add carnical-edge-1 -o raw > /etc/carnical-crowdsec/carnical-edge-1.key'
sudo chown root:carnical-edge /etc/carnical-crowdsec/carnical-edge-1.key
sudo chmod 0640 /etc/carnical-crowdsec/carnical-edge-1.key
```

Supply the key through a private file, never as a flag value or in source control. On Linux and
macOS, Carnical refuses a key file that its group can write or that others can access at all (0640
as above is fine). It reads it once at startup; rotate it by replacing the file and restarting. Key and CA file symlinks must
resolve within their named parent directory; use the actual file path for a target elsewhere. An
initial authenticated, complete decision snapshot must succeed before listening, even with
`-crowdsec-fail-open` enabled.

```sh
carnical -upstream https://application.example -mode block -listen 127.0.0.1:8082 \
  -crowdsec-api http://127.0.0.1:8080 \
  -crowdsec-key-file /etc/carnical-crowdsec/carnical-edge-1.key
```

The default Carnical listener also uses port 8080. Choose a different `-listen` address, a TLS
listener or systemd socket activation when LAPI uses that port. For a remote LAPI use HTTPS; the
certificate and hostname are always verified. Use `-crowdsec-ca-file /path/to/ca.pem` for a private
CA. HTTP is accepted only on a literal loopback address. Redirects and environment HTTP proxies are
refused. URLs must name the API origin without `/v1`, credentials, query or fragment.

On Linux, CrowdSec 1.8 supports a Unix socket. Configure `api.server.listen_socket` on CrowdSec and
give the Carnical user permission to traverse its directory and connect to the socket. Then use
`-crowdsec-api /run/crowdsec/crowdsec_api.sock`. This is the preferred local connection with the
supplied deployment's network policy: `carnical.nft` deliberately denies the edge access to private
IP addresses, including loopback.

For TCP, add an explicit destination/port exception for LAPI before the private-address denial; do
not broadly allow the private network. When using `-confine`, the API TCP port must also appear in
`-confine-connect`. The program checks that list at startup. Keys and CA certificates are loaded
before confinement.

Behind a CDN or load balancer, configure `-trusted-proxies` with the actual peer ranges. Carnical
checks the first untrusted address from the right of the forwarding chain. Untrusted connections
cannot choose their identity with X-Forwarded-For. A ban covering the CDN peer does not
automatically ban an unrelated verified visitor.

## Updates, outages and monitoring

The request path performs local prefix lookups; it never contacts LAPI. The first pull uses
`startup=true`, then polls deltas every 10 seconds. Any failed pull forces a full resync on the next
attempt, since LAPI may have advanced its cursor. Changes are published atomically. Deletions use
decision IDs, so deleting one ban cannot erase another overlapping decision. Bans also expire
locally during an API outage. CrowdSec rounds remaining durations to seconds, so expiry follows that
API precision.

| Flag | Default and behavior |
| --- | --- |
| `-crowdsec-poll` | `10s`; supported range `1s` to `1h`; additions/deletions apply at the next successful poll |
| `-crowdsec-timeout` | `5s`; supported range `100ms` to `30s`; includes reading the response |
| `-crowdsec-max-stale` | `2m`; measured from the start of the last successful pull; at least poll + timeout, at most `24h` |
| `-crowdsec-fail-open` | `false`; stale/uninitialized cache returns 503. When true, unlisted visitors continue through all other WAF protections. Unexpired cached bans still return 403 |
| `-crowdsec-max-decisions` | `200000`; bounds stored bans and total new/deleted entries in one response; configurable up to `1000000` |
| `-crowdsec-origins` | empty, meaning all LAPI decision origins; optional comma-separated filter such as `cscli,crowdsec,CAPI,lists` |

Responses are also bounded to 64 MiB in the CLI. The Go package allows configuring this limit up to
256 MiB. Capacity overflow, malformed updates, authentication failure and timeouts preserve the
previous snapshot and count as failed refreshes. Choose capacity for the complete blocklist and
deletion history; an oversized initial snapshot prevents startup.

Every IPv4 lookup makes at most 33 prefix probes, every IPv6 lookup at most 129, independent of
blocklist size. Ranges are stored as prefixes, never expanded into individual addresses.

JSON logs report `entries`, `skipped` (latest pull), `syncs`, `failures`, `stale`, `blocked` and
`unavailable` counters after every refresh. Sampled request refusals use rule **5000060** for bans
and **5000061** for unavailable decisions, capped at one combined event per second per edge.
Counters include every refusal.

The 403 and 503 responses have `Cache-Control: no-store`; 503 includes `Retry-After: 10`. Keys,
decision values, API response bodies and URLs are not logged by this client. The existing
`-log-details` option can include visitor addresses and URIs in sampled request logs; leave it
disabled unless those details are needed.

## Validate and remove

Use an isolated test address, not an administrator's production address:

```sh
sudo cscli decisions add --ip 192.0.2.9 --duration 1m
sudo cscli decisions list
# Delete the particular decision ID when other range bans overlap.
sudo cscli decisions delete --id DECISION_ID
```

For a local reverse proxy configured to trust loopback, send a request with `X-Forwarded-For:
192.0.2.9` and verify 403, then verify a clean address reaches the origin. Do this only against a
test listener; do not trust arbitrary internet peers just to test a forwarding header.

The repository's `.github/security/test_crowdsec.py --binary build/carnical-ci` starts an isolated
real CrowdSec LAPI, creates its own test credentials, checks TCP/Unix sockets, IPv6, overlap,
expiry, outages, recovery and updates after process confinement, and sends 20,000 mixed requests
plus 200 varied SQL probes through the running WAF. CI also runs race tests with a 100,000-entry
decision list and malformed/overflowing updates.

To disable, remove all `-crowdsec-*` arguments and restart Carnical. Revoke its bouncer using `cscli
bouncers delete carnical-edge-1` and remove the private key file when no longer needed. The
integration does not alter or remove CrowdSec decisions. A separately installed firewall bouncer can
continue protecting TCP and other services; HTTP bans in Carnical do not replace kernel L3/L4
protection.

References: [CrowdSec bouncer
protocol](https://docs.crowdsec.net/docs/contributing/specs/bouncer_appsec_specs/), [LAPI
configuration](https://docs.crowdsec.net/docs/local_api/configuration/), [firewall
bouncer](https://docs.crowdsec.net/u/bouncers/firewall/).
