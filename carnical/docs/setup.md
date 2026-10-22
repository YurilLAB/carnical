# Set up an installed Carnical WAF

On Windows (PowerShell) or Linux, run:

```sh
carnical setup
carnical check
carnical start
```

If the binary is not on PATH, use `./carnical setup` on Linux or `./carnical.exe setup`
in PowerShell. Build from `carnical/` with `go build -o carnical ./cmd/carnical` on Linux
or `go build -o carnical.exe ./cmd/carnical` on Windows.

## Commands

| Command | What it does |
| --- | --- |
| `carnical setup` | Asks about the site, checks the answers and saves them. |
| `carnical check [FILE]` | Checks the saved settings and connects to the origin (DNS, TCP and TLS; no HTTP request), without listening. |
| `carnical start [FILE]` | Starts the WAF with the saved settings. |
| `carnical help [TOPIC]` | A short guide; topics `setup`, `profiles`, `security`, `bots`, and `flags` for every flag. |
| `carnical version` | The version of the embedded rules. |

Without `FILE`, `check` and `start` use the site setup saved in its default place (below). Flags
after the command change a setting for that run only, as in `carnical start -mode block`; every
flag still works on its own, as in `carnical -config site.json`.

## The questions

Press Enter to take the recommended answer shown in `[brackets]`, or type `?` for help on the
question. A question with no brackets has no safe default and must be answered.

1. **Your website**: the names visitors use, and the origin server Carnical forwards to. A bare
   address means HTTPS; use an explicit `http://` for a local HTTP origin. A private origin
   address must be allowed explicitly; for an origin name, give the private addresses it resolves to.
2. **Visitors**: `https` when Carnical holds the certificate (it must be current, match its key and
   cover every website name), `proxy` behind an existing TLS gateway (a specific loopback/private
   listener and the gateway's addresses; restrict network access to those peers, as trusting
   forwarding headers alone does not restrict who can connect), or `local` for loopback HTTP tests.
   An HTTPS origin can have its own CA bundle and a client certificate.
3. **Protection profile**: the site type and the attack detection level.
4. **Security settings**: whether attacks are blocked or only logged, flood protection, auto-block,
   a login limit, which bots to block and intrusion alerts.
5. **Attack alerts**: an HTTPS endpoint told of each intrusion alert, and when an attack starts,
   goes on and ends, with the attacked ports and protocols (blank for none), the private addresses
   it may be at, and a signing secret file; leave the secret blank and setup makes one when it
   saves, next to the key. See [alert endpoint](alert-endpoint.md).
6. **Check and save**: the settings are checked as start-up checks them, a summary is shown, and
   setup asks before saving.

| Site type | Flags it sets |
| --- | --- |
| `general` (recommended) | none |
| `wordpress` | `-wordpress`: no scripts from upload and cache directories, `xmlrpc.php` off, 10 login attempts a minute |
| `api` | `-api-guard monitor`; flood protection `relaxed` is then recommended |
| `java` | `-allow-path-params`, for `;jsessionid=` |

| Detection level | Flags it sets |
| --- | --- |
| `relaxed` | `-inbound-threshold 8 -outbound-threshold 8`: blocks at a score of 8 |
| `normal` (recommended) | none: CRS paranoia level 1, blocking at 5 |
| `strict` | `-paranoia 2`: finds more and flags more ordinary traffic |

| Security question | Recommended | Flags |
| --- | --- | --- |
| When an attack is found | `detect` | `-mode`, and `-formats-mode block` with `block` |
| Flood protection | `normal` (`relaxed` for an API) | `-ddos` |
| Ban addresses that keep attacking | `monitor` | `-auto-block`; see [repeat offenders](ddos.md#repeat-offenders) |
| Login page to protect | none | `-limit 'POST PATH 10/m'` (WordPress has its own) |
| Bots to block | `fake` | `-bots`; `fake` refuses scanners and fake search engines, `ai` adds AI and SEO crawlers, `strict` every kind. In detect mode only scanners are refused and the rest go in `-bots-monitor`; see [bots](bots.md) |
| Intrusion alerts | `on` | `-alerts`; see [intrusion alerts](proxy-reference.md#intrusion-alerts) |

Detection mode records CRS findings and monitors request formats. Blocking mode enables both
content layers. Flood and proxy safety checks still enforce in detection mode. Review real
application traffic before changing production policy.

The check runs the normal startup validation without starting a listener. The optional origin
check resolves the origin and checks TCP/TLS within ten seconds; it sends no HTTP request.
Setup does not change DNS, firewall rules, certificates or installed services.

## Save and start

After the summary, the wizard asks whether to save. Answer `n` to leave no configuration or key
file. Otherwise it saves the site file and a separate key file, by default in the account's
configuration directory, where `check` and `start` find them:

| Platform | Site file | Key directory |
| --- | --- | --- |
| Linux | `$XDG_CONFIG_HOME/carnical/site.json`, or `$HOME/.config/carnical/site.json` | `$XDG_CONFIG_HOME/carnical/keys`, or `$HOME/.config/carnical/keys` |
| Windows | `%APPDATA%\carnical\site.json` | `%APPDATA%\carnical\keys` |

Existing files are never replaced: when a site is already saved there, setup offers `site.json`
in the current directory instead, and the printed commands name it (`carnical start site.json`).
A custom key location adds `-config-key-file` to them. The printed quoting is for the host's
shell: PowerShell on Windows, a POSIX shell on Linux. Interrupted setup before saving leaves no files.
Run the WAF with the same account as setup, or prepare the key for the service account below.
Settings load once, before listening and confinement; changes require restart. CLI options
override site-file values, including encrypted fields; invalid ciphertext still fails startup.
To limit how fast one client may call an API, add rate rules to the `flags` object, as in
`"limit": "POST /login 5/m; /api 600/m"`; see [rate rules](proxy-reference.md#rate-rules).

## What is encrypted

The site file keeps website names, listener, profile and security settings in its readable
`flags` object. The `private` object contains a random key ID and AES-256-GCM ciphertext for
the origin URL, origin HTTP Host, private allowances, trusted peers, certificate/key paths and the
alert endpoint's URL, allowance, CA file and secret file path.
Each save creates an independent random 32-byte key and random nonce. Authentication failure,
unknown fields, duplicate flags across sections and unsafe key files fail startup.

An error that stops startup or `-check` leaves the encrypted settings out, along with any address
(the origin's resolved address follows from them): `invalid origin range "[private setting]"`.
To see the values, give the same settings as flags on the command line.

The default key location is in the table [above](#save-and-start). If the account has no configuration directory, enter an explicit key-file path. A blank answer
is refused. The printed check and start commands include `-config-key-file` for that path.

The key file contains exactly 32 binary bytes. Linux keys require owner-only permissions;
setup writes 0600. Windows setup uses a protected ACL with access only for the setup account
and SYSTEM. Windows applies that ACL during exclusive file creation, before another
account can obtain an inherited read handle. Inherited or additional grants are refused
when loading the key. Windows filenames with streams, reserved devices or trailing dots
and spaces are refused. Existing files remain untouched.

Private certificate/key contents remain in their existing credential files. Setup asks for
paths, never raw passwords, tokens or private keys, and does not rewrite those files. Protect
them using the [origin credential requirements](website-onboarding.md#operator-authenticate-the-waf-to-the-origin).

Encryption protects private settings when the site file is copied without its key. It does
not protect them from an administrator or a compromised WAF account that can read the key.
Public settings remain editable operator policy; encryption does not authenticate those
settings. Keep configuration, key files and parent directories under operator control.

## In a container

The image built from [`deploy/container`](../deploy/container/) runs `carnical` as its entry point, so
`setup`, `check` and `start` work inside it. The wizard runs as the image's unprivileged user
(UID 65532), so give it a directory it can write the site file and key into, and certificate files
it can read:

```sh
mkdir config && sudo chown 65532:65532 config   # the wizard writes site.json and the key here
# visitor certificate and key in ./tls, with the key readable by GID 65532 (e.g. root-owned 0640)
docker run --rm -it -v "$PWD/config:/config" -v "$PWD/tls:/tls:ro" carnical:local setup
```

Answer the questions as above. Give the certificate paths as `/tls/cert.pem` and `/tls/key.pem`,
and when it asks where to save, type `/config/site.json` and `/config/site.key`: the default it
offers is the account's configuration directory, which the image's user cannot write. Then run the
saved file read-only, as the [container guide](availability-and-deployment.md#linux-container)
shows:

```sh
docker run -d -p 443:8443 --read-only --cap-drop ALL \
  -v "$PWD/config:/config:ro" -v "$PWD/tls:/tls:ro" \
  --tmpfs /var/lib/carnical/uploads:size=64m,mode=0700,uid=65532,gid=65532 \
  carnical:local start /config/site.json -config-key-file /config/site.key \
  -listen :8443 -upload-dir /var/lib/carnical/uploads
```

`check` runs the same way with the config mounted read-only. The read-only root needs the writable
upload tmpfs; without it startup stops at the rule set's filesystem check.

## Services, backups and updates

For another account, copy the key through an approved secret-transfer path and grant access
only to that account (plus SYSTEM on Windows). Pass its absolute path with
`-config-key-file`; the key ID in the site file does not need to change.
Install the configuration where the service account can read it, while keeping write access
with the operator. Setup's initial configuration is private to the setup account.
On Linux, install it with the service account as owner and mode 0600. On Windows, replace the
setup account's ACL entry with the service account's entry, retain SYSTEM and disable inheritance.
Validate under the actual service identity before restarting. Containers can mount the key
read-only with owner-only permissions; this is separate from the site-file mount.

Run the wizard again into a new file to change encrypted settings. Review the new settings,
validate with the production service identity, then arrange the replacement and restart.
Ordinary readable settings can still be edited or overridden through CLI flags.

Back up the site file and key separately. Losing the key requires recreating the configuration;
there is no recovery key. A failed configuration write may leave its newly created key behind;
the error identifies that file and no existing configuration is replaced. The wizard does not
store a plaintext copy of private settings or put the key itself in printed commands.

Before DNS cutover, follow [website onboarding](website-onboarding.md) to restrict direct-origin
access, test real hostnames through the WAF and record rollback settings.

Review: [wizard](../cmd/carnical/setup.go), [strict loader](../cmd/carnical/siteconfig.go),
[encryption and files](../cmd/carnical/siteprivate.go),
[Windows ACLs](../cmd/carnical/siteprivate_windows.go).
Crypto reference: [Go authenticated encryption](https://pkg.go.dev/crypto/cipher#NewGCMWithRandomNonce).
