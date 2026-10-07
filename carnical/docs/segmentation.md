# Carnical: segmentation

Two walls matter once Carnical hosts other people's websites:

1. **Between what faces the internet and what is sensitive.** The edge and the customer portal take input from strangers all day. The signing keys, the registry, every customer's data and the owner's own machine must stay out of their reach even if an edge or the portal is fully compromised.
2. **Between one customer and the next.** A customer, or whoever has taken over a customer's site, must be able to see and affect nothing of any other customer's.

This document says where the walls are, how they are built, and how they are checked several times a day. The checker is `carnical-audit` (`carnical/audit`, `carnical/cmd/carnical-audit`).

The first section is what the existing backend looks like today, because the design is a response to it. It comes from a read-only survey of `D:\Dev\5Weeks1k` (three passes: secrets and trust zones, tenant separation, and the contracts an engine must honour). Where a claim below is marked **checked**, I re-read the code it points at myself; the rest is the survey's reading and has not been run.

---

## 1. What exists today, and where it falls short for hosting

Today there is no hosted service: each protected site runs its own PHP firewall and console on its own host, and Harbourline pulls a signed feed from the owner's PC. Separation between customers is "each has their own host". A hosted Carnical removes that, so the following assumptions stop holding.

### The owner side is one trust zone

- Everything on the owner PC runs as one Windows user, with one Credential Manager and one default-permission `data\` folder: the console, both scheduled tasks, every parser (mail, docx, feeds, customer feed JSON, prospect pages in a browser with JavaScript on), and the encrypted key files. No code sets a file mode or ACL.
- **The console has no authentication** (**checked**): a per-run random token is rendered into every page, there are no sessions, and any local process can read it and post. It holds the key passphrases and every verb. `sending.smtp_host` is editable from it (**checked**), so a forged post could point the next send at a host of the attacker's choosing, with the mailbox app password. `integrity.PUBLISHER_FIELDS` does not cover `sending.*` (**checked**), so the tripwire would not notice.
- No real keys exist yet (`data\waf\keys` is absent), so key custody can still be decided properly. The root key defaults to the PC, is typed into the networked console for every root action, and would sit in 14 daily backup zips.

None of this is a Carnical bug. It is the reason the owner PC must stay **pull-only** and hold nothing a hosted component needs.

### Customers are not a first-class thing

- There is no tenant id. Firms are a folder name, sites are a slug typed by the owner, and the only link between them is a `client` string checked once when a site is added.
- `remove_site` keeps the site's reports and a later site can be given the same slug, so it inherits them (**checked** against the docstring and `write_due`).
- `Brand.slug` is read from `brand.yaml` with no check and becomes a folder name that is passed to `shutil.rmtree` (**checked**, `pack.py:59-63`). Harmless while only the owner edits that file, a file-deletion bug the day a customer can.
- Several fleet readers have no site parameter (`open_marks`, `bans`, `offenders`, `shared_addresses`). A customer-facing view built on them leaks by omission.
- One mailbox quota, one global lock around all feed reads (one slow site stalls the rest), one backup zip of every customer's data, and the fleet-repeat list that publishes one customer's visitor addresses to all customers on a consent flag the site sets for itself.

These are the things Carnical's own design has to do differently. The first decision it makes is to **not inherit the slug model**.

### What already works in our favour

The feed (version 1) is pull-only, HMAC-signed, scoped, rate-limited and bound to one site id. The release scheme has an offline root key and an online release key that cannot sign engine code. Per-site rows are keyed by the register slug, and the event hash includes it, so one site's feed cannot write another's rows. Feed parsing is strict (size, depth, types, lengths, parameterised writes, escaped output). The firm mail path re-checks each message against that firm's own list. These are kept.

---

## 2. Zones

| Zone | What runs there | What it holds | Faces |
|---|---|---|---|
| **visitors** | anyone | nothing of ours | the internet |
| **edge** | Carnical proxies, one WAF instance per tenant | per-hostname TLS keys for the tenants it serves, the signed configuration it was given, an event spool | the internet (443) |
| **portal** | the customer web UI and its API | session secrets; no database credentials of its own | the internet (443) |
| **control** | site registry, per-tenant stores, the configuration compiler, the feed server, event ingestion | tenant data (encrypted per tenant), the data-key master | edge, portal and owner only |
| **signer** | one small program that signs compiled configuration | the configuration-signing key | control only |
| **owner** | the existing Python console and daily tasks | the root key (offline copy), the mailbox, the business | nothing inbound; it pulls |
| **origins** | customers' own servers | nothing of ours | outbound from edge only |

The root key (which authorises the signing keys) lives offline and in no zone above. The configuration-signing key is a *different* key from the release key and from the root key, so losing it cannot sign engine code or a release.

### Which connections are allowed

Everything not in this table is closed. This is the map that `carnical-audit` is given (`zones.json`); a change to the network that is not in it is a finding.

| From | To | What | Why |
|---|---|---|---|
| visitors | edge | HTTPS | the product |
| visitors | portal | HTTPS | customers logging in |
| edge | origins | HTTP/HTTPS, **public addresses only** | forwarding clean requests |
| edge | control | fetch signed configuration; push events | the only two things it needs |
| portal | control | the intent API | changing a setting is a request, not a write |
| control | signer | "sign this compiled configuration" | |
| owner | control | the per-site feed, and staff operations over a tunnel | the owner pulls |

Not in the table, and so refused: edge to portal, edge to signer, edge to owner, portal to edge, portal to signer, portal to owner, control to origins, owner to anything it does not pull. An edge that is taken over finds a config fetch and an event pipe, and nothing else on the network.

### How each wall is built

- **Edge to the rest.** The edge process runs as its own unprivileged user with a read-only file system apart from the spool, no shell, no access to any key but its own tenants' TLS keys, and a network policy that allows the two connections above. It never receives a credential for control, the signer or the owner; it authenticates to control with its own identity, and that identity can only fetch its own assignment and push events stamped with the edge's id.
- **Edge to origins: the origin guard** (built, `carnical/proxy/origin.go`). A customer chooses where their origin is, so the choice is not trusted. Every outgoing connection is checked on the address it is really about to use, after the name has been resolved: loopback, private, link-local and cloud-metadata ranges, the tunnelling prefixes that can carry an IPv4 address inside, and this machine's own addresses are refused. A name that answers with a public address first and a private one later gets nothing. The operator can allow a range for a named origin (`-origin-allow`); `carnical-audit` then checks that the allow list does not cover any internal zone.
- **Portal to control.** The portal can say "tenant T proposes setting S = V". The tenant is taken from the login session, never from the request. Control validates the proposal against the settings schema (and the customer's locks and roles) and compiles it; the portal cannot write a store, a key or a configuration directly.
- **Control to signer.** The signer takes a compiled configuration for one tenant, checks it against the allowed shape (section 3, T7), and signs it with tenant id, sequence number, expiry and the edge it is for inside the signed bytes. Control never holds the key.
- **Owner.** Nothing inbound. It reads the same feed v1 it reads today. A hosted Carnical looks to the owner console like one more feed per site; the owner PC never receives a connection from a hosted component, and holds no hosted key (`backend-compat.md`).

---

## 3. Customers from each other

| # | Rule | Why |
|---|---|---|
| **T1** | **An opaque tenant id**: 128 random bits, immutable, never reused, never derived from a name or a hostname. Slugs and names are display text only. | A reissued slug inheriting a removed site's reports (the existing behaviour) must be impossible by construction. |
| **T2** | **Data is reached only through a handle for one tenant.** `store.For(id)` returns an object with no method that takes another tenant and no "all tenants" read. Anything that aggregates across tenants is a separate, named `Aggregator` with an explicit list of the fields it may read. | Today's cross-tenant readers are safe only because the one viewer is the owner. |
| **T3** | **One database file per tenant**, its path built from the tenant id by a single function that rejects anything that is not 32 hex digits, and the contents encrypted with a per-tenant key derived (HKDF) from a master held only in control. | A wrong `WHERE` cannot cross a file. Deleting a tenant is deleting a file and a key. A file copied between tenants does not open. |
| **T4** | **A separate WAF instance per tenant** (own rules, exclusions, thresholds, body limit), chosen by an **exact match on the normalised Host** (lower case, no trailing dot, no port) against the registry. The TLS name the client connected to must belong to the same tenant as the Host header, otherwise the answer is 421. Forwarded-host headers and absolute-form targets are never used to pick a tenant. Per-tenant ceilings on in-flight requests, body size and request rate. The tenant id on an event is stamped by the edge. | This is the data-plane form of "which policy is applied to this request". Getting it wrong lets someone use their own relaxed policy to attack a neighbour. `tenant-policy-confusion` is the check for exactly this. |
| **T5** | **Signed configuration names its tenant, a sequence, an expiry and the edge it is for**; an edge refuses a configuration for a tenant it is not assigned and one with a lower sequence. | The existing signature preimage has no audience, so a valid bundle for one tenant could be replayed to another. |
| **T6** | **One feed key per site, and one feed path per site**, answered only from that tenant's store; `site_id` bound at registration and unique across tenants. Addresses are cut to /24 and /48 unless the customer says otherwise. | The existing reader already treats one feed as one site, and pins the site id. |
| **T7** | **Customer rules are data, not code.** A rule is built from the structured form the console already has (`pm`, `contains` and `rx` over named targets, bounded length, bounded count), compiled by us into SecLang in a reserved id range. Raw SecLang from a customer is never accepted: no `Include`, no `ctl` outside the tenant's own scope, no operators that read files or reach the network. Regexes are RE2 with a size cap, compiled with a time limit. | A rule is code that runs in the shared edge process. |
| **T8** | **Sharing between customers is explicit.** The fleet-repeat reputation list is built only by the `Aggregator`, with consent recorded centrally (not asserted by the site), and with weight by the number of independent tenants. | Two cooperating sites can currently list any public address. |
| **T9** | **A hostname is routed to a tenant only after proof they control it** (a DNS TXT record under a name we choose, rechecked on a schedule). | Otherwise a customer can claim another's domain and receive its traffic or its certificate. |
| **T10** | **Offboarding deletes**: the tenant file and key, its certificates, its report folder and its feed key; the id is not reused. Backups are per tenant so erasure is possible. | The owner PC's single backup zip of everyone is not acceptable for hosted customer data. |

---

## 4. The checks, and when they run

`carnical-audit` runs a catalogue of checks from each place where they mean something. Four runs a day, each a random time (up to 45 minutes) after the hour, so a run cannot be dodged by timing. Not more often: the checks send real requests through the real data plane, and several times a day is enough to notice a mistake within hours rather than weeks.

The checker is built to be believed:

- a check that **could not run is `skip`, not `pass`**, and a skip is a failing exit status (3) unless the operator has said it is expected;
- a check that **exercised zero cases fails**, it does not pass;
- every tenant check begins with a **positive control** (a tenant can read its own planted record, a block-mode tenant blocks the canary attack aimed straight at it), because "could not read the other's" means nothing if it could not read its own either;
- reports name the tenant, the kind of record and the way it was tried, never the content or the planted markers;
- every check is tested against a deliberately broken setup that it has to catch (section 5).

| Check | Runs from | What it watches | State |
|---|---|---|---|
| `origin-guard` | edge | The origin policy the edge really runs with still refuses every address in every internal zone, the machine itself and the metadata services. It exists to catch an `-origin-allow` entry that grows to cover the backend. | **Works now.** |
| `zone-reach` | each zone | From this zone, every listener in every other zone is reachable exactly when the zone map allows it; both an open wall and a broken allowed flow are findings. | **Works now.** Needs the real zone map. |
| `tenant-api-isolation` | outside | With a canary tenant's own credentials, no record of another canary can be read by changing the identifier (case, suffix, traversal, separators, wildcards, encoding), and no listing contains another's records. | Written and tested against stand-ins. **Needs the hosted portal and registry** to run against. |
| `tenant-edge-routing` | outside | A request is answered by the origin of the host it names and no other, however the host is written (case, dot, port, user-info, NUL, naming headers, absolute-form target) and whatever name was connected to. | As above, needs the hosted edge. |
| `tenant-policy-confusion` | outside | An attack that one tenant's policy would allow is still blocked by the policy of the tenant it is aimed at, over every one of those routes. | As above. |
| *planned* `edge-secrets` | edge | The edge user cannot open the signer key, the data-key master, the control database, or any other tenant's TLS key. | Needs the hosts. |
| *planned* `config-integrity` | edge | The configuration the edge is running is exactly the signed one (digest), nothing newer-looking is loaded unsigned, and no tenant configuration contains a directive outside the allowed shape (T7). | Needs the compiler. |
| *planned* `origin-drift` | control | Each registered origin hostname still resolves only to public addresses (a name can be moved after it is accepted), and the domain proof (T9) still holds. | Needs the registry. |
| *planned* `noisy-neighbour` | outside | One canary hammering its own host does not move another canary's latency or error rate beyond a bound. | Needs the hosted edge. |
| *planned* `tenant-erasure` | control | A removed canary leaves no file, key, report, feed key or certificate behind. | Needs the registry. |

"Outside" matters: the tenant checks have to run from a machine with no internal access, holding only what a customer holds, because that is the position they test. The edge and control checks run on those machines, as their own unprivileged user.

### When something fails

- The run appends one JSON line to the log and writes a complete temporary status file (`when`, `ok`, `counts`, `problems`) before replacing the destination. Use different files for `-log` and `-status`, in directories controlled by the audit operator. Identical paths and filesystem aliases are rejected without replacing the log.
- Console, log and status output failures return exit 1. A failed console or log write also sets `ok` to false when the status file can be written. Check counts remain unchanged. Watch mode retries on the next run and can recover after the output path is repaired. New output files use mode 0600 on Unix; existing log permissions and Windows ACLs remain the operator's responsibility.
- The status file is what the existing owner view can read: feed v1 has a `health.errors[]` list in which every entry is a red standing alert on the owner's Desk, so a failing check appears where the owner already looks, with no new channel. (The feed server that would carry it is part of the backend work in `backend-compat.md`.)
- A failed `tenant-*` or `zone-reach` check should also stop the world it protects: an edge that finds its own wall open takes itself out of rotation. That reaction is not built; it is a decision for the owner (section 6).

### Scheduling

`carnical-audit -print-schedule systemd` and `-print-schedule schtasks` print a ready timer and a ready task; nothing is installed by the program, and nothing has been installed anywhere. Four runs a day, six hours apart, each with a random delay.

---

## 5. What has and has not been verified

**Verified.**
- The origin guard: address table (including IPv4-mapped, NAT64, 6to4, metadata, carrier-grade NAT, zones), a name that resolves to loopback is refused at connect time and the same name is reached once the range is allowed, the allow list refuses `/0`. Mutation checks: removing the dial hook, or the range list, makes the tests fail. Passes on Windows and under Linux in WSL.
- The auditor: runner semantics (skip, zero cases, panic, timeout, an empty run), zone-map validation, `lastAddr`, `origin-guard` against allow lists that cover each internal zone, `zone-reach` against real listeners (open wall, broken flow, no `here`), and the three tenant checks against a stand-in tenancy with nine ways of going wrong (a clean one passes; each fault is caught by the checks that should catch it and by no other). Mutation checks on the checks themselves: making the marker invisible fails the leak cases; trying only the exact identifier fails the case-folding and suffix leaks; dropping the header disguises fails the forwarded-host leak.
- The command: an open wall gives exit 1 and a status file naming it; an allow list covering the control plane gives exit 1; a vantage point with no deployment gives exit 3 with three skips; a clean map exits 0. Reporting tests on native Windows and Linux cover missing directories, directory destinations, invalid JSON timestamps, temporary-file collisions and aliased log/status paths. Linux additionally exercises `/dev/full` for console and log writes. Live Windows checks confirm the original false-success and log-loss cases now return exit 1, with log history retained, and a watch run recovers after its missing log directory is created.

**Not verified, because it does not exist yet.**
- The hosted edge, registry, portal, control plane and signer. The tenant checks have never run against a real multi-tenant deployment, only against stand-ins written to leak in the ways the checks look for. A stand-in that leaks differently from real code could pass them. The first job when the registry exists is to implement `audit.Tenancy` for it and run the checks against a deliberately broken copy.
- The network policies and file permissions in section 2 are a design, not a configuration on any machine.
- Nothing here has been run against the owner PC.

---

## 6. Decisions for the owner

1. **How many machines.** Recommended: separate machines for **edge** (stateless, replaceable, may be several), **portal**, and **control + signer** (signer a separate user with no network except to control). The portal takes passwords and uploads from strangers; keeping it off the machine with every customer's data is the most valuable single wall. A cheaper start is edge on one VPS and portal + control on a second, split by user and network namespace, with the signer still its own user. The walls then rest on the operating system rather than on the network.
2. **Where the root key lives.** The current default is the owner PC, typed into the networked console. Because no key exists yet, it can go to a hardware token or a laptop that is never online instead, with the owner PC holding only the online release key. Recommended.
3. **Whether customers may write their own rules** in the hosted product. Recommended: structured rules only (T7), no raw SecLang, ever.
4. **How hostname ownership is proved** (T9). Recommended: a DNS TXT record under a name we choose, checked at registration and then daily.
5. **What an edge does when its own check finds an open wall.** Recommended: stop serving and say why, rather than keep serving and alert. The cost is an outage for the customers on that edge.

The existing owner PC is not changed by any of this, and none of the existing-backend defects in section 1 has been fixed. They are listed with the fix each needs in `backend-compat.md`.
