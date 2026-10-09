# Historical segmentation background — 5 October 2026

This is the external-backend survey that informed the segmentation design. It describes that
survey, not a deployed Carnical service or a current assessment of the separate backend.
Use [segmentation](segmentation.md) for the zone/tenant contracts and audit scope.

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
