"""Drives the owner console's real feed reader (newsletter/brief/waf/feed.py and fleet.py) for the Go tests.

The Go tests run this with CARNICAL_READER_DIR set to the newsletter folder. It only imports the reader; it never writes
inside that folder (bytecode is switched off, and everything the reader stores goes to a temporary folder).

Modes (each prints one JSON document on standard output):

  vector                                   the shared test vector, signed by the reader's own code
  request <feed_path> <cursor|-> <days> <key_id> <secret_text> <ts> <nonce>
                                           the request the reader would make: path and query, and its Authorization header
  parse <file>                             feed.parse() on the bytes of an answer: what it kept and what it left out
  refusal <status> <file> [retry_after]    feed.refusal() on an error answer: the state and the sentence the owner would read
  pull <base_url> <key_id> <secret_text> <ts> <folder> <times>
                                           fleet.pull_site() against a server on <base_url> (plain http on loopback), <times>
                                           in a row, with a fresh register and store in <folder>
"""

import datetime as dt
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

sys.dont_write_bytecode = True
READER = os.environ.get("CARNICAL_READER_DIR", "")
if not READER:
    sys.exit("CARNICAL_READER_DIR is not set")
sys.path.insert(0, READER)

from brief import intel  # noqa: E402
from brief.waf import feed, fleet  # noqa: E402
from brief.waf.layout import Layout  # noqa: E402

VECTOR_SECRET = bytes(range(1, 33))
VECTOR_PATH = "/feed?since=abc&days=7"
VECTOR_TS = 1791014400
VECTOR_NONCE = "0123456789abcdef0123456789abcdef"


def out(doc):
    print(json.dumps(doc, sort_keys=True))


def mode_vector(_args):
    out({"signature": feed.signature(VECTOR_SECRET, VECTOR_PATH, VECTOR_TS, VECTOR_NONCE),
         "signed": feed.signed_text(VECTOR_PATH, VECTOR_TS, VECTOR_NONCE)})


def mode_request(args):
    feed_path, cursor, days, key_id, secret_text, ts, nonce = args
    secret = feed.secret_bytes(secret_text)
    path_query = feed.request_path(feed_path, None if cursor == "-" else cursor, int(days))
    out({"path": path_query, "authorization": feed.authorization(key_id, secret, path_query, int(ts), nonce)})


def mode_parse(args):
    body = Path(args[0]).read_bytes()
    try:
        a = feed.parse(body)
    except feed.NotAFeed as exc:
        out({"not_a_feed": str(exc)})
        return
    out({"generated": a.generated, "site": a.site, "scopes": list(a.scopes), "addresses": a.addresses, "cursor": a.cursor,
         "more": a.more, "events": len(a.events),
         "traffic": None if a.traffic is None else len(a.traffic),
         "bans": None if a.bans is None else len(a.bans),
         "offenders": None if a.offenders is None else len(a.offenders),
         "marks": None if a.marks is None else len(a.marks),
         "health": a.health, "left_out": a.left_out, "reasons": a.reasons,
         "event_ips": [e.get("ip") for e in a.events],
         "event_ids": [e.get("id") for e in a.events],
         "canonical": [feed.canonical(e) for e in a.events],
         "ban_ips": [b["ip"] for b in (a.bans or [])],
         "offender_ips": [o["ip"] for o in (a.offenders or [])]})


def mode_refusal(args):
    status, path = int(args[0]), args[1]
    headers = {"retry-after": args[2]} if len(args) > 2 else {}
    state, sentence = feed.refusal(intel.Response(status, Path(path).read_bytes(), headers, "https://x.example/feed"))
    out({"state": state, "sentence": sentence})


def mode_pull(args):
    base, key_id, secret_text, ts, folder, times = args
    tmp = Path(folder)
    layout = Layout(data=tmp / "waf", out=tmp / "out" / "waf", register=tmp / "waf_sources.yaml", signatures=tmp / "signatures",
                    intel_db=tmp / "intel" / "intel.db")
    (tmp / "clients").mkdir(parents=True, exist_ok=True)
    fl = fleet.Fleet.at(layout, clients=tmp / "clients", secrets=fleet.MemorySecrets())
    site = fleet.add_site(fl, "Alpha Plumbing", "https://fw-admin.alpha.example/feed", key_id, secret_text,
                          today=dt.date(2026, 9, 1))
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))

    def transport(url, headers):
        parts = urllib.parse.urlsplit(url)
        target = base + parts.path + (f"?{parts.query}" if parts.query else "")
        request = urllib.request.Request(target, headers=headers, method="GET")
        try:
            with opener.open(request, timeout=20) as resp:
                return intel.Response(resp.status, resp.read(), {k.lower(): v for k, v in resp.headers.items()}, url)
        except urllib.error.HTTPError as exc:
            return intel.Response(exc.code, exc.read(), {k.lower(): v for k, v in exc.headers.items()}, url)

    results = []
    for _ in range(int(times)):
        read = fleet.pull_site(fl, site, fl.store(), clock=lambda: float(ts), transport=transport)
        st = fl.store()
        counts = {t: st.rows(f"SELECT count(*) AS n FROM {t}")[0]["n"] for t in ("events", "traffic", "bans", "offenders", "health")}
        row = st.site_row(site.slug)
        results.append({"state": read.state, "note": read.note, "pages": read.pages, "events": read.events, "days": read.days,
                        "marks": read.marks, "more": read.more, "counts": counts, "site_id": row["site_id"],
                        "cursor": row["cursor"], "addresses": row["addresses"]})
    out(results)


MODES = {"vector": mode_vector, "request": mode_request, "parse": mode_parse, "refusal": mode_refusal, "pull": mode_pull}

if __name__ == "__main__":
    if len(sys.argv) < 2 or sys.argv[1] not in MODES:
        sys.exit("usage: reader_compat.py " + "|".join(MODES))
    MODES[sys.argv[1]](sys.argv[2:])
