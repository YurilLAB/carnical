"""Gate supported injection regressions while retaining context-dependent cases.

With a baseline file, every attack template must also be refused and every benign control forwarded, except those the
baseline lists, and every entry of the baseline must still hold: what is blocked now stays blocked, and what is newly
blocked is locked in once the baseline is regenerated with --write. Every attack that reaches the origin must raise an
alert, which the run records with loadtest -alert-probe.
"""

import hashlib
import json
import pathlib
import sys

ADMITTED, REFUSED = "[admitted attacks]", "[refused controls]"
TEMPLATE_PIN = "# templates-sha256-v1: "


def template_digest(report):
    """Identify every declared constructed request, independently of ordering, measurements and outcomes."""
    rows, names = [], set()
    for row in report["Results"]:
        name, attack, digest = row.get("Name"), row.get("Attack"), row.get("RequestSHA256")
        if (not isinstance(name, str) or not name or name in names or not isinstance(attack, bool)
                or not isinstance(digest, str) or len(digest) != 64
                or any(c not in "0123456789abcdef" for c in digest)):
            raise SystemExit("invalid template manifest identity")
        names.add(name)
        rows.append([name, attack, digest])
    encoded = json.dumps(sorted(rows), ensure_ascii=True, separators=(",", ":")).encode("ascii")
    return hashlib.sha256(b"carnical-live-templates-v1\n" + encoded + b"\n").hexdigest()


def formats_monitored(report):
    """Whether the run kept the format checks in monitor mode, the default of a site that does not set them."""
    args = report.get("WAFArgs") or []
    return any(a == "-formats-mode" and b == "monitor" for a, b in zip(args, args[1:]))


def valid_measurement(report):
    """Check the producer's success invariants from rows, even when summaries are stale."""
    if type(report.get("Count")) is not int or report["Count"] != 10000:
        return False
    if any(type(report.get(key)) is not int or report[key] != 0 for key in ("TransportErrors", "Unavailable")):
        return False
    rows = report.get("Results")
    if not isinstance(rows, list):
        return False
    total = 0
    for row in rows:
        if not isinstance(row, dict):
            return False
        values = [row.get(key) for key in ("Requests", "Errors", "OriginReached")]
        if any(type(value) is not int or value < 0 for value in values):
            return False
        requests, errors, origin = values
        statuses = row.get("Statuses")
        if requests <= 0 or requests > report["Count"] or errors or not isinstance(statuses, dict):
            return False
        for status, count in statuses.items():
            if (not isinstance(status, str) or len(status) != 3 or not status.isascii() or not status.isdigit()
                    or not 100 <= int(status) <= 599 or type(count) is not int or not 0 <= count <= requests):
                return False
            if count and int(status) >= 500 and status != "501":
                return False
        if sum(statuses.values()) != requests or origin != statuses.get("200", 0):
            return False
        total += requests
        if total > report["Count"]:
            return False
    return total == report["Count"]


def valid_summaries(report):
    """Reconcile numeric summaries with measured rows, using the loadtest producer's classifications."""
    totals = {side + field: 0 for side in ("Attack", "Benign") for field in ("Requests", "Passed", "Refused")}
    totals.update(OriginAttacks=0, OriginBenign=0, UniqueAttackTemplates=0, UniqueBenignTemplates=0)
    fields = ("AttackCases", "BenignCases", "AdmittedAttackCases", "AttackRequests", "BenignRequests",
              "AttackRefused", "BenignRefused", "AttackOrigin", "BenignOrigin", "Errors", "Unavailable",
              "UniqueAttackTemplates", "UniqueBenignTemplates", "VariantAttackCases", "VariantBenignCases")
    categories, unique, labels = {}, {}, {}
    for row in report["Results"]:
        attack, digest, variation = row["Attack"], row["RequestSHA256"], row.get("Variation")
        # A successful producer cannot label the same constructed request as both attack and control.
        if not isinstance(variation, str) or digest in labels and labels[digest] != attack:
            return False
        labels[digest] = attack
        side = "Attack" if attack else "Benign"
        name = row["Name"].split("/", 1)[0]
        category = categories.setdefault(name, dict.fromkeys(fields, 0))
        seen = unique.setdefault((name, side), set())
        category["Unique" + side + "Templates"] += digest not in seen
        seen.add(digest)
        category[side + "Cases"] += 1
        category["Variant" + side + "Cases"] += variation != ""
        category["AdmittedAttackCases"] += attack and row["OriginReached"] > 0
        category[side + "Requests"] += row["Requests"]
        category[side + "Origin"] += row["OriginReached"]
        refused = sum(n for status, n in row["Statuses"].items() if 400 <= int(status) < 500 or status == "501")
        category[side + "Refused"] += refused
        totals[side + "Requests"] += row["Requests"]
        totals[side + "Passed"] += row["Statuses"].get("200", 0)
        totals[side + "Refused"] += refused
        totals["OriginAttacks" if attack else "OriginBenign"] += row["OriginReached"]
    for side, attack in (("Attack", True), ("Benign", False)):
        totals["Unique" + side + "Templates"] = sum(label == attack for label in labels.values())
    if any(type(report.get(field)) is not int or report[field] != value for field, value in totals.items()):
        return False
    claimed = report.get("CategoryResults")
    if not isinstance(claimed, list) or len(claimed) != len(categories):
        return False
    seen = set()
    for category in claimed:
        if not isinstance(category, dict):
            return False
        name = category.get("Category")
        if not isinstance(name, str) or name not in categories or name in seen:
            return False
        seen.add(name)
        # Errors and unavailable counts are zero because valid_measurement already checked every row.
        if any(type(category.get(field)) is not int or category[field] != value
               for field, value in categories[name].items()):
            return False
    return True


def gate(report, baseline):
    if not valid_measurement(report):
        raise SystemExit("invalid live WAF measurement")
    template_digest(report)
    if not valid_summaries(report):
        raise SystemExit("inconsistent live WAF summaries")
    # With the format checks only monitoring, the attacks only they refuse (GraphQL envelopes, duplicate JSON keys,
    # parameter-name tricks) reach the origin by design; the baseline says which, template by template.
    monitored = formats_monitored(report)
    if monitored and baseline is None:
        raise SystemExit("a run with the format checks in monitor mode needs a baseline")
    supported = {"java", "ldap", "lfi", "nosql", "php", "protocol", "prototype",
                 "rce", "regression", "scanner", "sqli", "ssi", "ssrf", "ssti",
                 "wordpress", "xpath", "xss", "xxe"}
    categories = {row["Category"]: row for row in report["CategoryResults"]}
    if not supported.issubset(categories):
        raise SystemExit("missing required attack categories")
    for name in sorted(supported):
        row = categories[name]
        if any(row[field] <= 0 for field in ("AttackCases", "AttackRequests", "UniqueAttackTemplates")):
            raise SystemExit("required attack category not exercised: " + name)
        if row["Errors"] or row["Unavailable"] or not monitored and (row["AttackOrigin"] or row["AdmittedAttackCases"]):
            raise SystemExit("supported injection reached the origin: " + name)
    for name in ("search", "json"):
        controls = [row for row in report["Results"] if not row["Attack"]
                    and row["Name"].split("/")[0] == name]
        if not controls or any(row["Requests"] <= 0 or row["OriginReached"] != row["Requests"] for row in controls):
            raise SystemExit("ordinary search/JSON controls refused or not exercised")


def outcome(report):
    """The attack templates that reached the origin and the controls that were refused, by name."""
    admitted, refused = set(), set()
    for row in report["Results"]:
        if row["Requests"] <= 0:
            raise SystemExit("template not exercised: " + row["Name"])
        if row["Attack"] and row["OriginReached"] > 0:
            admitted.add(row["Name"])
        elif not row["Attack"] and row["OriginReached"] < row["Requests"]:
            refused.add(row["Name"])
    return admitted, refused


def read_baseline(text):
    lists, current = {ADMITTED: set(), REFUSED: set()}, None
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if line in lists:
            current = lists[line]
        elif current is None:
            raise SystemExit("baseline entry outside a section: " + line)
        else:
            current.add(line)
    return lists[ADMITTED], lists[REFUSED]


def check_baseline(report, path):
    check_baseline_text(report, pathlib.Path(path).read_text(encoding="utf-8"))


def check_baseline_text(report, text):
    pins = [line[len(TEMPLATE_PIN):] for line in text.splitlines()
            if line.startswith(TEMPLATE_PIN)]
    if len(pins) != 1 or pins[0] != template_digest(report):
        raise SystemExit("template manifest changed or baseline pin missing/invalid; review the suite before --write")
    admitted, refused = outcome(report)
    allowed, expected_refused = read_baseline(text)
    rows = {row["Name"]: row for row in report["Results"]}
    problems = []
    for name in sorted(allowed | expected_refused):
        if name not in rows:
            problems.append("baseline names a template not in the suite: " + name)
        elif rows[name]["Attack"] != (name in allowed):
            problems.append("baseline lists a template under the wrong section: " + name)
    for name in sorted(admitted - allowed):
        problems.append("attack now reaches the origin: " + name)
    for name in sorted(refused - expected_refused):
        problems.append("benign control now refused: " + name)
    for name in sorted((allowed - admitted) & rows.keys()):
        if rows[name]["Attack"]:
            problems.append("attack is now refused; take it off the baseline to keep it blocked: " + name)
    for name in sorted((expected_refused - refused) & rows.keys()):
        if not rows[name]["Attack"]:
            problems.append("control now passes; take it off the baseline: " + name)
    for name in sorted(allowed & admitted):
        row = rows[name]
        if row["OriginReached"] != row["Requests"]:
            problems.append("attack reached the origin on only some requests: " + name)
    for name in sorted(expected_refused & refused):
        if rows[name]["OriginReached"]:
            problems.append("control refused on only some requests: " + name)
    if not report.get("AlertProbe"):
        problems.append("the run did not record the alerts of the attacks that reach the origin (loadtest -alert-probe)")
    else:
        for name in sorted(admitted):
            if not rows[name].get("Alerts"):
                problems.append("attack reached the origin without an alert: " + name)
    if problems:
        raise SystemExit("\n".join(problems))


def write_baseline(report, path):
    digest = template_digest(report)
    admitted, refused = outcome(report)
    rows = {row["Name"]: row for row in report["Results"]}
    old = pathlib.Path(path).read_text(encoding="utf-8").splitlines() if pathlib.Path(path).exists() else []
    header = []
    for line in old:
        if not line.startswith("#"):
            break
        if not line.startswith(TEMPLATE_PIN):
            header.append(line)
    out = header + [TEMPLATE_PIN + digest, ""]
    for section, names in ((ADMITTED, admitted), (REFUSED, refused)):
        out.append(section)
        category = None
        for name in sorted(names):
            if name.split("/")[0] != category:
                category = name.split("/")[0]
                out.append("# " + category + ": " + (rows[name].get("Description") or "").strip())
            out.append(name)
        out.append("")
    text = "\n".join(out)
    check_baseline_text(report, text)
    try:
        encoded = text.encode("utf-8")
    except UnicodeEncodeError as error:
        raise SystemExit("baseline entries must be valid UTF-8") from error
    pathlib.Path(path).write_bytes(encoded)


def main():
    args = [arg for arg in sys.argv[1:] if arg != "--write"]
    report = json.loads(pathlib.Path(args[0]).read_text(encoding="utf-8"))
    gate(report, args[1] if len(args) > 1 else None)
    if len(args) > 1:
        if "--write" in sys.argv:
            write_baseline(report, args[1])
            print("Baseline written: " + args[1])
        check_baseline(report, args[1])
        print("Every attack refused and every control forwarded but those the baseline lists, each admitted attack alerted")
    print("Supported injection regressions blocked; ordinary search/JSON controls passed")
    print("Context-dependent admissions and other benign refusals remain in the artifact")


if __name__ == "__main__":
    main()
