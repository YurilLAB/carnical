"""Gate supported injection regressions while retaining context-dependent cases.

With a baseline file, every attack template must also be refused and every benign control forwarded, except those the
baseline lists, and every entry of the baseline must still hold: what is blocked now stays blocked, and what is newly
blocked is locked in once the baseline is regenerated with --write.
"""

import json
import pathlib
import sys

ADMITTED, REFUSED = "[admitted attacks]", "[refused controls]"


def formats_monitored(report):
    """Whether the run kept the format checks in monitor mode, the default of a site that does not set them."""
    args = report.get("WAFArgs") or []
    return any(a == "-formats-mode" and b == "monitor" for a, b in zip(args, args[1:]))


def gate(report, baseline):
    if report["TransportErrors"] or report["Unavailable"] or report["Count"] != 10000:
        raise SystemExit("invalid live WAF measurement")
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


def read_baseline(path):
    lists, current = {ADMITTED: set(), REFUSED: set()}, None
    for line in pathlib.Path(path).read_text(encoding="utf-8").splitlines():
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
    admitted, refused = outcome(report)
    allowed, expected_refused = read_baseline(path)
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
    if problems:
        raise SystemExit("\n".join(problems))


def write_baseline(report, path):
    admitted, refused = outcome(report)
    rows = {row["Name"]: row for row in report["Results"]}
    old = pathlib.Path(path).read_text(encoding="utf-8").splitlines() if pathlib.Path(path).exists() else []
    header = []
    for line in old:
        if not line.startswith("#"):
            break
        header.append(line)
    out = header + [""]
    for section, names in ((ADMITTED, admitted), (REFUSED, refused)):
        out.append(section)
        category = None
        for name in sorted(names):
            if name.split("/")[0] != category:
                category = name.split("/")[0]
                out.append("# " + category + ": " + (rows[name].get("Description") or "").strip())
            out.append(name)
        out.append("")
    pathlib.Path(path).write_text("\n".join(out), encoding="utf-8")


def main():
    args = [arg for arg in sys.argv[1:] if arg != "--write"]
    report = json.loads(pathlib.Path(args[0]).read_text(encoding="utf-8"))
    gate(report, args[1] if len(args) > 1 else None)
    if len(args) > 1:
        if "--write" in sys.argv:
            write_baseline(report, args[1])
            print("Baseline written: " + args[1])
        check_baseline(report, args[1])
        print("Every attack refused and every control forwarded but those the baseline lists")
    print("Supported injection regressions blocked; ordinary search/JSON controls passed")
    print("Context-dependent admissions and other benign refusals remain in the artifact")


if __name__ == "__main__":
    main()
