"""Verify that the live WAF gate rejects missing coverage and failed controls."""

import copy
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


SUPPORTED = {"java", "ldap", "lfi", "nosql", "php", "protocol", "prototype",
             "rce", "regression", "scanner", "sqli", "ssi", "ssrf", "ssti",
             "wordpress", "xpath", "xss", "xxe"}
CHECKER = Path(__file__).with_name("check_live_report.py")


def case(name, attack, requests, status):
    return {"Name": name, "Attack": attack, "Requests": requests, "Errors": 0,
            "Statuses": {str(status): requests}, "OriginReached": requests if status == 200 else 0,
            "RequestSHA256": hashlib.sha256(name.encode()).hexdigest()}


def report(results):
    categories = {}
    for row in results:
        name = row["Name"].split("/")[0]
        cat = categories.setdefault(name, {"Category": name, "AttackCases": 0,
            "AttackRequests": 0, "UniqueAttackTemplates": 0, "AdmittedAttackCases": 0,
            "AttackOrigin": 0, "Errors": 0, "Unavailable": 0})
        if row["Attack"]:
            cat["AttackCases"] += 1
            cat["AttackRequests"] += row["Requests"]
            cat["UniqueAttackTemplates"] += 1  # these fixtures have distinct request hashes
            cat["AdmittedAttackCases"] += row["OriginReached"] > 0
            cat["AttackOrigin"] += row["OriginReached"]
        cat["Errors"] += row["Errors"]
        cat["Unavailable"] += sum(n for status, n in row["Statuses"].items()
                                  if int(status) >= 500 and int(status) != 501)
        assert sum(row["Statuses"].values()) + row["Errors"] == row["Requests"]
    return {"Count": sum(row["Requests"] for row in results),
            "TransportErrors": sum(row["Errors"] for row in results),
            "Unavailable": sum(row["Unavailable"] for row in categories.values()),
            "CategoryResults": list(categories.values()), "Results": results}


def ordinary_report():
    per_case, extra = divmod(4999, len(SUPPORTED))
    rows = [case(name + "/attack", True, per_case + (i < extra), 403)
            for i, name in enumerate(sorted(SUPPORTED))]
    # Context-dependent attacks and other benign refusals remain diagnostic, not gate failures.
    rows.extend([case("csrf/context", True, 1, 200), case("search/ordinary", False, 2498, 200),
                 case("json/ordinary", False, 2500, 200), case("sqli/ordinary", False, 1, 200),
                 case("malformed/ordinary", False, 1, 403)])
    assert sum(row["Requests"] for row in rows if row["Attack"]) == 5000
    assert sum(row["Requests"] for row in rows if not row["Attack"]) == 5000
    return report(rows)


def omit(original, prefix, attack):
    rows = copy.deepcopy(original["Results"])
    removed = [row for row in rows if row["Attack"] == attack and row["Name"].startswith(prefix + "/")]
    rows = [row for row in rows if row not in removed]
    target_name = "xss/attack" if attack else "sqli/ordinary"
    target = next(row for row in rows if row["Name"] == target_name)
    requests = sum(row["Requests"] for row in removed)
    target["Requests"] += requests
    target["Statuses"]["403" if attack else "200"] += requests
    if not attack:
        target["OriginReached"] += requests
    return report(rows)


class LiveReportTests(unittest.TestCase):
    def test_required_coverage_and_controls(self):
        original = ordinary_report()
        cases = [("valid including diagnostic cases", original, None),
                 ("missing SQLi attacks", omit(original, "sqli", True), "not exercised"),
                 ("missing search controls", omit(original, "search", False), "controls"),
                 ("missing JSON controls", omit(original, "json", False), "controls")]
        cases.append(("both control groups missing", omit(omit(original, "search", False), "json", False), "controls"))
        for field in ("AttackCases", "AttackRequests", "UniqueAttackTemplates"):
            changed = copy.deepcopy(original)
            next(row for row in changed["CategoryResults"] if row["Category"] == "sqli")[field] = 0
            cases.append(("zero " + field, changed, "not exercised"))
        for field in ("Errors", "Unavailable", "AttackOrigin", "AdmittedAttackCases"):
            changed = copy.deepcopy(original)
            next(row for row in changed["CategoryResults"] if row["Category"] == "sqli")[field] = 1
            cases.append(("bad category " + field, changed, "supported injection"))
        changed = copy.deepcopy(original)
        changed["CategoryResults"] = [row for row in changed["CategoryResults"] if row["Category"] != "sqli"]
        cases.append(("missing category", changed, "missing required"))
        for group in ("search", "json"):
            for field in ("Requests", "OriginReached"):
                changed = copy.deepcopy(original)
                next(row for row in changed["Results"] if row["Name"].startswith(group + "/"))[field] = 0
                cases.append((group + " zero " + field, changed, "controls"))
        for field in ("Count", "TransportErrors", "Unavailable"):
            changed = copy.deepcopy(original)
            changed[field] = 9999 if field == "Count" else 1
            cases.append(("invalid " + field, changed, "invalid live WAF measurement"))
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "report.json"
            for name, data, error in cases:
                with self.subTest(name=name):
                    path.write_text(json.dumps(data), encoding="utf-8")
                    result = subprocess.run([sys.executable, str(CHECKER), str(path)],
                                            capture_output=True, text=True, timeout=30, check=False)
                    if error is None:
                        self.assertEqual(result.returncode, 0, result.stderr)
                    else:
                        self.assertNotEqual(result.returncode, 0, result.stdout)
                        self.assertIn(error, result.stderr)


if __name__ == "__main__":
    unittest.main()
