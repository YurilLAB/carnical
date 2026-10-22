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


def templates_pin(data):
    rows = sorted([[row["Name"], row["Attack"], row["RequestSHA256"]] for row in data["Results"]])
    encoded = json.dumps(rows, ensure_ascii=True, separators=(",", ":")).encode("ascii")
    digest = hashlib.sha256(b"carnical-live-templates-v1\n" + encoded + b"\n").hexdigest()
    return "# templates-sha256-v1: " + digest + "\n"


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
            "CategoryResults": list(categories.values()), "Results": results, "AlertProbe": True}


def ordinary_report():
    per_case, extra = divmod(4999, len(SUPPORTED))
    rows = [case(name + "/attack", True, per_case + (i < extra), 403)
            for i, name in enumerate(sorted(SUPPORTED))]
    php = next(row for row in rows if row["Name"] == "php/attack")
    php["Requests"] -= 1
    php["Statuses"]["403"] -= 1
    rows.append(case("php/second", True, 1, 403))
    # Context-dependent attacks and other benign refusals remain diagnostic, not gate failures.
    rows.extend([dict(case("csrf/context", True, 1, 200), Alerts=["crs-1 detected"]), case("search/ordinary", False, 2498, 200),
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

    def test_baseline(self):
        # ordinary_report admits csrf/context and refuses malformed/ordinary; everything else is refused or forwarded.
        original = ordinary_report()
        entries = "[admitted attacks]\ncsrf/context\n[refused controls]\nmalformed/ordinary\n"
        exact = templates_pin(original) + entries
        partly = copy.deepcopy(original)
        row = next(row for row in partly["Results"] if row["Name"] == "csrf/context")
        row["Requests"], row["Statuses"], row["OriginReached"] = 2, {"200": 1, "403": 1}, 1
        target = next(row for row in partly["Results"] if row["Name"] == "xss/attack")
        target["Requests"] -= 1
        target["Statuses"]["403"] -= 1
        partly = report(partly["Results"])
        monitored = copy.deepcopy(original)
        monitored["WAFArgs"] = ["-formats-mode", "monitor"]
        sqli = next(row for row in monitored["Results"] if row["Name"] == "sqli/attack")
        sqli["Statuses"], sqli["OriginReached"], sqli["Alerts"] = {"200": sqli["Requests"]}, sqli["Requests"], ["crs-1 detected"]
        monitored = dict(report(monitored["Results"]), WAFArgs=monitored["WAFArgs"])
        silent = copy.deepcopy(original)
        del next(row for row in silent["Results"] if row["Name"] == "csrf/context")["Alerts"]
        cases = [
            ("the baseline holds", original, exact, None),
            ("an attack it lists reaches the origin without an alert", silent, exact, "without an alert: csrf/context"),
            ("the run did not record alerts", dict(original, AlertProbe=False), exact, "did not record the alerts"),
            ("an attack outside it reaches the origin", original, templates_pin(original) + "[refused controls]\nmalformed/ordinary\n", "attack now reaches the origin: csrf/context"),
            ("a control outside it is refused", original, templates_pin(original) + "[admitted attacks]\ncsrf/context\n", "benign control now refused: malformed/ordinary"),
            ("an attack it lists is refused", original, exact.replace("csrf/context", "csrf/context\nxss/attack"), "attack is now refused"),
            ("a control it lists passes", original, exact + "json/ordinary\n", "control now passes"),
            ("it names a template the suite does not have", original, exact + "gone/control\n", "not in the suite: gone/control"),
            ("it lists an attack as a control", original, exact + "xss/attack\n", "wrong section: xss/attack"),
            ("an entry outside a section", original, "csrf/context\n" + exact, "outside a section"),
            ("an attack it lists reaches the origin on some requests only", partly, exact, "only some requests: csrf/context"),
            ("format checks monitored, with the admitted injection listed", monitored, exact.replace("csrf/context", "csrf/context\nsqli/attack"), None),
            ("format checks monitored, with the injection not listed", monitored, exact, "attack now reaches the origin: sqli/attack"),
        ]
        reordered = copy.deepcopy(original)
        reordered["Results"].reverse()
        cases.append(("template order does not change identity", reordered, exact, None))
        omitted = copy.deepcopy(original["Results"])
        omitted = [row for row in omitted if row["Name"] != "php/second"]
        target = next(row for row in omitted if row["Name"] == "php/attack")
        target["Requests"] += 1
        target["Statuses"]["403"] += 1
        cases.append(("a blocked template disappears but its category remains", report(omitted), exact, "template manifest"))
        for label, field, value in (("renamed", "Name", "php/renamed"),
                                    ("request changed", "RequestSHA256", "0" * 64),
                                    ("invalid hash", "RequestSHA256", "not-a-hash"),
                                    ("non-boolean class", "Attack", 1)):
            changed = copy.deepcopy(original)
            next(row for row in changed["Results"] if row["Name"] == "php/second")[field] = value
            cases.append((label, changed, exact, "template manifest"))
        changed = copy.deepcopy(original)
        next(row for row in changed["Results"] if row["Name"] == "php/second")["Attack"] = False
        cases.append(("reclassified with new outcome listed", report(changed["Results"]), exact + "php/second\n", "template manifest"))
        added = copy.deepcopy(original["Results"])
        target = next(row for row in added if row["Name"] == "php/attack")
        target["Requests"] -= 1
        target["Statuses"]["403"] -= 1
        added.append(case("php/third", True, 1, 403))
        cases.append(("an extra template", report(copy.deepcopy(added)), exact, "template manifest"))
        added[-1]["Name"] = "php/second"
        cases.append(("duplicate template names", report(added), exact, "template manifest"))
        cases.extend([
            ("a missing template pin", original, entries, "template manifest"),
            ("duplicate template pins", original, templates_pin(original) + exact, "template manifest"),
            ("an invalid template pin", original, "# templates-sha256-v1: invalid\n" + entries, "template manifest"),
        ])
        with tempfile.TemporaryDirectory() as directory:
            path, baseline = Path(directory) / "report.json", Path(directory) / "baseline.txt"
            for name, data, text, error in cases:
                with self.subTest(name=name):
                    path.write_text(json.dumps(data), encoding="utf-8")
                    baseline.write_text(text, encoding="utf-8")
                    result = subprocess.run([sys.executable, str(CHECKER), str(path), str(baseline)],
                                            capture_output=True, text=True, timeout=30, check=False)
                    if error is None:
                        self.assertEqual(result.returncode, 0, result.stderr)
                    else:
                        self.assertNotEqual(result.returncode, 0, result.stdout)
                        self.assertIn(error, result.stderr)
            with self.subTest(name="format checks monitored without a baseline"):
                path.write_text(json.dumps(monitored), encoding="utf-8")
                result = subprocess.run([sys.executable, str(CHECKER), str(path)], capture_output=True, text=True, timeout=30, check=False)
                self.assertNotEqual(result.returncode, 0, result.stdout)
                self.assertIn("needs a baseline", result.stderr)
            with self.subTest(name="a written baseline holds and keeps its header"):
                path.write_text(json.dumps(original), encoding="utf-8")
                baseline.write_text("# kept\n[admitted attacks]\n", encoding="utf-8")
                result = subprocess.run([sys.executable, str(CHECKER), str(path), str(baseline), "--write"],
                                        capture_output=True, text=True, timeout=30, check=False)
                self.assertEqual(result.returncode, 0, result.stderr)
                written = baseline.read_text(encoding="utf-8")
                self.assertTrue(written.startswith("# kept\n"), written)
                self.assertIn(templates_pin(original), written)
                self.assertIn("\ncsrf/context\n", written)
                self.assertIn("\nmalformed/ordinary\n", written)
            malformed = copy.deepcopy(original)
            malformed["Results"][0]["RequestSHA256"] = "invalid"
            duplicate = copy.deepcopy(original)
            duplicate["Results"].append(copy.deepcopy(duplicate["Results"][0]))
            for label, data in (("malformed request identity", malformed), ("duplicate template name", duplicate)):
                with self.subTest(name="writing refuses " + label):
                    path.write_text(json.dumps(data), encoding="utf-8")
                    before = "# kept\n" + exact
                    baseline.write_text(before, encoding="utf-8")
                    result = subprocess.run([sys.executable, str(CHECKER), str(path), str(baseline), "--write"],
                                            capture_output=True, text=True, timeout=30, check=False)
                    self.assertNotEqual(result.returncode, 0, result.stdout)
                    self.assertIn("template manifest", result.stderr)
                    self.assertEqual(baseline.read_text(encoding="utf-8"), before)


if __name__ == "__main__":
    unittest.main()
