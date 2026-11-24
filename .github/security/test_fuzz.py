#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Check real Mage scheduling against compiler-discovered core fuzz targets."""
from collections import Counter
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
RECORDER = r"""
package main

import (
    "encoding/json"
    "fmt"
    "os"
)

func main() {
    f, err := os.OpenFile(os.Getenv("CARNICAL_FUZZ_TEST_LOG"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
    if err != nil {
        fmt.Fprintln(os.Stderr, err)
        os.Exit(97)
    }
    info, err := f.Stat()
    if err != nil {
        fmt.Fprintln(os.Stderr, err)
        os.Exit(97)
    }
    first := info.Size() == 0
    if err := json.NewEncoder(f).Encode(os.Args[1:]); err != nil {
        fmt.Fprintln(os.Stderr, err)
        os.Exit(97)
    }
    if err := f.Close(); err != nil {
        fmt.Fprintln(os.Stderr, err)
        os.Exit(97)
    }
    if first && os.Getenv("CARNICAL_FUZZ_TEST_FAIL_FIRST") == "1" {
        fmt.Fprintln(os.Stderr, "simulated target failure")
        os.Exit(7)
    }
}
"""


def command(args, env, timeout=180):
    return subprocess.run(
        args, cwd=ROOT, env=env, capture_output=True, text=True, encoding="utf-8",
        timeout=timeout, creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0,
    )


def listed_targets(output):
    targets = set()
    for line in output.splitlines():
        event = json.loads(line)
        name = event.get("Output", "").strip()
        if event.get("Action") == "output" and re.fullmatch(r"Fuzz\w+", name):
            targets.add((event["Package"], name))
    return targets


class CoreFuzzSelection(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.env = os.environ.copy()
        cls.env["GOTOOLCHAIN"] = "local"
        cls.env.pop("GOOS", None)
        cls.env.pop("GOARCH", None)
        selected = cls.env.get("CARNICAL_TEST_GO", "go")
        found = shutil.which(selected)
        if not found:
            raise RuntimeError("Go is required for the compiler-backed fuzz runner check")
        cls.go = str(Path(found).resolve())
        cls.temp = tempfile.TemporaryDirectory(prefix="carnical-fuzz-runner-")
        cls.addClassCleanup(cls.temp.cleanup)
        cls.work = Path(cls.temp.name)
        suffix = ".exe" if os.name == "nt" else ""
        cls.runner = cls.work / ("mage-runner" + suffix)
        cls.bin = cls.work / "bin"
        cls.bin.mkdir()
        recorder = cls.work / "recorder.go"
        recorder.write_text(RECORDER, encoding="utf-8")
        for args in [
            [cls.go, "run", "mage.go", "-gocmd", cls.go, "-compile", str(cls.runner)],
            [cls.go, "build", "-o", str(cls.bin / ("go" + suffix)), str(recorder)],
        ]:
            result = command(args, cls.env)
            if result.returncode:
                raise AssertionError(result.stdout + result.stderr)
        discovery = command(
            [cls.go, "test", "-json", "-list", "^Fuzz", "./internal/..."], cls.env,
        )
        if discovery.returncode:
            raise AssertionError(discovery.stdout + discovery.stderr)
        cls.expected = listed_targets(discovery.stdout)
        if not cls.expected:
            raise AssertionError("compiler discovery found no core fuzz targets")
        module = re.search(r"(?m)^module\s+(\S+)", (ROOT / "go.mod").read_text(encoding="utf-8")).group(1).strip('"')
        cls.aliases = {}
        for package, _ in cls.expected:
            if not package.startswith(module + "/internal/"):
                raise AssertionError("unexpected core package: " + package)
            cls.aliases[package] = package
            cls.aliases["./" + package[len(module) + 1:]] = package
        cls.matches = {}

    def decode_invocation(self, args):
        self.assertEqual(args[0], "test", args)
        options, packages = {}, []
        cursor = 1
        while cursor < len(args):
            item = args[cursor]
            if item.startswith("-"):
                key, separator, value = item.partition("=")
                self.assertIn(key, {"-run", "-parallel", "-fuzz", "-fuzztime"}, args)
                if not separator:
                    cursor += 1
                    self.assertLess(cursor, len(args), args)
                    value = args[cursor]
                options.setdefault(key, []).append(value)
            else:
                packages.append(item)
            cursor += 1
        self.assertEqual(len(packages), 1, args)
        self.assertIn(packages[0], self.aliases, args)
        self.assertEqual(options.get("-run"), ["^$"], args)
        self.assertEqual(options.get("-parallel"), ["2"], args)
        self.assertEqual(len(options.get("-fuzz", [])), 1, args)
        key = (packages[0], options["-fuzz"][0])
        if key not in self.matches:
            # Use Go's matcher, including the B64Decode end anchor, rather than simulating its regex rules.
            result = command(
                [self.go, "test", "-json", "-list", key[1], key[0]], self.env,
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.matches[key] = listed_targets(result.stdout)
        selected = self.matches[key]
        self.assertEqual(len(selected), 1, (args, selected))
        pair = next(iter(selected))
        self.assertEqual(pair[0], self.aliases[packages[0]], args)
        self.assertIn(pair, self.expected, args)
        return pair, options

    def test_core_scheduling(self):
        # Mage process scheduling cannot be expressed as an engine rules/request profile.
        cases = [
            ("default_duration", None, False, "3m"),
            ("explicit_duration", "25ms", False, "25ms"),
            ("failure_keeps_remaining_targets", "25ms", True, "25ms"),
        ]
        for name, duration, fail_first, expected_duration in cases:
            with self.subTest(name=name):
                log = self.work / (name + ".jsonl")
                env = self.env.copy()
                original_path = next((v for k, v in env.items() if k.lower() == "path"), "")
                for key in list(env):
                    if key.lower() == "path":
                        del env[key]
                env["PATH"] = str(self.bin) + os.pathsep + original_path
                env.pop("FUZZ_PACKAGES", None)
                env.pop("FUZZ_TIME", None)
                if duration is not None:
                    env["FUZZ_TIME"] = duration
                env["CARNICAL_FUZZ_TEST_LOG"] = str(log)
                env["CARNICAL_FUZZ_TEST_FAIL_FIRST"] = "1" if fail_first else "0"
                result = command([str(self.runner), "-t", "30s", "fuzz"], env, timeout=45)
                self.assertTrue(log.is_file(), result.stdout + result.stderr)
                calls = [json.loads(line) for line in log.read_text(encoding="utf-8").splitlines()]
                decoded = [self.decode_invocation(args) for args in calls]
                actual = Counter(pair for pair, _ in decoded)
                expected = Counter({pair: 1 for pair in self.expected})
                self.assertEqual(actual, expected, f"missing={expected - actual}; extra={actual - expected}")
                for _, options in decoded:
                    self.assertEqual(options.get("-fuzztime"), [expected_duration])
                if fail_first:
                    self.assertNotEqual(result.returncode, 0)
                    output = result.stdout + result.stderr
                    self.assertIn("[CARNICAL_FUZZ_TARGET_FAILED]", output)
                    self.assertIn(calls[0][-1] + " " + decoded[0][1]["-fuzz"][0], output)
                else:
                    self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
