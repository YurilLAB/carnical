"""Verify that the security-tool installer refuses tampering and unsafe archives."""

import contextlib
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import ssl
import tarfile
import tempfile
import unittest
from unittest.mock import patch
import zipfile

spec = importlib.util.spec_from_file_location("installer", Path(__file__).with_name("install.py"))
installer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(installer)


def answer(body, unsent=0):
    """A urlopen response; unsent is how many declared bytes the server closed the connection without sending."""
    response = io.BytesIO(body)
    response.length = unsent or None
    return response


class InstallerTests(unittest.TestCase):
    def test_verified_install_and_rejections(self):
        payload = b"synthetic scanner executable"
        cases = [("raw", "linux", False), ("zip", "windows", False),
                 ("tar", "linux", False), ("symlink", "linux", True),
                 ("oversized", "linux", True), ("tampered", "linux", True)]
        for kind, system, reject in cases:
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as directory:
                executable = "scanner.exe" if system == "windows" else "scanner"
                asset = "scanner"
                data = payload
                if kind == "zip":
                    asset += ".zip"
                    buffer = io.BytesIO()
                    with zipfile.ZipFile(buffer, "w") as archive:
                        archive.writestr(executable, payload)
                        archive.writestr("../escape", b"must not be extracted")
                    data = buffer.getvalue()
                elif kind in {"tar", "symlink", "oversized"}:
                    asset += ".tar.gz"
                    buffer = io.BytesIO()
                    with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
                        member = tarfile.TarInfo(executable)
                        member.size = len(payload)
                        if kind == "symlink":
                            member.type = tarfile.SYMTYPE
                            member.linkname = "../escape"
                            member.size = 0
                        elif kind == "oversized":
                            member.size = 129 * 1024 * 1024
                        # An oversized header is enough: the installer must reject
                        # it before reading or allocating its declared contents.
                        archive.fileobj.write(member.tobuf())
                        if kind != "oversized":
                            archive.fileobj.write(payload.ljust(512, b"\0"))
                    data = buffer.getvalue()
                digest = hashlib.sha256(data).hexdigest()
                if kind == "tampered":
                    digest = "0" * 64
                manifest = {"scanner": {"repository": "example/scanner", "version": "v1",
                            system: {"asset": asset, "sha256": digest}}}
                target = Path(directory) / "tools"
                arguments = ["install.py", "scanner", "--output-dir", str(target)]
                with patch.object(installer.Path, "read_text", return_value=json.dumps(manifest)), \
                     patch.object(installer.platform, "machine", return_value="AMD64"), \
                     patch.object(installer.platform, "system", return_value=system), \
                     patch.object(installer.urllib.request, "urlopen", return_value=answer(data)) as urlopen, \
                     patch("sys.argv", arguments), contextlib.redirect_stdout(io.StringIO()):
                    if reject:
                        with self.assertRaises(ValueError):
                            installer.main()
                        self.assertFalse((target / executable).exists())
                        self.assertEqual(urlopen.call_count, 1)  # a tampered or unsafe release is not fetched again
                    else:
                        installer.main()
                        self.assertEqual((target / executable).read_bytes(), payload)
                        self.assertEqual(list(target.iterdir()), [target / executable])
                        self.assertFalse((Path(directory) / "escape").exists())

    def test_only_transient_download_failures_are_retried(self):
        def http_error(code):
            return installer.urllib.error.HTTPError("https://example.invalid", code, "error", {}, None)

        clock = [0.0]  # time.sleep moves this clock on, so the retry budget is spent without waiting

        def down_for(seconds, failure):
            def urlopen(*args, **kwargs):
                if clock[0] < seconds:
                    raise failure
                return answer(b"ok")
            return urlopen

        cases = [("a gateway timeout, then the release", [http_error(504), b"ok"], b"ok", 2),
                 ("a rate limit, then the release", [http_error(429), b"ok"], b"ok", 2),
                 ("a dropped connection, then the release", [ConnectionResetError(), b"ok"], b"ok", 2),
                 ("a connect timeout, then the release", [installer.urllib.error.URLError(TimeoutError()), b"ok"], b"ok", 2),
                 ("a body cut short, then the release", [answer(b"o", unsent=1), b"ok"], b"ok", 2),
                 ("gateway timeouts for two minutes, then the release", down_for(120, http_error(504)), b"ok", None),
                 ("a release that is not there", [http_error(404)], installer.urllib.error.HTTPError, 1),
                 ("a certificate that does not verify", [installer.urllib.error.URLError(ssl.SSLCertVerificationError())],
                  installer.urllib.error.URLError, 1),
                 ("a server that never recovers", down_for(float("inf"), http_error(503)),
                  installer.urllib.error.HTTPError, None)]
        for name, answers, want, calls in cases:
            if isinstance(answers, list):
                answers = [answer(a) if isinstance(a, bytes) else a for a in answers]
            clock[0] = 0.0
            with self.subTest(name), \
                 patch.object(installer.urllib.request, "urlopen", side_effect=answers) as urlopen, \
                 patch.object(installer.time, "monotonic", side_effect=lambda: clock[0]), \
                 patch.object(installer.time, "sleep", side_effect=lambda s: clock.__setitem__(0, clock[0] + s)):
                if isinstance(want, bytes):
                    self.assertEqual(installer.fetch("https://example.invalid", 10), want)
                else:
                    with self.assertRaises(want):
                        installer.fetch("https://example.invalid", 10)
                if calls is not None:
                    self.assertEqual(urlopen.call_count, calls)
                self.assertLessEqual(clock[0], installer.RETRY_SECONDS)  # never waits past the budget
                if want is installer.urllib.error.HTTPError and calls is None:
                    self.assertGreater(clock[0], installer.RETRY_SECONDS - installer.MAX_DELAY)  # gives up only once it is spent

if __name__ == "__main__":
    unittest.main()
