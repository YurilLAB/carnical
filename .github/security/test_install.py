"""Verify that the security-tool installer refuses tampering and unsafe archives."""

import contextlib
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest.mock import patch
import zipfile

spec = importlib.util.spec_from_file_location("installer", Path(__file__).with_name("install.py"))
installer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(installer)


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
                     patch.object(installer.urllib.request, "urlopen", return_value=io.BytesIO(data)), \
                     patch("sys.argv", arguments), contextlib.redirect_stdout(io.StringIO()):
                    if reject:
                        with self.assertRaises(ValueError):
                            installer.main()
                        self.assertFalse((target / executable).exists())
                    else:
                        installer.main()
                        self.assertEqual((target / executable).read_bytes(), payload)
                        self.assertEqual(list(target.iterdir()), [target / executable])
                        self.assertFalse((Path(directory) / "escape").exists())


if __name__ == "__main__":
    unittest.main()
