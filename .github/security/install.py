"""Install pinned scanner releases after verifying their SHA256 digests.

Only the named executable is extracted, never arbitrary archive paths. The
release digests are recorded in tools.json rather than trusted from a download.
This helper needs only Python's standard library; it supports x64 Linux/Windows.
"""

import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import platform
import tarfile
import tempfile
import urllib.request
import zipfile


def main():
    manifest = json.loads(Path(__file__).with_name("tools.json").read_text())
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("tool", choices=manifest)
    parser.add_argument("--output-dir", type=Path, default=Path("build/security-tools"))
    args = parser.parse_args()
    if platform.machine().lower() not in {"amd64", "x86_64"}:
        parser.error("only x64 scanner releases are pinned")
    system = platform.system().lower()
    if system not in {"linux", "windows"}:
        parser.error("only Linux and Windows scanner releases are pinned")
    tool = manifest[args.tool]
    release = tool[system]
    url = f"https://github.com/{tool['repository']}/releases/download/{tool['version']}/{release['asset']}"
    download_limit = 64 * 1024 * 1024
    extraction_limit = 128 * 1024 * 1024
    with urllib.request.urlopen(url, timeout=60) as response:
        data = response.read(download_limit + 1)
    if len(data) > download_limit:
        raise ValueError("release exceeds the 64 MiB download limit")
    if hashlib.sha256(data).hexdigest() != release["sha256"]:
        raise ValueError("release checksum mismatch; refusing to install")
    executable = args.tool + (".exe" if system == "windows" else "")
    if release["asset"].endswith(".zip"):
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            member = archive.getinfo(executable)
            if member.is_dir() or member.file_size > extraction_limit:
                raise ValueError("executable is not a bounded file")
            with archive.open(member) as stream:
                data = stream.read(extraction_limit + 1)
    elif release["asset"].endswith(".tar.gz"):
        with tarfile.open(fileobj=io.BytesIO(data), mode="r|gz") as archive:
            for member in archive:
                if member.size > extraction_limit:
                    raise ValueError("archive member exceeds the extraction limit")
                if member.name == executable:
                    if not member.isfile():
                        raise ValueError("executable is not a regular file")
                    data = archive.extractfile(member).read(extraction_limit + 1)
                    break
            else:
                raise ValueError("archive does not contain the scanner executable")
    if len(data) > extraction_limit:
        raise ValueError("executable exceeds the 128 MiB extraction limit")
    args.output_dir.mkdir(parents=True, exist_ok=True)
    target = args.output_dir / executable
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(dir=args.output_dir, delete=False) as stream:
            temporary = Path(stream.name)
            stream.write(data)
        temporary.chmod(0o755)
        os.replace(temporary, target)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)
    print(f"Installed {args.tool} {tool['version']} with verified SHA256")


if __name__ == "__main__":
    main()
