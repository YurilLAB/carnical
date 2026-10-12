"""Install pinned scanner releases after verifying their SHA256 digests.

Only the named executable is extracted, never arbitrary archive paths. The
release digests are recorded in tools.json rather than trusted from a download.
This helper needs only Python's standard library; it supports x64 Linux/Windows.
"""

import argparse
import hashlib
import http.client
import io
import json
import os
from pathlib import Path
import platform
import ssl
import tarfile
import tempfile
import time
import urllib.error
import urllib.request
import zipfile

# Answers that say the server could not serve the request just then. Release downloads go through a CDN that now and then
# answers 502 or 504; anything else (404, 403, a checksum mismatch) is permanent and is not retried.
TRANSIENT_STATUS = {408, 429, 500, 502, 503, 504}
# How long a download is retried for. The CDN has answered 504 for half a minute at a time, so the backoff spans three
# minutes, still well inside the shortest job's timeout.
RETRY_SECONDS = 180
MAX_DELAY = 30


def fetch(url, limit):
    """Read at most limit bytes from url, retrying a transient failure (a 5xx or 429 answer, a timeout, a dropped or cut
    connection) with backoff for up to RETRY_SECONDS. What is read is still checked against the pinned digest by the caller."""
    deadline = time.monotonic() + RETRY_SECONDS
    delay = 2

    def out_of_time():
        return time.monotonic() + delay > deadline

    while True:
        try:
            with urllib.request.urlopen(url, timeout=30) as response:
                data = response.read(limit)
                # A body cut short by a closed connection comes back without an error. It is retried as a dropped
                # connection, rather than reaching the digest check as a checksum mismatch.
                if response.length and len(data) < limit:
                    raise http.client.IncompleteRead(data, response.length)
                return data
        except urllib.error.HTTPError as err:
            if err.code not in TRANSIENT_STATUS or out_of_time():
                raise
        except urllib.error.URLError as err:
            # A refused or reset connection, a timeout or a lookup that failed is retried; a bad certificate or URL is not.
            if not isinstance(err.reason, OSError) or isinstance(err.reason, ssl.CertificateError) or out_of_time():
                raise
        except (TimeoutError, ConnectionError, http.client.HTTPException):
            if out_of_time():
                raise
        time.sleep(delay)
        delay = min(delay * 2, MAX_DELAY)


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
    data = fetch(url, download_limit + 1)
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
