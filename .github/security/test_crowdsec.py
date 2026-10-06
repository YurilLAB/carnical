#!/usr/bin/env python3
"""Run Carnical against an isolated, real CrowdSec 1.8.1 LAPI on loopback.

No system installation, central API enrollment or host firewall changes. The
optional official release download is pinned and verified before extracting the
two named executables. Credentials and raw requests are not printed.
"""
import argparse
import concurrent.futures
import hashlib
import http.client
import json
import os
from pathlib import Path
import socket
import subprocess
import tarfile
import tempfile
import threading
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

VERSION = "1.8.1"
SHA256 = "ae64cdab8ee49534d6c36eab4ce40b5478842a4b4abfe83f7796aace569821eb"
URL = f"https://github.com/crowdsecurity/crowdsec/releases/download/v{VERSION}/crowdsec-release.tgz"


def port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def wait_for(check, label, timeout=20):
    until = time.monotonic() + timeout
    while time.monotonic() < until:
        if check():
            return
        time.sleep(0.1)
    raise AssertionError(f"timed out waiting for {label}")


def stop(proc):
    if proc.poll() is None:
        proc.terminate()
        try:
            proc.wait(timeout=15)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=5)


def binaries(work, supplied):
    if supplied:
        root = Path(supplied).resolve()
        return root / "cmd/crowdsec/crowdsec", root / "cmd/crowdsec-cli/cscli"
    archive = work / "crowdsec.tgz"
    with urllib.request.urlopen(URL, timeout=30) as response, archive.open("wb") as target:
        # A release size bound prevents an accidental unbounded download.
        remaining = 128 << 20
        while chunk := response.read(1 << 20):
            remaining -= len(chunk)
            if remaining < 0:
                raise AssertionError("CrowdSec archive exceeds download limit")
            target.write(chunk)
    if hashlib.sha256(archive.read_bytes()).hexdigest() != SHA256:
        raise AssertionError("CrowdSec official release digest mismatch")
    result = []
    with tarfile.open(archive, "r:gz") as bundle:
        for name in ("cmd/crowdsec/crowdsec", "cmd/crowdsec-cli/cscli"):
            member = bundle.getmember(f"crowdsec-v{VERSION}/{name}")
            if not member.isfile() or member.size > 128 << 20:
                raise AssertionError("unexpected release executable")
            destination = work / Path(name).name
            with bundle.extractfile(member) as source, destination.open("wb") as target:
                while chunk := source.read(1 << 20):
                    target.write(chunk)
            destination.chmod(0o700)
            result.append(destination)
    return result


def run(args):
    Path("build").mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="cs-sock-", dir="/dev/shm") as socket_tmp, tempfile.TemporaryDirectory(prefix="crowdsec-live-", dir="build") as tmp:
        work = Path(tmp).resolve()
        crowdsec, cscli = binaries(work, args.crowdsec_root)
        api_port = port()
        api_url = f"http://127.0.0.1:{api_port}"
        api_socket = Path(socket_tmp) / "api.sock"
        credentials = work / "credentials.yaml"
        config = work / "config.yaml"
        for dirname in ("hub", "data", "notifications", "plugins"):
            (work / dirname).mkdir()
        (work / "profiles.yaml").write_text('name: isolated-test-remediation\nfilters:\n  - Alert.Remediation == true\ndecisions:\n  - type: ban\n    duration: 1h\non_success: break\n')
        (work / "console.yaml").write_text("{}\n")
        (work / "simulation.yaml").write_text("simulation: false\n")
        (work / "hub/.index.json").write_text("{}\n")
        config.write_text(json.dumps({
            "common": {"daemonize": False, "log_media": "stdout", "log_level": "info"},
            "config_paths": {"config_dir": str(work), "data_dir": str(work / "data"),
                             "hub_dir": str(work / "hub"), "index_path": str(work / "hub/.index.json"),
                             "simulation_path": str(work / "simulation.yaml"),
                             "notification_dir": str(work / "notifications"), "plugin_dir": str(work / "plugins")},
            "db_config": {"type": "sqlite", "db_path": str(work / "data/crowdsec.db")},
            "api": {"client": {"credentials_path": str(credentials)}, "server": {
                "listen_uri": f"127.0.0.1:{api_port}", "listen_socket": str(api_socket),
                "profiles_path": str(work / "profiles.yaml"), "console_path": str(work / "console.yaml"),
                "trusted_ips": ["127.0.0.1", "::1"]}},
            "cscli": {"output": "raw", "color": "no"}, "prometheus": {"enabled": False}
        }))

        def cli(*words):
            result = subprocess.run([str(cscli), "-c", str(config), "-o", "raw", *words],
                                    capture_output=True, text=True, timeout=20)
            if result.returncode:
                # Do not echo stdout/stderr: commands can produce credentials.
                raise AssertionError(f"cscli {words[0]} failed with exit {result.returncode}")
            return result.stdout.strip()

        cli("machines", "add", "carnical-live-test", "--auto", "--url", api_url)
        api_key = cli("bouncers", "add", "carnical-live-test")
        if not api_key or any(c.isspace() for c in api_key):
            raise AssertionError("unexpected cscli raw key format")
        key_file = work / "bouncer.key"
        key_file.write_text(api_key + "\n")
        key_file.chmod(0o600)
        api_log = (work / "crowdsec.log").open("w")
        api = subprocess.Popen([str(crowdsec), "-c", str(config), "-no-cs", "-no-capi"], stdout=api_log, stderr=subprocess.STDOUT)

        def api_ready():
            try:
                with socket.create_connection(("127.0.0.1", api_port), timeout=0.2):
                    return True
            except OSError:
                return False

        origin_count = 0
        count_lock = threading.Lock()

        class Origin(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def do_GET(self):
                nonlocal origin_count
                with count_lock:
                    origin_count += 1
                self.send_response(200)
                self.send_header("Content-Type", "text/plain")
                self.send_header("Content-Length", "2")
                self.end_headers()
                self.wfile.write(b"ok")

            def log_message(self, *unused):
                pass

        class OriginServer(ThreadingHTTPServer):
            request_queue_size = 256
            daemon_threads = True

        origin = OriginServer(("127.0.0.1", 0), Origin)
        origin_thread = threading.Thread(target=origin.serve_forever, daemon=True)
        origin_thread.start()
        wafs, logs = [], []
        try:
            wait_for(api_ready, "real CrowdSec LAPI")

            # Startup must refuse a real authentication failure, including when
            # fail-open is selected; neither the key nor response body is logged.
            invalid_key = "invalid-live-test-bouncer-key"
            invalid_file = work / "invalid.key"
            invalid_file.write_text(invalid_key)
            invalid_file.chmod(0o600)
            rejected = subprocess.run([str(Path(args.binary).resolve()), "-upstream", "https://application.example",
                "-crowdsec-api", api_url, "-crowdsec-key-file", str(invalid_file), "-crowdsec-fail-open"],
                capture_output=True, text=True, timeout=15)
            assert rejected.returncode != 0 and any(s in rejected.stderr for s in ("HTTP 401", "HTTP 403")), rejected.stderr.replace(api_key, "[redacted]").replace(invalid_key, "[redacted]")
            assert invalid_key not in rejected.stderr

            def start_waf(*extra, endpoint=api_url):
                p = port()
                log_path = work / f"waf-{p}.log"
                log = log_path.open("w")
                logs.append(log_path)
                proc = subprocess.Popen([str(Path(args.binary).resolve()), "-listen", f"127.0.0.1:{p}",
                    "-upstream", f"http://127.0.0.1:{origin.server_port}", "-origin-allow", "127.0.0.1",
                    "-mode", "block", "-formats-mode", "block", "-ddos", "off", "-trusted-proxies", "127.0.0.1",
                    "-crowdsec-api", endpoint, "-crowdsec-key-file", str(key_file), "-crowdsec-poll", "1s",
                    "-crowdsec-timeout", "500ms", "-crowdsec-max-stale", "3s", *extra],
                    stdout=log, stderr=subprocess.STDOUT)
                wafs.append((proc, log))
                wait_for(lambda: request(p, "198.51.100.9") == 200, "Carnical with CrowdSec")
                return p

            def request(p, addr, target="/"):
                try:
                    conn = http.client.HTTPConnection("127.0.0.1", p, timeout=5)
                    conn.request("GET", target, headers={"X-Forwarded-For": addr})
                    response = conn.getresponse()
                    response.read()
                    status = response.status
                    conn.close()
                    return status
                except (OSError, http.client.HTTPException):
                    return 0

            tcp = start_waf()
            # A second independent stream needs its own key. Re-register between
            # instances so their server cursors cannot interfere.
            cli("decisions", "add", "--ip", "192.0.2.9", "--duration", "1h")
            wait_for(lambda: request(tcp, "192.0.2.9") == 403, "IPv4 ban")
            query = urllib.request.Request(api_url + "/v1/decisions?ip=192.0.2.9&contains=false", headers={"X-Api-Key": api_key})
            with urllib.request.urlopen(query, timeout=5) as response:
                ip_id = next(d["id"] for d in json.load(response) if d["value"] == "192.0.2.9")
            cli("decisions", "add", "--range", "2001:db8::/64", "--duration", "1h")
            wait_for(lambda: request(tcp, "2001:db8::9") == 403, "IPv6 range ban")
            assert request(tcp, "2001:db8:1::9") == 200
            assert request(tcp, "198.51.100.9, 192.0.2.9") == 403
            cli("decisions", "add", "--range", "192.0.2.0/24", "--duration", "1h")
            wait_for(lambda: request(tcp, "192.0.2.10") == 403, "overlapping range ban")
            cli("decisions", "delete", "--id", str(ip_id))
            time.sleep(1.2)
            assert request(tcp, "192.0.2.9") == 403, "overlapping range ban was removed"
            cli("decisions", "delete", "--range", "192.0.2.0/24")
            wait_for(lambda: request(tcp, "192.0.2.9") == 200, "ban deletion")
            cli("decisions", "add", "--ip", "192.0.2.9", "--duration", "3s")
            wait_for(lambda: request(tcp, "192.0.2.9") == 403, "short-lived ban")
            wait_for(lambda: request(tcp, "192.0.2.9") == 200, "ban expiry")
            cli("decisions", "add", "--ip", "192.0.2.9", "--duration", "1h")
            wait_for(lambda: request(tcp, "192.0.2.9") == 403, "load-test ban")

            before = origin_count
            def worker(n):
                conn = http.client.HTTPConnection("127.0.0.1", tcp, timeout=10)
                good = bad = attacks = 0
                try:
                    for i in range(args.requests // 20):
                        banned = i % 2 == 0
                        conn.request("GET", f"/page?visit={n}-{i}", headers={"X-Forwarded-For": "192.0.2.9" if banned else "198.51.100.9"})
                        response = conn.getresponse(); response.read()
                        assert response.status == (403 if banned else 200)
                        if banned: bad += 1
                        else: good += 1
                    for i in range(10):
                        target = f"/page?id={i}%27%20OR%20%271%27%3D%271"
                        conn.request("GET", target, headers={"X-Forwarded-For": "198.51.100.9"})
                        response = conn.getresponse(); response.read()
                        assert response.status == 403, "CRS SQL probe bypassed"
                        attacks += 1
                    return good, bad, attacks
                finally:
                    conn.close()

            with concurrent.futures.ThreadPoolExecutor(max_workers=20) as pool:
                results = list(pool.map(worker, range(20)))
            good, banned, attacks = (sum(r[i] for r in results) for i in range(3))
            assert origin_count - before == good, "blocked requests reached origin"
            batch_origin_received = origin_count - before

            # Kill the actual service, then recover it using the same DB and key.
            stop(api)
            wait_for(lambda: request(tcp, "198.51.100.9") == 503, "fail-closed stale cache")
            assert request(tcp, "192.0.2.9") == 403
            api = subprocess.Popen([str(crowdsec), "-c", str(config), "-no-cs", "-no-capi"], stdout=api_log, stderr=subprocess.STDOUT)
            wait_for(lambda: request(tcp, "198.51.100.9") == 200, "LAPI recovery")
            stop(wafs[0][0])
            unix = start_waf(endpoint=str(api_socket))
            assert request(unix, "192.0.2.9") == 403
            assert request(unix, "2001:db8::9") == 403
            stop(wafs[-1][0])
            opened = start_waf("-crowdsec-fail-open")
            stop(api)
            time.sleep(3.2)
            assert request(opened, "198.51.100.9") == 200
            assert request(opened, "192.0.2.9") == 403
            for proc, log in wafs:
                stop(proc); log.flush()
            for path in logs:
                text = path.read_text()
                assert api_key not in text, "bouncer key leaked in WAF logs"
            print(json.dumps({"crowdsec": VERSION, "benign_allowed": good, "ip_bans_blocked": banned,
                              "varied_sql_blocked": attacks, "batch_origin_received": batch_origin_received,
                              "tcp_unix_ipv6_deletion_overlap_expiry_outage_recovery": "passed"}))
        finally:
            for proc, log in wafs:
                stop(proc); log.close()
            stop(api); api_log.close()
            origin.shutdown(); origin.server_close(); origin_thread.join(timeout=5)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True)
    parser.add_argument("--crowdsec-root", help="directory containing verified release cmd/ executables")
    parser.add_argument("--requests", type=int, default=20000)
    arguments = parser.parse_args()
    if arguments.requests < 40 or arguments.requests % 40:
        parser.error("--requests must be a positive multiple of 40, at least 40")
    run(arguments)
