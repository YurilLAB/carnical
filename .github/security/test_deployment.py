#!/usr/bin/env python3
"""Test deployment lifecycle using real processes, TCP and two WAF replicas.

This owns POSIX signal/drain and container-runtime behavior; CLI option validation
lives in main_test.go. Attack/application traffic stays on loopback; the container trust check makes
only a TLS handshake to github.com. The LAPI
fixture controls outages and decision updates; real CrowdSec is tested separately.
"""
import argparse
from concurrent.futures import ThreadPoolExecutor
import http.client
import json
import os
from pathlib import Path
import secrets
import socket
import subprocess
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import quote


def command(words, timeout=20, check=True, **kwargs):
    result = subprocess.run(words, capture_output=True, text=True, timeout=timeout, **kwargs)
    if check and result.returncode:
        raise AssertionError(f"{Path(words[0]).name} failed: {result.stderr[:1000]}")
    return result


def port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def request(address, path="/", method="GET", body=None, host="site.test", source=None):
    conn = http.client.HTTPConnection("127.0.0.1", address, timeout=10,
                                      source_address=(source, 0) if source else None)
    try:
        headers = {"Host": host}
        if body is not None:
            headers["Content-Type"] = "application/json"
        conn.request(method, path, body=body, headers=headers)
        response = conn.getresponse()
        return response.status, response.read(), dict(response.getheaders())
    finally:
        conn.close()


def await_state(check, seconds=8):
    until = time.monotonic() + seconds
    while time.monotonic() < until:
        try:
            if check():
                return
        except (OSError, http.client.HTTPException):
            pass
        time.sleep(0.04)
    raise AssertionError("expected deployment state did not arrive")


class Server(ThreadingHTTPServer):
    daemon_threads = True


class DecisionService:
    def __init__(self, secret, outage=False):
        self.outage = outage
        self.ban_public = False
        self.successes = []
        self.secret = secret
        owner = self

        class Decisions(BaseHTTPRequestHandler):
            def log_message(self, *_):
                pass

            def do_GET(self):
                if self.headers.get("X-Api-Key") != owner.secret:
                    self.send_error(403)
                    return
                if owner.outage:
                    self.send_error(503)
                    return
                new = [{"id": 2, "type": "ban", "scope": "ip", "value": "127.0.0.2",
                        "duration": "1h", "origin": "test"}]
                deleted = [] if owner.ban_public else [{"id": 1}]
                if owner.ban_public:
                    new.append({"id": 1, "type": "ban", "scope": "ip", "value": "127.0.0.1",
                                "duration": "1h", "origin": "test"})
                data = json.dumps({"new": new, "deleted": deleted}).encode()
                owner.successes.append(time.monotonic())
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

        self.server = Server(("127.0.0.1", 0), Decisions)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def close(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)


class Edge:
    def __init__(self, args, work, origin, name, crowdsec=True, fail_open=False,
                 startup_outage=False, drain="4s", shutdown="6s", confine=False, defaults=False):
        self.args = args
        self.address, self.health_address = (8443, 8082) if defaults else (port(), port())
        self.name = name
        self.proc, self.container = None, None
        self.path = work / name
        self.path.mkdir(mode=0o750)
        self.key = secrets.token_hex(32)
        self.decisions = DecisionService(self.key, startup_outage) if crowdsec else None
        keyfile = self.path / "bouncer.key"
        keyfile.write_text(self.key)
        keyfile.chmod(0o640 if args.image else 0o600)
        flags = {"listen": f"127.0.0.1:{self.address}", "upstream": origin,
                 "origin-allow": "127.0.0.0/8", "hosts": "site.test", "upstream-host": "site.test",
                 "mode": "block", "formats-mode": "block", "ddos": "off",
                 "health-listen": f"127.0.0.1:{self.health_address}",
                 "drain-delay": drain, "shutdown-timeout": shutdown}
        if self.decisions:
            flags.update({"crowdsec-api": f"http://127.0.0.1:{self.decisions.server.server_port}",
                          "crowdsec-key-file": "/etc/carnical/bouncer.key" if args.image else str(keyfile),
                          "crowdsec-poll": "1s", "crowdsec-timeout": "200ms",
                          "crowdsec-max-stale": "1500ms", "crowdsec-fail-open": fail_open})
        if confine:
            flags.update({"confine": True, "confine-connect": origin.rsplit(":", 1)[1]+",53"})
        if args.image:
            flags["upload-dir"] = "/var/lib/carnical/uploads"
        sitefile = self.path / "site.json"
        sitefile.write_text(json.dumps({"version": 1, "flags": flags}))
        sitefile.chmod(0o640)
        self.logfile = self.path / "runtime.log"
        if args.image:
            result = command(["docker", "run", "--detach", "--network=host", "--read-only",
                              "--user=65532:65532", "--group-add", str(os.getgid()), "--cap-drop=ALL",
                              "--security-opt=no-new-privileges:true",
                              "--tmpfs=/var/lib/carnical/uploads:size=32m,mode=0700,uid=65532,gid=65532,noexec,nosuid,nodev",
                              "--mount", f"type=bind,source={self.path},target=/etc/carnical,readonly",
                              # CLI health overrides use a shell, absent in this image.
                              # The default-command replica checks the baked-in exec probe;
                              # temporary-port replicas use explicit executable probes.
                              *([] if defaults else ["--no-healthcheck"]),
                              args.image, *([] if defaults else ["-config", "/etc/carnical/site.json"])])
            self.container = result.stdout.strip()
        else:
            self.log = self.logfile.open("w")
            self.proc = subprocess.Popen([str(Path(args.binary).resolve()), "-config", str(sitefile)],
                                         stdout=self.log, stderr=self.log)

    def status(self, kind):
        try:
            return request(self.health_address, "/"+kind+"z", method="HEAD",
                           host=f"127.0.0.1:{self.health_address}")[0]
        except (OSError, http.client.HTTPException):
            stopped = self.proc is not None and self.proc.poll() is not None
            if self.container:
                stopped = command(["docker", "inspect", "--format", "{{.State.Running}}",
                                   self.container]).stdout.strip() == "false"
            if stopped:
                raise AssertionError(f"{self.name} exited before its health listener: "
                                     + self.logs().replace(self.key, "[redacted]")[:1500])
            raise

    def probe(self, kind, address=None):
        words = ["-health-listen", f"127.0.0.1:{address or self.health_address}", "-probe", kind]
        environment = os.environ.copy()
        environment.update(HTTP_PROXY="http://127.0.0.1:1", NO_PROXY="")
        if self.container:
            return command(["docker", "exec", "--env", "HTTP_PROXY=http://127.0.0.1:1", "--env", "NO_PROXY=",
                            self.container, "/carnical", *words], check=False)
        return command([str(Path(self.args.binary).resolve()), *words], check=False, env=environment)

    def signal(self):
        if self.container:
            command(["docker", "kill", "--signal=TERM", self.container])
        else:
            self.proc.terminate()

    def wait(self, seconds=10):
        if self.container:
            return int(command(["docker", "wait", self.container], timeout=seconds).stdout.strip())
        return self.proc.wait(timeout=seconds)

    def logs(self):
        if self.container:
            result = command(["docker", "logs", self.container])
            return result.stdout + result.stderr
        self.log.flush()
        return self.logfile.read_text()

    def close(self):
        if self.container:
            command(["docker", "rm", "--force", self.container], check=False)
        if self.proc:
            if self.proc.poll() is None:
                self.proc.kill()
            self.proc.wait(timeout=5)
            self.log.close()
        if self.decisions:
            self.decisions.close()


def run(args):
    if os.name != "posix":
        raise AssertionError("the signal fixture requires POSIX; native Windows CLI is tested by Go")
    results = []
    lock = threading.Lock()
    records = []
    entered, release = threading.Event(), threading.Event()

    class Application(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def handle_request(self):
            body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
            with lock:
                records.append((self.command, self.path, body))
            if self.path == "/slow":
                entered.set()
                if not release.wait(10):
                    return
            data = b"origin"
            try:
                self.send_response(200)
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                if self.command != "HEAD":
                    self.wfile.write(data)
            except (OSError, http.client.HTTPException):
                pass

        do_GET = do_POST = do_HEAD = handle_request

    app = Server(("127.0.0.1", 0), Application)
    thread = threading.Thread(target=app.serve_forever, daemon=True)
    thread.start()
    edges = []
    try:
        with tempfile.TemporaryDirectory(prefix="carnical-deployment-") as tmp:
            work = Path(tmp)
            # Read-only bind-mounted fixtures are service-group readable; keys
            # meet the same 0640 guard as operator-managed production credentials.
            if args.image:
                work.chmod(0o750)
            origin = f"http://127.0.0.1:{app.server_port}"

            def edge(name, **options):
                instance = Edge(args, work, origin, name, **options)
                edges.append(instance)
                return instance

            if args.image:
                default = edge("default-command", crowdsec=False, defaults=True)
                await_state(lambda: default.status("ready") == 200)
                assert request(default.address, "/default-command")[0] == 200
                # Exercise the baked-in check, not the fixture override.
                await_state(lambda: command(["docker", "inspect", "--format", "{{.State.Health.Status}}", default.container]).stdout.strip() == "healthy", seconds=15)
                results.append("image default command accepts its regular site file and its baked-in health check becomes healthy")
            first, second = edge("first"), edge("second")
            for instance in (first, second):
                await_state(lambda: instance.status("ready") == 200)
                assert instance.probe("ready").returncode == 0
                assert instance.probe("live").returncode == 0
            results.append("two independent replicas become ready; executable probes ignore environment proxies")

            if args.image:
                inspect = json.loads(command(["docker", "inspect", first.container]).stdout)[0]
                assert inspect["Config"]["Healthcheck"]["Test"] == ["NONE"]
                assert inspect["Config"]["User"] == "65532:65532"
                assert inspect["HostConfig"]["ReadonlyRootfs"] is True
                assert "ALL" in inspect["HostConfig"]["CapDrop"]
                assert "no-new-privileges:true" in inspect["HostConfig"]["SecurityOpt"]
                status = Path(f'/proc/{inspect["State"]["Pid"]}/status').read_text()
                assert "NoNewPrivs:\t1" in status
                assert "CapEff:\t0000000000000000" in status
                command(["docker", "exec", first.container, "/carnical", "-upstream", "https://github.com",
                         "-check", "-check-origin"], timeout=20)
                results.append("real container runs as non-root with no capabilities, no new privileges, read-only root and working system TLS roots")

            health = first.health_address
            for path, method, body, host, expected in [
                ("/readyz", "HEAD", None, f"127.0.0.1:{health}", 200),
                ("/livez", "GET", None, f"127.0.0.1:{health}", 200),
                ("/readyz", "POST", None, f"127.0.0.1:{health}", 405),
                ("/readyz", "POST", "{}", f"127.0.0.1:{health}", 400),
                ("/readyz", "HEAD", None, "rebinding.invalid", 403),
                ("/readyz?admin=1", "HEAD", None, f"127.0.0.1:{health}", 404),
                ("/%72eadyz", "HEAD", None, f"127.0.0.1:{health}", 404),
                ("/admin", "GET", None, f"127.0.0.1:{health}", 404),
            ]:
                result, _, headers = request(health, path, method, body, host)
                assert result == expected, (path, method, result, expected)
                assert headers["Cache-Control"] == "no-store"
            assert request(first.address, "/readyz")[1] == b"origin"
            assert request(first.address, "/readyz?q="+quote("<script>alert(42)</script>"))[0] == 403
            results.append("private probe protocol rejects body, method, Host and target confusion; visitor paths remain WAF protected")

            def traffic(index):
                instance = first if index % 2 == 0 else second
                if index % 4 == 0:
                    return "attack", request(instance.address, "/?q="+quote(f"<ScRiPt>alert({index})</sCrIpT>"))[0]
                if index % 4 == 1:
                    return "attack", request(instance.address, "/api/save", "POST", f'{{"id":{index},"id":{index+1}}}')[0]
                return "good", request(instance.address, f"/index?i={index}")[0]

            with ThreadPoolExecutor(max_workers=4) as pool:
                mixed = list(pool.map(traffic, range(200)))
            assert all(status == 200 if category == "good" else status >= 400 for category, status in mixed)
            results.append("200 varied requests across both replicas: 100 benign accepted and 100 attacks refused")

            first.decisions.outage = True
            await_state(lambda: first.status("ready") == 503)
            assert first.status("live") == 200
            assert first.probe("ready").returncode != 0 and first.probe("live").returncode == 0
            assert request(first.address, "/outage")[0] == 503
            assert request(first.address, "/outage", source="127.0.0.2")[0] == 403
            assert second.status("ready") == 200 and request(second.address, "/surviving-replica")[0] == 200
            first.decisions.outage = False
            await_state(lambda: first.status("ready") == 200)
            results.append("required stale CrowdSec withdraws one replica, retains bans and fails closed; surviving replica serves and recovery needs no restart")

            unavailable = edge("startup-unavailable", startup_outage=True)
            assert unavailable.wait(5) != 0
            for address in (unavailable.address, unavailable.health_address):
                with socket.socket() as sock:
                    sock.settimeout(0.3)
                    assert sock.connect_ex(("127.0.0.1", address)) != 0
            results.append("failed initial decision snapshot refuses startup without visitor or health listeners")

            fail_open = edge("explicit-fail-open", fail_open=True, drain="0s", shutdown="2s")
            await_state(lambda: fail_open.status("ready") == 200)
            fail_open.decisions.outage = True
            await_state(lambda: '"stale":true' in fail_open.logs())
            assert fail_open.status("ready") == 200 and fail_open.status("live") == 200
            assert request(fail_open.address, "/explicit-outage")[0] == 200
            assert request(fail_open.address, "/banned", source="127.0.0.2")[0] == 403
            results.append("explicit fail-open policy remains ready while preserving unexpired bans")

            class Redirect(BaseHTTPRequestHandler):
                def log_message(self, *_):
                    pass

                def do_HEAD(self):
                    self.send_response(302)
                    self.send_header("Location", origin+"/redirect-sink")
                    self.end_headers()

            redirect = Server(("127.0.0.1", 0), Redirect)
            redirect_thread = threading.Thread(target=redirect.serve_forever, daemon=True)
            redirect_thread.start()
            try:
                assert second.probe("ready", redirect.server_port).returncode != 0
                assert not any(record[1] == "/redirect-sink" for record in records)
            finally:
                redirect.shutdown()
                redirect.server_close()
                redirect_thread.join(timeout=2)
            results.append("health executable refuses redirects instead of reaching an application")

            entered.clear()
            release.clear()
            with ThreadPoolExecutor(max_workers=1) as pool:
                active = pool.submit(request, first.address, "/slow")
                assert entered.wait(4)
                signalled = time.monotonic()
                first.signal()
                await_state(lambda: first.status("ready") == 503, seconds=1)
                assert first.status("live") == 200
                assert second.status("ready") == 200 and request(second.address, "/during-rollout")[0] == 200
                # A newly delivered ban must still be learned during drain.
                first.decisions.ban_public = True
                await_state(lambda: request(first.address, "/new-ban-during-drain")[0] == 403, seconds=3)
                assert any(when > signalled for when in first.decisions.successes)
                release.set()
                assert active.result(timeout=3)[0] == 200
                assert first.wait(8) == 0
                assert time.monotonic() - signalled >= 3.8
            logs = first.logs()
            assert '"msg":"draining"' in logs and '"msg":"shutdown complete"' in logs
            assert first.key not in logs
            results.append("SIGTERM withdraws readiness, keeps decision refresh and inspection during drain, completes admitted requests and preserves peer traffic")

            entered.clear()
            release.clear()
            deadline = edge("deadline", crowdsec=False, drain="100ms", shutdown="500ms")
            await_state(lambda: deadline.status("ready") == 200)
            with ThreadPoolExecutor(max_workers=1) as pool:
                active = pool.submit(request, deadline.address, "/slow")
                assert entered.wait(4)
                started = time.monotonic()
                deadline.signal()
                assert deadline.wait(4) != 0
                assert time.monotonic() - started < 3
                release.set()
                try:
                    assert active.result(timeout=3)[0] != 200
                except (OSError, http.client.HTTPException):
                    pass
            assert '"msg":"shutdown incomplete"' in deadline.logs()
            results.append("shared shutdown deadline aborts an overlong origin request and reports failure")

            if not args.image:
                confined = edge("confined-health", crowdsec=False, confine=True, drain="0s", shutdown="2s")
                await_state(lambda: confined.status("ready") == 200)
                assert request(confined.address, "/confined-health")[0] == 200
                assert request(confined.address, "/?q="+quote("<script>alert(99)</script>"))[0] == 403
                assert confined.probe("ready").returncode == 0
                confined.signal()
                assert confined.wait(4) == 0
                confinement = confined.logs()
                assert '"files":true' in confinement and '"ports":true' in confinement and '"seccomp":true' in confinement
                results.append("strict Linux confinement supports the private listener, checked forwarding, inspection and clean shutdown")
            if args.arm64_image:
                created = command(["docker", "create", "--platform=linux/arm64", args.arm64_image]).stdout.strip()
                try:
                    binary = work / "arm64-binary"
                    command(["docker", "cp", created+":/carnical", str(binary)])
                    with binary.open("rb") as file:
                        header = file.read(20)
                    assert header[:6] == b"\x7fELF\x02\x01"
                    assert int.from_bytes(header[18:20], "little") == 183
                    results.append("arm64 image contains an actual Linux aarch64 executable; no emulated runtime claim")
                finally:
                    command(["docker", "rm", created], check=False)
            for instance in edges:
                assert instance.key not in instance.logs()
    finally:
        release.set()
        for instance in reversed(edges):
            instance.close()
        app.shutdown()
        app.server_close()
        thread.join(timeout=2)
    print(json.dumps({"runtime": "container" if args.image else "native-linux",
                      "scenarios": len(results), "passed": results}, indent=2))


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    target = parser.add_mutually_exclusive_group(required=True)
    target.add_argument("--binary")
    target.add_argument("--image")
    parser.add_argument("--arm64-image", help="inspect the cross-built image without executing it")
    args = parser.parse_args()
    if args.arm64_image and not args.image:
        parser.error("--arm64-image requires --image")
    run(args)
