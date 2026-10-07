#!/usr/bin/env python3
"""Validate the shipped origin mTLS template with NGINX and the running WAF.

All servers and attacks stay on loopback. Fresh test-only keys are deleted on
exit. Certificate authorization is checked at the real backend, including
same-CA identity confusion, header spoofing and SNI/Host routing differences.
"""
import argparse
import http.client
import json
from pathlib import Path
import socket
import ssl
import subprocess
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


def port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def stop(proc):
    if proc.poll() is None:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=5)


def command(words):
    result = subprocess.run(words, capture_output=True, text=True, timeout=20)
    if result.returncode:
        raise AssertionError(f"{Path(words[0]).name} failed: {result.stderr}")
    return result


def run(args):
    binary = str(Path(args.binary).resolve())
    template = Path(__file__).resolve().parents[2] / "carnical/deploy/nginx/origin-mtls.conf"
    results = []
    with tempfile.TemporaryDirectory(prefix="carnical-origin-auth-") as tmp:
        work = Path(tmp)
        processes = []
        logs = []
        records = []
        lock = threading.Lock()
        mode = {"head": "ok", "sink": 0}

        def key(name):
            path = work / f"{name}.key"
            command(["openssl", "genpkey", "-algorithm", "ED25519", "-out", str(path)])
            path.chmod(0o600)
            return path

        def ca(name):
            private = key(name)
            cert = work / f"{name}.crt"
            command(["openssl", "req", "-new", "-x509", "-key", str(private),
                     "-out", str(cert), "-days", "1", "-subj", f"/CN={name}",
                     "-addext", "basicConstraints=critical,CA:TRUE",
                     "-addext", "keyUsage=critical,keyCertSign,cRLSign"])
            return cert, private

        def identity(name, issuer, serial, purpose):
            private = key(name)
            csr, cert, extensions = [work / f"{name}.{suffix}" for suffix in ("csr", "crt", "ext")]
            command(["openssl", "req", "-new", "-key", str(private), "-out", str(csr),
                     "-subj", f"/CN={name}"])
            text = f"basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage={purpose}\n"
            if purpose == "serverAuth":
                text += "subjectAltName=DNS:localhost,DNS:other.example.test\n"
            extensions.write_text(text)
            command(["openssl", "x509", "-req", "-in", str(csr), "-CA", str(issuer[0]),
                     "-CAkey", str(issuer[1]), "-set_serial", str(serial), "-days", "1",
                     "-extfile", str(extensions), "-out", str(cert)])
            return cert, private

        server_ca, client_ca, foreign_ca = [ca(name) for name in ("server-ca", "site-ca", "other-site-ca")]
        server = identity("origin", server_ca, 1, "serverAuth")
        good = identity("approved-edge", client_ca, 10, "clientAuth")
        wrong = identity("unapproved-edge", client_ca, 11, "clientAuth")
        foreign = identity("foreign-edge", foreign_ca, 10, "clientAuth")
        serial = command(["openssl", "x509", "-in", str(good[0]), "-noout", "-serial"]).stdout.strip().split("=")[1]

        class App(BaseHTTPRequestHandler):
            def log_message(self, *_):
                pass

            def handle_request(self):
                length = int(self.headers.get("Content-Length", "0"))
                body = self.rfile.read(length)
                with lock:
                    records.append((self.command, self.path, body, {k.lower(): v for k, v in self.headers.items()}))
                if self.command == "HEAD" and mode["head"] == "redirect":
                    self.send_response(302)
                    self.send_header("Location", f"http://127.0.0.1:{sink.server_port}/")
                elif self.command == "HEAD" and mode["head"] == "deny":
                    self.send_response(403)
                elif self.command == "HEAD" and mode["head"] == "large":
                    self.send_response(200)
                    self.send_header("X-Budget-Test", "a" * (40 << 10))
                else:
                    self.send_response(200)
                self.send_header("Content-Length", "2")
                self.send_header("Content-Type", "text/plain")
                self.end_headers()
                if self.command != "HEAD":
                    self.wfile.write(b"ok")

            do_GET = do_HEAD = do_POST = handle_request

        class Sink(BaseHTTPRequestHandler):
            def log_message(self, *_):
                pass

            def do_HEAD(self):
                mode["sink"] += 1
                self.send_response(200)
                self.end_headers()

            do_GET = do_HEAD

        app = ThreadingHTTPServer(("127.0.0.1", 0), App)
        sink = ThreadingHTTPServer(("127.0.0.1", 0), Sink)
        for httpd in (app, sink):
            threading.Thread(target=httpd.serve_forever, daemon=True).start()
        origin_port, edge_port = port(), port()

        def start(words, name):
            log = (work / f"{name}.log").open("wb")
            logs.append(log)
            proc = subprocess.Popen(words, stdout=log, stderr=log)
            processes.append(proc)
            return proc

        def context(identity_pair=None):
            ctx = ssl.create_default_context(cafile=str(server_ca[0]))
            ctx.minimum_version = ssl.TLSVersion.TLSv1_2
            if identity_pair:
                ctx.load_cert_chain(str(identity_pair[0]), str(identity_pair[1]))
            return ctx

        def direct(identity_pair, sni="localhost", host="localhost", forged=False, protocol=None):
            headers = {"Host": host, "Connection": "close"}
            if forged:
                headers.update({"X-SSL-Client-Verify": "SUCCESS", "X-SSL-Client-Serial": serial,
                                "X-Forwarded-Client-Cert": "By=localhost;Subject=approved-edge",
                                "SSL-Client-Verify": "SUCCESS", "SSL-Client-Serial": serial})
            with socket.create_connection(("127.0.0.1", origin_port), timeout=3) as raw:
                ctx = context(identity_pair)
                if protocol is not None:
                    ctx.minimum_version = ctx.maximum_version = protocol
                with ctx.wrap_socket(raw, server_hostname=sni) as conn:
                    request = "GET /direct HTTP/1.1\r\n" + "".join(f"{k}: {v}\r\n" for k, v in headers.items()) + "\r\n"
                    conn.sendall(request.encode("ascii"))
                    response = http.client.HTTPResponse(conn)
                    response.begin()
                    response.read()
                    return response.status

        config = template.read_text().replace("origin.example.com", "localhost")
        replacements = {
            "listen 443 ssl;": f"listen 127.0.0.1:{origin_port} ssl;",
            "REPLACE_WITH_APPROVED_CERTIFICATE_SERIAL": serial,
            "/etc/nginx/carnical/origin.crt": str(server[0]),
            "/etc/nginx/carnical/origin.key": str(server[1]),
            "/etc/nginx/carnical/site-client-ca.crt": str(client_ca[0]),
            "/var/log/nginx/carnical-origin-access.log": str(work / "access.log"),
            "http://127.0.0.1:8081": f"http://127.0.0.1:{app.server_port}",
        }
        for old, new in replacements.items():
            assert old in config, f"template no longer includes {old}"
            config = config.replace(old, new)
        # A second site deliberately trusts another CA. Switching HTTP Host after
        # its TLS handshake must not authorize access to the protected site.
        other = f"""
server {{
    listen 127.0.0.1:{origin_port} ssl;
    server_name other.example.test;
    ssl_certificate {server[0]};
    ssl_certificate_key {server[1]};
    ssl_client_certificate {foreign_ca[0]};
    ssl_verify_client on;
    ssl_session_tickets off;
    location / {{ return 204; }}
}}
"""
        nginx_config = work / "nginx.conf"
        nginx_config.write_text(f"""
worker_processes 1;
pid {work}/nginx.pid;
error_log {work}/nginx-error.log info;
events {{ worker_connections 128; }}
http {{
    access_log off;
    client_body_temp_path {work}/body;
    proxy_temp_path {work}/proxy;
    fastcgi_temp_path {work}/fastcgi;
    uwsgi_temp_path {work}/uwsgi;
    scgi_temp_path {work}/scgi;
    {config}
    {other}
}}
""")
        nginx_args = [args.nginx, "-p", str(work) + "/", "-c", str(nginx_config)]
        try:
            command(nginx_args + ["-t"])
            nginx = start(nginx_args + ["-g", "daemon off;"], "nginx")
            deadline = time.monotonic() + 10
            last_probe = None
            while True:
                if nginx.poll() is not None:
                    raise AssertionError((work / "nginx-error.log").read_text())
                try:
                    last_probe = direct(good)
                    if last_probe == 200:
                        break
                except OSError as error:
                    last_probe = str(error)
                assert time.monotonic() < deadline, ("NGINX did not become ready", last_probe, (work / "nginx-error.log").read_text()[-4000:], (work / "access.log").read_text()[-4000:])
                time.sleep(0.1)

            for name, cert, sni, host, forged, allowed in [
                ("approved certificate", good, "localhost", "localhost", False, True),
                ("missing certificate", None, "localhost", "localhost", True, False),
                ("same CA wrong identity and forged headers", wrong, "localhost", "localhost", True, False),
                ("foreign CA same serial and forged headers", foreign, "localhost", "localhost", True, False),
                ("unapproved HTTP Host", good, "localhost", "attacker.example.test", True, False),
                ("different SNI same approved certificate", good, "other.example.test", "localhost", True, False),
                ("other site verified certificate then Host switch", foreign, "other.example.test", "localhost", True, False),
            ]:
                with lock:
                    before = len(records)
                try:
                    status = direct(cert, sni, host, forged)
                    accepted = 200 <= status < 300
                except (OSError, http.client.HTTPException):
                    status, accepted = "TLS refusal", False
                with lock:
                    reached = len(records) - before
                assert accepted == allowed and reached == int(allowed), (name, status, reached)
                results.append({"case": name, "status": status, "origin_requests": reached})

            for protocol in (ssl.TLSVersion.TLSv1_2, ssl.TLSVersion.TLSv1_3):
                with lock:
                    before = len(records)
                status = direct(good, protocol=protocol)
                with lock:
                    reached = len(records) - before
                assert status == 200 and reached == 1, (protocol.name, status, reached)
                results.append({"case": "approved identity " + protocol.name, "status": status, "origin_requests": reached})

            site = work / "site.json"
            flags = {"upstream": f"https://localhost:{origin_port}", "upstream-host": "localhost",
                     "origin-allow": "127.0.0.0/8,::1/128", "hosts": "example.com",
                     "listen": f"127.0.0.1:{edge_port}", "mode": "block", "formats-mode": "block",
                     "ddos": "off", "confine": False, "origin-ca-file": str(server_ca[0]),
                     "origin-client-cert": str(good[0]), "origin-client-key": str(good[1])}
            site.write_text(json.dumps({"version": 1, "flags": flags}))
            site.chmod(0o600)

            def probe(name, identity_pair, accepted, override=None):
                options = ["-config", str(site), "-check", "-check-origin", "-check-origin-http"]
                if identity_pair:
                    options += ["-origin-client-cert", str(identity_pair[0]), "-origin-client-key", str(identity_pair[1])]
                else:
                    options += ["-origin-client-cert=", "-origin-client-key="]
                options += override or []
                with lock:
                    before = len(records)
                result = subprocess.run([binary, *options], capture_output=True, text=True, timeout=15)
                with lock:
                    reached = len(records) - before
                assert (result.returncode == 0) == accepted, (name, result.stderr)
                # A probe may reach the application and receive a refusal. Missing
                # and unauthorized identities must be refused before application access.
                if identity_pair != good or override:
                    assert reached == 0, (name, reached)
                if accepted:
                    assert reached == 1 and records[-1][:2] == ("HEAD", "/"), (name, reached)
                results.append({"case": name, "passed": result.returncode == 0, "origin_requests": reached})

            probe("authenticated HTTP preflight", good, True)
            probe("HTTP preflight without identity", None, False)
            probe("HTTP preflight wrong same-CA identity", wrong, False)
            probe("HTTP preflight foreign CA", foreign, False)
            probe("server name cannot be replaced by Host", good, False,
                  ["-upstream", f"https://127.0.0.1:{origin_port}", "-upstream-host", "localhost"])
            probe("untrusted origin server", good, False, ["-origin-ca-file", str(foreign_ca[0])])
            mode["head"] = "redirect"
            probe("HTTP preflight does not follow redirect", good, True)
            assert mode["sink"] == 0, "preflight followed a redirect"
            mode["head"] = "deny"
            probe("HTTP preflight refuses application denial", good, False)
            mode["head"] = "large"
            # NGINX itself also bounds upstream headers. A failed HEAD must never
            # be reported as a successful onboarding probe.
            probe("HTTP preflight refuses oversized response", good, False)
            mode["head"] = "ok"

            waf = start([binary, "-config", str(site)], "waf")

            def edge_request(method="GET", target="/", body=None, headers=None):
                conn = http.client.HTTPConnection("127.0.0.1", edge_port, timeout=5)
                try:
                    conn.request(method, target, body, {"Host": "example.com", **(headers or {})})
                    response = conn.getresponse()
                    response.read()
                    return response.status
                finally:
                    conn.close()

            deadline = time.monotonic() + 20
            while True:
                assert waf.poll() is None, (work / "waf.log").read_text()
                try:
                    if edge_request() == 200:
                        break
                except OSError:
                    pass
                assert time.monotonic() < deadline, "WAF did not become ready"
                time.sleep(0.1)

            for name, method, target, body, headers, allowed in [
                ("ordinary page", "GET", "/page?lang=en", None, {}, True),
                ("JSON API", "POST", "/api/item", '{"title":"hello"}', {"Content-Type": "application/json"}, True),
                ("login cookies", "POST", "/login", "username=alice", {"Content-Type": "application/x-www-form-urlencoded", "Cookie": "session=test-only"}, True),
                ("XSS remains inspected with mTLS", "GET", "/?q=%3Cscript%3Ealert%281%29%3C%2Fscript%3E", None, {}, False),
                ("SQL injection remains inspected with mTLS", "GET", "/?id=1%27%20OR%201%3D1%20--", None, {}, False),
                ("unapproved visitor Host", "GET", "/page", None, {"Host": "attacker.example.test"}, False),
                ("ambiguous JSON remains refused", "POST", "/api/item", '{"role":"user","role":"admin"}', {"Content-Type": "application/json"}, False),
                ("visitor cannot replace origin identity", "GET", "/page", None,
                 {"X-SSL-Client-Verify": "FAILED", "X-SSL-Client-Serial": "BAD", "X-Forwarded-Client-Cert": "unapproved"}, True),
            ]:
                with lock:
                    before = len(records)
                status = edge_request(method, target, body, headers)
                with lock:
                    reached = len(records) - before
                assert (status == 200) == allowed and reached == int(allowed), (name, status, reached)
                if allowed:
                    assert records[-1][:2] == (method, target)
                    assert records[-1][2] == (body or "").encode()
                    assert records[-1][3]["host"] == "example.com"
                    for claim in ("x-ssl-client-verify", "x-ssl-client-serial", "x-forwarded-client-cert", "ssl-client-verify", "ssl-client-serial"):
                        assert claim not in records[-1][3], (name, claim)
                results.append({"case": name, "status": status, "origin_requests": reached})
            stop(waf)
            confined = start([binary, "-config", str(site), "-confine", "-confine-connect", f"{origin_port},53"], "confined-waf")
            deadline = time.monotonic() + 20
            while True:
                assert confined.poll() is None, (work / "confined-waf.log").read_text()
                try:
                    if edge_request() == 200:
                        break
                except OSError:
                    pass
                assert time.monotonic() < deadline, "confined WAF did not become ready"
                time.sleep(0.1)
            confinement_log = (work / "confined-waf.log").read_text()
            confinement = next(event for event in map(json.loads, confinement_log.splitlines()) if event["msg"] == "confined")
            assert confinement["landlock_abi"] >= 4
            assert all(confinement[key] for key in ("files", "ports", "seccomp", "no_new_privs")), confinement
            for name, target, allowed in [("confined authenticated forwarding", "/page", True),
                                          ("confined inspected injection", "/?q=%3Cscript%3Ealert%281%29%3C%2Fscript%3E", False)]:
                with lock:
                    before = len(records)
                status = edge_request(target=target)
                with lock:
                    reached = len(records) - before
                assert (status == 200) == allowed and reached == int(allowed), (name, status, reached)
                results.append({"case": name, "status": status, "origin_requests": reached})
            stop(confined)
            for name, pair in [("serving WAF with no origin identity", None),
                               ("serving WAF with wrong same-CA identity", wrong),
                               ("serving WAF with foreign identity", foreign)]:
                options = [binary, "-config", str(site), "-origin-client-cert=" + (str(pair[0]) if pair else ""),
                           "-origin-client-key=" + (str(pair[1]) if pair else "")]
                refused_waf = start(options, "refused-waf-" + str(len(results)))
                with lock:
                    before = len(records)
                deadline = time.monotonic() + 20
                while True:
                    assert refused_waf.poll() is None, name
                    try:
                        statuses = [edge_request(target="/page")]
                        break
                    except OSError:
                        pass
                    assert time.monotonic() < deadline, name
                    time.sleep(0.1)
                statuses.append(edge_request(target="/page", headers={"X-SSL-Client-Verify": "SUCCESS",
                                                                         "X-SSL-Client-Serial": serial}))
                with lock:
                    reached = len(records) - before
                assert all(status >= 400 for status in statuses) and reached == 0, (name, statuses, reached)
                results.append({"case": name, "statuses": statuses, "origin_requests": reached})
                stop(refused_waf)
            assert mode["sink"] == 0
            # Audit records omit paths, bodies, cookies and certificate subjects.
            access = (work / "access.log").read_text()
            events = [json.loads(line) for line in access.splitlines()]
            assert any(event["mtls"] == "SUCCESS" and event["serial"] == serial for event in events)
            wrong_serial = command(["openssl", "x509", "-in", str(wrong[0]), "-noout", "-serial"]).stdout.strip().split("=")[1]
            assert any(event["status"] == 403 and event["mtls"] == "SUCCESS" and event["serial"] == wrong_serial for event in events)
            assert any(event["status"] == 400 and event["mtls"] == "NONE" for event in events)
            assert any(event["status"] == 400 and event["mtls"].startswith("FAILED") for event in events)
            assert "session=test-only" not in access and '"title":"hello"' not in access
            print(json.dumps({"nginx": command([args.nginx, "-v"]).stderr.strip(),
                              "cases": results, "redirect_requests": mode["sink"],
                              "origin_auth_log_events": len(events)}, indent=2))
        finally:
            for proc in reversed(processes):
                stop(proc)
            for httpd in (app, sink):
                httpd.shutdown()
                httpd.server_close()
            for log in logs:
                log.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", required=True)
    parser.add_argument("--nginx", default="nginx")
    run(parser.parse_args())
