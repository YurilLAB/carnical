"""Exercise the deployed L3/L4 rules with live packets in disposable Linux network namespaces."""

import argparse
import contextlib
import concurrent.futures
import http.client
import http.server
import ipaddress
import json
import math
import os
import pathlib
import socket
import ssl
import struct
import subprocess
import sys
import tempfile
import threading
import time

ROOT = pathlib.Path(__file__).resolve().parents[2]
POLICY = ROOT / "carnical/deploy/nftables/carnical.nft"
SERVER_MAC = bytes.fromhex("02ca00000001")
CLIENT_MAC = bytes.fromhex("02ca00000002")
V4, V6 = "10.201.0.1", "fd00:ca::1"
PEER4, PEER6 = "10.201.0.2", "fd00:ca::2"
sys.path.insert(0, str(POLICY.parent))
from render_policy import PROFILES, render


def run(*args, **kwargs):
    try:
        return subprocess.run(args, check=True, text=True, capture_output=True, timeout=15, **kwargs).stdout
    except subprocess.CalledProcessError as error:
        raise RuntimeError(f"{args[0]} failed: {error.stderr.strip()}") from error


def checksum(data):
    if len(data) % 2:
        data += b"\0"
    value = sum(struct.unpack("!" + "H" * (len(data) // 2), data))
    while value >> 16:
        value = (value & 65535) + (value >> 16)
    return (~value) & 65535


def equal(actual, expected, message):
    if actual != expected:
        raise AssertionError(f"{message}: got {actual!r}, expected {expected!r}")


def tcp_counters():
    values = {}
    for filename in ("/proc/net/netstat", "/proc/net/snmp"):
        lines = pathlib.Path(filename).read_text().splitlines()
        for names, counts in zip(lines[::2], lines[1::2]):
            if names.split()[0] in ("Tcp:", "TcpExt:"):
                values.update(zip(names.split()[1:], map(int, counts.split()[1:])))
    return {name: values[name] for name in ("ListenOverflows", "ListenDrops", "TCPSynRetrans", "SyncookiesSent",
                                           "TCPReqQFullDoCookies", "TCPReqQFullDrop", "ActiveOpens", "RetransSegs")}


def delta(after, before):
    return {name: after[name] - value for name, value in before.items()}


def latency(samples):
    if not samples:
        return {"count": 0, "p99_ms": 0, "max_ms": 0}
    ordered = sorted(samples)
    return {"count": len(samples), "p99_ms": round(ordered[math.ceil(len(ordered) * .99) - 1] * 1000, 2),
            "max_ms": round(ordered[-1] * 1000, 2)}


def frame(src, proto=6, flags=2, ident=1, hop=64, payload=None, port=443, dst=None, mac=None):
    source = ipaddress.ip_address(src)
    dst = ipaddress.ip_address(dst or (V4 if source.version == 4 else V6))
    if payload is None:
        if proto == 6:
            payload = struct.pack("!HHIIBBHHH", 40000 + ident % 20000, port, ident, 0, 80, flags, 65535, 0, 0)
        elif proto == 17:
            payload = struct.pack("!HHHH", 40000 + ident % 20000, port, 8, 0)
        else:
            raise ValueError("payload required")
    pseudo = source.packed + dst.packed
    if source.version == 4:
        pseudo += struct.pack("!BBH", 0, proto, len(payload))
        header = struct.pack("!BBHHHBBH4s4s", 69, 0, 20 + len(payload), ident % 65536, 0, hop, proto, 0, source.packed, dst.packed)
        header = header[:10] + struct.pack("!H", checksum(header)) + header[12:]
        ethernet = (mac or SERVER_MAC) + CLIENT_MAC + b"\x08\x00"
    else:
        pseudo += struct.pack("!I3xB", len(payload), proto)
        header = struct.pack("!IHBB16s16s", 6 << 28, len(payload), proto, hop, source.packed, dst.packed)
        ethernet = (mac or SERVER_MAC) + CLIENT_MAC + b"\x86\xdd"
    offset = {6: 16, 17: 6, 58: 2}[proto]
    payload = payload[:offset] + struct.pack("!H", checksum(pseudo + payload) or 65535) + payload[offset + 2:]
    return (ethernet + header + payload).hex()


def udp(src, sport, dport, size=8, dst=None, mac=None):
    """A UDP datagram from src:sport to the WAF's address (or dst, on the link address mac) at dport, with size bytes
    of data."""
    data = bytes(size)
    return frame(src, proto=17, payload=struct.pack("!HHHH", sport, dport, 8 + len(data), 0) + data, dst=dst, mac=mac)


def fragments(src, flags, ident):
    # IPv6's first fragment includes the complete TCP header (RFC 7112); both families reassemble a valid checksum.
    tcp = struct.pack("!HHIIBBHHH", 40000 + ident, 443, ident, 0, 80, flags, 65535, 0, 0) + b"fragmentdata"
    full = bytes.fromhex(frame(src, ident=ident, payload=tcp))
    if ipaddress.ip_address(src).version == 4:
        header, data = full[14:34], full[34:]
        frames = []
        for offset, part, more in ((0, data[:16], True), (16, data[16:], False)):
            ip = bytearray(header)
            ip[2:4] = struct.pack("!H", 20 + len(part))
            ip[6:8] = struct.pack("!H", offset // 8 | (8192 if more else 0))
            ip[10:12] = b"\0\0"
            ip[10:12] = struct.pack("!H", checksum(ip))
            frames.append((full[:14] + ip + part).hex())
        return frames
    header, data = full[14:54], full[54:]
    frames = []
    for offset, part, more in ((0, data[:24], True), (24, data[24:], False)):
        ip = bytearray(header)
        ip[4:6] = struct.pack("!H", 8 + len(part))
        ip[6] = 44
        frag = struct.pack("!BBHI", 6, 0, offset | int(more), ident)
        frames.append((full[:14] + ip + frag + part).hex())
    return frames


def peer():
    print("ready", flush=True)
    flood_thread, flood_result = None, {}
    with socket.socket(socket.AF_PACKET, socket.SOCK_RAW) as wire:
        wire.settimeout(5)
        for line in sys.stdin:
            task = json.loads(line)
            if task["kind"] == "packets":
                wire.bind(("client-test", 0))
                for packet in task["frames"]:
                    raw = bytes.fromhex(packet)
                    if wire.send(raw) != len(raw):
                        raise RuntimeError("partial packet send")
                result = {"sent": len(task["frames"])}
            elif task["kind"] == "flood_start":
                if flood_thread is not None and flood_thread.is_alive():
                    raise RuntimeError("flood already running")
                count = task["count"]
                duration = task.get("duration", 0)
                flood_result = {}
                def flood_packets(count=count, duration=duration):
                    try:
                        with socket.socket(socket.AF_PACKET, socket.SOCK_RAW) as attack_wire:
                            attack_wire.settimeout(5)
                            attack_wire.bind(("client-test", 0))
                            begin = time.monotonic()
                            for index in range(count):
                                if index % 32 == 0:
                                    pause = duration * index / count - (time.monotonic() - begin)
                                    if pause > 0:
                                        time.sleep(pause)
                                src = f"fd00:de::{index % 65500 + 1:x}"
                                packet = frame(src, proto=17 if index % 3 == 1 else 6,
                                               flags=3 if index % 3 == 0 else 2, ident=index + 1)
                                raw = bytes.fromhex(packet)
                                if attack_wire.send(raw) != len(raw):
                                    raise RuntimeError("partial flood packet send")
                        flood_result["sent"] = count
                    except OSError as error:
                        flood_result["error"] = str(error)
                flood_thread = threading.Thread(target=flood_packets, daemon=True)
                flood_thread.start()
                result = {"started": True}
            elif task["kind"] == "udp_reply_start":
                # A resolver or clock the WAF's host asks: answer each datagram on the port with a larger one, as DNS
                # and NTP do, so that the reply comes from a reflection port and is established.
                reply_sockets = []
                for family, address in ((socket.AF_INET, PEER4), (socket.AF_INET6, PEER6)):
                    s = socket.socket(family, socket.SOCK_DGRAM)
                    s.bind((address, task["port"]))
                    s.settimeout(5)
                    reply_sockets.append(s)
                reply_result = {"replied": 0}
                def answer(sockets=reply_sockets, want=task["count"], result=reply_result):
                    try:
                        for s in sockets:
                            for _ in range(want):
                                data, where = s.recvfrom(2048)
                                s.sendto(data * 8, where)
                                result["replied"] += 1
                    except OSError as error:
                        result["error"] = str(error)
                    finally:
                        for s in sockets:
                            s.close()
                reply_thread = threading.Thread(target=answer, daemon=True)
                reply_thread.start()
                result = {"listening": True}
            elif task["kind"] == "udp_reply_wait":
                reply_thread.join(timeout=10)
                result = reply_result
            elif task["kind"] == "flood_wait":
                flood_thread.join(timeout=30)
                if flood_thread.is_alive():
                    raise RuntimeError("flood did not finish within 30 seconds")
                result = flood_result
            elif task["kind"] == "http_batch":
                # One connection per worker exercises keep-alive without hiding the number of new handshakes.
                def visitor(worker):
                    family = task["family"] or (4 if worker % 2 == 0 else 6)
                    address = V4 if family == 4 else V6
                    if task.get("ca_file"):
                        tls = ssl.create_default_context(cafile=task["ca_file"])
                        conn = http.client.HTTPSConnection(address, 443, timeout=10, context=tls)
                    else:
                        conn = http.client.HTTPConnection(address, 443, timeout=10)
                    statuses, latencies, errors = {}, [], 0
                    stages = {name: [] for name in ("connect", "write", "headers", "body", "reused")}
                    slow, flooded_requests = [], 0
                    for index in range(worker, task["count"], task["workers"]):
                        begin = time.monotonic()
                        if flood_thread is not None and flood_thread.is_alive():
                            flooded_requests += 1
                        new_connection = conn.sock is None
                        connected = written = headers = begin
                        try:
                            if new_connection:
                                conn.connect()
                                connected = time.monotonic()
                                stages["connect"].append(connected - begin)
                            path = "/?q=%27%20OR%201%3D1--" if task.get("attack") else f"/static/{index % 31}.css"
                            conn.request("GET", path, headers={"Host": "example.test", "User-Agent": "scale-test/1.0"})
                            written = time.monotonic()
                            response = conn.getresponse()
                            headers = time.monotonic()
                            body = response.read()
                            finished = time.monotonic()
                            stages["write"].append(written - connected)
                            stages["headers"].append(headers - written)
                            stages["body"].append(finished - headers)
                            if not new_connection:
                                stages["reused"].append(finished - begin)
                            if finished - begin > .5 and len(slow) < 4:
                                slow.append({"family": family, "request": index, "new_connection": new_connection,
                                             "connect_ms": round((connected - begin) * 1000, 2),
                                             "headers_ms": round((headers - written) * 1000, 2),
                                             "total_ms": round((finished - begin) * 1000, 2)})
                            status = str(response.status)
                            statuses[status] = statuses.get(status, 0) + 1
                            if response.status == 200 and body != b"origin-ok":
                                errors += 1
                        except (OSError, http.client.HTTPException):
                            errors += 1
                            conn.close()
                        latencies.append(time.monotonic() - begin)
                        if task.get("pace"):
                            time.sleep(task["pace"])
                    conn.close()
                    return str(family), statuses, latencies, errors, stages, slow, flooded_requests
                begin = time.monotonic()
                tcp_before = tcp_counters()
                totals, times, errors, families = {}, [], 0, {}
                stages = {name: [] for name in ("connect", "write", "headers", "body", "reused")}
                slow, flooded_requests = [], 0
                with concurrent.futures.ThreadPoolExecutor(max_workers=task["workers"]) as pool:
                    for family, statuses, latencies, failed, measured, delayed, during_flood in pool.map(visitor, range(task["workers"])):
                        errors += failed
                        times.extend(latencies)
                        for status, count in statuses.items():
                            totals[status] = totals.get(status, 0) + count
                            family_totals = families.setdefault(family, {})
                            family_totals[status] = family_totals.get(status, 0) + count
                        for name, samples in measured.items():
                            stages[name].extend(samples)
                        slow.extend(delayed)
                        flooded_requests += during_flood
                result = {"statuses": totals, "families": families, "errors": errors, "seconds": round(time.monotonic() - begin, 3),
                          **latency(times), "stages": {name: latency(samples) for name, samples in stages.items()},
                          "slow_samples": slow[:8], "flood_requests": flooded_requests,
                          "client_tcp": delta(tcp_counters(), tcp_before)}
            elif task["kind"] == "serve_origin":
                server = OriginServer(("0.0.0.0", 80), Origin)
                threading.Thread(target=server.serve_forever, daemon=True).start()
                result = {"started": True}
            else:
                # Live HTTP traverses the veth, kernel policy and running Carnical binary.
                address = V4 if task["family"] == 4 else V6
                conn = http.client.HTTPConnection(address, task.get("port", 443), timeout=5)
                try:
                    conn.request("GET", task["path"], headers={"Host": "example.test", "Connection": "close"})
                    response = conn.getresponse()
                    result = {"status": response.status, "body": response.read().decode("utf-8", "replace")}
                finally:
                    conn.close()
            print(json.dumps(result), flush=True)


class Lab:
    def __init__(self):
        self.client = subprocess.Popen(["unshare", "--net", sys.executable, str(pathlib.Path(__file__).resolve()), "--peer"],
                                       stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
        if self.client.stdout.readline().strip() != "ready":
            raise RuntimeError("peer namespace did not start")

    def close(self):
        self.client.terminate()
        try:
            self.client.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self.client.kill()
            self.client.wait(timeout=5)

    def setup(self):
        run("ip", "link", "set", "lo", "up")
        run("ip", "link", "add", "waf-test", "type", "veth", "peer", "name", "client-test")
        run("ip", "link", "set", "client-test", "netns", str(self.client.pid))
        self.ip("link", "set", "lo", "up")
        for remote, dev, mac, ipv4, ipv6 in [
            (False, "waf-test", SERVER_MAC, V4, V6), (True, "client-test", CLIENT_MAC, PEER4, PEER6)
        ]:
            ip = self.ip if remote else lambda *args: run("ip", *args)
            ip("link", "set", dev, "address", ":".join(f"{x:02x}" for x in mac))
            ip("addr", "add", ipv4 + "/24", "dev", dev)
            ip("-6", "addr", "add", ipv6 + "/64", "dev", dev, "nodad")
            ip("link", "set", dev, "up")
        run("ip", "addr", "add", "198.51.100.1/24", "dev", "waf-test")
        self.ip("addr", "add", "198.51.100.2/24", "dev", "client-test")
        run("ip", "route", "add", "default", "via", PEER4, "dev", "waf-test")

    def ip(self, *args):
        return run("nsenter", "--target", str(self.client.pid), "--net", "ip", *args)

    def ask(self, task):
        self.client.stdin.write(json.dumps(task) + "\n")
        self.client.stdin.flush()
        line = self.client.stdout.readline()
        if not line:
            raise RuntimeError("peer exited before answering")
        return json.loads(line)

    def send(self, frames):
        result = self.ask({"kind": "packets", "frames": frames})
        if result["sent"] != len(frames):
            raise AssertionError("not all packets sent")

    def load(self, *, small_set=False, low_global=False, profile="standard", peers=False, overrides=None, port=443):
        settings = dict(overrides or {})
        if small_set:
            settings.update(syn_meter_size=4, syn_peer_meter_size=4, syn_meter_ttl=1)
        if low_global:
            settings.update(syn_global_rate=10, syn_global_burst=20)
        ranges = (PEER4, "fd00:ca::/64") if peers is True else (peers or ())
        text = render(profile, port=port, peers=ranges, overrides=settings)
        # No host accounts are created. Numeric fixture UIDs affect only the isolated namespace's egress policy.
        for index, name in enumerate(["edge", "portal", "ctl", "signer", "audit"], 61001):
            text = text.replace('"carnical-' + name + '"', str(index))
        # Production rendering replaces this one table atomically; exercise real reloads rather than pre-deleting it.
        run("nft", "--check", "--file", "-", input=text)
        run("nft", "--file", "-", input=text)

    def count(self, name):
        data = json.loads(run("nft", "--json", "list", "counter", "inet", "carnical", name))
        return next(item["counter"]["packets"] for item in data["nftables"] if "counter" in item)

    def set_counts(self, name):
        """The packets each element of a counting set holds, by port."""
        data = json.loads(run("nft", "--json", "list", "set", "inet", "carnical", name))
        elems = next(item["set"] for item in data["nftables"] if "set" in item).get("elem", [])
        return {item["elem"]["val"]: item["elem"]["counter"]["packets"] for item in elems}

    def expect(self, name, minimum):
        deadline = time.monotonic() + 2
        while time.monotonic() < deadline:
            actual = self.count(name)
            if actual >= minimum:
                return actual
            time.sleep(0.02)
        raise AssertionError(f"{name}: got {actual}, expected at least {minimum}")


class Origin(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        with self.server.metrics_lock:
            self.server.requests += 1
        self.send_response(200)
        if self.protocol_version == "HTTP/1.1":
            self.send_header("Content-Length", "9")
        self.end_headers()
        self.wfile.write(b"origin-ok")

    def log_message(self, *args):
        pass


class LegacyOrigin(Origin):
    protocol_version = "HTTP/1.0"


class OriginServer(http.server.ThreadingHTTPServer):
    # The fixture must not limit the WAF's 64-worker workload to Python's default queue of five.
    request_queue_size = 256
    no_delay = True

    def __init__(self, address, handler):
        self.metrics_lock = threading.Lock()
        self.accepted, self.requests = 0, 0
        super().__init__(address, handler)

    def metrics(self):
        with self.metrics_lock:
            return self.accepted, self.requests

    def get_request(self):
        conn, address = super().get_request()
        try:
            if self.no_delay:
                conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        except OSError:
            conn.close()
            raise
        with self.metrics_lock:
            self.accepted += 1
        return conn, address


def egress():
    task = json.load(sys.stdin)
    os.setgroups([])
    os.setgid(task["uid"])
    os.setuid(task["uid"])
    connected = 0
    for _ in range(task["attempts"]):
        try:
            with socket.create_connection((task["host"], task["port"]), timeout=task["timeout"]):
                connected += 1
        except OSError:
            pass
    print(json.dumps({"connected": connected}), flush=True)


def test(binary, investigate=False, egress_users=True):
    if os.geteuid() != 0:
        raise RuntimeError("network namespace test requires root")
    if os.stat("/proc/self/ns/net").st_ino == os.stat("/proc/1/ns/net").st_ino:
        raise RuntimeError("refusing to change the host network namespace")
    for arguments in (["--port", "0"], ["--port", "22"], ["--port", "65536"], ["--peer", "0.0.0.0/0"], ["--peer", "::/0"],
                      ["--peer", "192.0.2.1/24"], ["--peer", "fe80::%x;drop/128"],
                      ["--set", "syn_source_rate=0"], ["--set", "syn_source_burst=-1"],
                      ["--set", "syn_meter_size=1048577"], ["--set", "unknown=5"],
                      ["--set", "syn_source_rate=10", "--set", "syn_source_rate=20"]):
        result = subprocess.run([sys.executable, str(POLICY.with_name("render_policy.py")), *arguments],
                                text=True, capture_output=True, timeout=5)
        equal(result.returncode, 2, "unsafe renderer configuration must be rejected")
        equal(result.stdout, "", "invalid renderer input must not emit a policy")
    print("PASS: invalid ports, unbounded/scoped peers and invalid/duplicate budgets rejected before policy output", flush=True)
    with contextlib.ExitStack() as stack:
        lab = Lab()
        stack.callback(lab.close)
        lab.setup()
        run("nft", "--file", "-", input="table inet carnical_test_canary {\n counter intact { packets 7 bytes 42 }\n}\n")
        origin = OriginServer(("127.0.0.1", 0), Origin)
        stack.callback(origin.server_close)
        threading.Thread(target=origin.serve_forever, daemon=True).start()
        stack.callback(origin.shutdown)
        log = stack.enter_context(tempfile.TemporaryFile(mode="w+"))
        def stop_waf(waf):
            waf.terminate()
            try:
                waf.wait(timeout=5)
            except subprocess.TimeoutExpired:
                waf.kill()
                waf.wait(timeout=5)
        def start_waf(extra, port=443):
            waf = subprocess.Popen([str(binary), "-listen", f"[::]:{port}", "-upstream", f"http://127.0.0.1:{origin.server_port}",
                                    "-origin-allow", "127.0.0.0/8", "-mode", "block", *extra], stdout=log, stderr=log)
            stack.callback(stop_waf, waf)
            deadline = time.monotonic() + 15
            while True:
                if waf.poll() is not None:
                    log.seek(0)
                    raise RuntimeError("WAF failed to start: " + log.read())
                try:
                    with socket.create_connection(("127.0.0.1", port), timeout=0.1):
                        return waf
                except OSError:
                    if time.monotonic() > deadline:
                        raise RuntimeError("WAF did not listen")
                    time.sleep(0.05)
        def measured_batch(task, *, require_origin=True):
            before = tcp_counters()
            accepted, requests = origin.metrics()
            result = lab.ask({"kind": "http_batch", **task})
            result["server_tcp"] = delta(tcp_counters(), before)
            after_accepted, after_requests = origin.metrics()
            result["origin_connections"] = after_accepted - accepted
            result["origin_requests"] = after_requests - requests
            if require_origin:
                equal(result["origin_requests"], 0 if task.get("attack") else task["count"], "requests actually reaching the origin")
            return result
        if investigate:
            # One-factor controls use the same binary, WAF limits, policy, workers and requests.
            for label, handler, backlog, no_delay in (
                ("legacy-queue5", LegacyOrigin, 5, False),
                ("legacy-queue256", LegacyOrigin, 256, False),
                ("persistent-queue256", Origin, 256, False),
                ("persistent-nodelay-queue256", Origin, 256, True),
            ):
                # Timed-out requests in the overloaded control can arrive later.
                # Give each comparison its own origin and counters, so late work
                # cannot inflate the next comparison's exact request count.
                origin.shutdown()
                origin.server_close()
                origin = OriginServer(("127.0.0.1", 0), handler)
                stack.callback(origin.server_close)
                threading.Thread(target=origin.serve_forever, daemon=True).start()
                stack.callback(origin.shutdown)
                origin.socket.listen(backlog)
                origin.no_delay = no_delay
                lab.load(profile="large", peers=True)
                waf = start_waf(["-ddos", "on", "-ddos-rate", "50000", "-ddos-burst", "100000",
                                 "-ddos-baseline-rate", "10000", "-ddos-max-conns", "4096",
                                 "-max-evaluations", "64", "-max-upstream", "128"])
                for flooded in (False, True):
                    if flooded:
                        lab.ask({"kind": "flood_start", "count": 100000, "duration": 8})
                    result = measured_batch({"family": 0, "count": 10000, "workers": 64}, require_origin=False)
                    # Always preserve the measurement, including an intentionally overloaded control's failures.
                    print(f"MEASURE: {label} flood={flooded} {json.dumps(result)}", flush=True)
                    equal(result["count"], 10000, "all control attempts must be measured")
                    if backlog != 5:
                        equal(result["errors"], 0, "sized-origin latency investigation transport errors")
                        equal(result["families"], {"4": {"200": 5000}, "6": {"200": 5000}}, "sized-origin latency investigation responses")
                        equal(result["origin_requests"], 10000, "sized-origin requests must all reach the backend")
                    if handler is Origin and result["origin_connections"] > 128:
                        raise AssertionError("persistent origin did not reuse connections")
                    if backlog == 256:
                        equal(result["server_tcp"]["ListenOverflows"], 0, "sized origin accept queue must not overflow")
                    if flooded:
                        if result["flood_requests"] < 5000:
                            raise AssertionError("latency control did not overlap the packet stream sufficiently")
                        equal(lab.ask({"kind": "flood_wait"}), {"sent": 100000}, "investigation flood generation")
                        lab.expect("edge_bad_tcp", 33334)
                        lab.expect("edge_udp_drop", 33333)
                        lab.expect("edge_syn_source_drop", 20000)
                        equal(sum(lab.count(name) for name in ("edge_syn_admitted", "edge_syn_source_drop", "edge_syn_network_drop", "edge_syn_global_drop")),
                              33333, "investigation flood SYN accounting")
                for family in (4, 6):
                    result = measured_batch({"family": family, "count": 25, "workers": 1, "attack": True, "pace": .05})
                    equal(result["errors"], 0, "latency control SQL probe transport errors")
                    equal(result["statuses"], {"403": 25}, "SQL injection blocked in every latency control")
                    equal(result["origin_connections"], 0, "blocked SQL probe must not open an origin connection")
                print(f"PASS: {label} SQL injection 50/50 blocked before the origin", flush=True)
                stop_waf(waf)
            return
        waf = start_waf(["-ddos", "off"])

        lab.load()
        for family in (4, 6):
            benign = lab.ask({"kind": "http", "family": family, "path": "/"})
            equal(benign, {"status": 200, "body": "origin-ok"}, "ordinary request")
            hostile = lab.ask({"kind": "http", "family": family, "path": "/?q=%27%20OR%201%3D1--"})
            equal(hostile["status"], 403, "SQL injection")
        print("PASS: live IPv4/IPv6 WAF traffic: ordinary requests served, SQL injection blocked", flush=True)

        lab.load()
        lab.send([frame(PEER4, flags=flag, ident=i) for i, flag in enumerate((0, 1, 41, 3, 6), 1)])
        lab.send([frame(PEER6, flags=flag, ident=i) for i, flag in enumerate((0, 1, 41, 3, 6), 10)])
        lab.expect("edge_bad_tcp", 10)
        lab.send([frame(PEER4, flags=194), frame(PEER6, flags=194)])  # ECN-capable SYN
        lab.expect("edge_syn_admitted", 2)
        equal(lab.count("edge_bad_tcp"), 10, "ECN SYN must not be refused as malformed")
        for src in ("127.0.0.2", "0.1.2.3", "224.0.0.1", "240.0.0.1", "::"):
            before = lab.count("edge_bad_source")
            lab.send([frame(src)])
            lab.expect("edge_bad_source", before + 1)
        # Linux rejects IPv6 loopback on a non-loopback interface and multicast sources before the nft prerouting hook.
        before = lab.count("edge_syn_admitted")
        lab.send([frame("::1"), frame("ff02::1")])
        equal(lab.count("edge_syn_admitted"), before, "kernel-rejected IPv6 sources must not reach SYN admission")
        lab.send([frame(PEER4, proto=17), frame(PEER6, proto=17)])
        lab.expect("edge_udp_drop", 2)
        print("PASS: malformed TCP, impossible TCP sources and UDP/443 dropped; ECN SYN preserved", flush=True)

        # Unsolicited UDP is sorted for carnical-netwatch: reflection replies from a service port by source port, the
        # rest by destination port. Everything is dropped as before; replies to what the host asked still arrive.
        lab.load()
        names = ("udp_flood_drop", "udp_reflection_drop", "edge_udp_drop", "input_denied", "udp_broadcast_drop")
        denied = lab.count("input_denied")
        flood = [udp(PEER4 if i % 2 else PEER6, 40000 + i, 1024 + i % 40, 64) for i in range(400)]
        lab.send(flood)
        lab.expect("udp_flood_drop", 400)
        ports = lab.set_counts("udp_ports")
        equal(len(ports), 40, "destination ports counted")
        equal(sum(ports.values()), 400, "packets counted by destination port")
        reflected = [udp(f"10.201.0.{3 + i % 50}" if i % 2 else f"fd00:ca::{3 + i % 50:x}", sport, 33000 + i, 400)
                     for i, sport in enumerate([53] * 150 + [123] * 100 + [11211] * 50)]
        lab.send(reflected)
        lab.expect("udp_reflection_drop", 300)
        equal(lab.set_counts("udp_reflectors"), {53: 150, 123: 100, 11211: 50}, "reflection replies counted by source port")
        equal(sorted(set(range(33000, 33300)) & set(lab.set_counts("udp_ports"))), [], "reflection replies kept out of the flood's ports")
        equal(lab.count("udp_flood_drop"), 400, "reflection replies are not counted as the flood")
        equal(lab.count("edge_udp_drop"), 0, "UDP/443 is the raw guard's, untouched by other UDP")
        equal(lab.count("input_denied"), denied, "UDP no longer reaches the general input drop")
        lab.send([frame(PEER4, proto=17), frame(PEER6, proto=17)])
        lab.expect("edge_udp_drop", 2)
        equal(lab.count("udp_flood_drop"), 400, "UDP/443 is dropped before it is sorted")
        # The local network's chatter, broadcast and multicast from reflection ports (mDNS, SSDP, DHCP), is dropped as
        # before but counted apart: it is not a flood aimed at this host, nor reflection.
        chatter = ([udp(PEER4, 5353, 5353, 100, dst="255.255.255.255", mac=b"\xff" * 6) for _ in range(50)]
                   + [udp(PEER4, 1900, 1900, 300, dst="224.0.0.1", mac=bytes.fromhex("01005e000001")) for _ in range(50)]
                   + [udp(PEER4, 67, 68, 300, dst="255.255.255.255", mac=b"\xff" * 6) for _ in range(20)]
                   + [udp(PEER6, 5353, 5353, 100, dst="ff02::1", mac=bytes.fromhex("333300000001")) for _ in range(50)])
        lab.send(chatter)
        lab.expect("udp_broadcast_drop", 170)
        equal(lab.count("udp_reflection_drop"), 300, "broadcast and multicast are not reflection")
        equal(lab.count("udp_flood_drop"), 400, "broadcast and multicast are not a flood")
        # The sets' elements time out, so what is checked is that none of the chatter's ports is in them.
        equal(sorted({5353, 1900, 68} & set(lab.set_counts("udp_ports"))), [], "broadcast and multicast not counted by port")
        equal(sorted({5353, 1900, 67} & set(lab.set_counts("udp_reflectors"))), [], "nor as reflectors")
        # A flood to more ports than the set holds is still dropped in full: only the counting by port stops.
        many = [udp(PEER4, 41000, 2000 + i) for i in range(2200)]
        for chunk in range(0, len(many), 500):
            lab.send(many[chunk:chunk + 500])
        lab.expect("udp_flood_drop", 2600)
        if len(lab.set_counts("udp_ports")) > 2048:
            raise AssertionError("the destination port set grew past its size")
        # Negative control for false positives: the host asks a resolver (port 53) and a clock (port 123) in the
        # other namespace, and every larger reply, from a reflection port, comes back and is counted nowhere.
        before = {name: lab.count(name) for name in names}
        for port in (53, 123):
            equal(lab.ask({"kind": "udp_reply_start", "port": port, "count": 5}), {"listening": True}, "reply peer listening")
            received = 0
            for family, address in ((socket.AF_INET, PEER4), (socket.AF_INET6, PEER6)):
                with socket.socket(family, socket.SOCK_DGRAM) as s:
                    s.settimeout(2)
                    for n in range(5):
                        s.sendto(b"q%02d" % n, (address, port))
                        data, _ = s.recvfrom(2048)
                        received += data == (b"q%02d" % n) * 8
            equal(received, 10, f"replies from port {port} to the host's own queries")
            equal(lab.ask({"kind": "udp_reply_wait"}), {"replied": 10}, f"port {port} peer answered")
        equal({name: lab.count(name) for name in names}, before, "established replies must not be counted or dropped")
        print("PASS: unsolicited UDP sorted by kind and port and dropped in full (set bounded); broadcast and multicast "
              "counted apart; replies from DNS and NTP ports to the host's own queries arrive untouched", flush=True)

        lab.load()
        for i, src in enumerate((PEER4, PEER6), 1):
            lab.send(fragments(src, 2, i * 10))
            lab.send(fragments(src, 3, i * 10 + 1))
        lab.expect("edge_syn_admitted", 2)
        lab.expect("edge_bad_tcp", 2)
        print("PASS: IPv4/IPv6 fragments reassemble before filtering; fragmented SYN+FIN cannot bypass the guard", flush=True)

        for family in (4, 6):
            lab.load()
            srcs = [PEER4] * 512 if family == 4 else [f"fd00:ca::{i + 256:x}" for i in range(512)]
            lab.send([frame(src, ident=i + 1) for i, src in enumerate(srcs)])
            lab.expect("edge_syn_source_drop", 200)
            lab.expect("edge_syn_admitted", 200)
            if family == 6:
                before = lab.count("edge_syn_admitted")
                lab.send([frame("fd00:cb::1")])
                lab.expect("edge_syn_admitted", before + 1)
        print("PASS: IPv4 source flood and IPv6 /64 rotation limited; another /64 retains its budget", flush=True)

        lab.load(low_global=True)
        lab.send([frame(f"203.0.113.{i + 1}", ident=i) for i in range(100)])
        lab.expect("edge_syn_global_drop", 60)
        lab.expect("edge_syn_admitted", 20)
        print("PASS: aggregate SYN limit holds across different source addresses (reduced threshold fixture)", flush=True)

        for family in (4, 6):
            # Four buckets in each meter, and sixty-four sources, each in a network of its own.
            lab.load(small_set=True)
            sources = [f"203.0.{i}.1" if family == 4 else f"fd00:{i + 256:x}::1" for i in range(64)]
            lab.send([frame(src, ident=i + 1) for i, src in enumerate(sources)])
            lab.expect("edge_syn_admitted", 64)
            equal(lab.count("edge_syn_source_drop") + lab.count("edge_syn_network_drop"), 0,
                  "sources beyond the number of buckets must not be refused")
        print("PASS: more IPv4/IPv6 sources than a meter has buckets are all admitted: a flood of new sources cannot fill it", flush=True)

        # With one bucket every source shares one budget: sharing a bucket never adds up to more than its budget.
        lab.load(overrides={"syn_meter_size": 1})
        lab.send([frame(f"203.{i // 200}.{i % 200}.1", ident=i + 1) for i in range(400)])
        lab.expect("edge_syn_source_drop", 150)
        lab.expect("edge_syn_admitted", 200)
        equal(lab.count("edge_syn_admitted") + lab.count("edge_syn_source_drop"), 400, "shared-bucket SYN accounting")
        print("PASS: sources that share a bucket share its budget and do not exceed it", flush=True)

        # One loud source is cut down by its own budget before the aggregate: the others still have all of that.
        lab.load(overrides={"syn_global_rate": 150, "syn_global_burst": 300})
        lab.send([frame(PEER4, ident=i + 1) for i in range(3000)])
        lab.expect("edge_syn_source_drop", 2500)
        equal(lab.count("edge_syn_global_drop"), 0, "a source over its own budget must not use up the aggregate")
        before = lab.count("edge_syn_admitted")
        lab.send([frame(f"203.0.{i}.1", ident=i + 1) for i in range(40)])
        lab.expect("edge_syn_admitted", before + 40)
        equal(lab.count("edge_syn_global_drop"), 0, "other sources keep the aggregate while one source floods")
        print("PASS: a source flood is refused by its own budget and leaves the aggregate to everyone else", flush=True)

        for family in (4, 6):
            # 120 sources in one IPv4 /24, or 120 /64s in one IPv6 /48: no source is over its budget, the network is.
            lab.load(overrides={"syn_network_rate": 20, "syn_network_burst": 40})
            sources = [f"203.0.113.{i + 1}" if family == 4 else f"fd00:cc:0:{i + 1:x}::1" for i in range(120)]
            lab.send([frame(src, ident=i + 1) for i, src in enumerate(sources)])
            lab.expect("edge_syn_network_drop", 60)
            lab.expect("edge_syn_admitted", 40)
            equal(lab.count("edge_syn_source_drop"), 0, "no source of the network is over its own budget")
            before = lab.count("edge_syn_admitted")
            lab.send([frame("203.0.114.1" if family == 4 else "fd00:cd::1")])
            lab.expect("edge_syn_admitted", before + 1)
        print("PASS: an IPv4 /24 and an IPv6 /48 are held to the network's budget; another network keeps its own", flush=True)

        lab.load()
        echo = struct.pack("!BBHHH", 128, 0, 0, 1, 1)
        lab.send([frame(PEER6, proto=58, payload=echo, ident=i) for i in range(256)])
        lab.expect("edge_echo_admitted", 40)
        lab.expect("edge_echo_drop", 100)
        # Unexpected TCP ports exercise the separate bounded log path, without one message per early refusal. (Unsolicited
        # UDP has counters of its own and is not logged: a UDP scan or flood would use up the log's budget.)
        lab.send([frame(PEER6, proto=6, port=4444, ident=i) for i in range(128)])
        lab.expect("input_denied", 100)
        lab.expect("input_logged", 1)
        if lab.count("input_logged") > 5:
            raise AssertionError("input refusal logging exceeded its burst budget")
        ns = struct.pack("!BBHI16sBB6s", 135, 0, 0, 0, ipaddress.ip_address(V6).packed, 1, 1, CLIENT_MAC)
        before = lab.count("input_denied")
        lab.send([frame(PEER6, proto=58, hop=254, payload=ns)])
        lab.expect("input_denied", before + 1)
        before = lab.count("edge_discovery_accept")
        lab.send([frame(PEER6, proto=58, hop=255, payload=ns)])
        lab.expect("edge_discovery_accept", before + 1)
        print("PASS: IPv6 discovery survives an echo flood; invalid hop limit refused; packet-drop logging stays bounded", flush=True)
        lab.load()
        equal(lab.ask({"kind": "http", "family": 6, "path": "/"})["status"], 200, "post-flood IPv6 HTTP")
        print("PASS: ordinary IPv6 HTTP remains available after the packet tests", flush=True)

        lab.load()
        lab.ask({"kind": "serve_origin"})
        for uid, host, port, connected, counter in [] if not egress_users else [
            (61001, "198.51.100.2", 80, 16, None),
            (61001, "127.0.0.1", origin.server_port, 0, "egress_private_drop"),
            (61001, "168.63.129.16", 80, 0, "egress_private_drop"),
            (61001, "169.254.169.254", 80, 0, "egress_imds_drop"),
            (61001, "198.51.100.2", 25, 0, "egress_edge_drop"),
            (61002, "198.51.100.2", 80, 0, "egress_internal_drop"),
        ]:
            # Counters add up across rows, so each row must raise its own by the attempts it makes.
            before = lab.count(counter) if counter else 0
            task = {"uid": uid, "host": host, "port": port, "attempts": 16, "timeout": 2 if connected else 0.05}
            result = json.loads(run(sys.executable, str(pathlib.Path(__file__).resolve()), "--egress", input=json.dumps(task)))
            equal(result["connected"], connected, "service UID egress policy")
            if counter:
                lab.expect(counter, before + 16)
        # Six refusals beyond each logging burst must still be refused; successful public-port connections are the control.
        if egress_users:
            print("PASS: service-UID egress still refuses private/metadata/Azure platform/SMTP/internal traffic after log-budget exhaustion", flush=True)
        else:
            print("SKIPPED: service-UID egress (asked for with --no-egress-users: this user cannot become another)", flush=True)

        # Exercise the same deployed policy at small and large budgets, including shared peers, finite overflow,
        # ordinary HTTP keep-alive and the entire WAF with its Go connection shield enabled.
        stop_waf(waf)
        for profile, workers, requests, packets in (("small", 4, 240, 6000), ("large", 32, 5000, 100000)):
            budget = PROFILES[profile]
            lab.load(profile=profile)
            burst = budget["syn_source_burst"] // 2
            for family in (4, 6):
                src = PEER4 if family == 4 else PEER6
                lab.send([frame(src, ident=i + 1) for i in range(burst)])
            equal(lab.count("edge_syn_admitted"), 2 * burst, "ordinary source burst")
            equal(lab.count("edge_syn_source_drop"), 0, "ordinary bursts must not be refused")
            # A shared address's larger burst cannot be served by the ordinary bucket alone.
            lab.load(profile=profile, peers=True)
            burst = budget["syn_peer_burst"] // 2
            for family in (4, 6):
                src = PEER4 if family == 4 else PEER6
                lab.send([frame(src, ident=i + 1) for i in range(burst)])
            equal(lab.count("edge_syn_peer_admitted"), 2 * burst, "shared peer burst")
            equal(lab.count("edge_syn_source_drop"), 0, "peers must use their own budget")
            equal(lab.count("edge_syn_global_drop"), 0, "ordinary peer bursts fit aggregate capacity")
            lab.send([frame(PEER4, flags=3), frame(PEER6, flags=6), frame(PEER4, proto=17), frame(PEER6, proto=17)])
            lab.expect("edge_bad_tcp", 2)
            lab.expect("edge_udp_drop", 2)
            print(f"PASS: {profile} ordinary and shared-peer bursts admitted without packet-budget refusals", flush=True)

            # Reduce only the peer budget to exhaust it deterministically; keep each profile's aggregate ceiling.
            for src in (PEER4, PEER6):
                lab.load(profile=profile, peers=True, overrides={"syn_peer_rate": 10, "syn_peer_burst": 20})
                lab.send([frame(src, ident=i + 1) for i in range(200)])
                lab.expect("edge_syn_peer_drop", 150)
                equal(lab.count("edge_syn_admitted"), 0, "exhausted peer must not fall back to ordinary budget")
                equal(lab.count("edge_syn_peer_admitted") + lab.count("edge_syn_peer_drop"), 200,
                      "a peer over its budget is refused once and admitted no other way")
                # A peer within its own budget still comes under the aggregate.
                lab.load(profile=profile, peers=True, low_global=True)
                lab.send([frame(src, ident=i + 1) for i in range(200)])
                lab.expect("edge_syn_global_drop", 150)
                equal(lab.count("edge_syn_peer_admitted") + lab.count("edge_syn_global_drop"), 200,
                      "peer SYN accounting under the aggregate")
            print(f"PASS: {profile} peer budgets and aggregate ceiling remain enforced (reduced exhaustion fixture)", flush=True)

            lab.load(profile=profile, peers=True)
            waf = start_waf(["-ddos", "on", "-ddos-rate", "50000", "-ddos-burst", "100000", "-ddos-baseline-rate", "10000",
                             "-ddos-max-conns", "64" if profile == "small" else "4096",
                             "-max-evaluations", str(2 * workers), "-max-upstream", str(4 * workers)])
            for family in (4, 6):
                result = measured_batch({"family": family, "count": requests, "workers": workers,
                                         "pace": .025 if profile == "small" else 0})
                equal(result["errors"], 0, "ordinary request errors")
                equal(result["statuses"], {"200": requests}, "ordinary requests must reach the origin")
                print(f"PASS: {profile} IPv{family} ordinary traffic {json.dumps(result)}", flush=True)
            # Compare against the flood at identical concurrency; the per-family batches use half as many workers.
            control = measured_batch({"family": 0, "count": 2 * requests, "workers": 2 * workers,
                                      "pace": .025 if profile == "small" else 0})
            equal(control["errors"], 0, "matched-concurrency ordinary request errors")
            equal(control["families"], {"4": {"200": requests}, "6": {"200": requests}}, "matched-concurrency responses")
            print(f"PASS: {profile} simultaneous IPv4/IPv6 without flood {json.dumps(control)}", flush=True)
            lab.ask({"kind": "flood_start", "count": packets, "duration": 3 if profile == "small" else 8})
            result = measured_batch({"family": 0, "count": 2 * requests, "workers": 2 * workers,
                                     "pace": .025 if profile == "small" else 0})
            equal(result["errors"], 0, "legitimate traffic errors during packet flood")
            equal(result["families"], {"4": {"200": requests}, "6": {"200": requests}}, "both IP families during packet flood")
            if result["flood_requests"] < requests:
                raise AssertionError("profile workload did not overlap the packet stream sufficiently")
            for measured in (control, result):
                equal(measured["server_tcp"]["ListenOverflows"], 0, "origin and WAF accept queues must not overflow")
                equal(measured["client_tcp"]["TCPSynRetrans"], 0, "legitimate edge handshakes must not retransmit")
                if measured["origin_connections"] > 4 * workers:
                    raise AssertionError("origin keep-alive did not bound connection churn")
                if measured["p99_ms"] >= 500:
                    raise AssertionError(f"{profile} laboratory p99 exceeded 500 ms: {measured['p99_ms']}")
            print(f"PASS: {profile} simultaneous IPv4/IPv6 traffic across packet flood {json.dumps(result)}", flush=True)
            equal(lab.ask({"kind": "flood_wait"}), {"sent": packets}, "varied flood generation")
            lab.expect("edge_bad_tcp", (packets + 2) // 3)
            lab.expect("edge_udp_drop", (packets + 1) // 3)
            syn = sum(lab.count(name) for name in ("edge_syn_admitted", "edge_syn_source_drop", "edge_syn_network_drop", "edge_syn_global_drop"))
            equal(syn, packets // 3, "every flood SYN must be admitted or refused by a named counter")
            if profile == "large":
                lab.expect("edge_syn_source_drop", 20000)
            else:
                lab.expect("edge_syn_source_drop", 1500)
            for family in (4, 6):
                result = lab.ask({"kind": "http_batch", "family": family, "count": 25, "workers": 1, "attack": True, "pace": .05})
                equal(result["errors"], 0, "hostile HTTP request transport errors")
                equal(result["statuses"], {"403": 25}, "SQL injection must still be blocked")
            counts = {name: lab.count(name) for name in ("edge_bad_tcp", "edge_udp_drop", "edge_syn_admitted",
                                                        "edge_syn_source_drop", "edge_syn_network_drop", "edge_syn_global_drop")}
            print(f"PASS: {profile} varied flood {packets} packets accounted for {json.dumps(counts)}; SQL injection 50/50 blocked", flush=True)
            stop_waf(waf)

        # Revoking a high-volume peer on reload must remove both membership and its old meter budget.
        lab.load(profile="large", peers=True)
        lab.send([frame(PEER4)])
        lab.expect("edge_syn_peer_admitted", 1)
        lab.load(profile="small")
        lab.send([frame(PEER4, ident=i + 1) for i in range(300)])
        equal(lab.count("edge_syn_peer_admitted"), 0, "revoked peer must lose its larger budget")
        lab.expect("edge_syn_source_drop", 150)
        equal(lab.count("edge_syn_peer_drop"), 0, "old peer set must not survive replacement")
        print("PASS: atomic large-to-small reload revokes old peers and applies the smaller budget", flush=True)

        for family in (4, 6):
            lab.load(small_set=True, peers=("198.51.100.0/24", "fd00::/16"))
            sources = [f"198.51.100.{i + 10}" if family == 4 else f"fd00:{i + 10:x}::1" for i in range(64)]
            lab.send([frame(src, ident=i + 1) for i, src in enumerate(sources)])
            lab.expect("edge_syn_peer_admitted", 64)
            equal(lab.count("edge_syn_peer_drop"), 0, "peers beyond the number of buckets must not be refused")
            equal(lab.count("edge_syn_admitted"), 0, "peers must not be counted as ordinary admission")
        print("PASS: more IPv4/IPv6 peers than the peer meter has buckets are admitted, by the peer budget alone", flush=True)

        lab.load(port=9443)
        waf = start_waf(["-ddos", "off"], port=9443)
        for family in (4, 6):
            equal(lab.ask({"kind": "http", "family": family, "path": "/", "port": 9443})["status"], 200, "custom public port")
        lab.send([frame(PEER4, flags=3, port=9443), frame(PEER6, proto=17, port=9443)])
        lab.expect("edge_bad_tcp", 1)
        lab.expect("edge_udp_drop", 1)
        before = lab.count("edge_syn_admitted")
        lab.send([frame(PEER4, port=443)])
        lab.expect("input_denied", 1)
        equal(lab.count("edge_syn_admitted"), before, "old port must not retain public admission")
        print("PASS: custom port 9443 serves both IP families with the same guards; old port remains closed", flush=True)
        stop_waf(waf)

        directory = pathlib.Path(stack.enter_context(tempfile.TemporaryDirectory()))
        certificate, key = directory / "test-cert.pem", directory / "test-key.pem"
        run("openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", str(key), "-out", str(certificate),
            "-days", "1", "-subj", "/CN=example.test", "-addext", f"subjectAltName=DNS:example.test,IP:{V4},IP:{V6}")
        lab.load(profile="large", peers=True)
        waf = start_waf(["-ddos", "on", "-ddos-rate", "50000", "-ddos-burst", "100000", "-max-evaluations", "32",
                         "-tls-cert", str(certificate), "-tls-key", str(key)])
        result = measured_batch({"family": 0, "count": 1000, "workers": 16, "ca_file": str(certificate)})
        equal(result["errors"], 0, "TLS request errors")
        equal(result["families"], {"4": {"200": 500}, "6": {"200": 500}}, "verified TLS requests")
        print(f"PASS: verified TLS with kernel policy, shield and CRS enabled {json.dumps(result)}", flush=True)
        lab.ask({"kind": "flood_start", "count": 100000, "duration": 8})
        result = measured_batch({"family": 0, "count": 4000, "workers": 16, "pace": .02, "ca_file": str(certificate)})
        equal(result["errors"], 0, "verified TLS transport errors during packet flood")
        equal(result["families"], {"4": {"200": 2000}, "6": {"200": 2000}}, "verified TLS responses during packet flood")
        equal(result["server_tcp"]["ListenOverflows"], 0, "TLS flood accept queues must not overflow")
        equal(result["client_tcp"]["TCPSynRetrans"], 0, "TLS edge handshakes must not retransmit")
        if result["p99_ms"] >= 500 or result["origin_connections"] > 32 or result["flood_requests"] < 2000:
            raise AssertionError(f"TLS flood latency, connection reuse or overlap regression: {result}")
        print(f"PASS: verified TLS during varied packet flood {json.dumps(result)}", flush=True)
        equal(lab.ask({"kind": "flood_wait"}), {"sent": 100000}, "TLS flood generation")
        lab.expect("edge_bad_tcp", 33334)
        lab.expect("edge_udp_drop", 33333)
        lab.expect("edge_syn_source_drop", 20000)
        equal(sum(lab.count(name) for name in ("edge_syn_admitted", "edge_syn_source_drop", "edge_syn_network_drop", "edge_syn_global_drop")),
              33333, "TLS flood SYN accounting")
        for family in (4, 6):
            result = lab.ask({"kind": "http_batch", "family": family, "count": 25, "workers": 1,
                              "attack": True, "pace": .05, "ca_file": str(certificate)})
            equal(result["errors"], 0, "TLS attack transport errors")
            equal(result["statuses"], {"403": 25}, "SQL injection over verified TLS")
        print("PASS: verified TLS SQL injection 50/50 blocked in both IP families", flush=True)
        # Custom values that equal another field's template defaults must not cascade into that field's replacement.
        lab.load(peers=(PEER6,), overrides={"syn_meter_size": 4096, "syn_source_rate": 5000, "syn_source_burst": 10000,
                                          "syn_peer_rate": 20, "syn_peer_burst": 40, "echo_rate": 100, "echo_burst": 200})
        lab.send([frame(PEER4, ident=i + 1) for i in range(100)])
        equal(lab.count("edge_syn_admitted"), 100, "custom source budget must remain independent of peer defaults")
        lab.send([frame(PEER6, ident=i + 1) for i in range(100)])
        lab.expect("edge_syn_peer_drop", 50)
        print("PASS: custom overlapping numeric values retain independent source, peer and echo budgets", flush=True)
        intact = json.loads(run("nft", "--json", "list", "counter", "inet", "carnical_test_canary", "intact"))
        equal(next(item["counter"]["packets"] for item in intact["nftables"] if "counter" in item), 7,
              "policy replacements must preserve unrelated tables and state")
        print("PASS: unrelated nftables table and its counter survive every profile replacement", flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--inside", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--peer", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--egress", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--binary", type=pathlib.Path)
    parser.add_argument("--latency-investigation", action="store_true", help="compare origin queue, keep-alive and TCP flush controls")
    parser.add_argument("--no-egress-users", action="store_true",
                        help="leave out the checks that run as the service users (for a user namespace, where root cannot become them)")
    args = parser.parse_args()
    if args.peer or args.egress:
        if os.stat("/proc/self/ns/net").st_ino == os.stat("/proc/1/ns/net").st_ino:
            raise RuntimeError("refusing to run a test helper in the host network namespace")
    if args.egress:
        egress()
    elif args.peer:
        peer()
    elif not args.binary:
        parser.error("--binary is required")
    elif not args.inside:
        os.execvp("unshare", ["unshare", "--net", sys.executable, str(pathlib.Path(__file__).resolve()),
                              "--inside", "--binary", str(args.binary.resolve()),
                              *(["--latency-investigation"] if args.latency_investigation else []),
                              *(["--no-egress-users"] if args.no_egress_users else [])])
    else:
        test(args.binary.resolve(), investigate=args.latency_investigation, egress_users=not args.no_egress_users)


if __name__ == "__main__":
    main()
