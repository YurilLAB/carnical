"""Exercise the deployed L3/L4 rules with live packets in disposable Linux network namespaces."""

import argparse
import contextlib
import http.client
import http.server
import ipaddress
import json
import os
import pathlib
import socket
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


def frame(src, proto=6, flags=2, ident=1, hop=64, payload=None, port=443):
    source = ipaddress.ip_address(src)
    dst = ipaddress.ip_address(V4 if source.version == 4 else V6)
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
        ethernet = SERVER_MAC + CLIENT_MAC + b"\x08\x00"
    else:
        pseudo += struct.pack("!I3xB", len(payload), proto)
        header = struct.pack("!IHBB16s16s", 6 << 28, len(payload), proto, hop, source.packed, dst.packed)
        ethernet = SERVER_MAC + CLIENT_MAC + b"\x86\xdd"
    offset = {6: 16, 17: 6, 58: 2}[proto]
    payload = payload[:offset] + struct.pack("!H", checksum(pseudo + payload) or 65535) + payload[offset + 2:]
    return (ethernet + header + payload).hex()


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
            elif task["kind"] == "serve_origin":
                server = http.server.ThreadingHTTPServer(("0.0.0.0", 80), Origin)
                threading.Thread(target=server.serve_forever, daemon=True).start()
                result = {"started": True}
            else:
                # Live HTTP traverses the veth, kernel policy and running Carnical binary.
                address = V4 if task["family"] == 4 else V6
                conn = http.client.HTTPConnection(address, 443, timeout=5)
                try:
                    conn.request("GET", task["path"], headers={"Host": "example.test", "Connection": "close"})
                    response = conn.getresponse()
                    result = {"status": response.status, "body": response.read().decode("utf-8", "replace")}
                finally:
                    conn.close()
            print(json.dumps(result), flush=True)


class Lab:
    def __init__(self):
        self.loaded = False
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

    def load(self, *, small_set=False, low_global=False):
        text = POLICY.read_text(encoding="utf-8")
        # No host accounts are created. Numeric fixture UIDs affect only the isolated namespace's egress policy.
        for index, name in enumerate(["edge", "portal", "ctl", "signer", "audit"], 61001):
            text = text.replace('"carnical-' + name + '"', str(index))
        if small_set:
            text = text.replace("size 65536", "size 4").replace("timeout 60s", "timeout 1s")
        if low_global:
            text = text.replace("10000/second burst 20000", "10/second burst 20")
        # flush table intentionally retains named objects on a production reload. Each test needs fresh counters/meters.
        if self.loaded:
            run("nft", "delete", "table", "inet", "carnical")
        run("nft", "--check", "--file", "-", input=text)
        run("nft", "--file", "-", input=text)
        self.loaded = True

    def count(self, name):
        data = json.loads(run("nft", "--json", "list", "counter", "inet", "carnical", name))
        return next(item["counter"]["packets"] for item in data["nftables"] if "counter" in item)

    def expect(self, name, minimum):
        deadline = time.monotonic() + 2
        while time.monotonic() < deadline:
            actual = self.count(name)
            if actual >= minimum:
                return actual
            time.sleep(0.02)
        raise AssertionError(f"{name}: got {actual}, expected at least {minimum}")


class Origin(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"origin-ok")

    def log_message(self, *args):
        pass


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


def test(binary):
    if os.geteuid() != 0:
        raise RuntimeError("network namespace test requires root")
    if os.stat("/proc/self/ns/net").st_ino == os.stat("/proc/1/ns/net").st_ino:
        raise RuntimeError("refusing to change the host network namespace")
    with contextlib.ExitStack() as stack:
        lab = Lab()
        stack.callback(lab.close)
        lab.setup()
        origin = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Origin)
        stack.callback(origin.server_close)
        threading.Thread(target=origin.serve_forever, daemon=True).start()
        stack.callback(origin.shutdown)
        log = stack.enter_context(tempfile.TemporaryFile(mode="w+"))
        waf = subprocess.Popen([str(binary), "-listen", "[::]:443", "-upstream", f"http://127.0.0.1:{origin.server_port}",
                                "-origin-allow", "127.0.0.0/8", "-mode", "block", "-ddos", "off"], stdout=log, stderr=log)
        def stop_waf():
            waf.terminate()
            try:
                waf.wait(timeout=5)
            except subprocess.TimeoutExpired:
                waf.kill()
                waf.wait(timeout=5)
        stack.callback(stop_waf)
        deadline = time.monotonic() + 15
        while True:
            if waf.poll() is not None:
                log.seek(0)
                raise RuntimeError("WAF failed to start: " + log.read())
            try:
                with socket.create_connection(("127.0.0.1", 443), timeout=0.1):
                    break
            except OSError:
                if time.monotonic() > deadline:
                    raise RuntimeError("WAF did not listen")
                time.sleep(0.05)

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
            lab.load(small_set=True)
            sources = [f"203.0.113.{i + 1}" if family == 4 else f"fd00:{i + 256:x}::1" for i in range(5)]
            lab.send([frame(src, ident=i) for i, src in enumerate(sources)])
            lab.expect("edge_syn_admitted", 4)
            lab.expect("edge_syn_source_drop", 1)
            equal(lab.count("edge_syn_admitted"), 4, "full meter set must refuse an untracked source")
            lab.send([frame(sources[0], ident=7)])
            lab.expect("edge_syn_admitted", 5)
            time.sleep(1.2)
            # Kernel garbage collection and RCU reclamation can lag the element timeout. Retry until capacity returns.
            deadline = time.monotonic() + 5
            while lab.count("edge_syn_admitted") < 6 and time.monotonic() < deadline:
                lab.send([frame(sources[4], ident=8)])
                time.sleep(0.1)
            lab.expect("edge_syn_admitted", 6)
        print("PASS: full IPv4/IPv6 meter sets fail closed; existing keys work and expired entries release capacity", flush=True)

        lab.load()
        echo = struct.pack("!BBHHH", 128, 0, 0, 1, 1)
        lab.send([frame(PEER6, proto=58, payload=echo, ident=i) for i in range(256)])
        lab.expect("edge_echo_admitted", 40)
        lab.expect("edge_echo_drop", 100)
        # Unexpected UDP ports exercise the separate bounded log path, without one message per early refusal.
        lab.send([frame(PEER6, proto=17, port=4444, ident=i) for i in range(128)])
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
        for uid, host, port, connected, counter in [
            (61001, "198.51.100.2", 80, 16, None),
            (61001, "127.0.0.1", origin.server_port, 0, "egress_private_drop"),
            (61001, "169.254.169.254", 80, 0, "egress_imds_drop"),
            (61001, "198.51.100.2", 25, 0, "egress_edge_drop"),
            (61002, "198.51.100.2", 80, 0, "egress_internal_drop"),
        ]:
            task = {"uid": uid, "host": host, "port": port, "attempts": 16, "timeout": 2 if connected else 0.05}
            result = json.loads(run(sys.executable, str(pathlib.Path(__file__).resolve()), "--egress", input=json.dumps(task)))
            equal(result["connected"], connected, "service UID egress policy")
            if counter:
                lab.expect(counter, 16)
        # Six refusals beyond each logging burst must still be refused; successful public-port connections are the control.
        print("PASS: service-UID egress still refuses private/metadata/SMTP/internal traffic after log-budget exhaustion", flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--inside", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--peer", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--egress", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--binary", type=pathlib.Path)
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
                              "--inside", "--binary", str(args.binary.resolve())])
    else:
        test(args.binary.resolve())


if __name__ == "__main__":
    main()
