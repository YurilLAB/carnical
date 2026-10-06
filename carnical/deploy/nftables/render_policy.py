"""Render a bounded Carnical network policy to stdout. Never loads rules or changes the host."""

import argparse
import ipaddress
import pathlib
import re

DEFAULTS = dict(syn_global_rate=10000, syn_global_burst=20000, syn_source_rate=100, syn_source_burst=200,
                syn_peer_rate=5000, syn_peer_burst=10000, syn_meter_size=65536, syn_peer_meter_size=4096,
                syn_meter_ttl=60, echo_rate=20, echo_burst=40)
PROFILES = {
    "standard": DEFAULTS,
    "small": dict(DEFAULTS, syn_global_rate=1000, syn_global_burst=2000, syn_source_rate=50, syn_source_burst=100,
                  syn_peer_rate=500, syn_peer_burst=1000, syn_meter_size=8192, syn_peer_meter_size=1024, syn_meter_ttl=30),
    "large": dict(DEFAULTS, syn_global_rate=100000, syn_global_burst=200000, syn_source_rate=1000, syn_source_burst=2000,
                  syn_peer_rate=20000, syn_peer_burst=40000, syn_meter_size=262144, echo_rate=100, echo_burst=200),
}


def render(profile="standard", *, port=443, peers=(), overrides=None):
    if profile not in PROFILES:
        raise ValueError("unknown profile")
    settings = dict(PROFILES[profile])
    for key, value in (overrides or {}).items():
        if key not in settings or type(value) is not int or not 1 <= value <= 1048576:
            raise ValueError(f"invalid budget {key}: require an integer in 1..1048576")
        settings[key] = value
    if type(port) is not int or not 1 <= port <= 65535:
        raise ValueError("port must be in 1..65535")
    ranges = {4: [], 6: []}
    for peer in peers:
        if "%" in peer:
            raise ValueError("scoped addresses are not peer ranges")
        network = ipaddress.ip_network(peer, strict=True)
        if network.prefixlen == 0:
            raise ValueError("a peer range must not cover every source")
        ranges[network.version].append(str(network))
    text = pathlib.Path(__file__).with_name("carnical.nft").read_text(encoding="utf-8")
    # nft's rate/size grammar requires numeric literals, not symbolic variables. Keep one policy, fail on template drift.
    changes = [("define edge_port = 443", f"define edge_port = {port}", 1),
               ("timeout 60s", f"timeout {settings['syn_meter_ttl']}s", 4),
               ("size 65536", f"size {settings['syn_meter_size']}", 2),
               ("size 4096", f"size {settings['syn_peer_meter_size']}", 2)]
    for category, count in (("global", 1), ("source", 2), ("peer", 2)):
        key = f"syn_{category}"
        before = f"{DEFAULTS[key + '_rate']}/second burst {DEFAULTS[key + '_burst']} packets"
        after = f"{settings[key + '_rate']}/second burst {settings[key + '_burst']} packets"
        changes.append((before, after, count))
    changes.append(("20/second burst 40 packets", f"{settings['echo_rate']}/second burst {settings['echo_burst']} packets", 1))
    # Replace all matches against the original template, so custom values cannot accidentally become later matches.
    replacements = {}
    for before, after, count in changes:
        if text.count(before) != count:
            raise ValueError(f"policy template changed: expected {count} occurrences of {before!r}")
        replacements[before] = after
    text = re.sub("|".join(re.escape(item) for item in replacements), lambda match: replacements[match[0]], text)
    for family, entries in ranges.items():
        if entries:
            before = f"set edge_peers{family} {{ type ipv{family}_addr; flags interval; }}"
            after = before[:-2] + " elements = { " + ", ".join(entries) + " }; }"
            if text.count(before) != 1:
                raise ValueError("peer set template changed")
            text = text.replace(before, after)
    # Replace this table in the same nft transaction: no old peer ranges, meter rates, sizes or timeouts survive.
    before = "table inet carnical\nflush table inet carnical"
    if text.count(before) != 1:
        raise ValueError("table replacement template changed")
    text = text.replace(before, "destroy table inet carnical")
    header = f"# Rendered profile: {profile}; verify budgets against measured per-edge capacity.\n"
    first, rest = text.split("\n", 1)
    return first + "\n" + header + rest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", choices=PROFILES, default="standard")
    parser.add_argument("--port", type=int, default=443)
    parser.add_argument("--peer", action="append", default=[], help="verified CDN/load-balancer address or canonical CIDR")
    parser.add_argument("--set", action="append", default=[], metavar="BUDGET=INTEGER", help="override a named budget")
    args = parser.parse_args()
    try:
        overrides = {}
        for setting in args.set:
            key, value = setting.split("=", 1)
            if key in overrides:
                raise ValueError(f"duplicate budget {key}")
            overrides[key] = int(value)
        text = render(args.profile, port=args.port, peers=args.peer, overrides=overrides)
    except ValueError as error:
        parser.error(str(error))
    print(text, end="")


if __name__ == "__main__":
    main()
