"""Independent test vectors for package config (workstation tooling, not shipped).

This builds the signed bytes of an envelope and of a key list from the layout written in docs/config-and-policy.md, using
Python's struct and the cryptography package, and prints them. vectors_test.go holds the same values as constants and checks
that the Go code produces them byte for byte. Run: python vectors.py
Fixed seeds, so the output never changes (Ed25519 signatures are deterministic).
"""
import base64
import hashlib
import json
import struct
from datetime import datetime, timezone

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

SEED_CONFIG = bytes(range(0x01, 0x21))
SEED_ROOT = bytes(range(0x41, 0x61))


def pub(seed):
    return Ed25519PrivateKey.from_private_bytes(seed).public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


def key_id(p):
    return hashlib.sha256(p).hexdigest()[:16]


def b64u(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def lp(b):
    return struct.pack(">I", len(b)) + b


def secs(text):
    return int(datetime.strptime(text, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc).timestamp())


tenant = "00112233445566778899aabbccddeeff"
audience = "edge-eu-1"
seq = 7
not_before = "2026-10-05T00:00:00Z"
not_after = "2026-10-12T00:00:00Z"
payload = b'{"schema":1,"mode":"block"}'

cfg_key = Ed25519PrivateKey.from_private_bytes(SEED_CONFIG)
kid = key_id(pub(SEED_CONFIG))

signed = (b"carnical-config-v1" + lp(struct.pack(">H", 1)) + lp(tenant.encode()) + lp(audience.encode())
          + lp(struct.pack(">Q", seq)) + lp(struct.pack(">q", secs(not_before))) + lp(struct.pack(">q", secs(not_after)))
          + lp(kid.encode()) + lp(payload))
sig = cfg_key.sign(signed)
wire = {"v": 1, "tenant": tenant, "audience": audience, "seq": seq, "not_before": not_before, "not_after": not_after,
        "key_id": kid, "payload": b64u(payload), "sig": b64u(sig)}

print("config public key  :", pub(SEED_CONFIG).hex())
print("config key id      :", kid)
print("signed bytes (hex) :", signed.hex())
print("signature (hex)    :", sig.hex())
print("wire JSON          :", json.dumps(wire, separators=(",", ":")))

root_key = Ed25519PrivateKey.from_private_bytes(SEED_ROOT)
root_id = key_id(pub(SEED_ROOT))
keys_payload = json.dumps({
    "schema": 1, "seq": 3, "issued": "2026-10-01T00:00:00Z", "expires": "2027-10-01T00:00:00Z",
    "keys": [{"id": kid, "alg": "ed25519", "pub": b64u(pub(SEED_CONFIG)), "roles": ["config"],
              "not_before": "2026-10-01T00:00:00Z", "not_after": "2027-04-01T00:00:00Z"}],
    "revoked": ["0123456789abcdef"]}, separators=(",", ":")).encode()
keys_signed = b"carnical-keys-v1" + lp(struct.pack(">H", 1)) + lp(root_id.encode()) + lp(keys_payload)
keys_sig = root_key.sign(keys_signed)
keys_wire = {"v": 1, "key_id": root_id, "payload": b64u(keys_payload), "sig": b64u(keys_sig)}
print("root public key    :", pub(SEED_ROOT).hex())
print("root key id        :", root_id)
print("key list payload   :", keys_payload.decode())
print("key list signed hex:", keys_signed.hex())
print("key list signature :", keys_sig.hex())
print("key list wire JSON :", json.dumps(keys_wire, separators=(",", ":")))
