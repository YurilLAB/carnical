"""Checks the control API's signing test vector with a second Ed25519 implementation (pyca/cryptography)."""
import base64
import hashlib
import sys

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

body = b'{"mode":"block","threshold":5}'
fields = ["carnical-control-v1", "PUT", "control.example:8443", "/v1/tenants/" + "a" * 32 + "/policy",
          hashlib.sha256(body).hexdigest(), "1791201600", "000102030405060708090a0b0c0d0e0f", "ui-prod", "a" * 32,
          "user-42", "1791201500", '"7"', "-"]
canonical = "\n".join(fields).encode()
key = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
pub = key.public_key().public_bytes_raw()
sig = key.sign(canonical)
print("canonical", canonical)
print("public key", base64.urlsafe_b64encode(pub).rstrip(b"=").decode())
print("signature hex", sig.hex())
print("signature b64", base64.urlsafe_b64encode(sig).rstrip(b"=").decode())
want = sys.argv[1] if len(sys.argv) > 1 else ""
if want:
    print("MATCH" if sig.hex() == want else "MISMATCH")
