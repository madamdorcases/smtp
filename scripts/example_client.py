#!/usr/bin/env python3
"""
Reference client for the SMTP Verification Service.

Demonstrates the full request flow:
1. Build message dict (api_pub_key, allowed_ip, to_email/subject/discription, etc.)
2. Compute z = SHA-256(canonical_json(message))
3. Sign z with ECDSA secp256k1 → r, s
4. Build envelope: {"signatures": {"_r": hex(r), "_s": hex(s), "_z": hex(z)},
                    "message": message}
5. Encrypt envelope JSON with AES-256-GCM (key = bytes.fromhex(ADMIN_CURVE_KEY))
6. POST {"secrate_data": "<base64>"} to endpoint

Responses are encrypted with the same AES key — this client decrypts them.

Usage:
    # Admin: list allowed apps
    python scripts/example_client.py \\
        --url http://YOUR-VPS-IP:15484/admin/allowed-apps \\
        --method GET \\
        --privkey 8510e43ccf7b33e4f39ff5147a4e985b9c806430a003277e671527e9898f990d \\
        --admin \\
        --client-ip YOUR.REAL.IP

    # Send email (requires an allowed_app registration first)
    python scripts/example_client.py \\
        --url http://YOUR-VPS-IP:15484/api/send \\
        --method POST \\
        --privkey <app_ecdsa_private_key_hex> \\
        --client-ip YOUR.REAL.IP \\
        --message '{"to_email":"user@gmail.com","subject":"Your code","discription":"123456"}'
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import sys
import urllib.error
import urllib.request

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import serialization


# ============================================================
# Crypto helpers (mirror of smtp/security.py)
# ============================================================

def derive_pub_hex(priv_hex: str) -> str:
    value = int(priv_hex, 16)
    priv = ec.derive_private_key(value, ec.SECP256K1())
    raw = priv.public_key().public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.UncompressedPoint,
    )
    return raw.hex()


def canonical_message_bytes(message: dict) -> bytes:
    return json.dumps(message, sort_keys=True, separators=(",", ":")).encode("utf-8")


def sign_message(priv_hex: str, message: bytes) -> tuple[int, int, int]:
    value = int(priv_hex, 16)
    priv = ec.derive_private_key(value, ec.SECP256K1())
    z = int.from_bytes(hashlib.sha256(message).digest(), "big")
    der = priv.sign(message, ec.ECDSA(hashes.SHA256()))
    r, s = decode_dss_signature(der)
    return r, s, z


def encrypt_envelope(plaintext: bytes, aes_key: bytes) -> str:
    iv = os.urandom(12)
    aesgcm = AESGCM(aes_key)
    ct_with_tag = aesgcm.encrypt(iv, plaintext, None)
    return base64.b64encode(iv + ct_with_tag).decode("ascii")


def decrypt_envelope(secrate_data_b64: str, aes_key: bytes) -> bytes:
    combined = base64.b64decode(secrate_data_b64)
    iv, ct_with_tag = combined[:12], combined[12:]
    aesgcm = AESGCM(aes_key)
    return aesgcm.decrypt(iv, ct_with_tag, None)


# ============================================================
# Main
# ============================================================

def build_request(priv_hex: str, client_ip: str, message_extra: dict | None, admin: bool) -> bytes:
    pub_hex = derive_pub_hex(priv_hex)
    message = {
        "api_pub_key": pub_hex,
        "allowed_ip": client_ip,
    }
    if message_extra:
        # Merge user-supplied fields (to_email, subject, discription, payload, etc.)
        for k, v in message_extra.items():
            message[k] = v

    canonical = canonical_message_bytes(message)
    r, s, z = sign_message(priv_hex, canonical)

    envelope = {
        "signatures": {
            "_r": format(r, "x"),
            "_s": format(s, "x"),
            "_z": format(z, "x"),
        },
        "message": message,
    }
    return json.dumps(envelope, separators=(",", ":")).encode("utf-8")


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--url", required=True)
    p.add_argument("--method", default="POST", choices=["GET", "POST", "PUT", "DELETE"])
    p.add_argument("--privkey", required=True, help="ECDSA secp256k1 private key hex")
    p.add_argument("--admin-curvehex", default=None,
                   help="ADMIN_CURVE_KEY hex (for AES encryption). Defaults to --privkey for admin calls.")
    p.add_argument("--client-ip", required=True, help="Your real public IP (must match allowed_ip)")
    p.add_argument("--admin", action="store_true", help="Call is to /admin/* endpoint")
    p.add_argument("--message", default=None,
                   help="JSON string with extra message fields (to_email, subject, discription, payload, ...)")
    args = p.parse_args()

    # AES key: for /admin/*, use ADMIN_CURVE_KEY; for /api/send, also use ADMIN_CURVE_KEY
    # (because the SERVER always decrypts with ADMIN_CURVE_KEY from .env).
    aes_hex = args.admin_curvehex or args.privkey
    if len(aes_hex) != 64:
        print(f"ERROR: AES key hex must be 64 chars (32 bytes). Got {len(aes_hex)}", file=sys.stderr)
        return 2
    aes_key = bytes.fromhex(aes_hex)

    extra = None
    if args.message:
        try:
            extra = json.loads(args.message)
        except json.JSONDecodeError as e:
            print(f"ERROR: --message is not valid JSON: {e}", file=sys.stderr)
            return 2

    envelope_bytes = build_request(args.privkey, args.client_ip, extra, args.admin)
    secrate_data = encrypt_envelope(envelope_bytes, aes_key)
    body = json.dumps({"secrate_data": secrate_data}).encode("utf-8")

    req = urllib.request.Request(
        args.url,
        data=body if args.method != "GET" else None,
        method=args.method,
        headers={"Content-Type": "application/json"},
    )

    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            status_code = resp.status
            resp_body = resp.read()
    except urllib.error.HTTPError as e:
        status_code = e.code
        resp_body = e.read()
    except urllib.error.URLError as e:
        print(f"ERROR: network failure: {e}", file=sys.stderr)
        return 1

    print(f"HTTP {status_code}")
    print(f"Raw: {resp_body!r}")

    # Try to decrypt the response
    try:
        resp_json = json.loads(resp_body.decode("utf-8"))
        secrate = resp_json.get("secrate_data")
        if secrate:
            decrypted = decrypt_envelope(secrate, aes_key)
            print(f"Decrypted: {decrypted.decode('utf-8')}")
    except Exception as e:
        # Response wasn't an encrypted envelope (e.g. error detail)
        pass

    return 0 if status_code == 200 else 1


if __name__ == "__main__":
    sys.exit(main())
