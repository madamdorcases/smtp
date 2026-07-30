"""
Cryptographic primitives.

Two layers of crypto are used on every request:

1. OUTER LAYER (transport):
   - Body: {"secrate_data": "<base64>"}
   - The base64 payload is AES-256-GCM encrypted.
   - AES key = bytes.fromhex(ADMIN_CURVE_KEY)  (32 raw bytes from .env)
   - IV (12 bytes) and tag (16 bytes) are prepended to the ciphertext inside the base64:
       base64( iv(12) || ciphertext || tag(16) )
   - This is the "secrate_data" envelope.

2. INNER LAYER (signature + identity):
   - The AES-decrypted plaintext is JSON:
       {
         "signatures": {"_r": "<hex>", "_s": "<hex>", "_z": "<hex>"},
         "message": {
           "api_pub_key": "<hex>",      # uncompressed secp256k1 pub key (04‖X‖Y)
           "allowed_ip": "1.2.3.4",     # client's IP, must match MongoDB
           "to_email": "...",            # for /api/send
           "subject": "...",             # for /api/send
           "discription": "...",         # for /api/send
           "payload": {...}              # any extra request data
         }
       }
   - The signature is Bitcoin-style ECDSA over secp256k1:
       z  = SHA-256(message_canonical_bytes)
       r,s = ECDSA(z, private_key)
   - We verify:  ECDSA-Verify(z, r, s, api_pub_key) == True
   - Then we look up api_pub_key in MongoDB (allowed_apps collection)
     and verify that the stored allowed_ip matches the request's allowed_ip
     AND the request's actual client IP (X-Forwarded-For / CF-Connecting-IP).

For /admin/* endpoints, the api_pub_key MUST equal the admin public key
derived from ADMIN_CURVE_KEY in .env, AND allowed_ip must match an entry
in the admin_settings.admin_allowed_ips list.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
from typing import Any, Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import (
    decode_dss_signature,
    encode_dss_signature,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .config import settings


# ============================================================
# Hashing
# ============================================================

def sha256_hex(data: str | bytes) -> str:
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def sha256_bytes(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def constant_time_eq(a: str, b: str) -> bool:
    return hmac.compare_digest(a.encode("utf-8"), b.encode("utf-8"))


# ============================================================
# ECDSA secp256k1 (Bitcoin-style r/s/z)
# ============================================================

def private_key_from_hex(hex_key: str) -> ec.EllipticCurvePrivateKey:
    value = int(hex_key, 16)
    return ec.derive_private_key(value, ec.SECP256K1())


def public_key_to_hex(pub: ec.EllipticCurvePublicKey) -> str:
    raw = pub.public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.UncompressedPoint,
    )
    return raw.hex()


def hex_to_public_key(hex_key: str) -> ec.EllipticCurvePublicKey:
    raw = bytes.fromhex(hex_key)
    return ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256K1(), raw)


def derive_public_hex(private_hex: str) -> str:
    return public_key_to_hex(private_key_from_hex(private_hex).public_key())


def generate_private_key_hex() -> str:
    priv = ec.generate_private_key(ec.SECP256K1())
    return priv.private_numbers().private_value.to_bytes(32, "big").hex()


def compute_z(message: bytes) -> int:
    """Bitcoin-style: z = SHA-256(message) as integer."""
    return int.from_bytes(sha256_bytes(message), "big")


def ecdsa_sign_r_s_z(private_hex: str, message: bytes) -> tuple[int, int, int]:
    """Sign message. Returns (r, s, z) as integers (Bitcoin-style)."""
    priv = private_key_from_hex(private_hex)
    z = compute_z(message)
    der_sig = priv.sign(message, ec.ECDSA(hashes.SHA256()))
    r, s = decode_dss_signature(der_sig)
    return r, s, z


def ecdsa_verify_r_s_z(public_hex: str, r: int, s: int, z: int) -> bool:
    """Verify a Bitcoin-style ECDSA signature.

    We re-encode r,s into DER and ask cryptography to verify against
    a reconstructed message whose SHA-256 has the same leading bits as z.
    For secp256k1 the order n is < 2^256, so we use z mod n directly.
    """
    try:
        if not (1 <= r < _SECP256K1_N and 1 <= s < _SECP256K1_N):
            return False
        der = encode_dss_signature(r, s)
        pub = hex_to_public_key(public_hex)

        # cryptography's verify recomputes z = SHA-256(message) internally.
        # To make it accept our externally-supplied z, we craft a "message"
        # whose SHA-256 equals z mod n. That's only feasible if we instead
        # use the raw verify path via _backend... but a simpler approach is
        # to require the caller to also pass the original message bytes,
        # which we do in ecdsa_verify_with_message below.
        #
        # For pure (r,s,z) verification (no message), we use a manual
        # ECDSA verify math against secp256k1 parameters.
        return _ecdsa_verify_raw(pub, r, s, z)
    except (InvalidSignature, ValueError, Exception):
        return False


def ecdsa_verify_with_message(public_hex: str, r: int, s: int, message: bytes) -> bool:
    """Verify (r, s) is a valid ECDSA signature over `message` for `public_hex`."""
    try:
        if not (1 <= r < _SECP256K1_N and 1 <= s < _SECP256K1_N):
            return False
        der = encode_dss_signature(r, s)
        pub = hex_to_public_key(public_hex)
        pub.verify(der, message, ec.ECDSA(hashes.SHA256()))
        return True
    except Exception:
        return False


# ============================================================
# secp256k1 curve parameters for manual verify
# ============================================================

# Curve order n for secp256k1
_SECP256K1_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
# Generator point
_SECP256K1_GX = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
_SECP256K1_GY = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
# Field prime p
_SECP256K1_P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F


def _inv_mod(a: int, m: int) -> int:
    return pow(a, -1, m)


def _point_add(P, Q):
    if P is None:
        return Q
    if Q is None:
        return P
    x1, y1 = P
    x2, y2 = Q
    if x1 == x2 and (y1 + y2) % _SECP256K1_P == 0:
        return None
    if P == Q:
        m = (3 * x1 * x1) * _inv_mod(2 * y1, _SECP256K1_P) % _SECP256K1_P
    else:
        m = (y2 - y1) * _inv_mod((x2 - x1) % _SECP256K1_P, _SECP256K1_P) % _SECP256K1_P
    x3 = (m * m - x1 - x2) % _SECP256K1_P
    y3 = (m * (x1 - x3) - y1) % _SECP256K1_P
    return (x3, y3)


def _scalar_mul(k: int, P):
    result = None
    addend = P
    while k:
        if k & 1:
            result = _point_add(result, addend)
        addend = _point_add(addend, addend)
        k >>= 1
    return result


def _ecdsa_verify_raw(pub: ec.EllipticCurvePublicKey, r: int, s: int, z: int) -> bool:
    """Manual ECDSA verify against secp256k1 parameters using public key point."""
    # Extract point from public key
    raw = pub.public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.UncompressedPoint,
    )
    if raw[0] != 0x04 or len(raw) != 65:
        return False
    x = int.from_bytes(raw[1:33], "big")
    y = int.from_bytes(raw[33:65], "big")
    Q = (x, y)

    if r < 1 or r >= _SECP256K1_N:
        return False
    if s < 1 or s >= _SECP256K1_N:
        return False
    z = z % _SECP256K1_N

    s_inv = _inv_mod(s, _SECP256K1_N)
    u1 = (z * s_inv) % _SECP256K1_N
    u2 = (r * s_inv) % _SECP256K1_N

    G = (_SECP256K1_GX, _SECP256K1_GY)
    point = _point_add(_scalar_mul(u1, G), _scalar_mul(u2, Q))
    if point is None:
        return False
    x_r, _ = point
    return (x_r % _SECP256K1_N) == r


# ============================================================
# AES-256-GCM envelope (secrate_data)
# ============================================================

def encrypt_envelope(plaintext: bytes, aes_key: bytes) -> str:
    """Encrypt with AES-256-GCM. Returns base64( iv(12) || ciphertext || tag(16) )."""
    if len(aes_key) != 32:
        raise ValueError("AES-256 key must be 32 bytes")
    iv = os.urandom(12)
    aesgcm = AESGCM(aes_key)
    ct_with_tag = aesgcm.encrypt(iv, plaintext, None)  # tag appended (16 bytes)
    combined = iv + ct_with_tag
    return base64.b64encode(combined).decode("ascii")


def decrypt_envelope(secrate_data_b64: str, aes_key: bytes) -> bytes:
    """Inverse of encrypt_envelope."""
    if len(aes_key) != 32:
        raise ValueError("AES-256 key must be 32 bytes")
    combined = base64.b64decode(secrate_data_b64)
    if len(combined) < 12 + 16:
        raise ValueError("ciphertext too short")
    iv = combined[:12]
    ct_with_tag = combined[12:]
    aesgcm = AESGCM(aes_key)
    return aesgcm.decrypt(iv, ct_with_tag, None)


# ============================================================
# Helpers
# ============================================================

def canonical_message_bytes(message: dict) -> bytes:
    """Deterministic JSON encoding so both client and server compute the same z."""
    return json.dumps(message, sort_keys=True, separators=(",", ":")).encode("utf-8")


def client_pubkey_matches_admin(api_pub_key: str) -> bool:
    return constant_time_eq(api_pub_key.lower(), settings.ADMIN_PUBLIC_KEY_HEX.lower())
