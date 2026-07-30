"""
Unified authentication for ALL endpoints (except /api/health).

Flow:
1. Body must be JSON: {"secrate_data": "<base64-AES-256-GCM-envelope>"}
2. Decrypt envelope with AES key = bytes.fromhex(ADMIN_CURVE_KEY)
3. Decrypted plaintext is JSON:
   {
     "signatures": {"_r": "<hex>", "_s": "<hex>", "_z": "<hex>"},
     "message": {
       "api_pub_key": "<hex>",
       "allowed_ip": "1.2.3.4",
       ... other fields (to_email, subject, discription, payload, etc.)
     }
   }
4. Verify signature:
   - Reconstruct canonical bytes from message (sorted keys, no spaces)
   - Compute z = SHA-256(canonical) as int
   - Verify _z matches computed z (reject if not)
   - Verify ECDSA-Verify(api_pub_key, r, s, z) == True
5. Verify identity:
   - For /admin/* endpoints: api_pub_key must equal admin pub key (from .env)
   - For /api/send, /api/status: api_pub_key must exist in allowed_apps collection
6. Verify IP:
   - allowed_ip in message must match the client's real IP
     (Cf-Connecting-IP > X-Forwarded-For > request.client.host)
   - For /api/send, /api/status: must also match the IP stored in allowed_apps doc
   - For /admin/*: must match an entry in admin_settings.admin_allowed_ips

On any failure → 401 Unauthorized.
On success → returns the parsed message dict to the route handler.
"""
from __future__ import annotations

import time
from typing import Any, Optional

from fastapi import HTTPException, Request, status

from .config import settings
from .database import col_admin_settings, col_allowed_apps
from .logger import log_api
from .security import (
    canonical_message_bytes,
    client_pubkey_matches_admin,
    compute_z,
    decrypt_envelope,
    ecdsa_verify_r_s_z,
)


class AuthResult:
    """Result of successful authentication. Passed to route handlers."""
    def __init__(self, message: dict, api_pub_key: str, client_ip: str, is_admin: bool):
        self.message = message
        self.api_pub_key = api_pub_key
        self.client_ip = client_ip
        self.is_admin = is_admin

    def get(self, key: str, default: Any = None) -> Any:
        return self.message.get(key, default)


def _client_ip(request: Request) -> str:
    cf = request.headers.get("Cf-Connecting-IP")
    if cf:
        return cf.strip()
    xff = request.headers.get("X-Forwarded-For")
    if xff:
        return xff.split(",")[0].strip()
    if request.client:
        return request.client.host
    return "unknown"


def _fail(reason: str) -> HTTPException:
    return HTTPException(status.HTTP_401_UNAUTHORIZED, detail=reason)


async def authenticate(request: Request, raw_body: bytes, is_admin_endpoint: bool = False) -> AuthResult:
    """Validate request. Returns AuthResult on success, raises HTTPException(401) on failure."""
    start = time.perf_counter()
    client_ip = _client_ip(request)
    sig_valid: Optional[bool] = None
    ip_valid: Optional[bool] = None
    error: Optional[str] = None

    try:
        # ---- 1. Parse envelope ----
        import json
        try:
            envelope = json.loads(raw_body.decode("utf-8"))
        except Exception:
            error = "envelope-not-json"
            raise _fail("Malformed envelope")

        secrate_data = envelope.get("secrate_data") if isinstance(envelope, dict) else None
        if not secrate_data:
            error = "missing-secrate-data"
            raise _fail("Missing secrate_data")

        # ---- 2. Decrypt with admin curve key ----
        try:
            plaintext = decrypt_envelope(secrate_data, settings.ADMIN_AES_KEY)
        except Exception:
            error = "decrypt-failed"
            raise _fail("Decryption failed")

        try:
            payload = json.loads(plaintext.decode("utf-8"))
        except Exception:
            error = "payload-not-json"
            raise _fail("Malformed payload")
        del plaintext

        signatures = payload.get("signatures") or {}
        message = payload.get("message") or {}
        if not isinstance(signatures, dict) or not isinstance(message, dict):
            error = "bad-payload-shape"
            raise _fail("Bad payload shape")

        api_pub_key = (message.get("api_pub_key") or "").lower()
        allowed_ip = message.get("allowed_ip") or ""
        if not api_pub_key or not allowed_ip:
            error = "missing-pubkey-or-ip"
            raise _fail("Missing api_pub_key or allowed_ip")

        # ---- 3. Verify signature (Bitcoin-style r/s/z) ----
        try:
            r = int(signatures.get("_r", "0"), 16) if isinstance(signatures.get("_r"), str) else int(signatures.get("_r", 0))
            s = int(signatures.get("_s", "0"), 16) if isinstance(signatures.get("_s"), str) else int(signatures.get("_s", 0))
            z_provided = int(signatures.get("_z", "0"), 16) if isinstance(signatures.get("_z"), str) else int(signatures.get("_z", 0))
        except Exception:
            error = "signature-not-int"
            raise _fail("Bad signature values")

        # Recompute z from canonical message
        canonical = canonical_message_bytes(message)
        z_computed = compute_z(canonical)
        if z_computed != z_provided:
            sig_valid = False
            error = "z-mismatch"
            raise _fail("Signature z mismatch")

        # Verify ECDSA
        ok = ecdsa_verify_r_s_z(api_pub_key, r, s, z_provided)
        sig_valid = ok
        if not ok:
            error = "bad-signature"
            raise _fail("Invalid signature")

        # ---- 4. Verify identity (admin vs allowed_app) ----
        if is_admin_endpoint:
            if not client_pubkey_matches_admin(api_pub_key):
                error = "not-admin-pubkey"
                raise _fail("Not admin key")

            # IP must match admin allowed_ips list
            admin_settings_doc = await col_admin_settings().find_one({"setting_key": "admin_allowed_ips"})
            allowed_ips: list[str] = []
            if admin_settings_doc:
                allowed_ips = admin_settings_doc.get("setting_value", []) or []
            if allowed_ips and client_ip not in allowed_ips:
                ip_valid = False
                error = "admin-ip-not-allowed"
                raise _fail("Admin IP not allowed")
            if allowed_ip != client_ip:
                ip_valid = False
                error = "ip-mismatch"
                raise _fail("IP mismatch")
            ip_valid = True
        else:
            # /api/send, /api/status: api_pub_key must be a registered allowed_app
            app_doc = await col_allowed_apps().find_one({"api_pub_key": api_pub_key, "enabled": True})
            if not app_doc:
                error = "unknown-app"
                raise _fail("Unknown app")

            stored_ips = app_doc.get("allowed_ips") or []
            if stored_ips and client_ip not in stored_ips:
                ip_valid = False
                error = "ip-not-allowed"
                raise _fail("IP not allowed")
            if allowed_ip != client_ip:
                ip_valid = False
                error = "ip-mismatch"
                raise _fail("IP mismatch")
            ip_valid = True

        return AuthResult(
            message=message,
            api_pub_key=api_pub_key,
            client_ip=client_ip,
            is_admin=is_admin_endpoint,
        )

    finally:
        elapsed = (time.perf_counter() - start) * 1000.0
        status_code = 200 if (sig_valid and ip_valid) else 401
        await log_api(
            endpoint=request.url.path,
            method=request.method,
            ip=client_ip,
            status_code=status_code,
            processing_time_ms=elapsed,
            signature_valid=sig_valid,
            ip_valid=ip_valid,
            error_details=error,
        )


# ============================================================
# Response encryption (server → client)
# ============================================================

def encrypt_response(payload: dict) -> dict:
    """Encrypt a response payload with the admin AES key. Returns {"secrate_data": ...}."""
    import json
    from .security import encrypt_envelope
    plaintext = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    secrate_data = encrypt_envelope(plaintext, settings.ADMIN_AES_KEY)
    return {"secrate_data": secrate_data}
