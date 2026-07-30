"""
Admin endpoints. All require admin ECDSA signature (api_pub_key = admin pub key from .env).

Every endpoint receives {"secrate_data": "<base64>"} and responds with the same envelope.
The decrypted message contains api_pub_key, allowed_ip, and a "payload" object with the
actual operation parameters.

Endpoints:
    POST   /admin/login            (no signature required - email+password only, returns JWT)
    GET    /admin/allowed-apps
    POST   /admin/allowed-apps
    DELETE /admin/allowed-apps/{id}
    GET    /admin/api-keys
    POST   /admin/api-keys
    DELETE /admin/api-keys/{id}
    GET    /admin/logs?type=email|api|smtp&hours=24
    GET    /admin/stats
    GET    /admin/settings
    PUT    /admin/settings
    GET    /admin/dkim
"""
from __future__ import annotations

import gc
import time
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status

from smtp.auth import authenticate, encrypt_response
from smtp.database import (
    col_admin_settings,
    col_allowed_apps,
    col_api_keys,
    col_api_logs,
    col_dkim,
    col_email_logs,
    col_smtp_logs,
)
from smtp.dkim_signer import dns_record_for, ensure_dkim_keypair
from smtp.logger import log_event
from smtp.models import EncryptedRequest
from smtp.security import (
    derive_public_hex,
    generate_private_key_hex,
    sha256_hex,
)

router = APIRouter(prefix="/admin", tags=["admin"])

LOG_TTL_HOURS_MAX = 168  # 7 days


# ============================================================
# Helpers
# ============================================================

def _serializable(d: dict) -> dict:
    out = {}
    for k, v in d.items():
        if isinstance(v, datetime):
            out[k] = v.isoformat()
        elif k == "_id":
            out["id"] = str(v)
        else:
            out[k] = v
    return out


def _msg_payload(auth_message: dict) -> dict:
    return auth_message.get("payload") or {}


# ============================================================
# Allowed apps (registered external apps that can call /api/send)
# ============================================================

@router.get("/allowed-apps")
async def list_allowed_apps(request: Request, req: EncryptedRequest):
    auth = await authenticate(request, req.model_dump_json().encode("utf-8"), is_admin_endpoint=True)
    out = []
    async for d in col_allowed_apps().find({}, {"_id": 1, "app_name": 1, "api_pub_key": 1, "allowed_ips": 1, "enabled": 1, "created_at": 1}):
        out.append(_serializable(d))
    gc.collect()
    return encrypt_response({"apps": out})


@router.post("/allowed-apps")
async def create_allowed_app(request: Request, req: EncryptedRequest):
    auth = await authenticate(request, req.model_dump_json().encode("utf-8"), is_admin_endpoint=True)
    payload = _msg_payload(auth.message)
    app_name = payload.get("app_name")
    api_pub_key = (payload.get("api_pub_key") or "").lower()
    allowed_ips = payload.get("allowed_ips") or []
    enabled = payload.get("enabled", True)

    if not app_name or not api_pub_key:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Missing app_name or api_pub_key")

    if await col_allowed_apps().find_one({"$or": [{"app_name": app_name}, {"api_pub_key": api_pub_key}]}):
        raise HTTPException(status.HTTP_409_CONFLICT, "App already exists")

    doc = {
        "app_name": app_name,
        "api_pub_key": api_pub_key,
        "allowed_ips": allowed_ips,
        "enabled": enabled,
        "created_at": datetime.now(timezone.utc),
    }
    res = await col_allowed_apps().insert_one(doc)
    await log_event("allowed_app_created", auth.api_pub_key[:16], {"app_name": app_name})
    return encrypt_response({"id": str(res.inserted_id), "app_name": app_name, "api_pub_key": api_pub_key, "allowed_ips": allowed_ips, "enabled": enabled})


@router.delete("/allowed-apps/{app_id}")
async def delete_allowed_app(app_id: str, request: Request, req: EncryptedRequest):
    auth = await authenticate(request, req.model_dump_json().encode("utf-8"), is_admin_endpoint=True)
    from bson import ObjectId
    try:
        oid = ObjectId(app_id)
    except Exception:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Invalid id")
    res = await col_allowed_apps().delete_one({"_id": oid})
    if res.deleted_count == 0:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Not found")
    await log_event("allowed_app_deleted", auth.api_pub_key[:16], {"app_id": app_id})
    return encrypt_response({"deleted": True})


# ============================================================
# API keys (for admin's own programmatic use - separate from allowed_apps)
# ============================================================

@router.get("/api-keys")
async def list_api_keys(request: Request, req: EncryptedRequest):
    auth = await authenticate(request, req.model_dump_json().encode("utf-8"), is_admin_endpoint=True)
    out = []
    async for d in col_api_keys().find({}, {"_id": 1, "key_name": 1, "curve_public_key": 1, "allowed_ips": 1, "enabled": 1, "created_at": 1}):
        out.append(_serializable(d))
    return encrypt_response({"keys": out})


@router.post("/api-keys")
async def create_api_key(request: Request, req: EncryptedRequest):
    auth = await authenticate(request, req.model_dump_json().encode("utf-8"), is_admin_endpoint=True)
    payload = _msg_payload(auth.message)
    key_name = payload.get("key_name")
    allowed_ips = payload.get("allowed_ips") or []

    if not key_name:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Missing key_name")
    if await col_api_keys().find_one({"key_name": key_name}):
        raise HTTPException(status.HTTP_409_CONFLICT, "Key name exists")

    private_hex = generate_private_key_hex()
    public_hex = derive_public_hex(private_hex)

    doc = {
        "key_name": key_name,
        "curve_public_key": public_hex,
        "allowed_ips": allowed_ips,
        "enabled": True,
        "created_at": datetime.now(timezone.utc),
    }
    res = await col_api_keys().insert_one(doc)
    await log_event("api_key_created", auth.api_pub_key[:16], {"key_name": key_name})

    # private_hex is shown ONCE in the encrypted response
    return encrypt_response({
        "id": str(res.inserted_id),
        "key_name": key_name,
        "curve_public_key": public_hex,
        "allowed_ips": allowed_ips,
        "enabled": True,
        "private_key": private_hex,  # CLIENT MUST STORE - shown once
    })


@router.delete("/api-keys/{key_id}")
async def delete_api_key(key_id: str, request: Request, req: EncryptedRequest):
    auth = await authenticate(request, req.model_dump_json().encode("utf-8"), is_admin_endpoint=True)
    from bson import ObjectId
    try:
        oid = ObjectId(key_id)
    except Exception:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Invalid id")
    res = await col_api_keys().delete_one({"_id": oid})
    if res.deleted_count == 0:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Not found")
    await log_event("api_key_deleted", auth.api_pub_key[:16], {"key_id": key_id})
    return encrypt_response({"deleted": True})


# ============================================================
# Logs (TTL 24h, capped at 500 rows)
# ============================================================

@router.get("/logs")
async def get_logs(request: Request, req: EncryptedRequest, type: str = Query("email"), hours: int = Query(24, ge=1, le=LOG_TTL_HOURS_MAX)):
    auth = await authenticate(request, req.model_dump_json().encode("utf-8"), is_admin_endpoint=True)
    cutoff = datetime.now(timezone.utc) - timedelta(hours=hours)
    col = {"email": col_email_logs, "api": col_api_logs, "smtp": col_smtp_logs}[type]()
    out = []
    async for d in col.find({"created_at": {"$gte": cutoff}}, {"_id": 0}).sort("created_at", -1).limit(500):
        out.append(_serializable(d))
    return encrypt_response({"logs": out, "type": type, "count": len(out)})


# ============================================================
# Stats
# ============================================================

@router.get("/stats")
async def stats(request: Request, req: EncryptedRequest):
    auth = await authenticate(request, req.model_dump_json().encode("utf-8"), is_admin_endpoint=True)
    cutoff = datetime.now(timezone.utc) - timedelta(hours=24)
    sent = await col_email_logs().count_documents({"status": "sent", "created_at": {"$gte": cutoff}})
    failed = await col_email_logs().count_documents({"status": "failed", "created_at": {"$gte": cutoff}})
    queued = await col_email_logs().count_documents({"status": "queued", "created_at": {"$gte": cutoff}})
    api_req = await col_api_logs().count_documents({"created_at": {"$gte": cutoff}})
    return encrypt_response({
        "sent_24h": sent,
        "failed_24h": failed,
        "queued_now": queued,
        "api_requests_24h": api_req,
    })


# ============================================================
# Settings (permanent)
# ============================================================

@router.get("/settings")
async def get_settings_route(request: Request, req: EncryptedRequest):
    auth = await authenticate(request, req.model_dump_json().encode("utf-8"), is_admin_endpoint=True)
    out: dict = {
        "admin_allowed_ips": [],
        "rate_limit_per_minute": 60,
        "blocked_domains": [],
    }
    async for d in col_admin_settings().find({}, {"_id": 0, "setting_key": 1, "setting_value": 1}):
        out[d["setting_key"]] = d["setting_value"]
    return encrypt_response(out)


@router.put("/settings")
async def update_settings(request: Request, req: EncryptedRequest):
    auth = await authenticate(request, req.model_dump_json().encode("utf-8"), is_admin_endpoint=True)
    payload = _msg_payload(auth.message)
    updates = payload.get("settings") or {}
    if not isinstance(updates, dict):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "settings must be object")
    for k, v in updates.items():
        await col_admin_settings().update_one(
            {"setting_key": k},
            {"$set": {"setting_key": k, "setting_value": v}},
            upsert=True,
        )
    await log_event("settings_updated", auth.api_pub_key[:16], updates)
    return encrypt_response({"updated": list(updates.keys())})


# ============================================================
# DKIM info
# ============================================================

@router.get("/dkim")
async def dkim_info(request: Request, req: EncryptedRequest):
    auth = await authenticate(request, req.model_dump_json().encode("utf-8"), is_admin_endpoint=True)
    doc = await ensure_dkim_keypair("smtp1")
    return encrypt_response({
        "selector": doc["selector"],
        "domain": doc["domain"],
        "dns_name": f"{doc['selector']}._domainkey.{doc['domain']}",
        "dns_value": await dns_record_for("smtp1"),
    })
