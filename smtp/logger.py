"""
MongoDB-only logger. Never writes to stdout, stderr, or files.
"""
from __future__ import annotations

import time
from datetime import datetime, timezone
from typing import Any, Optional

from .database import (
    col_api_logs,
    col_email_logs,
    col_events,
    col_smtp_logs,
    col_temp,
)


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _ts() -> float:
    return time.time()


# ---- Email logs (TTL 24h) ----

async def log_email(
    message_id: str,
    to: str,
    subject: str,
    status: str,
    api_pub_key: Optional[str] = None,
    error_message: Optional[str] = None,
) -> None:
    await col_email_logs().insert_one({
        "message_id": message_id,
        "to": to,
        "subject": subject,
        "status": status,
        "api_pub_key": api_pub_key,
        "error_message": error_message,
        "created_at": _now(),
    })


async def update_email_status(message_id: str, status: str, error: Optional[str] = None) -> None:
    await col_email_logs().update_one(
        {"message_id": message_id},
        {"$set": {"status": status, "error_message": error}},
    )


# ---- API logs (TTL 24h) ----

async def log_api(
    endpoint: str,
    method: str,
    ip: str,
    status_code: int,
    processing_time_ms: float,
    signature_valid: Optional[bool] = None,
    ip_valid: Optional[bool] = None,
    error_details: Optional[str] = None,
) -> None:
    await col_api_logs().insert_one({
        "endpoint": endpoint,
        "method": method,
        "ip": ip,
        "status_code": status_code,
        "processing_time_ms": processing_time_ms,
        "request_signature_valid": signature_valid,
        "request_ip_valid": ip_valid,
        "error_details": error_details,
        "created_at": _now(),
    })


# ---- SMTP logs (TTL 24h) ----

async def log_smtp(
    message_id: str,
    recipient_domain: str,
    delivery_time_ms: float,
    dkim_signed: bool = True,
    mx_server_used: Optional[str] = None,
    error_details: Optional[str] = None,
) -> None:
    await col_smtp_logs().insert_one({
        "message_id": message_id,
        "recipient_domain": recipient_domain,
        "dkim_signed": dkim_signed,
        "delivery_time_ms": delivery_time_ms,
        "mx_server_used": mx_server_used,
        "error_details": error_details,
        "created_at": _now(),
    })


# ---- Permanent audit events (no TTL) ----

async def log_event(event_type: str, actor: str, details: dict[str, Any]) -> None:
    await col_events().insert_one({
        "event_type": event_type,
        "actor": actor,
        "details": details,
        "ts": _ts(),
        "created_at": _now(),
    })


# ---- Temp storage (TTL 1h, deleted on completion) ----

async def temp_create(operation_id: str, operation_type: str, temp_data: dict) -> None:
    await col_temp().insert_one({
        "operation_id": operation_id,
        "operation_type": operation_type,
        "temp_data": temp_data,
        "status": "processing",
        "created_at": _now(),
    })


async def temp_complete(operation_id: str, status: str = "completed") -> None:
    await col_temp().delete_one({"operation_id": operation_id})


async def temp_get(operation_id: str) -> Optional[dict]:
    return await col_temp().find_one({"operation_id": operation_id}, {"_id": 0})
