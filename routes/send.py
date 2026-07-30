"""
POST /api/send - queue an email for sending.

Request body (encrypted):
    {"secrate_data": "<base64 AES-256-GCM envelope>"}

Decrypted payload:
    {
      "signatures": {"_r": "...", "_s": "...", "_z": "..."},
      "message": {
        "api_pub_key": "<hex>",
        "allowed_ip": "1.2.3.4",
        "to_email": "user@example.com",
        "subject": "Your verification code",
        "discription": "123456"   # body text / code
      }
    }

Response (encrypted):
    {"secrate_data": "<base64>"}  → decrypts to {"message_id": "...", "status": "queued"}
"""
from __future__ import annotations

import gc
import json
import uuid

from fastapi import APIRouter, Depends, HTTPException, Request, status

from smtp.auth import AuthResult, authenticate, encrypt_response
from smtp.logger import log_email, temp_complete, temp_create
from smtp.models import EncryptedRequest
from smtp.redis_client import QUEUE_KEY, get_redis

router = APIRouter()


@router.post("/api/send")
async def send(req: EncryptedRequest, request: Request):
    raw_body = (await request.body()) if False else req.model_dump_json().encode("utf-8")
    # We re-serialize to deterministic bytes for signature re-computation.
    # (Client signs the canonical JSON of the message field, not the envelope.)

    auth = await authenticate(request, raw_body, is_admin_endpoint=False)

    to_email = auth.message.get("to_email")
    subject = auth.message.get("subject")
    description = auth.message.get("discription") or auth.message.get("description") or ""

    if not to_email or not subject:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Missing to_email or subject")

    message_id = str(uuid.uuid4())
    operation_id = str(uuid.uuid4())

    job = {
        "message_id": message_id,
        "to": to_email,
        "subject": subject,
        "description": description,
        "api_pub_key": auth.api_pub_key,
    }

    await temp_create(operation_id, "send_email", {"queued_at": __import__("time").time()})

    try:
        redis = get_redis()
        await redis.lpush(QUEUE_KEY, json.dumps(job))
        await log_email(
            message_id=message_id,
            to=to_email,
            subject=subject,
            status="queued",
            api_pub_key=auth.api_pub_key,
        )
    except Exception:
        await temp_complete(operation_id, status="failed")
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "Queue unavailable")

    del job
    await temp_complete(operation_id, status="completed")
    gc.collect()

    return encrypt_response({"message_id": message_id, "status": "queued"})
