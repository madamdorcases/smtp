"""
GET /api/status/{message_id} - check delivery status.

Same encrypted+signed envelope as /api/send. The message_id is a path param,
but the body still must be a valid encrypted+signed envelope (per spec —
"Every Request GET/POST/PUT/DELETE provides signatures, message(api_pub_key, allowed_ip)").
"""
from __future__ import annotations

import gc

from fastapi import APIRouter, HTTPException, Request

from smtp.auth import authenticate, encrypt_response
from smtp.database import col_email_logs
from smtp.models import EncryptedRequest

router = APIRouter()


@router.get("/api/status/{message_id}")
async def get_status(message_id: str, request: Request, req: EncryptedRequest):
    raw_body = req.model_dump_json().encode("utf-8")
    await authenticate(request, raw_body, is_admin_endpoint=False)

    doc = await col_email_logs().find_one({"message_id": message_id}, {"_id": 0})
    if not doc:
        gc.collect()
        return encrypt_response({"status": "expired", "error": None})

    out = {
        "status": doc.get("status", "unknown"),
        "error": doc.get("error_message"),
        "to": doc.get("to"),
        "subject": doc.get("subject"),
    }
    gc.collect()
    return encrypt_response(out)
