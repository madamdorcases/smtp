"""
Background queue worker.

Polls Redis BLPOP for outbound email jobs, sends via SMTP relay,
logs to MongoDB, deletes the job, runs gc.collect().
"""
from __future__ import annotations

import asyncio
import gc
import json
import logging
from typing import Optional

from .database import col_email_logs
from .email_sender import send_email
from .logger import log_email, update_email_status
from .redis_client import QUEUE_KEY, get_redis

log = logging.getLogger("worker")


async def _process_one(raw: str) -> None:
    try:
        job = json.loads(raw)
        message_id = job["message_id"]
        to_addr = job["to"]
        subject = job["subject"]
        description = job.get("description", "")
        api_pub_key = job.get("api_pub_key")

        await log_email(
            message_id=message_id,
            to=to_addr,
            subject=subject,
            status="queued",
            api_pub_key=api_pub_key,
        )

        await update_email_status(message_id, "sending", None)
        result = await send_email(
            to_addr=to_addr,
            subject=subject,
            body_text=description,
        )

        # The send_email generates its own message_id; we link them
        await col_email_logs().update_one(
            {"message_id": message_id},
            {"$set": {
                "status": result["status"],
                "error_message": result["error"],
                "smtp_message_id": result["message_id"],
            }},
        )
    except Exception as exc:  # noqa: BLE001
        log.debug("worker error: %s", exc, exc_info=False)
    finally:
        del raw
        gc.collect()


async def run_worker(stop_event: asyncio.Event) -> None:
    redis = get_redis()
    try:
        while not stop_event.is_set():
            try:
                result = await redis.blpop(QUEUE_KEY, timeout=5.0)
                if result is None:
                    continue
                _key, raw = result
                await _process_one(raw)
                del result, raw
            except asyncio.CancelledError:
                break
            except Exception:  # noqa: BLE001
                await asyncio.sleep(1.0)
    finally:
        try:
            await redis.aclose()
        except Exception:
            pass
