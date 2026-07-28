"""
Redis-backed outbound queue.

Messages waiting to be delivered are stored as JSON in a Redis list:
    smtp:queue:pending    → LIST of JSON envelopes

Each envelope looks like:
    {
      "id": "<uuid>",
      "sender": "user@api-solv-rix-ai.top",
      "recipients": ["dest@example.com"],
      "raw_message_b64": "<base64-encoded RFC 5322 message bytes>",
      "username": "alice",     # SMTP user who submitted
      "client_ip": "1.2.3.4",
      "queued_at": "2026-07-28T15:25:21.983663+00:00",
      "attempts": 0,
    }

A background worker (see ``core.queue.run_worker``) pops envelopes and
hands them to ``core.outbound.deliver_message``. Failed deliveries are
re-queued with an incremented ``attempts`` counter, up to
``OUTBOUND_MAX_RETRIES``.

When TTL_SECONDS elapses since ``queued_at``, the envelope is dropped
(self-destruct) — no message data is retained on disk.
"""
from __future__ import annotations

import asyncio
import base64
import json
import logging
import uuid
from datetime import datetime, timezone
from typing import Optional

from config import settings
from core.redis_client import get_redis
from core import outbound, dkim_signer

log = logging.getLogger("queue")

_KEY_PENDING = "smtp:queue:pending"
_KEY_PROCESSING = "smtp:queue:processing"   # in-flight envelopes
_KEY_FAILED = "smtp:queue:failed"           # permanently failed envelopes (TTL'd)


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


async def enqueue(
    *,
    sender: str,
    recipients: list[str],
    raw_message: bytes,
    username: str,
    client_ip: str,
) -> str:
    """Sign the message with DKIM and add it to the pending queue.

    Returns the envelope ID.
    """
    # DKIM-sign before queueing — signature stays valid through retries
    signed = dkim_signer.sign_message(raw_message)

    envelope = {
        "id": str(uuid.uuid4()),
        "sender": sender,
        "recipients": recipients,
        "raw_message_b64": base64.b64encode(signed).decode("ascii"),
        "username": username,
        "client_ip": client_ip,
        "queued_at": _now_iso(),
        "attempts": 0,
    }
    r = get_redis()
    await r.rpush(_KEY_PENDING, json.dumps(envelope))
    log.info("queue.enqueued id=%s sender=%s recipients=%d user=%s",
             envelope["id"], sender, len(recipients), username)
    return envelope["id"]


def _is_expired(envelope: dict) -> bool:
    """Return True if envelope has exceeded TTL_SECONDS since queued_at."""
    try:
        queued = datetime.fromisoformat(envelope["queued_at"])
    except (KeyError, ValueError):
        return True
    age = (datetime.now(timezone.utc) - queued).total_seconds()
    return age > (settings.ttl_seconds or 900)


async def _process_one(envelope_raw: str) -> bool:
    """Process one envelope. Returns True if envelope is done (success or
    permanent failure), False if it should be retried.
    """
    try:
        envelope = json.loads(envelope_raw)
    except json.JSONDecodeError:
        log.error("queue.bad_envelope")
        return True  # drop

    if _is_expired(envelope):
        log.warning("queue.expired id=%s — dropping", envelope.get("id"))
        return True

    raw_message = base64.b64decode(envelope["raw_message_b64"])
    sender = envelope["sender"]
    recipients = envelope["recipients"]

    results = await outbound.deliver_message(sender, recipients, raw_message)

    # Consider success if at least one domain succeeded
    any_success = any(r["success"] for r in results.values())
    all_success = all(r["success"] for r in results.values())

    if all_success:
        log.info("queue.delivered id=%s", envelope["id"])
        return True

    if any_success:
        # Partial — log but consider done (don't retry successful domains)
        log.warning("queue.partial id=%s results=%s", envelope["id"], results)
        return True

    # All domains failed — retry if attempts remain
    envelope["attempts"] += 1
    max_retries = settings.outbound_max_retries or 3
    if envelope["attempts"] >= max_retries:
        log.error(
            "queue.permanent_failure id=%s attempts=%d — dropping",
            envelope["id"], envelope["attempts"],
        )
        # Move to failed list with TTL for inspection
        r = get_redis()
        await r.lpush(_KEY_FAILED, json.dumps(envelope))
        await r.expire(_KEY_FAILED, settings.ttl_seconds or 900)
        return True

    # Re-queue for retry
    log.info(
        "queue.requeue id=%s attempts=%d/%d",
        envelope["id"], envelope["attempts"], max_retries,
    )
    r = get_redis()
    await r.rpush(_KEY_PENDING, json.dumps(envelope))
    return True


async def run_worker(stop_event: asyncio.Event) -> None:
    """Background worker — pops envelopes and delivers them.

    Runs forever until ``stop_event`` is set. Polls every 1 second.
    """
    log.info("worker.starting")
    r = get_redis()
    poll_interval = settings.cleanup_interval_seconds or 30
    # We poll the queue more aggressively than cleanup
    poll_seconds = 1

    while not stop_event.is_set():
        try:
            # BLPOP blocks for up to 5 seconds waiting for a new envelope
            result = await r.blpop(_KEY_PENDING, timeout=5)
            if result is None:
                continue
            _key, envelope_raw = result
            await _process_one(envelope_raw)
        except asyncio.CancelledError:
            break
        except Exception as e:
            log.error("worker.error %s: %s", type(e).__name__, e)
            await asyncio.sleep(poll_seconds)

    log.info("worker.stopped")


async def queue_depth() -> int:
    """Return current pending queue length."""
    r = get_redis()
    return await r.llen(_KEY_PENDING)
