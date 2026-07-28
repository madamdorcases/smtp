"""
15-minute auto-delete cleanup worker.

Runs as a background asyncio task alongside the queue worker. Every
``CLEANUP_INTERVAL_SECONDS`` (default 900 = 15 min) it:

  1. Wipes ALL keys in the Redis database (queue, rate-limit counters,
     user records — EVERYTHING). Users are re-bootstrapped from the
     SMTP_USERS env var on next start, but during a running session this
     means a hard reset.
  2. Truncates all log files in /var/log/smtp-relay/ on the host.
  3. Removes any temp files in /tmp/smtp-relay-*.

The goal: ZERO persistent data. After 15 minutes, the server has no
memory of what it sent, who sent it, or what logs it wrote. This is the
strictest possible "ephemeral" mode for a verification-email server.

NOTE: Wiping Redis also wipes SMTP user records. To avoid locking
everyone out, we re-bootstrap from SMTP_USERS env var after each wipe.
"""
from __future__ import annotations

import asyncio
import glob
import logging
import os
import time
from pathlib import Path

from config import settings
from core.redis_client import get_redis

log = logging.getLogger("cleanup")

LOG_DIR = Path(os.environ.get("LOG_DIR", "/var/log/smtp-relay"))
TEMP_GLOB = "/tmp/smtp-relay-*"


async def wipe_redis() -> int:
    """Delete ALL keys in the current Redis database. Returns count deleted."""
    r = get_redis()
    # FLUSHDB is atomic and faster than SCAN+DELETE
    try:
        count = await r.dbsize()
        await r.flushdb()
        return count
    except Exception as e:
        log.error("cleanup.redis_wipe_failed error=%s", e)
        return 0


def truncate_logs() -> int:
    """Truncate all *.log files in LOG_DIR. Returns count truncated.

    We truncate (not delete) so the file handle held by the logger stays
    valid — the logger can keep writing without needing a restart.
    """
    if not LOG_DIR.exists():
        return 0
    count = 0
    for log_file in LOG_DIR.glob("*.log"):
        try:
            with open(log_file, "w") as f:
                f.truncate(0)
            count += 1
        except Exception as e:
            log.error("cleanup.log_truncate_failed file=%s error=%s",
                      log_file, e)
    return count


def remove_temp_files() -> int:
    """Remove any /tmp/smtp-relay-* temp files. Returns count removed."""
    count = 0
    for path in glob.glob(TEMP_GLOB):
        try:
            if os.path.isfile(path):
                os.remove(path)
            elif os.path.isdir(path):
                import shutil
                shutil.rmtree(path)
            count += 1
        except Exception as e:
            log.error("cleanup.temp_remove_failed path=%s error=%s", path, e)
    return count


async def rebootstrap_users() -> int:
    """Re-create SMTP users from SMTP_USERS env var after a Redis wipe."""
    from core.smtp_users import bootstrap_from_env
    try:
        return await bootstrap_from_env()
    except Exception as e:
        log.error("cleanup.rebootstrap_failed error=%s", e)
        return 0


async def run_cleanup_once() -> dict:
    """Run one cleanup pass. Returns a summary dict for logging."""
    started = time.monotonic()
    redis_deleted = await wipe_redis()
    users_recreated = await rebootstrap_users()
    logs_truncated = truncate_logs()
    temps_removed = remove_temp_files()
    elapsed = (time.monotonic() - started) * 1000
    return {
        "redis_keys_deleted": redis_deleted,
        "users_recreated": users_recreated,
        "logs_truncated": logs_truncated,
        "temp_files_removed": temps_removed,
        "elapsed_ms": round(elapsed, 1),
    }


async def run_cleanup_worker(stop_event: asyncio.Event) -> None:
    """Background cleanup worker — runs forever until stop_event is set.

    Sleeps ``CLEANUP_INTERVAL_SECONDS`` between passes. First pass runs
    after the first interval (not immediately) so we don't wipe data on
    boot before anything has been sent.
    """
    interval = settings.cleanup_interval_seconds or 900
    log.info("cleanup.starting interval_s=%d log_dir=%s", interval, LOG_DIR)
    while not stop_event.is_set():
        try:
            await asyncio.wait_for(stop_event.wait(), timeout=interval)
            # If we get here, stop_event was set — exit cleanly
            break
        except asyncio.TimeoutError:
            # Interval elapsed — run a cleanup pass
            pass
        try:
            summary = await run_cleanup_once()
            log.info("cleanup.completed %s", summary)
        except Exception as e:
            log.error("cleanup.error %s: %s", type(e).__name__, e)
    log.info("cleanup.stopped")
