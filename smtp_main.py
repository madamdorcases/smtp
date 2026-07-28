"""
Pure SMTP relay entrypoint — no HTTP API, no admin panel.

Starts:
  1. Redis connection (for users, queue, rate limits)
  2. SMTP user bootstrap from env (creates any missing users)
  3. SMTP server on port 465 (implicit TLS) + 587 (STARTTLS)
  4. Background queue worker (delivers outbound mail)
  5. Background cleanup worker (15-min auto-delete of all data)

Runs forever. Set LOG_LEVEL=DEBUG to see verbose output.

Ports:
  - 465  SMTP implicit TLS  (primary — what users connect to)
  - 587  SMTP STARTTLS      (compatibility — firewall if unused)

No HTTP service is exposed. No admin panel. The only way to manage SMTP
users is via the CLI:
    docker exec -it smtp-relay python scripts/manage_user.py list
    docker exec -it smtp-relay python scripts/manage_user.py add alice 's3cret'

Logs are written to BOTH stdout (for `docker logs`) AND to
/var/log/smtp-relay/smtp-relay.log (on the host, mounted as a volume).
The cleanup worker truncates the log file every 15 minutes — so logs
never persist beyond 15 minutes either.
"""
from __future__ import annotations

import asyncio
import logging
import logging.handlers
import os
import signal
import sys
from pathlib import Path

import structlog

from config import settings
from core.redis_client import init_redis, close_redis
from core.smtp_users import bootstrap_from_env
from core.smtp_server import start_smtp_server, stop_smtp_server
from core.queue import run_worker
from core.cleanup import run_cleanup_worker

LOG_DIR = Path(os.environ.get("LOG_DIR", "/var/log/smtp-relay"))
LOG_FILE = LOG_DIR / "smtp-relay.log"


def _configure_logging() -> None:
    """Configure logging: JSON to stdout + rotating file in LOG_DIR.

    The file is truncated every 15 min by the cleanup worker, so we use
    a small maxBytes (10 MB) just as a safety net — under normal use
    the file will be wiped long before hitting 10 MB.
    """
    LOG_LEVEL = (settings.log_level or "INFO").upper()
    # Make sure log dir exists
    LOG_DIR.mkdir(parents=True, exist_ok=True)

    # Python stdlib root logger — used by `logging.getLogger("spam")` etc.
    root = logging.getLogger()
    root.setLevel(getattr(logging, LOG_LEVEL, logging.INFO))
    # Remove any default handlers (uvicorn etc. add their own)
    for h in list(root.handlers):
        root.removeHandler(h)

    # --- stdout handler (always on, for `docker logs`) ---
    stdout_h = logging.StreamHandler(sys.stdout)
    stdout_h.setFormatter(logging.Formatter(
        "%(asctime)s %(levelname)-7s %(name)-15s %(message)s"
    ))
    root.addHandler(stdout_h)

    # --- rotating file handler (on host-mounted volume) ---
    # The cleanup worker truncates this file every 15 min, but RotatingFileHandler
    # gives us a safety net if cleanup fails or is disabled.
    try:
        file_h = logging.handlers.RotatingFileHandler(
            str(LOG_FILE),
            maxBytes=10 * 1024 * 1024,  # 10 MB
            backupCount=0,               # no backups — we don't want any persistence
            encoding="utf-8",
        )
        file_h.setFormatter(logging.Formatter(
            "%(asctime)s %(levelname)-7s %(name)-15s %(message)s"
        ))
        root.addHandler(file_h)
    except (OSError, PermissionError) as e:
        # If we can't write to the log dir (e.g. not mounted), fall back to
        # stdout only — don't crash the server
        print(f"[logging] WARNING: cannot write to {LOG_FILE}: {e}", file=sys.stderr)
        print(f"[logging] Falling back to stdout-only logging", file=sys.stderr)

    # --- structlog config (used by core modules) ---
    structlog.configure(
        processors=[
            structlog.processors.add_log_level,
            structlog.processors.TimeStamper(fmt="iso", utc=True),
            structlog.processors.JSONRenderer(),
        ],
        wrapper_class=structlog.make_filtering_bound_logger(
            logging.INFO if LOG_LEVEL != "DEBUG" else logging.DEBUG
        ),
        logger_factory=structlog.stdlib.LoggerFactory(),
        cache_logger_on_first_use=True,
    )


async def main() -> None:
    """Main async lifecycle."""
    _configure_logging()
    log = structlog.get_logger("main")

    log.info("app.starting domain=%s environment=%s log_dir=%s",
             settings.domain, settings.environment, str(LOG_DIR))

    # 1. Redis
    await init_redis()
    log.info("redis.connected url=%s", settings.redis_url)

    # 2. Bootstrap SMTP users from env var
    created = await bootstrap_from_env()
    if created:
        log.info("users.bootstrapped count=%d", created)
    else:
        log.info("users.bootstrap_skipped env_SMTP_USERS_empty=true")

    # 3. SMTP server
    await start_smtp_server()

    # 4. Background workers
    stop_event = asyncio.Event()
    worker_task = asyncio.create_task(run_worker(stop_event))
    cleanup_task = asyncio.create_task(run_cleanup_worker(stop_event))

    # 5. Wait for shutdown signal
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, stop_event.set)
        except NotImplementedError:
            pass

    log.info("app.ready ports=[465,587] domain=%s ttl_seconds=%d cleanup_interval=%d",
             settings.domain, settings.ttl_seconds, settings.cleanup_interval_seconds)
    log.info("app.smtp_info hostname=mail.%s port=465 ssl=letsencrypt", settings.domain)
    log.info("app.cleanup_info log_dir=%s interval_s=%d — ALL data wiped every interval",
             str(LOG_DIR), settings.cleanup_interval_seconds)

    try:
        await stop_event.wait()
    except (KeyboardInterrupt, SystemExit):
        pass

    log.info("app.stopping")
    worker_task.cancel()
    cleanup_task.cancel()
    for task in (worker_task, cleanup_task):
        try:
            await task
        except asyncio.CancelledError:
            pass
    await stop_smtp_server()
    await close_redis()
    log.info("app.stopped")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n[interrupt] shutting down", file=sys.stderr)
        sys.exit(0)
