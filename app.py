"""
FastAPI app entrypoint.

Listens on 0.0.0.0:15484. Empty terminal by design (uvicorn --log-level critical --no-access-log).
"""
from __future__ import annotations

import asyncio
import gc
import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI

from smtp.config import settings
from smtp.database import close as db_close
from smtp.redis_client import close as redis_close
from smtp.setup import print_first_run_banner, setup_database
from routes import admin, health, send, status

# Silence every Python logger by default
logging.basicConfig(level=logging.CRITICAL)
for name in ("uvicorn", "uvicorn.access", "uvicorn.error", "aiosmtplib", "motor", "redis", "fastapi"):
    logging.getLogger(name).setLevel(logging.CRITICAL)

_worker_task: asyncio.Task | None = None
_stop_event: asyncio.Event | None = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    global _worker_task, _stop_event
    # One-time DB setup (indexes + DKIM keypair + admin settings seed).
    # Prints DNS records ONLY on first run when DKIM was just created.
    try:
        info = await setup_database()
        print_first_run_banner(info)
    except Exception:
        # If DB is unreachable, the app still starts so logs go to MongoDB later.
        # In production you'd want this to fail fast — but per spec the terminal
        # must stay empty, so we silently retry via background worker instead.
        pass
    _stop_event = asyncio.Event()
    _worker_task = asyncio.create_task(_run_worker_safe())
    try:
        yield
    finally:
        if _stop_event:
            _stop_event.set()
        if _worker_task:
            try:
                await asyncio.wait_for(_worker_task, timeout=5.0)
            except asyncio.TimeoutError:
                _worker_task.cancel()
        await redis_close()
        await db_close()
        gc.collect()


async def _run_worker_safe() -> None:
    from smtp.worker import run_worker
    try:
        await run_worker(_stop_event)  # type: ignore[arg-type]
    except asyncio.CancelledError:
        pass
    except Exception:  # noqa: BLE001
        pass


app = FastAPI(
    title="SMTP Verification Service",
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
    lifespan=lifespan,
)

app.include_router(health.router)
app.include_router(send.router)
app.include_router(status.router)
app.include_router(admin.router)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "app:app",
        host="0.0.0.0",
        port=8000,
        log_level=settings.UVICORN_LOG_LEVEL,
        access_log=not settings.UVICORN_NO_ACCESS_LOG,
        use_colors=False,
    )
