"""
Redis async client. Ephemeral queue. No persistence.
"""
from __future__ import annotations

from typing import Optional

import redis.asyncio as redis

from .config import settings

_client: Optional[redis.Redis] = None
QUEUE_KEY = "smtp:outbound"


def get_redis() -> redis.Redis:
    global _client
    if _client is None:
        _client = redis.from_url(
            settings.REDIS_URL_WITH_AUTH,
            encoding="utf-8",
            decode_responses=True,
            socket_timeout=5.0,
            socket_connect_timeout=5.0,
        )
    return _client


async def close() -> None:
    global _client
    if _client is not None:
        await _client.aclose()
    _client = None
