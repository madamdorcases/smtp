"""
Redis client helper — used by smtp_users, queue, rate_limit, and spam.

Single async Redis connection pool, lazily initialized on first use.
Closes cleanly on shutdown.
"""
from __future__ import annotations

import redis.asyncio as redis

from config import settings

_pool: redis.ConnectionPool | None = None
_client: redis.Redis | None = None


async def init_redis() -> redis.Redis:
    """Initialize the global Redis connection pool. Idempotent."""
    global _pool, _client
    if _client is not None:
        return _client
    password = settings.redis_password or None
    _pool = redis.ConnectionPool.from_url(
        settings.redis_url,
        password=password,
        encoding="utf-8",
        decode_responses=True,
        max_connections=32,
    )
    _client = redis.Redis(connection_pool=_pool)
    # sanity ping
    await _client.ping()
    return _client


async def close_redis() -> None:
    """Close the global Redis connection pool."""
    global _pool, _client
    if _client is not None:
        await _client.aclose()
    if _pool is not None:
        await _pool.disconnect()
    _client = None
    _pool = None


def get_redis() -> redis.Redis:
    """Return the initialized Redis client. Must call init_redis() first."""
    if _client is None:
        raise RuntimeError("Redis not initialized — call init_redis() first")
    return _client
