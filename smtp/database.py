"""
MongoDB async client + collection accessors + TTL index setup.

All collections live in the default database of the MONGO_URI.
TTL indexes auto-delete logs after their retention window.
Permanent collections (users, keys, allowed_apps, settings, events, dkim) have no TTL.
"""
from __future__ import annotations

from typing import Optional

from motor.motor_asyncio import AsyncIOMotorClient, AsyncIOMotorCollection, AsyncIOMotorDatabase

from .config import settings

_client: Optional[AsyncIOMotorClient] = None
_db: Optional[AsyncIOMotorDatabase] = None

LOG_TTL = 24 * 60 * 60       # 24 hours
TEMP_TTL = 60 * 60           # 1 hour


def get_client() -> AsyncIOMotorClient:
    global _client
    if _client is None:
        _client = AsyncIOMotorClient(
            settings.MONGO_URI,
            serverSelectionTimeoutMS=10000,
            connectTimeoutMS=10000,
        )
    return _client


def get_db() -> AsyncIOMotorDatabase:
    global _db
    if _db is None:
        _db = get_client()[settings.MONGO_DB_NAME]
    return _db


# ---- Collection accessors ----
def col_allowed_apps() -> AsyncIOMotorCollection:   return get_db()["allowed_apps"]
def col_api_keys() -> AsyncIOMotorCollection:       return get_db()["api_keys"]
def col_admin_settings() -> AsyncIOMotorCollection: return get_db()["admin_settings"]
def col_dkim() -> AsyncIOMotorCollection:           return get_db()["dkim_keys"]
def col_events() -> AsyncIOMotorCollection:         return get_db()["permanent_events"]
def col_email_logs() -> AsyncIOMotorCollection:     return get_db()["email_logs"]
def col_api_logs() -> AsyncIOMotorCollection:       return get_db()["api_debug_logs"]
def col_smtp_logs() -> AsyncIOMotorCollection:      return get_db()["smtp_debug_logs"]
def col_temp() -> AsyncIOMotorCollection:           return get_db()["temp_storage"]


async def ensure_indexes() -> None:
    """Idempotent index creation. Called at app startup."""
    # Allowed apps (registered external apps that can call /api/send)
    await col_allowed_apps().create_index("app_name", unique=True)
    await col_allowed_apps().create_index("api_pub_key", unique=True)

    # Admin API keys (for /admin/*)
    await col_api_keys().create_index("key_name", unique=True)

    # DKIM
    await col_dkim().create_index("selector", unique=True)

    # Settings
    await col_admin_settings().create_index("setting_key", unique=True, sparse=True)

    # Permanent events
    await col_events().create_index([("ts", -1)])

    # Email logs (TTL 24h)
    await col_email_logs().create_index("message_id")
    await col_email_logs().create_index([("created_at", -1)])
    await col_email_logs().create_index("created_at", expireAfterSeconds=LOG_TTL)

    # API logs (TTL 24h)
    await col_api_logs().create_index([("created_at", -1)])
    await col_api_logs().create_index("created_at", expireAfterSeconds=LOG_TTL)

    # SMTP logs (TTL 24h)
    await col_smtp_logs().create_index("message_id")
    await col_smtp_logs().create_index([("created_at", -1)])
    await col_smtp_logs().create_index("created_at", expireAfterSeconds=LOG_TTL)

    # Temp storage (TTL 1h)
    await col_temp().create_index("operation_id", unique=True)
    await col_temp().create_index("created_at", expireAfterSeconds=TEMP_TTL)


async def close() -> None:
    global _client, _db
    if _client is not None:
        _client.close()
    _client = None
    _db = None
