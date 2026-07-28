"""
SMTP user management — Redis-backed, Argon2-hashed passwords.

User records are stored in Redis under:
    smtp:user:<username>    → JSON {username, password_hash, created_at, active}

A set of all usernames is kept under:
    smtp:users              → SET of usernames

On startup, ``bootstrap_from_env()`` reads the SMTP_USERS env var
(format: ``"user1:pass1,user2:pass2"``) and creates any missing users.
Existing users are NOT overwritten — to change a password, use the CLI.

CLI usage (on the VPS host):
    docker exec -it smtp-relay python scripts/manage_user.py add  alice 's3cret'
    docker exec -it smtp-relay python scripts/manage_user.py remove alice
    docker exec -it smtp-relay python scripts/manage_user.py list
    docker exec -it smtp-relay python scripts/manage_user.py reset  alice 'newpass'
"""
from __future__ import annotations

import json
import os
import secrets
from datetime import datetime, timezone
from typing import Optional

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, InvalidHashError

from core.redis_client import get_redis

_hasher = PasswordHasher(
    time_cost=2,        # 2 iterations — fast enough for SMTP AUTH
    memory_cost=65536,  # 64 MB
    parallelism=2,
)

_PREFIX_USER = "smtp:user:"     # hash of single user
_KEY_USERS  = "smtp:users"      # set of all usernames


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


async def create_user(username: str, password: str, *, overwrite: bool = False) -> dict:
    """Create or overwrite an SMTP user. Returns the user record (without hash)."""
    username = (username or "").strip().lower()
    if not username or not password:
        raise ValueError("username and password are required")
    r = get_redis()
    # If exists and not overwrite, refuse
    if not overwrite and await r.exists(f"{_PREFIX_USER}{username}"):
        raise ValueError(f"user '{username}' already exists — use reset to change password")
    record = {
        "username": username,
        "password_hash": _hasher.hash(password),
        "created_at": _now_iso(),
        "active": True,
    }
    pipe = r.pipeline()
    pipe.set(f"{_PREFIX_USER}{username}", json.dumps(record))
    pipe.sadd(_KEY_USERS, username)
    await pipe.execute()
    return {
        "username": username,
        "created_at": record["created_at"],
        "active": True,
    }


async def remove_user(username: str) -> bool:
    """Delete an SMTP user. Returns True if removed, False if not found."""
    username = (username or "").strip().lower()
    r = get_redis()
    pipe = r.pipeline()
    pipe.delete(f"{_PREFIX_USER}{username}")
    pipe.srem(_KEY_USERS, username)
    deleted, _ = await pipe.execute()
    return bool(deleted)


async def reset_password(username: str, new_password: str) -> bool:
    """Reset an existing user's password. Returns True if reset, False if not found."""
    username = (username or "").strip().lower()
    r = get_redis()
    key = f"{_PREFIX_USER}{username}"
    raw = await r.get(key)
    if not raw:
        return False
    record = json.loads(raw)
    record["password_hash"] = _hasher.hash(new_password)
    await r.set(key, json.dumps(record))
    return True


async def list_users() -> list[dict]:
    """Return all usernames (without hashes)."""
    r = get_redis()
    usernames = sorted(await r.smembers(_KEY_USERS))
    out = []
    for u in usernames:
        raw = await r.get(f"{_PREFIX_USER}{u}")
        if not raw:
            continue
        rec = json.loads(raw)
        out.append({
            "username": rec["username"],
            "created_at": rec.get("created_at"),
            "active": rec.get("active", True),
        })
    return out


async def verify_credentials(username: str, password: str) -> Optional[dict]:
    """Verify username + password. Returns the user record (without hash) on
    success, None on failure or if user is inactive.
    """
    username = (username or "").strip().lower()
    if not username or not password:
        return None
    r = get_redis()
    raw = await r.get(f"{_PREFIX_USER}{username}")
    if not raw:
        return None
    try:
        record = json.loads(raw)
    except json.JSONDecodeError:
        return None
    if not record.get("active", True):
        return None
    try:
        _hasher.verify(record["password_hash"], password)
    except (VerifyMismatchError, InvalidHashError):
        return None
    return {
        "username": record["username"],
        "active": True,
    }


async def bootstrap_from_env() -> int:
    """Read SMTP_USERS env var (format: 'user1:pass1,user2:pass2') and create
    any users that don't already exist. Existing users are NOT modified.

    Returns the number of new users created.
    """
    raw = os.environ.get("SMTP_USERS", "").strip()
    if not raw:
        return 0
    created = 0
    for entry in raw.split(","):
        entry = entry.strip()
        if not entry or ":" not in entry:
            continue
        username, password = entry.split(":", 1)
        username = username.strip()
        password = password.strip()
        if not username or not password:
            continue
        try:
            await create_user(username, password, overwrite=False)
            created += 1
        except ValueError:
            # already exists — skip
            pass
    return created


# ---------------------------------------------------------------------------
# Token generation helper — used to generate a strong random password if the
# operator wants one. Not used internally; handy from the CLI.
# ---------------------------------------------------------------------------
def generate_password(length: int = 20) -> str:
    """Return a URL-safe random password of the given length."""
    return secrets.token_urlsafe(length)[:length]
