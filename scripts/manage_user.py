#!/usr/bin/env python3
"""
SMTP user management CLI — runs INSIDE the smtp-relay container.

Usage (from the VPS host):
    docker exec -it smtp-relay python scripts/manage_user.py list
    docker exec -it smtp-relay python scripts/manage_user.py add alice 's3cret'
    docker exec -it smtp-relay python scripts/manage_user.py add bob $(openssl rand -base64 18)
    docker exec -it smtp-relay python scripts/manage_user.py reset alice 'newpass'
    docker exec -it smtp-relay python scripts/manage_user.py remove alice
    docker exec -it smtp-relay python scripts/manage_user.py generate   # create one with a random password

Exit codes:
    0  success
    1  user not found / wrong args
    2  user already exists
"""
from __future__ import annotations

import asyncio
import json
import sys
from pprint import pprint

# Make /app importable so we can `from core...` etc.
sys.path.insert(0, "/app")


async def _init():
    from core.redis_client import init_redis
    await init_redis()


async def cmd_list() -> int:
    from core.smtp_users import list_users
    await _init()
    users = await list_users()
    if not users:
        print("(no SMTP users)")
        return 0
    print(f"Found {len(users)} SMTP user(s):")
    print()
    print(f"  {'USERNAME':<25}  {'ACTIVE':<8}  {'CREATED_AT'}")
    print(f"  {'-' * 25}  {'-' * 8}  {'-' * 30}")
    for u in users:
        print(f"  {u['username']:<25}  {str(u.get('active', True)):<8}  {u.get('created_at', '?')}")
    return 0


async def cmd_add(username: str, password: str) -> int:
    from core.smtp_users import create_user
    await _init()
    try:
        rec = await create_user(username, password, overwrite=False)
    except ValueError as e:
        if "already exists" in str(e):
            print(f"ERROR: {e}", file=sys.stderr)
            return 2
        print(f"ERROR: {e}", file=sys.stderr)
        return 1
    print(f"Created user '{rec['username']}'")
    print()
    print("SMTP connection details for this user:")
    print(f"  SMTP server : mail.{_get_domain()}")
    print(f"  SMTP port   : 465  (implicit TLS / SSL)")
    print(f"  Username    : {rec['username']}")
    print(f"  Password    : {password}")
    print(f"  From address: {rec['username']}@{_get_domain()}")
    print()
    print("(Password is stored Argon2-hashed in Redis — keep this output safe.)")
    return 0


async def cmd_reset(username: str, new_password: str) -> int:
    from core.smtp_users import reset_password
    await _init()
    ok = await reset_password(username, new_password)
    if not ok:
        print(f"ERROR: user '{username}' not found", file=sys.stderr)
        return 1
    print(f"Password reset for '{username}'")
    print(f"  New password: {new_password}")
    return 0


async def cmd_remove(username: str) -> int:
    from core.smtp_users import remove_user
    await _init()
    ok = await remove_user(username)
    if not ok:
        print(f"ERROR: user '{username}' not found", file=sys.stderr)
        return 1
    print(f"Removed user '{username}'")
    return 0


async def cmd_generate(username: str) -> int:
    """Create a user with a random 20-char password."""
    from core.smtp_users import create_user, generate_password
    await _init()
    password = generate_password(20)
    try:
        rec = await create_user(username, password, overwrite=False)
    except ValueError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 2
    print(f"Created user '{rec['username']}' with random password")
    print()
    print("SMTP connection details (SAVE THIS — password is not recoverable):")
    print(f"  SMTP server : mail.{_get_domain()}")
    print(f"  SMTP port   : 465  (implicit TLS / SSL)")
    print(f"  Username    : {rec['username']}")
    print(f"  Password    : {password}")
    print(f"  From address: {rec['username']}@{_get_domain()}")
    return 0


def _get_domain() -> str:
    import os
    return os.environ.get("DOMAIN", "api-solv-rix-ai.top")


def main() -> int:
    args = sys.argv[1:]
    if not args:
        print(__doc__)
        return 1
    cmd = args[0]
    try:
        if cmd == "list":
            return asyncio.run(cmd_list())
        elif cmd == "add" and len(args) == 3:
            return asyncio.run(cmd_add(args[1], args[2]))
        elif cmd == "reset" and len(args) == 3:
            return asyncio.run(cmd_reset(args[1], args[2]))
        elif cmd == "remove" and len(args) == 2:
            return asyncio.run(cmd_remove(args[1]))
        elif cmd == "generate" and len(args) == 2:
            return asyncio.run(cmd_generate(args[1]))
        else:
            print(__doc__)
            return 1
    except KeyboardInterrupt:
        return 0
    except Exception as e:
        print(f"FATAL: {type(e).__name__}: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
