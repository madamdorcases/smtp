#!/usr/bin/env python3
"""
Optional standalone setup script.

If you only run `app.py`, this script is NOT needed — app.py does the same
setup on first startup. Use this script only if you want to set up the DB
without starting the server (e.g. to inspect DNS records before deploy).

Usage:
    python scripts/init_db.py
"""
from __future__ import annotations

import asyncio
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from smtp.setup import print_first_run_banner, setup_database
from smtp.config import settings
from smtp.security import derive_public_hex


async def main() -> None:
    info = await setup_database()
    print_first_run_banner(info)
    print()
    print(f"Admin email   : {settings.ADMIN_EMAIL}")
    print(f"Admin pub key : {derive_public_hex(settings.ADMIN_CURVE_KEY)}")
    print(f"Database      : {settings.MONGO_DB_NAME}")
    print(f"SMTP relay    : {settings.SMTP_RELAY_HOST}:{settings.SMTP_RELAY_PORT}")
    print()
    print("Setup complete. You can now start the server with: python app.py")


if __name__ == "__main__":
    asyncio.run(main())
