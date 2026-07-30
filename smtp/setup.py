"""
One-time DB setup, called from app.py lifespan on every startup.

Idempotent: only does work that hasn't been done before.
- Creates indexes (idempotent)
- Generates DKIM keypair if missing (returns True if just created)
- Seeds admin_allowed_ips = [] if missing
- Prints DNS records to stdout ONLY if DKIM was just created
  (so terminal stays empty on subsequent restarts)
"""
from __future__ import annotations

from datetime import datetime, timezone

from .config import settings
from .database import (
    col_admin_settings,
    ensure_indexes,
)
from .dkim_signer import ensure_dkim_keypair
from .security import derive_public_hex


def _chunk(s: str, size: int = 200) -> str:
    parts = [s[i:i + size] for i in range(0, len(s), size)]
    return "\" \"".join(parts)


async def setup_database() -> dict:
    """Run all setup. Returns dict with setup info (used for one-time stdout printing)."""
    info: dict = {
        "indexes_created": False,
        "dkim_created": False,
        "admin_seeded": False,
        "dkim_doc": None,
    }

    # 1. Indexes (idempotent)
    await ensure_indexes()
    info["indexes_created"] = True

    # 2. DKIM keypair (creates only if missing)
    # We check existence first so we know whether to print DNS records.
    from .database import col_dkim
    existing_dkim = await col_dkim().find_one({"selector": "smtp1"})
    dkim_doc = await ensure_dkim_keypair("smtp1")
    info["dkim_doc"] = dkim_doc
    if existing_dkim is None:
        info["dkim_created"] = True

    # 3. Seed admin_allowed_ips (only if not present)
    existing_admin = await col_admin_settings().find_one({"setting_key": "admin_allowed_ips"})
    if existing_admin is None:
        await col_admin_settings().insert_one({
            "setting_key": "admin_allowed_ips",
            "setting_value": [],
            "updated_at": datetime.now(timezone.utc),
        })
        info["admin_seeded"] = True

    return info


def print_first_run_banner(info: dict) -> None:
    """Print DNS setup info — ONLY on first run when DKIM was just created."""
    if not info.get("dkim_created"):
        return

    dkim_doc = info["dkim_doc"]
    print("=" * 60)
    print(" FIRST RUN - Publish these DNS records at your DNS provider:")
    print("=" * 60)
    print()
    print("[1] DKIM public key (TXT record):")
    print(f"    Name : {dkim_doc['selector']}._domainkey.{dkim_doc['domain']}")
    print(f"    Value: v=DKIM1; k=rsa; p={_chunk(dkim_doc['public_b64'])}")
    print()
    print("[2] SPF (TXT record):")
    print(f"    Name : {settings.SENDING_DOMAIN} (or @)")
    print(f"    Value: v=spf1 a mx -all")
    print()
    print("[3] DMARC (TXT record):")
    print(f"    Name : _dmarc.{settings.SENDING_DOMAIN}")
    print(f"    Value: v=DMARC1; p=quarantine; rua=mailto:{settings.ADMIN_EMAIL}")
    print()
    print(f"[4] Admin public key (share with clients that need /admin/* access):")
    print(f"    {derive_public_hex(settings.ADMIN_CURVE_KEY)}")
    print()
    print(f"[5] SMTP relay: {settings.SMTP_RELAY_HOST}:{settings.SMTP_RELAY_PORT} as {settings.SMTP_RELAY_USER}")
    print()
    print(" After publishing DNS, register an allowed_app via /admin/allowed-apps.")
    print(" This banner will NOT appear on subsequent restarts.")
    print("=" * 60)
