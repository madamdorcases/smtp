"""
Configuration loader using python-dotenv.

Usage (anywhere in the app):
    from smtp.config import settings
    settings.ADMIN_CURVE_KEY

We do NOT use pydantic-settings here — direct os.environ.get as requested.
"""
from __future__ import annotations

import os
from dotenv import load_dotenv

# Load .env from current working directory (docker WORKDIR=/app)
load_dotenv()


def _get(key: str, default: str = "") -> str:
    return os.environ.get(key, default)


def _get_int(key: str, default: int) -> int:
    try:
        return int(os.environ.get(key, str(default)))
    except (TypeError, ValueError):
        return default


def _get_bool(key: str, default: bool) -> bool:
    v = os.environ.get(key, str(default)).lower().strip()
    return v in ("1", "true", "yes", "on")


class _Settings:
    ADMIN_EMAIL: str = _get("ADMIN_EMAIL")
    ADMIN_PASSWORD: str = _get("ADMIN_PASSWORD")
    ADMIN_CURVE_KEY: str = _get("ADMIN_CURVE_KEY")

    MONGO_URI: str = _get("MONGO_URI")
    MONGO_DB_NAME: str = _get("MONGO_DB_NAME", "smtp_db")
    REDIS_URL: str = _get("REDIS_URL", "redis://smtp-redis:6379/0")
    REDIS_PASSWORD: str = _get("REDIS_PASSWORD")

    SENDING_DOMAIN: str = _get("SENDING_DOMAIN")
    MAIL_FROM: str = _get("MAIL_FROM")

    SMTP_RELAY_HOST: str = _get("SMTP_RELAY_HOST")
    SMTP_RELAY_PORT: int = _get_int("SMTP_RELAY_PORT", 465)
    SMTP_RELAY_USER: str = _get("SMTP_RELAY_USER")
    SMTP_RELAY_PASS: str = _get("SMTP_RELAY_PASS")

    REQUEST_TIMESTAMP_WINDOW: int = _get_int("REQUEST_TIMESTAMP_WINDOW", 300)
    QUEUE_TTL: int = _get_int("QUEUE_TTL", 900)

    UVICORN_LOG_LEVEL: str = _get("UVICORN_LOG_LEVEL", "critical")
    UVICORN_NO_ACCESS_LOG: bool = _get_bool("UVICORN_NO_ACCESS_LOG", True)

    @property
    def ADMIN_AES_KEY(self) -> bytes:
        """AES-256 key derived from ADMIN_CURVE_KEY.

        We hex-decode the 64-char key → 32 raw bytes → use directly as AES-256 key.
        """
        return bytes.fromhex(self.ADMIN_CURVE_KEY)

    @property
    def ADMIN_PUBLIC_KEY_HEX(self) -> str:
        """Derived secp256k1 public key (uncompressed, 04‖X‖Y hex)."""
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import ec
        value = int(self.ADMIN_CURVE_KEY, 16)
        priv = ec.derive_private_key(value, ec.SECP256K1())
        raw = priv.public_key().public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.UncompressedPoint,
        )
        return raw.hex()

    @property
    def REDIS_URL_WITH_AUTH(self) -> str:
        """Inject REDIS_PASSWORD into URL if not already present."""
        url = self.REDIS_URL
        pwd = self.REDIS_PASSWORD
        if not pwd:
            return url
        if "@" in url.split("://", 1)[-1]:
            return url  # already has auth
        scheme, rest = url.split("://", 1)
        return f"{scheme}://{pwd}@{rest}"

    @property
    def USES_RELAY(self) -> bool:
        return bool(self.SMTP_RELAY_HOST and self.SMTP_RELAY_USER)


settings = _Settings()
