"""
Single project-wide configuration file.

This file is the ONE source of truth for all configuration. Every other
module in the project imports from here:

    from config import settings        # typed adapter (lower-case aliases)
    from config import config          # raw Config() singleton (UPPER_CASE)
    from config import Config          # the class itself

Layout
------
1. ``Config`` class — verbatim, as supplied by the operator. Every field is
   populated at class-definition time via ``os.environ.get(...)`` and is
   therefore ``str | None``. DO NOT MODIFY THIS CLASS.

2. ``config = Config()`` — the singleton instance of the raw Config class.

3. ``_SettingsAdapter`` — a thin wrapper that exposes the SAME env-backed
   values but with proper Python types (``int`` / ``bool`` / ``list[str]``)
   for fields the rest of the codebase treats as non-string, plus lower-case
   ``@property`` aliases (``settings.domain``, ``settings.api_port``, ...)
   so existing callers keep working without modification.
"""
import os

from dotenv import load_dotenv
load_dotenv()


# ==========================================================================
# USER-SPECIFIED CONFIG CLASS — VERBATIM, DO NOT MODIFY
# ==========================================================================
class Config:
    ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD")
    DOMAIN = os.environ.get("DOMAIN")
    MAIL_HOSTNAME=os.environ.get("MAIL_HOSTNAME")
    FROM_ADDRESS=os.environ.get("FROM_ADDRESS")
    SENDER_NAME=os.environ.get("SENDER_NAME")
    REPLY_TO_ADDRESS=os.environ.get("REPLY_TO_ADDRESS")
    SUBJECT_PREFIX=os.environ.get("SUBJECT_PREFIX")
    ENVIRONMENT=os.environ.get("ENVIRONMENT")
    API_HOST=os.environ.get("API_HOST")
    API_PORT=os.environ.get("API_PORT")
    API_IP_WHITELIST=os.environ.get("API_IP_WHITELIST")
    ADMIN_IP_WHITELIST=os.environ.get("ADMIN_IP_WHITELIST")
    ADMIN_EMAIL=os.environ.get("ADMIN_EMAIL")
    JWT_SECRET=os.environ.get("JWT_SECRET")
    JWT_TTL_SECONDS=os.environ.get("JWT_TTL_SECONDS")
    ADMIN_SESSION_IDLE_TIMEOUT=os.environ.get("ADMIN_SESSION_IDLE_TIMEOUT")
    BRUTE_FORCE_MAX_ATTEMPTS=os.environ.get("BRUTE_FORCE_MAX_ATTEMPTS")
    BRUTE_FORCE_LOCKOUT_SECONDS=os.environ.get("BRUTE_FORCE_LOCKOUT_SECONDS")
    PASSWORD_MIN_LENGTH=os.environ.get("PASSWORD_MIN_LENGTH")
    RECOVERY_EMAIL=os.environ.get("RECOVERY_EMAIL")
    SMTP_SUBMISSION_ENABLED=os.environ.get("SMTP_SUBMISSION_ENABLED")
    SMTP_STARTTLS_PORT=os.environ.get("SMTP_STARTTLS_PORT")
    SMTP_IMPLICIT_TLS_PORT=os.environ.get("SMTP_IMPLICIT_TLS_PORT")
    SMTP_INBOUND_PORT_25_ENABLED=os.environ.get("SMTP_INBOUND_PORT_25_ENABLED")
    SMTP_MAX_MESSAGE_BYTES=os.environ.get("SMTP_MAX_MESSAGE_BYTES")
    SMTP_USER_PASSWORD_ROTATION_DAYS=os.environ.get("SMTP_USER_PASSWORD_ROTATION_DAYS")
    ALLOWED_RECIPIENT_DOMAINS=os.environ.get("ALLOWED_RECIPIENT_DOMAINS")
    BLOCKED_RECIPIENT_DOMAINS=os.environ.get("BLOCKED_RECIPIENT_DOMAINS")
    BUSINESS_HOURS_START=os.environ.get("BUSINESS_HOURS_START")
    BUSINESS_HOURS_END=os.environ.get("BUSINESS_HOURS_END")
    TIMEZONE=os.environ.get("TIMEZONE")
    REDIS_URL=os.environ.get("REDIS_URL")
    REDIS_PASSWORD=os.environ.get("REDIS_PASSWORD")
    REDIS_NO_PERSISTENCE=os.environ.get("REDIS_NO_PERSISTENCE")
    AES_KEY_B64=os.environ.get("AES_KEY_B64")
    API_KEY_SALT=os.environ.get("API_KEY_SALT")
    DKIM_SELECTOR=os.environ.get("DKIM_SELECTOR")
    DKIM_ROTATION_DAYS=os.environ.get("DKIM_ROTATION_DAYS")
    DKIM_PRIVATE_KEY_PEM=os.environ.get("DKIM_PRIVATE_KEY_PEM")
    API_KEYS=os.environ.get("API_KEYS")
    RATE_PER_MINUTE_PER_KEY=os.environ.get("RATE_PER_MINUTE_PER_KEY")
    RATE_PER_HOUR_PER_KEY=os.environ.get("RATE_PER_HOUR_PER_KEY")
    RATE_PER_DAY_GLOBAL=os.environ.get("RATE_PER_DAY_GLOBAL")
    WARMUP_ENABLED=os.environ.get("WARMUP_ENABLED")
    WARMUP_START_PER_HOUR=os.environ.get("WARMUP_START_PER_HOUR")
    WARMUP_DOUBLE_EVERY_HOURS=os.environ.get("WARMUP_DOUBLE_EVERY_HOURS")
    TTL_SECONDS=os.environ.get("TTL_SECONDS")
    CLEANUP_INTERVAL_SECONDS=os.environ.get("CLEANUP_INTERVAL_SECONDS")
    SELF_PING_ENABLED=os.environ.get("SELF_PING_ENABLED")
    SELF_PING_INTERVAL_SECONDS=os.environ.get("SELF_PING_INTERVAL_SECONDS")
    AUTO_IP_DETECTION_ENABLED=os.environ.get("AUTO_IP_DETECTION_ENABLED")
    AUTO_IP_DETECTION_INTERVAL_SECONDS=os.environ.get("AUTO_IP_DETECTION_INTERVAL_SECONDS")
    SERVICE_URL=os.environ.get("SERVICE_URL")
    OUTBOUND_SMTP_TIMEOUT=os.environ.get("OUTBOUND_SMTP_TIMEOUT")
    OUTBOUND_TLS_REQUIRED=os.environ.get("OUTBOUND_TLS_REQUIRED")
    OUTBOUND_MAX_RETRIES=os.environ.get("OUTBOUND_MAX_RETRIES")
    AUTO_PAUSE_ON_BLACKLIST=os.environ.get("AUTO_PAUSE_ON_BLACKLIST")
    SYSTEM_ALERT_WEBHOOK_URL=os.environ.get("SYSTEM_ALERT_WEBHOOK_URL")
    WEBHOOK_HMAC_SECRET=os.environ.get("WEBHOOK_HMAC_SECRET")
    DAILY_SUMMARY_TO=os.environ.get("DAILY_SUMMARY_TO")
    DAILY_SUMMARY_FROM=os.environ.get("DAILY_SUMMARY_FROM")
    LOG_LEVEL=os.environ.get("LOG_LEVEL")
    LOG_TO_STDOUT_ONLY=os.environ.get("LOG_TO_STDOUT_ONLY")

config = Config()



def _get_int(name: str, default: int = 0) -> int:
    v = os.environ.get(name)
    if v is None or v == "":
        return default
    try:
        return int(str(v).strip())
    except (TypeError, ValueError):
        return default


def _get_bool(name: str, default: bool = False) -> bool:
    v = os.environ.get(name)
    if v is None or v == "":
        return default
    return str(v).strip().lower() in ("1", "true", "yes", "on", "y", "t")


def _get_list(name: str, default=None) -> list:
    v = os.environ.get(name)
    if v is None or v == "":
        return list(default) if default else []
    return [x.strip() for x in v.split(",") if x.strip()]


class _SettingsAdapter:
    app_name: str = "smtp-relay"
    spam_keyword_list: list = [
        "viagra", "cialis", "lottery", "winner", "free money",
        "casino", "porn", "adult", "escort", "loan", "bitcoin giveaway",
        "make money fast", "work from home", "miracle cure",
        "limited time offer", "act now",
    ]

    # --- str fields (lower-case aliases with defaults) ---
    @property
    def admin_password(self) -> str: return config.ADMIN_PASSWORD or ""
    @property
    def domain(self) -> str: return config.DOMAIN or "api-solv-rix-ai.top"
    @property
    def mail_hostname(self) -> str: return config.MAIL_HOSTNAME or f"mail.{self.domain}"
    @property
    def from_address(self) -> str: return config.FROM_ADDRESS or f"noreply@{self.domain}"
    @property
    def sender_name(self) -> str: return config.SENDER_NAME or "SMTP Relay"
    @property
    def environment(self) -> str: return config.ENVIRONMENT or "production"
    @property
    def admin_email(self) -> str: return config.ADMIN_EMAIL or ""
    @property
    def timezone(self) -> str: return config.TIMEZONE or "UTC"
    @property
    def redis_url(self) -> str: return config.REDIS_URL or "redis://localhost:6379/0"
    @property
    def redis_password(self) -> str: return config.REDIS_PASSWORD or ""
    @property
    def dkim_selector(self) -> str: return config.DKIM_SELECTOR or "default"
    @property
    def dkim_private_key_pem(self) -> str: return config.DKIM_PRIVATE_KEY_PEM or ""
    @property
    def log_level(self) -> str: return config.LOG_LEVEL or "INFO"

    # --- int fields ---
    @property
    def brute_force_max_attempts(self) -> int: return _get_int("BRUTE_FORCE_MAX_ATTEMPTS", 5)
    @property
    def smtp_max_message_bytes(self) -> int: return _get_int("SMTP_MAX_MESSAGE_BYTES", 102400)
    @property
    def dkim_rotation_days(self) -> int: return _get_int("DKIM_ROTATION_DAYS", 365)
    @property
    def rate_per_minute_per_key(self) -> int: return _get_int("RATE_PER_MINUTE_PER_KEY", 60)
    @property
    def rate_per_hour_per_key(self) -> int: return _get_int("RATE_PER_HOUR_PER_KEY", 1000)
    @property
    def ttl_seconds(self) -> int: return _get_int("TTL_SECONDS", 900)
    @property
    def cleanup_interval_seconds(self) -> int: return _get_int("CLEANUP_INTERVAL_SECONDS", 30)
    @property
    def outbound_smtp_timeout(self) -> int: return _get_int("OUTBOUND_SMTP_TIMEOUT", 30)
    @property
    def outbound_max_retries(self) -> int: return _get_int("OUTBOUND_MAX_RETRIES", 3)

    # --- bool fields ---
    @property
    def outbound_tls_required(self) -> bool: return _get_bool("OUTBOUND_TLS_REQUIRED", True)
    @property
    def auto_pause_on_blacklist(self) -> bool: return _get_bool("AUTO_PAUSE_ON_BLACKLIST", True)
    @property
    def log_to_stdout_only(self) -> bool: return _get_bool("LOG_TO_STDOUT_ONLY", True)

    # --- list fields ---
    @property
    def allowed_recipient_domains(self) -> list: return _get_list("ALLOWED_RECIPIENT_DOMAINS")
    @property
    def blocked_recipient_domains(self) -> list: return _get_list("BLOCKED_RECIPIENT_DOMAINS")

    # --- UPPER_CASE passthrough ---
    def __getattr__(self, name: str):
        return getattr(config, name)


# ==========================================================================
# Singletons
# ==========================================================================
settings = _SettingsAdapter()


def get_settings() -> _SettingsAdapter:
    """Return the singleton settings adapter (backward-compat helper)."""
    return settings
