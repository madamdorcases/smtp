"""
Spam protection — runs on every inbound message BEFORE it is queued for
outbound delivery. If any check fails, the SMTP handler rejects the message
with a 5xx code so the client knows it was refused.

Checks (in order):
 1. Rate limit per-user  (sliding window: per-minute + per-hour)
 2. Blocked recipient domains (env: BLOCKED_RECIPIENT_DOMAINS)
 3. Allowed recipient domains whitelist (env: ALLOWED_RECIPIENT_DOMAINS)
 4. Spam keyword filter   (env: SPAM_KEYWORDS or built-in list)
 5. Recipient count limit (max 50 recipients per message)
 6. Message size limit    (env: SMTP_MAX_MESSAGE_BYTES)

NOTE: DNSBL checks on the connecting client IP are also supported but
disabled by default — most legit SMTP submission clients will be on dynamic
IPs that aren't on DNSBLs anyway, and DNSBL lookups add latency. Enable
with ENABLE_DNSBL=true.
"""
from __future__ import annotations

import logging
import os
import re
import socket
from email import message_from_bytes
from email.policy import default as default_policy
from typing import Iterable, Optional

from config import settings
from core.redis_client import get_redis

log = logging.getLogger("spam")

# Built-in spam keywords — used if SPAM_KEYWORDS env var is not set.
_DEFAULT_SPAM_KEYWORDS = [
    "viagra", "cialis", "lottery", "winner", "free money",
    "casino", "porn", "adult", "escort", "loan", "bitcoin giveaway",
    "make money fast", "work from home", "miracle cure",
    "limited time offer", "act now",
]

# DNSBL servers to query when ENABLE_DNSBL=true
_DEFAULT_DNSBL_SERVERS = [
    "zen.spamhaus.org",
    "bl.spamcop.net",
    "dnsbl.sorbs.net",
]

_MAX_RECIPIENTS_PER_MESSAGE = 50


class SpamResult:
    """Outcome of a spam check."""
    __slots__ = ("allowed", "reason", "code")

    def __init__(self, allowed: bool, reason: str = "", code: int = 550):
        self.allowed = allowed
        self.reason = reason
        self.code = code

    @classmethod
    def ok(cls) -> "SpamResult":
        return cls(True, "", 250)

    @classmethod
    def reject(cls, reason: str, code: int = 550) -> "SpamResult":
        return cls(False, reason, code)


def _get_spam_keywords() -> list[str]:
    raw = (settings.spam_keyword_list if isinstance(settings.spam_keyword_list, list)
           else _DEFAULT_SPAM_KEYWORDS)
    if not raw:
        return _DEFAULT_SPAM_KEYWORDS
    return [k.lower() for k in raw]


async def check_dnsbl(client_ip: str) -> Optional[str]:
    """Return the DNSBL zone that listed ``client_ip``, or None if clean.

    Only called when ENABLE_DNSBL=true.
    """
    # Convert "1.2.3.4" → "4.3.2.1"
    try:
        parts = client_ip.split(".")
        if len(parts) != 4:
            return None
        reversed_ip = ".".join(reversed(parts))
    except Exception:
        return None

    import dns.resolver
    for zone in _DEFAULT_DNSBL_SERVERS:
        try:
            query = f"{reversed_ip}.{zone}"
            answers = dns.resolver.resolve(query, "A", lifetime=2.0)
            if answers:
                return zone
        except dns.resolver.NXDOMAIN:
            continue
        except dns.resolver.Timeout:
            continue
        except Exception:
            continue
    return None


async def check_rate_limit(username: str) -> SpamResult:
    """Per-user rate limit: ``RATE_PER_MINUTE_PER_KEY`` per minute,
    ``RATE_PER_HOUR_PER_KEY`` per hour.

    Uses Redis sorted sets with timestamp scores for a true sliding window.
    """
    r = get_redis()
    now = int(__import__("time").time())
    minute_key = f"rl:{username}:min"
    hour_key = f"rl:{username}:hour"

    pipe = r.pipeline()
    # Remove entries older than the window
    pipe.zremrangebyscore(minute_key, 0, now - 60)
    pipe.zremrangebyscore(hour_key, 0, now - 3600)
    # Count current entries
    pipe.zcard(minute_key)
    pipe.zcard(hour_key)
    pipe.execute()

    _, _, minute_count, hour_count = await pipe.execute()

    if minute_count >= settings.rate_per_minute_per_key:
        log.warning("rate_limit.hit user=%s window=min count=%d", username, minute_count)
        return SpamResult.reject(
            f"Rate limit exceeded: {minute_count}/min (max {settings.rate_per_minute_per_key}/min)",
            code=450,  # 4xx = temporary, client should retry later
        )
    if hour_count >= settings.rate_per_hour_per_key:
        log.warning("rate_limit.hit user=%s window=hour count=%d", username, hour_count)
        return SpamResult.reject(
            f"Rate limit exceeded: {hour_count}/hour (max {settings.rate_per_hour_per_key}/hour)",
            code=450,
        )

    # Add current request with a unique member (timestamp + counter)
    member = f"{now}:{minute_count}:{hour_count}"
    pipe = r.pipeline()
    pipe.zadd(minute_key, {member: now})
    pipe.zadd(hour_key, {member: now})
    pipe.expire(minute_key, 120)
    pipe.expire(hour_key, 7200)
    await pipe.execute()
    return SpamResult.ok()


def check_recipient_domains(recipients: Iterable[str]) -> SpamResult:
    """Check recipients against allowed/blocked domain lists.

    ALSO enforces SEND-ONLY mode: any RCPT TO addressed to our own domain
    (api-solv-rix-ai.top) is refused with a 550 — this server may not be
    used to receive mail. Only outbound mail to OTHER domains is allowed.
    """
    allowed = settings.allowed_recipient_domains or []
    blocked = settings.blocked_recipient_domains or []
    allowed_set = {d.lower().lstrip("@") for d in allowed}
    blocked_set = {d.lower().lstrip("@") for d in blocked}
    our_domain = (settings.domain or "").lower()

    for rcpt in recipients:
        # Extract domain from "user@domain" or "User <user@domain>"
        addr = rcpt.strip()
        if "<" in addr and ">" in addr:
            addr = addr[addr.find("<") + 1:addr.find(">")]
        if "@" not in addr:
            return SpamResult.reject(f"Invalid recipient address: {rcpt}", code=501)
        domain = addr.rsplit("@", 1)[1].lower().strip(">")

        # --- SEND-ONLY ENFORCEMENT ---
        # Refuse mail addressed to our own domain — this server SENDS only,
        # it does not RECEIVE. Without this, someone could SMTP-auth and
        # deliver mail to e.g. victim@api-solv-rix-ai.top via the queue.
        if our_domain and domain == our_domain:
            log.warning("send_only.reject rcpt=%s (own domain)", rcpt)
            return SpamResult.reject(
                f"This server is send-only — cannot deliver to @{domain}",
                code=550,
            )

        if domain in blocked_set:
            return SpamResult.reject(
                f"Recipient domain '{domain}' is blocked", code=550
            )
        if allowed_set and domain not in allowed_set:
            return SpamResult.reject(
                f"Recipient domain '{domain}' is not in the allowed list",
                code=550,
            )
    return SpamResult.ok()


def check_message_content(raw_message: bytes) -> SpamResult:
    """Scan the message body for spam keywords. Returns reject on match."""
    try:
        msg = message_from_bytes(raw_message, policy=default_policy)
    except Exception:
        # If we can't parse it, let the recipient's spam filter handle it
        return SpamResult.ok()

    # Combine subject + body for keyword scan
    subject = str(msg.get("Subject", "")).lower()
    body_parts: list[str] = [subject]
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_type() == "text/plain":
                try:
                    body_parts.append(part.get_content().lower())
                except Exception:
                    pass
            elif part.get_content_type() == "text/html":
                try:
                    body_parts.append(part.get_content().lower())
                except Exception:
                    pass
    else:
        try:
            body_parts.append(str(msg.get_content()).lower())
        except Exception:
            pass

    full_text = "\n".join(body_parts)
    for keyword in _get_spam_keywords():
        if keyword in full_text:
            log.warning("spam.keyword_hit keyword=%r", keyword)
            return SpamResult.reject(
                f"Message rejected: matches spam filter ('{keyword}')",
                code=522,
            )
    return SpamResult.ok()


def check_message_size(raw_message: bytes) -> SpamResult:
    """Enforce SMTP_MAX_MESSAGE_BYTES."""
    max_bytes = settings.smtp_max_message_bytes or 102400
    if len(raw_message) > max_bytes:
        return SpamResult.reject(
            f"Message too large: {len(raw_message)} bytes (max {max_bytes})",
            code=552,
        )
    return SpamResult.ok()


def check_recipient_count(recipients: list[str]) -> SpamResult:
    """Limit recipients per message."""
    if len(recipients) > _MAX_RECIPIENTS_PER_MESSAGE:
        return SpamResult.reject(
            f"Too many recipients: {len(recipients)} (max {_MAX_RECIPIENTS_PER_MESSAGE})",
            code=452,
        )
    return SpamResult.ok()


# --- Header-injection + dangerous-attachment checks (added for verification-email use case) ---

# Header-injection: a malicious client may try to inject CRLF into Subject /
# From / To headers to add extra BCC, etc. Python's email parser rejects
# these but we still scan raw bytes for the pattern.
_HEADER_INJECTION_PATTERN = re.compile(rb"\r\n(?![\r\n])")

# Attachment extensions that are commonly used to deliver malware.
# Refused outright — verification emails should never carry attachments.
_BLOCKED_ATTACHMENT_EXTS = {
    ".exe", ".scr", ".bat", ".cmd", ".com", ".pif", ".vbs", ".js", ".jar",
    ".msi", ".ps1", ".sh", ".deb", ".rpm", ".dmg", ".app",
    ".zip", ".rar", ".7z", ".tar.gz", ".tgz",  # archives commonly used for malware
    ".iso", ".img",
}


def check_header_injection(raw_message: bytes) -> SpamResult:
    """Reject messages with bare CRLF inside headers (header injection attack).

    A legit RFC 5322 message uses CRLF\\CRLF to separate headers from body.
    Extra bare CRLFs inside the header block can be used to inject extra
    headers (e.g. Bcc) — a classic spam vector.
    """
    # Find the first empty line (header/body separator)
    sep = raw_message.find(b"\r\n\r\n")
    if sep == -1:
        sep = raw_message.find(b"\n\n")
        if sep == -1:
            # No body separator at all — malformed, but let it through
            return SpamResult.ok()
        header_block = raw_message[:sep]
        sep_char = b"\n"
    else:
        header_block = raw_message[:sep]
        sep_char = b"\r\n"

    # A folded header line continues with whitespace. A bare CRLF NOT followed
    # by whitespace AND NOT at the separator is an injection attempt.
    lines = header_block.split(sep_char)
    for line in lines[1:]:  # skip the first line (the "From " envelope sometimes)
        # If the line is non-empty AND doesn't start with whitespace AND
        # doesn't look like a header (no colon), it's suspicious.
        if line and not line[:1].isspace() and b":" not in line:
            log.warning("header_injection.suspect line_prefix=%r",
                        line[:60])
            return SpamResult.reject(
                "Message rejected: malformed headers (possible injection)",
                code=554,
            )
    return SpamResult.ok()


def check_attachments(raw_message: bytes) -> SpamResult:
    """Refuse messages carrying dangerous attachment types.

    Verification emails should NEVER carry attachments. We allow text/plain
    and text/html only. Any other MIME part with a filename ending in a
    blocked extension is refused.
    """
    try:
        msg = message_from_bytes(raw_message, policy=default_policy)
    except Exception:
        return SpamResult.ok()  # let other checks decide

    for part in msg.walk():
        if part.is_multipart():
            continue
        filename = part.get_filename()
        if not filename:
            continue
        # Strip directory traversal + lowercase
        filename = os.path.basename(filename).lower()
        _, ext = os.path.splitext(filename)
        if ext in _BLOCKED_ATTACHMENT_EXTS:
            log.warning("attachment.blocked filename=%s ext=%s", filename, ext)
            return SpamResult.reject(
                f"Attachment type '{ext}' is blocked for security",
                code=552,
            )
    return SpamResult.ok()


async def run_all_checks(
    username: str,
    client_ip: str,
    recipients: list[str],
    raw_message: bytes,
) -> SpamResult:
    """Run all spam/protection checks. Returns the first failure, or ok.

    Order (fastest → slowest):
      1. DNSBL on client IP            (optional, env-gated)
      2. Rate limit per user           (Redis zset, ~1ms)
      3. Recipient count limit         (in-memory, ~0ms)
      4. Recipient domain checks       (in-memory, ~0ms)
         ── includes SEND-ONLY enforcement (refuse our own domain)
      5. Message size limit            (in-memory, ~0ms)
      6. Header-injection check        (in-memory, ~0ms)
      7. Dangerous attachment check    (in-memory, ~0ms)
      8. Spam keyword filter           (in-memory, ~1ms)
    """
    # 1. DNSBL (optional)
    if (settings.AUTO_PAUSE_ON_BLACKLIST or False) and client_ip != "127.0.0.1":
        listed = await check_dnsbl(client_ip)
        if listed:
            log.warning("dnsbl.listed ip=%s zone=%s", client_ip, listed)
            return SpamResult.reject(
                f"Client IP {client_ip} is listed on DNSBL {listed}",
                code=521,
            )

    # 2. Rate limit
    rl = await check_rate_limit(username)
    if not rl.allowed:
        return rl

    # 3. Recipient count
    rc = check_recipient_count(recipients)
    if not rc.allowed:
        return rc

    # 4. Recipient domains (allowed/blocked + send-only enforcement)
    rd = check_recipient_domains(recipients)
    if not rd.allowed:
        return rd

    # 5. Message size
    sz = check_message_size(raw_message)
    if not sz.allowed:
        return sz

    # 6. Header injection
    hi = check_header_injection(raw_message)
    if not hi.allowed:
        return hi

    # 7. Dangerous attachments
    at = check_attachments(raw_message)
    if not at.allowed:
        return at

    # 8. Spam keywords
    sk = check_message_content(raw_message)
    if not sk.allowed:
        return sk

    return SpamResult.ok()
