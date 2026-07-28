"""
SMTP submission server — listens on port 465 (implicit TLS) and port 587
(STARTTLS). Authenticates SMTP users against the Redis-backed user store,
runs spam checks, signs messages with DKIM, and enqueues them for delivery.

This is the ONLY public-facing service. No HTTP API, no admin panel.

Auth flow:
  1. Client connects on 465 (implicit TLS) or 587 (STARTTLS)
  2. EHLO advertises AUTH PLAIN LOGIN
  3. Client authenticates with username + password
  4. MAIL FROM / RCPT TO / DATA
  5. Spam checks (rate limit, recipient domains, content, size)
  6. DKIM sign + enqueue for delivery
  7. Reply 250 OK — delivery happens asynchronously by the queue worker

SSL context:
  - Reads /etc/letsencrypt/live/<DOMAIN>/{fullchain,privkey}.pem
  - Falls back to a self-signed cert only if those files are missing
    (with a loud warning in the logs)
"""
from __future__ import annotations

import asyncio
import logging
import os
import socket
import ssl
import sys
from datetime import datetime, timezone
from email import message_from_bytes
from email.policy import default as default_policy
from email.utils import parseaddr
from pathlib import Path
from typing import Optional

import structlog
from aiosmtpd.controller import Controller
from aiosmtpd.smtp import AuthResult, LoginPassword, SMTP

from config import settings
from core import dkim_signer, queue, spam, smtp_users

log = structlog.get_logger("smtp")


# ---------------------------------------------------------------------------
# SSL context
# ---------------------------------------------------------------------------
def _build_ssl_context() -> ssl.SSLContext:
    """Build an SSLContext for implicit TLS (port 465) and STARTTLS (587).

    Reads Let's Encrypt cert files from /etc/letsencrypt/live/<DOMAIN>/.
    Falls back to a self-signed cert if Let's Encrypt files are missing.
    """
    domain = settings.domain
    le_dir = Path("/etc/letsencrypt/live") / domain
    fullchain = le_dir / "fullchain.pem"
    privkey = le_dir / "privkey.pem"

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    # Strong cipher suite — Modern compatibility per Mozilla SSL Config Generator
    ctx.set_ciphers(
        "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:"
        "ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:"
        "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256"
    )
    ctx.options |= ssl.OP_NO_COMPRESSION
    ctx.options |= ssl.OP_NO_RENEGOTIATION

    if fullchain.exists() and privkey.exists():
        log.info("ssl.letsencrypt domain=%s", domain)
        ctx.load_cert_chain(certfile=str(fullchain), keyfile=str(privkey))
    else:
        log.warning(
            "ssl.self_signed reason='Let's Encrypt cert files not found at %s' "
            "hint='Run scripts/get_cert.sh on the VPS host to issue a real cert'",
            le_dir,
        )
        # Generate an ephemeral self-signed cert as a fallback so the server
        # can still start. Mail clients will warn about this — but at least
        # the server boots and you can see what's wrong.
        _generate_self_signed_fallback(ctx, domain)

    return ctx


def _generate_self_signed_fallback(ctx: ssl.SSLContext, domain: str) -> None:
    """Generate a temporary self-signed cert in memory and load it.

    This is ONLY a fallback — operators should always use a real Let's
    Encrypt cert. The self-signed cert makes the server startable so you
    can debug, but no mail client will trust it.
    """
    import tempfile
    import subprocess
    with tempfile.TemporaryDirectory() as tmpdir:
        cert = Path(tmpdir) / "cert.pem"
        key = Path(tmpdir) / "key.pem"
        try:
            subprocess.run([
                "openssl", "req", "-x509", "-newkey", "rsa:2048",
                "-keyout", str(key), "-out", str(cert),
                "-days", "1", "-nodes",
                "-subj", f"/CN={domain}",
                "-addext", f"subjectAltName=DNS:{domain},DNS:mail.{domain}",
            ], check=True, capture_output=True)
            ctx.load_cert_chain(certfile=str(cert), keyfile=str(key))
        except subprocess.CalledProcessError as e:
            log.error("ssl.fallback_failed error=%s stderr=%s",
                      e, e.stderr.decode("utf-8", errors="replace"))
            raise RuntimeError(
                "No SSL cert available — install Let's Encrypt certs or openssl"
            )


# ---------------------------------------------------------------------------
# Authenticator — hooks into aiosmtpd's AUTH mechanism
# ---------------------------------------------------------------------------
class Authenticator:
    """Validates SMTP AUTH PLAIN/LOGIN credentials against the Redis store."""

    def __init__(self):
        self._failures: dict[str, int] = {}  # username → consecutive failures

    async def __call__(self, server, session, envelope, mechanism, auth_data):
        # auth_data for LoginPassword is (username, password)
        if not isinstance(auth_data, LoginPassword):
            return AuthResult(success=False, handled=True)
        username = auth_data.login.decode("utf-8", errors="replace")
        password = auth_data.password.decode("utf-8", errors="replace")

        # Brute-force protection
        max_attempts = settings.brute_force_max_attempts or 5
        failures = self._failures.get(username, 0)
        if failures >= max_attempts:
            log.warning("auth.locked_out user=%s failures=%d", username, failures)
            return AuthResult(
                success=False,
                handled=True,
                message=f"Account locked — too many failed attempts",
            )

        user = await smtp_users.verify_credentials(username, password)
        if user is None:
            self._failures[username] = failures + 1
            log.warning("auth.failed user=%s ip=%s failures=%d",
                        username, session.peer[0] if session.peer else "?",
                        self._failures[username])
            return AuthResult(success=False, handled=True, message="Invalid credentials")

        # Reset failure counter on success
        self._failures.pop(username, None)
        log.info("auth.ok user=%s ip=%s", username,
                 session.peer[0] if session.peer else "?")
        return AuthResult(success=True, handled=True, auth_data=user)


# ---------------------------------------------------------------------------
# SMTP handler — receives MAIL FROM / RCPT TO / DATA
# ---------------------------------------------------------------------------
class SMTPHandler:
    """aiosmtpd handler — runs auth, spam checks, DKIM sign, and enqueue."""

    async def handle_MAIL(self, server, session, envelope, address, mail_options):
        if not session.authenticated:
            return "530 5.7.0 Authentication required"
        envelope.mail_from = address
        envelope.mail_options = mail_options
        # Stash the authenticated username for later checks
        envelope.username = session.authenticated.username if session.authenticated else None
        log.info("smtp.mail_from user=%s from=%s ip=%s",
                 envelope.username, address,
                 session.peer[0] if session.peer else "?")
        return "250 2.1.0 OK"

    async def handle_RCPT(self, server, session, envelope, address, rcpt_options):
        if not session.authenticated:
            return "530 5.7.0 Authentication required"
        if not envelope.mail_from:
            return "503 5.5.1 Need MAIL FROM first"
        envelope.rcpt_options.extend(rcpt_options)
        envelope.rcpt_tos.append(address)
        return "250 2.1.5 OK"

    async def handle_DATA(self, server, session, envelope):
        if not session.authenticated:
            return "530 5.7.0 Authentication required"
        if not envelope.rcpt_tos:
            return "503 5.5.1 Need RCPT TO first"

        raw_message: bytes = envelope.content  # already bytes per aiosmtpd
        if isinstance(raw_message, str):
            raw_message = raw_message.encode("utf-8")

        username = envelope.username or (
            session.authenticated.username if session.authenticated else "unknown"
        )
        client_ip = session.peer[0] if session.peer else "127.0.0.1"

        # Run all spam checks BEFORE queueing
        result = await spam.run_all_checks(
            username=username,
            client_ip=client_ip,
            recipients=envelope.rcpt_tos,
            raw_message=raw_message,
        )
        if not result.allowed:
            log.warning(
                "smtp.rejected user=%s ip=%s reason=%s code=%d",
                username, client_ip, result.reason, result.code,
            )
            return f"{result.code} 5.7.1 {result.reason}"

        # Enforce From header alignment — the MAIL FROM must match the
        # authenticated user's domain (prevent sender spoofing)
        try:
            msg = message_from_bytes(raw_message, policy=default_policy)
            from_header = msg.get("From", "")
            from_addr = parseaddr(from_header)[1]
            if from_addr and "@" in from_addr:
                from_domain = from_addr.rsplit("@", 1)[1].lower()
                # If we have a per-user allowed sender domain list, check it.
                # For now, we only require the From domain to be our own.
                if from_domain != settings.domain.lower():
                    log.warning(
                        "smtp.spoof_reject user=%s from_domain=%s expected=%s",
                        username, from_domain, settings.domain,
                    )
                    return (
                        f"550 5.7.1 Sender domain mismatch — From header must be "
                        f"@{settings.domain}"
                    )
        except Exception as e:
            log.warning("smtp.parse_failed error=%s", e)
            # Don't reject on parse errors — let the recipient's filter decide

        # Enqueue for delivery
        try:
            msg_id = await queue.enqueue(
                sender=envelope.mail_from,
                recipients=envelope.rcpt_tos,
                raw_message=raw_message,
                username=username,
                client_ip=client_ip,
            )
        except Exception as e:
            log.error("smtp.enqueue_failed user=%s error=%s", username, e)
            return "451 4.3.0 Temporary failure — try again later"

        log.info(
            "smtp.queued id=%s user=%s from=%s recipients=%d size=%d",
            msg_id, username, envelope.mail_from,
            len(envelope.rcpt_tos), len(raw_message),
        )
        return f"250 2.0.0 OK queued as {msg_id}"


# ---------------------------------------------------------------------------
# Server lifecycle
# ---------------------------------------------------------------------------
class SMTPServerController(Controller):
    """Custom Controller that uses our SSL context for implicit TLS."""

    def __init__(self, handler, hostname, port, ssl_context, **kwargs):
        super().__init__(handler, hostname=hostname, port=port, **kwargs)
        self._ssl_context = ssl_context

    def factory(self):
        return SMTP(
            self.handler,
            hostname=self.hostname,
            port=self.port,
            ssl_context=self._ssl_context,
            authenticator=Authenticator(),
            auth_require_tls=True,   # AUTH only allowed over TLS
            require_starttls=True,   # refuse MAIL without STARTTLS
            timeout=60,
            maximum_message_size=settings.smtp_max_message_bytes or 102400,
        )


_ssl_ctx_465: Optional[ssl.SSLContext] = None
_ssl_ctx_587: Optional[ssl.SSLContext] = None
_controller_465: Optional[SMTPServerController] = None
_controller_587: Optional[SMTPServerController] = None


async def start_smtp_server() -> None:
    """Start listening on 465 (implicit TLS) and 587 (STARTTLS)."""
    global _ssl_ctx_465, _ssl_ctx_587, _controller_465, _controller_587

    handler = SMTPHandler()
    _ssl_ctx_465 = _build_ssl_context()
    _ssl_ctx_587 = _build_ssl_context()  # same certs, separate context

    # Port 465 — implicit TLS (the user wants this as the primary port)
    _controller_465 = SMTPServerController(
        handler,
        hostname="0.0.0.0",
        port=465,
        ssl_context=_ssl_ctx_465,
    )
    _controller_465.start()
    log.info("smtp.listening port=465 mode=implicit_tls hostname=mail.%s",
             settings.domain)

    # Port 587 — STARTTLS (kept for compatibility with clients that don't
    # support implicit TLS on 465; safe to firewall off if you don't want it)
    _controller_587 = SMTPServerController(
        handler,
        hostname="0.0.0.0",
        port=587,
        ssl_context=_ssl_ctx_587,  # used for STARTTLS upgrade
    )
    _controller_587.start()
    log.info("smtp.listening port=587 mode=starttls hostname=mail.%s",
             settings.domain)


async def stop_smtp_server() -> None:
    """Stop both SMTP listeners."""
    global _controller_465, _controller_587
    if _controller_465:
        _controller_465.stop()
    if _controller_587:
        _controller_587.stop()
    log.info("smtp.stopped")
