"""
Outbound email sender.

MODE: relay-only (port 465, TLS, AUTH).
The service never receives inbound email. Port 465 is outbound-only via aiosmtplib.
No port mapping is exposed by docker-compose — sending happens from inside the container.
"""
from __future__ import annotations

import email.utils
import time
import uuid
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Optional

import aiosmtplib

from .config import settings
from .dkim_signer import ensure_dkim_keypair, sign_message
from .logger import log_smtp


async def send_email(to_addr: str, subject: str, body_text: str, body_html: Optional[str] = None) -> dict:
    message_id = str(uuid.uuid4())
    recipient_domain = to_addr.split("@", 1)[-1].lower() if "@" in to_addr else ""
    start = time.perf_counter()

    if body_html is None:
        body_html = f"<pre>{body_text}</pre>"

    from email.message import EmailMessage
    msg = MIMEMultipart("alternative")
    msg["From"] = settings.MAIL_FROM
    msg["To"] = to_addr
    msg["Subject"] = subject
    msg["Message-ID"] = f"<{message_id}@{settings.SENDING_DOMAIN}>"
    msg["Date"] = email.utils.formatdate(localtime=False)
    msg.attach(MIMEText(body_text, "plain", "utf-8"))
    msg.attach(MIMEText(body_html, "html", "utf-8"))

    error: Optional[str] = None
    mx_used: Optional[str] = settings.SMTP_RELAY_HOST
    dkim_signed = False

    try:
        # DKIM sign
        selector = "smtp1"
        dkim_doc = await ensure_dkim_keypair(selector)
        signed_bytes = sign_message(
            msg.as_bytes(),
            selector=selector,
            private_pem=dkim_doc["private_pem"],
            domain=settings.SENDING_DOMAIN,
        )
        dkim_signed = True

        # Send via relay (port 465 implicit TLS)
        await aiosmtplib.send(
            signed_bytes,
            sender=settings.MAIL_FROM,
            recipients=[to_addr],
            hostname=settings.SMTP_RELAY_HOST,
            port=settings.SMTP_RELAY_PORT,
            username=settings.SMTP_RELAY_USER,
            password=settings.SMTP_RELAY_PASS,
            use_tls=True,             # implicit TLS on 465
            start_tls=False,
            timeout=30.0,
        )
        status = "sent"
    except Exception as exc:  # noqa: BLE001
        error = f"{type(exc).__name__}: {exc}"
        status = "failed"
    finally:
        elapsed_ms = (time.perf_counter() - start) * 1000.0
        await log_smtp(
            message_id=message_id,
            recipient_domain=recipient_domain,
            delivery_time_ms=elapsed_ms,
            dkim_signed=dkim_signed,
            mx_server_used=mx_used,
            error_details=error,
        )

    return {"message_id": message_id, "status": status, "error": error}
