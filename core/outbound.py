"""
Outbound SMTP relay — delivers signed messages to recipient MX servers.

Uses ``aiosmtplib`` for async SMTP delivery with:
  - MX lookup via dnspython
  - Mandatory STARTTLS when ``OUTBOUND_TLS_REQUIRED=true`` (default)
  - Implicit TLS (port 465) supported if STARTTLS isn't available
  - Retry with exponential backoff per ``OUTBOUND_MAX_RETRIES``
  - Per-recipient delivery (one SMTP conversation per recipient's MX)

Messages are pulled from the Redis queue by the background worker
(``core.queue``), signed with DKIM, then handed off to ``deliver_message``.
"""
from __future__ import annotations

import asyncio
import base64
import logging
from email.message import Message
from email.utils import getaddresses, parseaddr
from typing import Optional

import aiosmtplib
import dns.resolver

from config import settings

log = logging.getLogger("outbound")


def _extract_recipient_domains(recipients: list[str]) -> dict[str, list[str]]:
    """Group recipients by domain. Returns ``{domain: [addr, addr, ...]}``."""
    out: dict[str, list[str]] = {}
    for rcpt in recipients:
        addr = rcpt.strip()
        if "<" in addr and ">" in addr:
            addr = addr[addr.find("<") + 1:addr.find(">")]
        if "@" not in addr:
            continue
        domain = addr.rsplit("@", 1)[1].lower().strip(">")
        out.setdefault(domain, []).append(addr)
    return out


def _resolve_mx(domain: str) -> Optional[str]:
    """Return the highest-priority MX hostname for ``domain``."""
    try:
        answers = dns.resolver.resolve(domain, "MX", lifetime=5.0)
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.Timeout):
        return None
    except Exception as e:
        log.warning("mx.lookup_failed domain=%s error=%s", domain, e)
        return None
    if not answers:
        return None
    # MX records sort by preference (lower = higher priority)
    mx_records = sorted(
        ((r.preference, str(r.exchange).rstrip(".")) for r in answers),
        key=lambda x: x[0],
    )
    return mx_records[0][1] if mx_records else None


async def _deliver_to_mx(
    mx_host: str,
    recipients: list[str],
    raw_message: bytes,
    sender: str,
) -> tuple[bool, str]:
    """Deliver to one MX host. Returns (success, message)."""
    timeout = settings.outbound_smtp_timeout or 30
    tls_required = settings.outbound_tls_required if isinstance(
        settings.outbound_tls_required, bool
    ) else str(settings.outbound_tls_required).lower() in ("1", "true", "yes", "on")

    try:
        # First try opportunistic STARTTLS on port 587
        try:
            client = aiosmtplib.SMTP(
                hostname=mx_host,
                port=587,
                timeout=timeout,
                start_tls=True,  # upgrade to TLS after EHLO
            )
            await client.connect()
            await client.ehlo()
            # Try STARTTLS if server supports it
            if client.supports_extension("starttls"):
                await client.starttls()
                await client.ehlo()
            await client.sendmail(sender, recipients, raw_message)
            await client.quit()
            return True, f"delivered via {mx_host}:587 STARTTLS"
        except Exception as starttls_err:
            if tls_required:
                # Try implicit TLS on 465 as fallback
                try:
                    client = aiosmtplib.SMTP(
                        hostname=mx_host,
                        port=465,
                        timeout=timeout,
                        use_tls=True,
                    )
                    await client.connect()
                    await client.ehlo()
                    await client.sendmail(sender, recipients, raw_message)
                    await client.quit()
                    return True, f"delivered via {mx_host}:465 implicit TLS"
                except Exception as implicit_err:
                    return False, (
                        f"TLS required but both STARTTLS ({starttls_err}) "
                        f"and implicit TLS ({implicit_err}) failed"
                    )
            # TLS not required — try plain SMTP on port 25
            try:
                client = aiosmtplib.SMTP(
                    hostname=mx_host,
                    port=25,
                    timeout=timeout,
                )
                await client.connect()
                await client.ehlo()
                await client.sendmail(sender, recipients, raw_message)
                await client.quit()
                return True, f"delivered via {mx_host}:25 plain"
            except Exception as plain_err:
                return False, (
                    f"STARTTLS failed ({starttls_err}); "
                    f"plain SMTP also failed ({plain_err})"
                )
    except asyncio.TimeoutError:
        return False, f"timeout connecting to {mx_host}"
    except Exception as e:
        return False, f"unexpected error: {type(e).__name__}: {e}"


async def deliver_message(
    sender: str,
    recipients: list[str],
    raw_message: bytes,
) -> dict[str, dict]:
    """Deliver a message to all recipients.

    Returns ``{domain: {"success": bool, "message": str, "recipients": [...]}}``.
    """
    results: dict[str, dict] = {}
    by_domain = _extract_recipient_domains(recipients)
    max_retries = settings.outbound_max_retries or 3
    delay = 2  # initial retry delay in seconds

    for domain, addrs in by_domain.items():
        mx_host = _resolve_mx(domain)
        if not mx_host:
            results[domain] = {
                "success": False,
                "message": f"no MX record for {domain}",
                "recipients": addrs,
            }
            continue

        last_msg = ""
        success = False
        for attempt in range(1, max_retries + 1):
            ok, msg = await _deliver_to_mx(mx_host, addrs, raw_message, sender)
            if ok:
                success = True
                last_msg = msg
                break
            last_msg = f"attempt {attempt}/{max_retries}: {msg}"
            log.warning(
                "outbound.retry domain=%s mx=%s attempt=%d error=%s",
                domain, mx_host, attempt, msg,
            )
            if attempt < max_retries:
                await asyncio.sleep(delay)
                delay *= 2  # exponential backoff

        results[domain] = {
            "success": success,
            "message": last_msg,
            "recipients": addrs,
            "mx": mx_host,
        }
        if success:
            log.info(
                "outbound.delivered domain=%s mx=%s recipients=%d",
                domain, mx_host, len(addrs),
            )
        else:
            log.error(
                "outbound.failed domain=%s mx=%s error=%s",
                domain, mx_host, last_msg,
            )

    return results
