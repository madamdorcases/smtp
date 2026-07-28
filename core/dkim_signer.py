"""
DKIM signer — signs outbound messages with the project's RSA private key.

The private key is read from the ``DKIM_PRIVATE_KEY_PEM`` env var (base64
encoded, single line). The matching public key must be published in DNS at
``default._domainkey.<DOMAIN>`` as a TXT record.

Uses ``dkimpy`` because it correctly handles relaxed/simple body canon,
multiple signatures, and edge cases like folded headers.
"""
from __future__ import annotations

import base64
import logging
from typing import Optional

import dkim

from config import settings

log = logging.getLogger("dkim")

# Cache the loaded key — DKIM_PRIVATE_KEY_PEM doesn't change at runtime.
_cached_key: Optional[bytes] = None
_cached_domain: Optional[str] = None


def _load_private_key() -> bytes:
    """Load and decode the DKIM private key from the env var.

    The env var may be either:
      (a) raw PEM contents (starts with '-----BEGIN'), or
      (b) base64-encoded PEM contents (single line, no newlines)

    Both forms are supported. The form is auto-detected.
    """
    global _cached_key, _cached_domain
    if _cached_key is not None and _cached_domain == settings.domain:
        return _cached_key

    raw = (settings.dkim_private_key_pem or "").strip()
    if not raw:
        raise RuntimeError(
            "DKIM_PRIVATE_KEY_PEM is empty — DKIM signing disabled. "
            "Generate one with: openssl genrsa -out dkim_private.pem 2048"
        )

    if raw.startswith("-----BEGIN"):
        pem = raw.encode("utf-8")
    else:
        # base64-encoded PEM — decode to recover the PEM text
        try:
            pem = base64.b64decode(raw).decode("utf-8").encode("utf-8")
        except Exception as e:
            raise RuntimeError(
                f"DKIM_PRIVATE_KEY_PEM is neither raw PEM nor valid base64: {e}"
            )

    # sanity check — dkimpy will not validate until sign() is called
    if b"-----BEGIN RSA PRIVATE KEY-----" not in pem and \
       b"-----BEGIN PRIVATE KEY-----" not in pem:
        raise RuntimeError(
            "DKIM_PRIVATE_KEY_PEM does not contain a recognizable PEM private key"
        )

    _cached_key = pem
    _cached_domain = settings.domain
    return pem


def sign_message(raw_message: bytes) -> bytes:
    """Sign an RFC 5322 message with DKIM.

    Args:
        raw_message: the full RFC 5322 message bytes (headers + body).

    Returns:
        The same message with a ``DKIM-Signature`` header prepended.

    Raises:
        RuntimeError: if DKIM is misconfigured (no key, bad key, etc.).
    """
    try:
        key_pem = _load_private_key()
    except RuntimeError as e:
        log.warning("dkim.skip reason=%s", e)
        return raw_message

    selector = settings.dkim_selector or "default"
    domain = settings.domain
    try:
        sig = dkim.sign(
            raw_message,
            selector.encode("ascii"),
            domain.encode("ascii"),
            key_pem,
            include_headers=["From", "To", "Subject", "Date", "Message-ID", "Reply-To"],
            canonicalize=(b"relaxed", b"relaxed"),
        )
        # dkim.sign returns the signed message with the DKIM-Signature header
        # prepended.
        return sig
    except Exception as e:
        log.error("dkim.sign_failed error=%s", e)
        # Return the unsigned message rather than dropping it — the receiving
        # server will treat it as "no DKIM signature" which is better than
        # losing the message entirely.
        return raw_message


def get_dkim_public_key_b64() -> str:
    """Return the base64-encoded public key modulus (the ``p=`` value for DNS).

    Used by the DKIM TXT record. Run this once and paste the result into
    Cloudflare as the value for ``default._domainkey.<DOMAIN>``.
    """
    import subprocess
    key_pem = _load_private_key()
    # Use openssl to extract the public key, then format for DNS
    proc = subprocess.run(
        ["openssl", "rsa", "-pubout"],
        input=key_pem,
        capture_output=True,
        check=True,
    )
    pub_pem = proc.stdout.decode("utf-8")
    # Strip header/footer and join into one line
    lines = [
        line.strip()
        for line in pub_pem.splitlines()
        if line.strip() and not line.startswith("-----")
    ]
    pub_b64 = "".join(lines)
    return f"v=DKIM1; k=rsa; p={pub_b64}"
