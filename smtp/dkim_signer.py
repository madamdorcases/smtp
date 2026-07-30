"""
DKIM signing. Private key stored in MongoDB (dkim_keys collection).
Public key published as TXT at <selector>._domainkey.<domain>.
"""
from __future__ import annotations

import base64
from typing import Optional

import dkim
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from .config import settings
from .database import col_dkim

DEFAULT_SELECTOR = "smtp1"


async def ensure_dkim_keypair(selector: str = DEFAULT_SELECTOR) -> dict:
    doc = await col_dkim().find_one({"selector": selector})
    if doc:
        return doc

    priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    priv_pem = priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("ascii")
    pub_der = priv.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    pub_b64 = base64.b64encode(pub_der).decode("ascii")

    doc = {
        "selector": selector,
        "private_pem": priv_pem,
        "public_b64": pub_b64,
        "domain": settings.SENDING_DOMAIN,
    }
    await col_dkim().insert_one(doc)
    return doc


def sign_message(message_bytes: bytes, selector: str, private_pem: str, domain: str) -> bytes:
    signer = dkim.DKIM(message_bytes)
    return signer.sign(
        selector=selector.encode("ascii"),
        domain=domain.encode("ascii"),
        privkey=private_pem.encode("ascii"),
    )


async def dns_record_for(selector: str = DEFAULT_SELECTOR) -> str:
    doc = await ensure_dkim_keypair(selector)
    return f"v=DKIM1; k=rsa; p={doc['public_b64']}"
