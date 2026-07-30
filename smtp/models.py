"""
Pydantic models for request/response.
"""
from __future__ import annotations

from typing import Any, Optional

from pydantic import BaseModel, Field


class EncryptedRequest(BaseModel):
    """All authenticated endpoints receive this body."""
    secrate_data: str = Field(..., description="AES-256-GCM base64 envelope")


class EncryptedResponse(BaseModel):
    secrate_data: str


class HealthResponse(BaseModel):
    status: str = "ok"
