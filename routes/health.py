"""GET /api/health - public, no auth, no logging."""
from __future__ import annotations

from fastapi import APIRouter

from smtp.models import HealthResponse

router = APIRouter()


@router.get("/api/health", response_model=HealthResponse)
async def health() -> HealthResponse:
    return HealthResponse(status="ok")
