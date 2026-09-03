"""Liveness and readiness endpoints."""

from __future__ import annotations

from fastapi import APIRouter
from pydantic import BaseModel

from jussiai_scanner import __version__
from jussiai_scanner.api.dependencies import SettingsDep

router = APIRouter(tags=["health"])


class HealthResponse(BaseModel):
    """Service health payload."""

    status: str
    version: str
    ai_enabled: bool


@router.get("/health", response_model=HealthResponse)
async def health(settings: SettingsDep) -> HealthResponse:
    """Report that the service is up and which optional features are enabled."""
    return HealthResponse(status="ok", version=__version__, ai_enabled=settings.ai_enabled)
