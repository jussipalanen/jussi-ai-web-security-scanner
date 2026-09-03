"""API-facing scan models."""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field


class ScanRequest(BaseModel):
    """A request to scan a single public URL."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    url: str = Field(min_length=1, max_length=2048, description="Public http(s) URL to scan.")
    include_ai_analysis: bool = Field(
        default=True,
        description="Whether to run the AI explanation layer over the deterministic findings.",
    )


class ErrorResponse(BaseModel):
    """Error payload returned for rejected or failed scans."""

    detail: str
