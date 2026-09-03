"""Findings produced by the deterministic scanner.

Findings are created by Python checks only. The AI layer may attach explanatory
prose to a finding, but never creates one and never alters its evidence.
"""

from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field


class Severity(StrEnum):
    """How serious a finding is, in the scanner's own terms."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class Confidence(StrEnum):
    """How certain the deterministic check is about a finding."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class Finding(BaseModel):
    """A single observation made by a check.

    Attributes:
        check_id: Stable identifier of the check that produced this finding.
        title: Short human-readable summary.
        severity: Scanner-assigned severity, used by the scoring module.
        confidence: How certain the check is.
        evidence: Verbatim observed values (header contents, status codes, ...).
            This is the only factual basis the AI layer is allowed to describe.
    """

    model_config = ConfigDict(frozen=True)

    check_id: str
    title: str
    severity: Severity
    confidence: Confidence = Confidence.HIGH
    description: str = ""
    evidence: dict[str, str] = Field(default_factory=dict)
