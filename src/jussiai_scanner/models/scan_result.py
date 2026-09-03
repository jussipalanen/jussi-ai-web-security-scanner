"""API response shapes for a completed scan."""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field

from jussiai_scanner.models.findings import Finding, Severity


class SeverityCounts(BaseModel):
    """How many findings landed in each severity band."""

    model_config = ConfigDict(frozen=True)

    high: int = 0
    medium: int = 0
    low: int = 0
    info: int = 0

    @classmethod
    def from_findings(cls, findings: tuple[Finding, ...]) -> SeverityCounts:
        counts = dict.fromkeys(Severity, 0)
        for finding in findings:
            counts[finding.severity] += 1
        return cls(
            high=counts[Severity.HIGH],
            medium=counts[Severity.MEDIUM],
            low=counts[Severity.LOW],
            info=counts[Severity.INFO],
        )


class ScanResponse(BaseModel):
    """The result of a scan.

    There is deliberately no ``score`` field yet: scoring is a separate,
    documented algorithm that has not been implemented. Nothing here is
    AI-generated - every description and remediation string is written by the
    Python check that produced the finding.
    """

    model_config = ConfigDict(frozen=True)

    requested_url: str
    final_url: str
    status_code: int
    duration_ms: float = Field(description="Wall-clock duration of the whole scan.")
    counts: SeverityCounts
    findings: list[Finding]
    checks_run: list[str]
    notes: list[str] = Field(
        default_factory=list,
        description="Things the scanner could not do, and why.",
    )
