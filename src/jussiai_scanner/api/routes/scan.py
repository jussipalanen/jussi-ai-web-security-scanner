"""The scan endpoint."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException

from jussiai_scanner.api.dependencies import SettingsDep
from jussiai_scanner.api.status_codes import HTTP_422_UNPROCESSABLE, HTTP_502_BAD_GATEWAY
from jussiai_scanner.models.scan import ScanRequest
from jussiai_scanner.models.scan_result import ScanResponse, SeverityCounts
from jussiai_scanner.scanner.engine import Scanner
from jussiai_scanner.scanner.http_client import FetchError

router = APIRouter(tags=["scan"])


@router.post(
    "/scan",
    response_model=ScanResponse,
    responses={
        HTTP_422_UNPROCESSABLE: {"description": "Target rejected by validation"},
        HTTP_502_BAD_GATEWAY: {"description": "Target could not be reached"},
    },
)
async def scan(request: ScanRequest, settings: SettingsDep) -> ScanResponse:
    """Run the non-destructive checks against a public URL.

    Every finding carries a description and a remediation step produced by the
    deterministic Python check, not by a language model.

    Raises:
        HTTPException: 502 when the target is valid but unreachable.
    """
    scanner = Scanner(settings)
    try:
        result = await scanner.scan(request.url)
    except FetchError as exc:
        raise HTTPException(status_code=HTTP_502_BAD_GATEWAY, detail=str(exc)) from exc

    return ScanResponse(
        requested_url=result.requested_url,
        final_url=result.final_url,
        status_code=result.status_code,
        duration_ms=round(result.duration_ms, 1),
        counts=SeverityCounts.from_findings(result.findings),
        findings=list(result.findings),
        checks_run=list(result.checks_run),
        notes=list(result.notes),
    )
