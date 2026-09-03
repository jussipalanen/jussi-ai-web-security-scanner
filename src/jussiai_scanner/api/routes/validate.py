"""Target validation endpoint.

Exposes the validation layer on its own so a client can check whether a URL is
scannable before committing to a full scan, and so the SSRF rules are directly
observable.
"""

from __future__ import annotations

from fastapi import APIRouter
from pydantic import BaseModel

from jussiai_scanner.api.dependencies import SettingsDep
from jussiai_scanner.api.status_codes import HTTP_422_UNPROCESSABLE
from jussiai_scanner.models.scan import ScanRequest
from jussiai_scanner.security.errors import TargetValidationError
from jussiai_scanner.security.url_validation import validate_target_url

router = APIRouter(tags=["validation"])


class ValidationResponse(BaseModel):
    """The normalised form of an accepted target."""

    url: str
    scheme: str
    host: str
    port: int


@router.post(
    "/validate",
    response_model=ValidationResponse,
    responses={HTTP_422_UNPROCESSABLE: {"description": "Target rejected"}},
)
async def validate(request: ScanRequest, settings: SettingsDep) -> ValidationResponse:
    """Validate a target URL without performing any network request.

    Raises:
        TargetValidationError: Handled by the application-wide exception handler
            and returned as HTTP 422.
    """
    target = validate_target_url(request.url, settings)
    return ValidationResponse(
        url=target.url, scheme=target.scheme, host=target.host, port=target.port
    )


__all__ = ["TargetValidationError", "router"]
