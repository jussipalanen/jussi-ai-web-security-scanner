"""A minimal browser page for exercising the scanner by hand.

Served from the backend itself so it is same-origin: no CORS configuration is
needed, and the API does not have to be exposed to a separate frontend during
development. The page is static; all rendering happens client-side against
``POST /scan``.
"""

from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter
from fastapi.responses import HTMLResponse

router = APIRouter(tags=["ui"])

STATIC_DIR = Path(__file__).resolve().parent.parent / "static"
_INDEX = STATIC_DIR / "index.html"

# The page renders header values echoed from scanned sites, so it is locked down
# rather than trusted: no inline script or style, no external origins at all.
CONTENT_SECURITY_POLICY = (
    "default-src 'none'; "
    "script-src 'self'; "
    "style-src 'self'; "
    "connect-src 'self'; "
    "form-action 'none'; "
    "base-uri 'none'; "
    "frame-ancestors 'none'"
)

SECURITY_HEADERS = {
    "Content-Security-Policy": CONTENT_SECURITY_POLICY,
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "X-Frame-Options": "DENY",
}


@router.get("/test-url", response_class=HTMLResponse, include_in_schema=False)
async def test_page() -> HTMLResponse:
    """Serve the manual test page."""
    return HTMLResponse(
        content=_INDEX.read_text(encoding="utf-8"),
        headers=SECURITY_HEADERS,
    )
