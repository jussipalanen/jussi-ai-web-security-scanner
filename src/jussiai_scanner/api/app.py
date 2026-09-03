"""FastAPI application factory."""

from __future__ import annotations

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from jussiai_scanner import __version__
from jussiai_scanner.api.routes import health, scan, validate
from jussiai_scanner.api.status_codes import HTTP_422_UNPROCESSABLE
from jussiai_scanner.security.errors import TargetValidationError

DESCRIPTION = """
Non-destructive, AI-assisted web security scanner.

Security findings and the JussiAI Web Security Scanner Score are produced
deterministically in Python. The language model only explains findings that the
scanner already made.
""".strip()


def create_app() -> FastAPI:
    """Build the application. Kept as a factory so tests can configure it freely."""
    app = FastAPI(
        title="JussiAI Web Security Scanner",
        description=DESCRIPTION,
        version=__version__,
    )

    @app.exception_handler(TargetValidationError)
    async def handle_target_validation_error(
        _request: Request, exc: TargetValidationError
    ) -> JSONResponse:
        """Return rejected targets as 422 with the (safe) rejection reason."""
        return JSONResponse(
            status_code=HTTP_422_UNPROCESSABLE,
            content={"detail": exc.reason},
        )

    app.include_router(health.router)
    app.include_router(validate.router)
    app.include_router(scan.router)
    return app


app = create_app()
