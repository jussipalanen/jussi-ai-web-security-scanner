"""End-to-end engine behaviour, with a mock transport."""

from __future__ import annotations

from collections.abc import Callable

import httpx
import pytest

from jussiai_scanner.scanner.engine import Scanner
from jussiai_scanner.scanner.http_client import FetchError
from jussiai_scanner.security.errors import TargetValidationError
from tests.conftest import build_settings
from tests.scanner.conftest import make_client


def _site(
    headers: dict[str, str] | None = None, http_redirects: bool = True
) -> Callable[[httpx.Request], httpx.Response]:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.headers.get("Host") and request.url.scheme == "http":
            if http_redirects:
                return httpx.Response(301, headers={"location": "https://example.com/"})
            return httpx.Response(200, text="plain")
        return httpx.Response(200, headers=headers or {}, text="<html></html>")

    return handler


async def test_scan_produces_findings() -> None:
    settings = build_settings()
    async with make_client(_site(), settings) as client:
        result = await Scanner(settings).scan("example.com", client=client)

    assert result.final_url == "https://example.com/"
    assert result.status_code == 200
    assert result.findings, "a bare site with no security headers must produce findings"
    assert {"check_availability", "check_transport"} <= set(result.checks_run)


async def test_every_finding_carries_a_remediation() -> None:
    settings = build_settings()
    async with make_client(_site(), settings) as client:
        result = await Scanner(settings).scan("example.com", client=client)

    missing = [f.check_id for f in result.findings if not f.remediation]
    assert not missing, f"findings without remediation: {missing}"


async def test_missing_http_upgrade_is_detected() -> None:
    settings = build_settings()
    async with make_client(_site(http_redirects=False), settings) as client:
        result = await Scanner(settings).scan("example.com", client=client)

    ids = {f.check_id for f in result.findings}
    assert "transport.http_redirect" in ids


async def test_invalid_target_never_reaches_the_network() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise AssertionError("must not be called")

    settings = build_settings()
    async with make_client(handler, settings) as client:
        with pytest.raises(TargetValidationError):
            await Scanner(settings).scan("http://169.254.169.254/", client=client)


async def test_unreachable_target_raises_fetch_error() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("refused")

    settings = build_settings()
    async with make_client(handler, settings) as client:
        with pytest.raises(FetchError):
            await Scanner(settings).scan("example.com", client=client)


async def test_http_probe_failure_is_a_note_not_a_scan_failure() -> None:
    """Port 80 being closed is normal and must not fail the scan."""

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.scheme == "http":
            raise httpx.ConnectError("refused")
        return httpx.Response(200)

    settings = build_settings()
    async with make_client(handler, settings) as client:
        result = await Scanner(settings).scan("https://example.com/", client=client)

    assert result.notes, "the failure should be recorded as a note"
    assert result.status_code == 200
