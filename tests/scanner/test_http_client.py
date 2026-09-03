"""The SSRF-safe client: pinning, per-hop revalidation, and hard limits."""

from __future__ import annotations

import httpx
import pytest

from jussiai_scanner.security.errors import BlockedAddressError, TargetValidationError
from jussiai_scanner.security.ip_rules import IPAddress
from tests.conftest import build_settings
from tests.scanner.conftest import PUBLIC_IP, make_client


async def test_connection_is_pinned_to_the_validated_ip() -> None:
    """The socket goes to the IP; Host and SNI still carry the hostname."""
    seen: dict[str, str] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["host_in_url"] = request.url.host
        seen["host_header"] = request.headers["Host"]
        seen["sni"] = request.extensions.get("sni_hostname", "")
        return httpx.Response(200, text="ok")

    async with make_client(handler) as client:
        await client.fetch("https://example.com/")

    assert seen["host_in_url"] == PUBLIC_IP, "connection must target the validated IP"
    assert seen["host_header"] == "example.com"
    assert seen["sni"] == "example.com", "TLS must still be verified against the hostname"


async def test_redirect_to_internal_address_is_blocked() -> None:
    """The core reason redirects are followed manually."""

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(302, headers={"location": "http://169.254.169.254/latest/"})

    async with make_client(handler) as client:
        with pytest.raises(TargetValidationError):
            await client.fetch("https://example.com/")


async def test_redirect_to_localhost_is_blocked() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(302, headers={"location": "http://localhost:80/admin"})

    async with make_client(handler) as client:
        with pytest.raises(TargetValidationError):
            await client.fetch("https://example.com/")


async def test_redirect_whose_host_resolves_internally_is_blocked() -> None:
    """A public-looking redirect target that resolves inside is still refused."""
    import ipaddress

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(302, headers={"location": "https://evil.example.net/"})

    def rebinding_resolver(host: str, port: int) -> list[IPAddress]:
        if host == "evil.example.net":
            return [ipaddress.ip_address("10.0.0.5")]
        return [ipaddress.ip_address(PUBLIC_IP)]

    from jussiai_scanner.scanner.http_client import SafeHttpClient

    client = SafeHttpClient(
        build_settings(), resolver=rebinding_resolver, transport=httpx.MockTransport(handler)
    )
    async with client:
        with pytest.raises(BlockedAddressError):
            await client.fetch("https://example.com/")


async def test_relative_redirect_is_resolved_and_followed() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(301, headers={"location": "/landing"})
        return httpx.Response(200, text="here")

    async with make_client(handler) as client:
        result = await client.fetch("https://example.com/")

    assert result.final_url == "https://example.com/landing"
    assert result.redirect_count == 1
    assert result.status_code == 200


async def test_redirect_limit_is_enforced() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(302, headers={"location": "https://example.com/next"})

    settings = build_settings(max_redirects=3)
    async with make_client(handler, settings) as client:
        with pytest.raises(TargetValidationError, match="redirect limit"):
            await client.fetch("https://example.com/")


async def test_response_body_is_capped() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=b"A" * 100_000)

    settings = build_settings(max_response_bytes=1024)
    async with make_client(handler, settings) as client:
        result = await client.fetch("https://example.com/")

    assert len(result.body) == 1024
    assert result.body_truncated is True


async def test_hops_are_recorded() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(301, headers={"location": "https://example.com/a"})
        if request.url.path == "/a":
            return httpx.Response(302, headers={"location": "https://example.com/b"})
        return httpx.Response(200)

    async with make_client(handler) as client:
        result = await client.fetch("https://example.com/")

    assert [h.status_code for h in result.hops] == [301, 302, 200]
    assert result.redirect_count == 2


async def test_invalid_target_is_rejected_before_any_request() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise AssertionError("no request may be sent for an invalid target")

    async with make_client(handler) as client:
        with pytest.raises(TargetValidationError):
            await client.fetch("http://127.0.0.1/")
