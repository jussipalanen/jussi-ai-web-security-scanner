"""Fixtures for scanner tests. No real network access happens anywhere here."""

from __future__ import annotations

import ipaddress
from collections.abc import Callable, Sequence

import httpx
import pytest

from jussiai_scanner.config import Settings
from jussiai_scanner.scanner.http_client import FetchResult, Hop, SafeHttpClient
from jussiai_scanner.security.ip_rules import IPAddress
from jussiai_scanner.security.url_validation import ValidatedTarget
from tests.conftest import build_settings

#: A well-known public resolver, used purely as a stand-in for "some globally
#: routable address". Tests never connect to it - the transport is mocked.
#: Never put a real address belonging to this project or its operator here.
PUBLIC_IP = "1.1.1.1"


def public_resolver(host: str, port: int) -> Sequence[IPAddress]:
    """Resolve every name to one public address."""
    return [ipaddress.ip_address(PUBLIC_IP)]


def make_client(
    handler: Callable[[httpx.Request], httpx.Response],
    settings: Settings | None = None,
) -> SafeHttpClient:
    """A SafeHttpClient wired to a mock transport and a fixed resolver."""
    return SafeHttpClient(
        settings or build_settings(),
        resolver=public_resolver,
        transport=httpx.MockTransport(handler),
    )


def make_result(
    url: str = "https://example.com/",
    status_code: int = 200,
    headers: dict[str, str] | None = None,
    elapsed_ms: float = 120.0,
    hops: tuple[Hop, ...] = (),
) -> FetchResult:
    """A synthetic FetchResult, so checks can be tested without any transport."""
    target = ValidatedTarget(
        url=url,
        scheme=url.split("://")[0],
        host="example.com",
        port=443 if url.startswith("https") else 80,
    )
    return FetchResult(
        requested_url=url,
        final_url=url,
        final_target=target,
        status_code=status_code,
        headers=httpx.Headers(headers or {}),
        body=b"",
        body_truncated=False,
        elapsed_ms=elapsed_ms,
        hops=hops,
    )


@pytest.fixture
def settings() -> Settings:
    return build_settings()
