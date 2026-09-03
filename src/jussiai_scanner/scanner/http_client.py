"""SSRF-safe HTTP client.

Two properties matter here and neither is provided by httpx out of the box:

1. **Address pinning.** The connection is opened against the IP that
   :mod:`jussiai_scanner.security.resolver` already validated, not against the
   hostname. Letting the TLS/TCP layer re-resolve would reopen DNS rebinding:
   the name can answer with a public address during validation and a private one
   milliseconds later. ``Host`` and SNI still carry the real hostname, so virtual
   hosting and certificate verification behave normally.

2. **Per-hop revalidation.** Redirects are followed manually. Every hop goes
   through the full validate-then-resolve pipeline, so a 302 to
   ``http://169.254.169.254/`` is rejected exactly like a directly supplied one.

Responses are read with a hard byte cap, so a malicious target cannot exhaust
memory by streaming indefinitely.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from urllib.parse import urljoin

import httpx

from jussiai_scanner.config import Settings
from jussiai_scanner.security.errors import TargetValidationError
from jussiai_scanner.security.resolver import Resolver, resolve_target_async, system_resolver
from jussiai_scanner.security.url_validation import ValidatedTarget, validate_target_url

_REDIRECT_STATUSES = frozenset({301, 302, 303, 307, 308})


@dataclass(frozen=True, slots=True)
class Hop:
    """One request/response in a redirect chain."""

    url: str
    status_code: int
    location: str | None = None


@dataclass(frozen=True, slots=True)
class FetchResult:
    """The outcome of fetching a target, including how it got there."""

    requested_url: str
    final_url: str
    final_target: ValidatedTarget
    status_code: int
    headers: httpx.Headers
    body: bytes
    body_truncated: bool
    elapsed_ms: float
    hops: tuple[Hop, ...] = field(default_factory=tuple)

    @property
    def redirect_count(self) -> int:
        return len(self.hops) - 1 if self.hops else 0

    def header(self, name: str) -> str | None:
        """Case-insensitive header lookup."""
        value = self.headers.get(name)
        return str(value) if value is not None else None


class FetchError(RuntimeError):
    """The target could not be fetched (connection, TLS or timeout failure)."""

    def __init__(self, message: str, *, kind: str) -> None:
        super().__init__(message)
        self.kind = kind


class SafeHttpClient:
    """An httpx client that only ever connects to validated public addresses."""

    def __init__(
        self,
        settings: Settings,
        *,
        resolver: Resolver = system_resolver,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self._settings = settings
        self._resolver = resolver
        self._client = httpx.AsyncClient(
            timeout=httpx.Timeout(settings.request_timeout_seconds),
            follow_redirects=False,  # handled manually so each hop is revalidated
            transport=transport,
            verify=True,
            headers={"User-Agent": "JussiAI-Web-Security-Scanner/0.1 (+non-destructive)"},
        )

    async def __aenter__(self) -> SafeHttpClient:
        return self

    async def __aexit__(self, *exc_info: object) -> None:
        await self.aclose()

    async def aclose(self) -> None:
        await self._client.aclose()

    async def fetch(self, raw_url: str, *, method: str = "GET") -> FetchResult:
        """Fetch ``raw_url``, following redirects with revalidation at each hop.

        Raises:
            TargetValidationError: The URL, or a redirect target, is not allowed.
            FetchError: The request could not be completed.
        """
        current = raw_url
        hops: list[Hop] = []
        started = time.perf_counter()

        for _ in range(self._settings.max_redirects + 1):
            target = validate_target_url(current, self._settings)
            resolved = await resolve_target_async(target, self._resolver)
            response = await self._send(target, resolved.connect_address.compressed, method)

            location = response.headers.get("location")
            hops.append(Hop(url=target.url, status_code=response.status_code, location=location))

            if response.status_code in _REDIRECT_STATUSES and location:
                await response.aclose()
                current = urljoin(target.url, location.strip())
                continue

            body, truncated = await self._read_capped(response)
            return FetchResult(
                requested_url=raw_url,
                final_url=target.url,
                final_target=target,
                status_code=response.status_code,
                headers=response.headers,
                body=body,
                body_truncated=truncated,
                elapsed_ms=(time.perf_counter() - started) * 1000,
                hops=tuple(hops),
            )

        raise TargetValidationError(
            f"the target exceeded the redirect limit of {self._settings.max_redirects}"
        )

    async def _send(self, target: ValidatedTarget, ip: str, method: str) -> httpx.Response:
        """Send one request, pinned to ``ip`` but presenting the real hostname."""
        pinned = httpx.URL(target.url).copy_with(host=ip)
        host_header = target.host
        if target.ip_literal is not None and target.ip_literal.version == 6:
            host_header = f"[{host_header}]"
        if target.port not in (80, 443):
            host_header = f"{host_header}:{target.port}"
        request = self._client.build_request(
            method,
            pinned,
            headers={"Host": host_header},
            # Drives both SNI and certificate verification, so TLS is still
            # checked against the real hostname rather than the pinned IP.
            extensions={"sni_hostname": target.host},
        )
        try:
            return await self._client.send(request, stream=True)
        except httpx.TimeoutException as exc:
            raise FetchError("the target did not respond in time", kind="timeout") from exc
        except httpx.ConnectError as exc:
            raise FetchError("the target could not be reached", kind="connection") from exc
        except httpx.HTTPError as exc:
            raise FetchError("the request failed", kind="http") from exc

    async def _read_capped(self, response: httpx.Response) -> tuple[bytes, bool]:
        """Read the body up to the configured cap, then close the stream."""
        limit = self._settings.max_response_bytes
        buffer = bytearray()
        truncated = False
        try:
            async for chunk in response.aiter_bytes():
                buffer.extend(chunk)
                if len(buffer) >= limit:
                    truncated = True
                    break
        except httpx.HTTPError as exc:
            raise FetchError("the response could not be read", kind="http") from exc
        finally:
            await response.aclose()
        return bytes(buffer[:limit]), truncated
