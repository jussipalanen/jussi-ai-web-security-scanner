"""Input handed to every check."""

from __future__ import annotations

from dataclasses import dataclass

from jussiai_scanner.scanner.http_client import FetchResult


@dataclass(frozen=True, slots=True)
class ScanContext:
    """Everything the engine gathered, shared by all checks.

    Checks are pure functions of this context: they perform no network access of
    their own, which keeps every request under the engine's SSRF-safe client.
    """

    requested_url: str
    primary: FetchResult
    #: Result of probing the plain-http origin, when one was attempted.
    http_probe: FetchResult | None = None
