"""Scan orchestration.

The engine owns all network access. It fetches the target once, optionally
probes the plain-HTTP origin, then runs every registered check over the gathered
evidence. Checks themselves never touch the network, so there is exactly one
place where the SSRF-safe client is used.
"""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field

from jussiai_scanner.config import Settings
from jussiai_scanner.models.findings import Finding
from jussiai_scanner.scanner.checks import ALL_CHECKS, Check
from jussiai_scanner.scanner.context import ScanContext
from jussiai_scanner.scanner.http_client import FetchError, FetchResult, SafeHttpClient
from jussiai_scanner.security.errors import TargetValidationError
from jussiai_scanner.security.url_validation import validate_target_url


@dataclass(frozen=True, slots=True)
class ScanResult:
    """Everything one scan produced."""

    requested_url: str
    final_url: str
    status_code: int
    findings: tuple[Finding, ...]
    duration_ms: float
    checks_run: tuple[str, ...] = field(default_factory=tuple)
    notes: tuple[str, ...] = field(default_factory=tuple)


class Scanner:
    """Runs the deterministic checks against a single target."""

    def __init__(self, settings: Settings, checks: tuple[Check, ...] = ALL_CHECKS) -> None:
        self._settings = settings
        self._checks = checks

    async def scan(self, raw_url: str, *, client: SafeHttpClient | None = None) -> ScanResult:
        """Scan ``raw_url`` and return the findings.

        Args:
            raw_url: Target supplied by the caller.
            client: Injected client, used by tests. When omitted the engine owns
                one for the duration of the scan.

        Raises:
            TargetValidationError: The target is not allowed to be scanned.
            FetchError: The target could not be reached.
        """
        started = time.perf_counter()
        # Validate before opening any socket, so an illegal target costs nothing.
        target = validate_target_url(raw_url, self._settings)

        owns_client = client is None
        client = client or SafeHttpClient(self._settings)
        try:
            async with asyncio.timeout(self._settings.total_scan_timeout_seconds):
                primary = await client.fetch(target.url)
                probe, notes = await self._probe_http_origin(client, target.host)
        except TimeoutError as exc:
            raise FetchError("the scan exceeded its total time budget", kind="timeout") from exc
        finally:
            if owns_client:
                await client.aclose()

        context = ScanContext(requested_url=raw_url, primary=primary, http_probe=probe)
        findings: list[Finding] = []
        for check in self._checks:
            findings.extend(check(context))

        return ScanResult(
            requested_url=raw_url,
            final_url=primary.final_url,
            status_code=primary.status_code,
            findings=tuple(findings),
            duration_ms=(time.perf_counter() - started) * 1000,
            checks_run=tuple(c.__name__ for c in self._checks),
            notes=notes,
        )

    async def _probe_http_origin(
        self, client: SafeHttpClient, host: str
    ) -> tuple[FetchResult | None, tuple[str, ...]]:
        """Fetch http://host/ to see whether it upgrades to HTTPS.

        A failure here is not a scan failure: plenty of hosts simply close port
        80. The reason is recorded as a note instead.
        """
        if 80 not in self._settings.allowed_ports:
            return None, ("HTTP origin not probed: port 80 is not in the allowed ports.",)
        try:
            return await client.fetch(f"http://{host}/"), ()
        except (FetchError, TargetValidationError) as exc:
            return None, (f"HTTP origin could not be probed: {exc}",)
