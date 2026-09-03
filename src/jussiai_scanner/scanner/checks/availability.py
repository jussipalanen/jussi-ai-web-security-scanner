"""HTTP status and response time."""

from __future__ import annotations

from collections.abc import Sequence

from jussiai_scanner.models.findings import Confidence, Finding, Severity
from jussiai_scanner.scanner.context import ScanContext

#: Above this, the site is slow enough to be worth reporting.
SLOW_RESPONSE_MS = 2000.0


def check_availability(context: ScanContext) -> Sequence[Finding]:
    """Report the final status code and how long the request took."""
    result = context.primary
    status = result.status_code
    findings = [
        Finding(
            check_id="availability.status",
            title=f"Site responded with HTTP {status}",
            severity=Severity.INFO if status < 400 else Severity.MEDIUM,
            confidence=Confidence.HIGH,
            description="The status code returned by the final URL in the redirect chain.",
            remediation=(
                "No action needed."
                if status < 400
                else "Investigate why the site returns this status. A 4xx may mean the "
                "path is wrong or access is restricted; a 5xx points at a server-side "
                "fault. Check application and web-server error logs for this request."
            ),
            evidence={"status_code": str(status), "final_url": result.final_url},
        )
    ]

    elapsed = round(result.elapsed_ms)
    findings.append(
        Finding(
            check_id="availability.response_time",
            title=f"Responded in {elapsed} ms",
            severity=Severity.LOW if result.elapsed_ms > SLOW_RESPONSE_MS else Severity.INFO,
            confidence=Confidence.MEDIUM,
            description=(
                "Wall-clock time for the whole redirect chain, measured once from a "
                "single vantage point. Indicative only."
            ),
            remediation=(
                "No action needed."
                if result.elapsed_ms <= SLOW_RESPONSE_MS
                else "Profile the slowest step: database queries, upstream API calls, or "
                "TLS handshake. Enable HTTP caching for static assets and consider a CDN. "
                "Re-measure from several locations before drawing conclusions - this is a "
                "single sample."
            ),
            evidence={"elapsed_ms": str(elapsed), "hops": str(len(result.hops))},
        )
    )
    return findings
