"""Server and framework information disclosure."""

from __future__ import annotations

import re
from collections.abc import Sequence

from jussiai_scanner.models.findings import Confidence, Finding, Severity
from jussiai_scanner.scanner.context import ScanContext

#: Headers that commonly name the software, and sometimes its exact version.
DISCLOSURE_HEADERS: tuple[str, ...] = ("server", "x-powered-by", "x-aspnet-version")

_VERSION_RE = re.compile(r"\d+\.\d+")

#: How to suppress each header, per common server/framework.
_REMEDIATION: dict[str, str] = {
    "server": (
        "Suppress or shorten the header. nginx: `server_tokens off;` (the full header "
        "needs the headers-more module: `more_clear_headers Server;`). Apache: "
        "`ServerTokens Prod` and `ServerSignature Off`. Behind a CDN or reverse proxy, "
        "strip it there. This is hardening, not a fix for a vulnerability - keep the "
        "software patched regardless."
    ),
    "x-powered-by": (
        "Remove the header. PHP: set `expose_php = Off` in php.ini. Express: "
        "`app.disable('x-powered-by')`. ASP.NET: remove it via `<httpProtocol>` "
        "`<customHeaders>` in web.config. Or strip it at the reverse proxy."
    ),
    "x-aspnet-version": (
        'Remove the header by setting `<httpRuntime enableVersionHeader="false" />` '
        "in web.config, or strip it at the reverse proxy."
    ),
}


def check_information_disclosure(context: ScanContext) -> Sequence[Finding]:
    """Flag headers that name the server software, especially with a version."""
    result = context.primary
    findings: list[Finding] = []

    for header in DISCLOSURE_HEADERS:
        value = result.header(header)
        if value is None:
            continue
        has_version = bool(_VERSION_RE.search(value))
        findings.append(
            Finding(
                check_id=f"disclosure.{header}",
                title=(
                    f"{header} header reveals software and version"
                    if has_version
                    else f"{header} header reveals server software"
                ),
                severity=Severity.LOW if has_version else Severity.INFO,
                confidence=Confidence.HIGH,
                description=(
                    "Naming the exact version helps an attacker match known "
                    "vulnerabilities to this host."
                    if has_version
                    else "The header names the software but not a specific version."
                ),
                remediation=_REMEDIATION[header],
                evidence={"header": header, "value": value[:200]},
            )
        )
    return findings
