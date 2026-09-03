"""Security response headers."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass

from jussiai_scanner.models.findings import Confidence, Finding, Severity
from jussiai_scanner.scanner.context import ScanContext


@dataclass(frozen=True, slots=True)
class HeaderRule:
    """A header the scanner expects, how much its absence matters, and the fix."""

    header: str
    severity: Severity
    purpose: str
    remediation: str
    https_only: bool = False


HEADER_RULES: tuple[HeaderRule, ...] = (
    HeaderRule(
        "strict-transport-security",
        Severity.MEDIUM,
        "instructs browsers to reach this site over HTTPS on future visits, "
        "closing the initial plain-HTTP request an attacker can intercept",
        "Send `Strict-Transport-Security: max-age=31536000; includeSubDomains`. "
        "Confirm every subdomain serves HTTPS first - includeSubDomains will break "
        "any that do not. Start with a short max-age (e.g. 300), verify nothing "
        "breaks, then raise it. Add `preload` only once you are certain, as "
        "preload-list removal is slow.",
        https_only=True,
    ),
    HeaderRule(
        "content-security-policy",
        Severity.MEDIUM,
        "restricts where scripts, styles and frames may load from, which is the "
        "main structural defence against cross-site scripting",
        "Roll out in report-only mode first: "
        "`Content-Security-Policy-Report-Only: default-src 'self'; report-uri /csp-report`. "
        "Collect violations, fold in the origins you genuinely need, then switch the "
        "header to enforcing. Avoid 'unsafe-inline' - use nonces or hashes for inline "
        "scripts.",
    ),
    HeaderRule(
        "x-content-type-options",
        Severity.LOW,
        "stops browsers guessing a response's type and treating, say, an uploaded "
        "text file as executable script",
        "Send `X-Content-Type-Options: nosniff` on every response, and make sure your "
        "Content-Type headers are accurate.",
    ),
    HeaderRule(
        "x-frame-options",
        Severity.LOW,
        "prevents the page being embedded in a hostile frame (clickjacking)",
        "Send `X-Frame-Options: DENY`, or `SAMEORIGIN` if you frame your own pages. "
        "Prefer the modern equivalent `Content-Security-Policy: frame-ancestors 'none'`, "
        "which supersedes it; send both while older browsers matter to you.",
    ),
    HeaderRule(
        "referrer-policy",
        Severity.LOW,
        "limits how much of the current URL leaks to third parties in the Referer header",
        "Send `Referrer-Policy: strict-origin-when-cross-origin`. Use `no-referrer` if "
        "URLs on this site contain tokens or identifiers.",
    ),
    HeaderRule(
        "permissions-policy",
        Severity.INFO,
        "switches off browser features the site does not use",
        "Send `Permissions-Policy: geolocation=(), camera=(), microphone=(), "
        "payment=()`, listing only the features you actually need.",
    ),
)


def check_security_headers(context: ScanContext) -> Sequence[Finding]:
    """Report present and missing security headers on the final response."""
    result = context.primary
    is_https = result.final_target.scheme == "https"
    findings: list[Finding] = []

    for rule in HEADER_RULES:
        if rule.https_only and not is_https:
            continue
        value = result.header(rule.header)
        if value is None:
            findings.append(
                Finding(
                    check_id=f"headers.{rule.header}",
                    title=f"{rule.header} header is missing",
                    severity=rule.severity,
                    confidence=Confidence.HIGH,
                    description=f"This header {rule.purpose}. It was not present.",
                    remediation=rule.remediation,
                    evidence={"header": rule.header, "present": "false"},
                )
            )
        else:
            findings.append(
                Finding(
                    check_id=f"headers.{rule.header}",
                    title=f"{rule.header} header is present",
                    severity=Severity.INFO,
                    confidence=Confidence.HIGH,
                    description=f"This header {rule.purpose}.",
                    remediation="No action needed. Review the value if the site's "
                    "requirements change.",
                    evidence={"header": rule.header, "present": "true", "value": value[:300]},
                )
            )

    nosniff = result.header("x-content-type-options")
    if nosniff is not None and nosniff.strip().lower() != "nosniff":
        findings.append(
            Finding(
                check_id="headers.x-content-type-options.value",
                title="x-content-type-options has an unexpected value",
                severity=Severity.LOW,
                confidence=Confidence.HIGH,
                description="The only value browsers act on is 'nosniff'; anything else "
                "is ignored, leaving MIME sniffing enabled.",
                remediation="Set the header to exactly `nosniff`.",
                evidence={"value": nosniff[:100]},
            )
        )
    return findings
