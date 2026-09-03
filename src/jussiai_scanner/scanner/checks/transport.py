"""HTTPS usage, HTTP-to-HTTPS upgrade, and the redirect chain."""

from __future__ import annotations

from collections.abc import Sequence

from jussiai_scanner.models.findings import Confidence, Finding, Severity
from jussiai_scanner.scanner.context import ScanContext

#: Chains longer than this are worth flagging as a latency/correctness smell.
LONG_CHAIN = 3


def check_transport(context: ScanContext) -> Sequence[Finding]:
    """Report on transport security and redirect behaviour."""
    findings: list[Finding] = []
    result = context.primary
    uses_https = result.final_target.scheme == "https"

    findings.append(
        Finding(
            check_id="transport.https",
            title="Final URL is served over HTTPS" if uses_https else "Final URL is plain HTTP",
            severity=Severity.INFO if uses_https else Severity.HIGH,
            confidence=Confidence.HIGH,
            description=(
                "Traffic to a plain-HTTP endpoint can be read and modified in transit."
                if not uses_https
                else "The final URL in the redirect chain uses TLS."
            ),
            remediation=(
                "No action needed."
                if uses_https
                else "Obtain a certificate (Let's Encrypt issues them free via certbot or "
                "your host's ACME client), serve the site on 443, and 301-redirect all "
                "port-80 traffic to the https:// equivalent. Then add HSTS."
            ),
            evidence={"scheme": result.final_target.scheme, "final_url": result.final_url},
        )
    )

    findings.extend(_redirect_chain_findings(context))
    findings.extend(_http_upgrade_findings(context))
    return findings


def _redirect_chain_findings(context: ScanContext) -> list[Finding]:
    result = context.primary
    findings: list[Finding] = []
    chain = " -> ".join(hop.url for hop in result.hops)

    if result.redirect_count:
        findings.append(
            Finding(
                check_id="transport.redirect_chain",
                title=f"Request followed {result.redirect_count} redirect(s)",
                severity=Severity.LOW if result.redirect_count > LONG_CHAIN else Severity.INFO,
                confidence=Confidence.HIGH,
                description="Each hop was revalidated against the SSRF rules "
                "before being followed.",
                remediation=(
                    "No action needed."
                    if result.redirect_count <= LONG_CHAIN
                    else "Collapse the chain so visitors reach the canonical URL in one "
                    "hop. Redirect straight to the final host+scheme rather than chaining "
                    "www -> apex -> https -> path. Each hop costs a round trip."
                ),
                evidence={"chain": chain, "redirects": str(result.redirect_count)},
            )
        )

    downgrades = [
        hop
        for hop in result.hops
        if hop.location and hop.url.startswith("https://") and hop.location.startswith("http://")
    ]
    if downgrades:
        findings.append(
            Finding(
                check_id="transport.https_downgrade",
                title="Redirect chain downgrades from HTTPS to HTTP",
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                description="A secure request is redirected onto an insecure one, so "
                "traffic that started protected ends up readable in transit.",
                remediation="Remove the redirect to http://. Keep every hop on https:// - "
                "check the web-server rewrite rules and any application-level redirects "
                "that build absolute URLs with a hard-coded scheme.",
                evidence={"from": downgrades[0].url, "to": downgrades[0].location or ""},
            )
        )
    return findings


def _http_upgrade_findings(context: ScanContext) -> list[Finding]:
    """Whether the plain-HTTP origin sends visitors to HTTPS."""
    probe = context.http_probe
    if probe is None:
        return []

    upgraded = probe.final_target.scheme == "https"
    return [
        Finding(
            check_id="transport.http_redirect",
            title=(
                "HTTP requests are redirected to HTTPS"
                if upgraded
                else "HTTP requests are not redirected to HTTPS"
            ),
            severity=Severity.INFO if upgraded else Severity.MEDIUM,
            confidence=Confidence.HIGH,
            description=(
                "Visitors who type the bare domain are upgraded to TLS."
                if upgraded
                else "The plain-HTTP origin serves content instead of redirecting to HTTPS."
            ),
            remediation=(
                "No action needed."
                if upgraded
                else "Configure the port-80 virtual host to issue a permanent redirect to "
                "https://. In nginx: `return 301 https://$host$request_uri;`. In Apache: "
                "`Redirect permanent / https://example.com/`. Serve no content over "
                "plain HTTP."
            ),
            evidence={
                "http_final_url": probe.final_url,
                "http_status": str(probe.status_code),
            },
        )
    ]
