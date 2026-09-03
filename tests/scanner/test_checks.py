"""Checks are pure functions over gathered evidence."""

from __future__ import annotations

from collections.abc import Sequence

from jussiai_scanner.models.findings import Finding, Severity
from jussiai_scanner.scanner.checks import (
    check_availability,
    check_information_disclosure,
    check_security_headers,
    check_transport,
)
from jussiai_scanner.scanner.checks.headers import HEADER_RULES
from jussiai_scanner.scanner.context import ScanContext
from jussiai_scanner.scanner.http_client import FetchResult, Hop
from tests.scanner.conftest import make_result

FULL_HEADERS = {
    "strict-transport-security": "max-age=31536000",
    "content-security-policy": "default-src 'self'",
    "x-content-type-options": "nosniff",
    "x-frame-options": "DENY",
    "referrer-policy": "no-referrer",
    "permissions-policy": "geolocation=()",
}


def ctx(result: FetchResult, probe: FetchResult | None = None) -> ScanContext:
    return ScanContext(requested_url=result.requested_url, primary=result, http_probe=probe)


def by_id(findings: Sequence[Finding], check_id: str) -> Finding:
    """The single finding with this id; raises if a check stopped emitting it."""
    return next(f for f in findings if f.check_id == check_id)


# --- availability ------------------------------------------------------------


def test_ok_status_is_info() -> None:
    f = by_id(check_availability(ctx(make_result())), "availability.status")
    assert f.severity == Severity.INFO
    assert f.evidence["status_code"] == "200"


def test_server_error_status_is_medium_with_remediation() -> None:
    f = by_id(check_availability(ctx(make_result(status_code=500))), "availability.status")
    assert f.severity == Severity.MEDIUM
    assert "error logs" in f.remediation


def test_slow_response_is_flagged() -> None:
    f = by_id(check_availability(ctx(make_result(elapsed_ms=5000))), "availability.response_time")
    assert f.severity == Severity.LOW
    assert f.remediation


# --- transport ---------------------------------------------------------------


def test_https_is_info() -> None:
    f = by_id(check_transport(ctx(make_result())), "transport.https")
    assert f.severity == Severity.INFO


def test_plain_http_is_high() -> None:
    f = by_id(check_transport(ctx(make_result(url="http://example.com/"))), "transport.https")
    assert f.severity == Severity.HIGH
    assert "certificate" in f.remediation


def test_missing_http_upgrade_is_medium() -> None:
    probe = make_result(url="http://example.com/", status_code=200)
    f = by_id(check_transport(ctx(make_result(), probe)), "transport.http_redirect")
    assert f.severity == Severity.MEDIUM
    assert "301" in f.remediation


def test_http_upgrade_present_is_info() -> None:
    probe = make_result(url="https://example.com/", status_code=200)
    f = by_id(check_transport(ctx(make_result(), probe)), "transport.http_redirect")
    assert f.severity == Severity.INFO


def test_https_downgrade_is_high() -> None:
    hops = (
        Hop("https://example.com/", 302, "http://example.com/x"),
        Hop("http://example.com/x", 200),
    )
    f = by_id(check_transport(ctx(make_result(hops=hops))), "transport.https_downgrade")
    assert f.severity == Severity.HIGH


def test_long_redirect_chain_is_low() -> None:
    hops = tuple(Hop(f"https://example.com/{i}", 301, "/next") for i in range(5)) + (
        Hop("https://example.com/end", 200),
    )
    f = by_id(check_transport(ctx(make_result(hops=hops))), "transport.redirect_chain")
    assert f.severity == Severity.LOW


# --- headers -----------------------------------------------------------------


def test_all_headers_missing_produces_one_finding_each() -> None:
    findings = check_security_headers(ctx(make_result()))
    assert len(findings) == len(HEADER_RULES)
    assert all(f.evidence["present"] == "false" for f in findings)
    assert all(f.remediation for f in findings), "every gap must carry a fix"


def test_all_headers_present_are_info() -> None:
    findings = check_security_headers(ctx(make_result(headers=FULL_HEADERS)))
    assert all(f.severity == Severity.INFO for f in findings)


def test_hsts_is_skipped_on_plain_http() -> None:
    """HSTS is meaningless over http, so absence must not be reported there."""
    findings = check_security_headers(ctx(make_result(url="http://example.com/")))
    assert not any(f.check_id == "headers.strict-transport-security" for f in findings)


def test_bad_nosniff_value_is_flagged() -> None:
    headers = {**FULL_HEADERS, "x-content-type-options": "sniff"}
    findings = check_security_headers(ctx(make_result(headers=headers)))
    assert by_id(findings, "headers.x-content-type-options.value").severity == Severity.LOW


# --- disclosure --------------------------------------------------------------


def test_no_disclosure_headers_means_no_findings() -> None:
    assert check_information_disclosure(ctx(make_result())) == []


def test_versioned_server_header_is_low() -> None:
    f = by_id(
        check_information_disclosure(ctx(make_result(headers={"server": "nginx/1.18.0"}))),
        "disclosure.server",
    )
    assert f.severity == Severity.LOW
    assert "server_tokens" in f.remediation


def test_unversioned_server_header_is_info() -> None:
    f = by_id(
        check_information_disclosure(ctx(make_result(headers={"server": "nginx"}))),
        "disclosure.server",
    )
    assert f.severity == Severity.INFO


def test_x_powered_by_is_reported() -> None:
    f = by_id(
        check_information_disclosure(ctx(make_result(headers={"x-powered-by": "PHP/8.1.2"}))),
        "disclosure.x-powered-by",
    )
    assert "expose_php" in f.remediation
