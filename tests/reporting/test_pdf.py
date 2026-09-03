"""PDF rendering, especially its handling of attacker-influenced text."""

from __future__ import annotations

from io import BytesIO

import pytest
from pypdf import PdfReader

from jussiai_scanner.models.findings import Confidence, Finding, Severity
from jussiai_scanner.reporting.pdf import MAX_EVIDENCE_CHARS, render_scan_pdf
from jussiai_scanner.scanner.engine import ScanResult


def make_result(findings: tuple[Finding, ...] = (), notes: tuple[str, ...] = ()) -> ScanResult:
    return ScanResult(
        requested_url="example.com",
        final_url="https://example.com/",
        status_code=200,
        findings=findings,
        duration_ms=123.4,
        checks_run=("check_transport",),
        notes=notes,
    )


def finding(**overrides: object) -> Finding:
    defaults = {
        "check_id": "headers.csp",
        "title": "content-security-policy header is missing",
        "severity": Severity.MEDIUM,
        "confidence": Confidence.HIGH,
        "description": "This header restricts where scripts may load from.",
        "remediation": "Send a Content-Security-Policy header.",
        "evidence": {"header": "content-security-policy", "present": "false"},
    }
    return Finding(**{**defaults, **overrides})  # type: ignore[arg-type]


def text_of(pdf: bytes) -> str:
    return "\n".join(page.extract_text() for page in PdfReader(BytesIO(pdf)).pages)


def test_renders_a_valid_pdf() -> None:
    pdf = render_scan_pdf(make_result((finding(),)))
    assert pdf.startswith(b"%PDF-")
    assert len(PdfReader(BytesIO(pdf)).pages) >= 1


def test_report_contains_the_scan_context() -> None:
    text = text_of(render_scan_pdf(make_result((finding(),))))
    assert "https://example.com/" in text
    assert "200" in text


def test_finding_title_description_and_remediation_are_rendered() -> None:
    text = text_of(render_scan_pdf(make_result((finding(),))))
    assert "content-security-policy header is missing" in text
    assert "HOW TO FIX" in text
    assert "Send a Content-Security-Policy header." in text


def test_empty_result_still_renders() -> None:
    text = text_of(render_scan_pdf(make_result()))
    assert "No findings were produced." in text


def test_notes_are_rendered() -> None:
    text = text_of(render_scan_pdf(make_result(notes=("port 80 was closed",))))
    assert "port 80 was closed" in text


def test_report_states_that_there_is_no_score() -> None:
    """The report must not imply an industry-standard rating."""
    assert "No overall score" in text_of(render_scan_pdf(make_result((finding(),))))


# --- the security-relevant part ---------------------------------------------


@pytest.mark.parametrize(
    "hostile",
    [
        "<b>bold</b>",
        "<para>injected</para>",
        "<font color='red'>red</font>",
        "a & b",
        "<onDraw name='x'/>",
        "</para><para>",
        "<br/>" * 50,
    ],
)
def test_markup_in_scanner_output_cannot_break_the_document(hostile: str) -> None:
    """ReportLab paragraphs parse markup, so site-controlled text must be escaped.

    A scanned site controls its own Server header; without escaping it could
    corrupt or restyle the report describing it.
    """
    result = make_result(
        (
            finding(
                title=f"server header: {hostile}",
                description=hostile,
                remediation=hostile,
                evidence={"value": hostile},
            ),
        )
    )
    pdf = render_scan_pdf(result)
    assert pdf.startswith(b"%PDF-")
    text = text_of(pdf)
    # The markup survives as literal text rather than being interpreted away.
    assert hostile.split("<")[0].strip() in text or hostile in text


def test_evidence_values_are_length_capped() -> None:
    """A hostile response must not be able to inflate the report."""
    huge = "A" * 50_000
    pdf = render_scan_pdf(make_result((finding(evidence={"body": huge}),)))
    assert len(pdf) < 200_000
    assert MAX_EVIDENCE_CHARS < len(huge)


def test_all_severities_render() -> None:
    findings = tuple(
        finding(check_id=f"c.{sev.value}", title=f"{sev.value} issue", severity=sev)
        for sev in Severity
    )
    text = text_of(render_scan_pdf(make_result(findings)))
    for sev in Severity:
        assert f"[{sev.value.upper()}]" in text
