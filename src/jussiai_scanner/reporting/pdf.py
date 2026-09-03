"""PDF rendering of a scan result.

Every dynamic string in a report originates, directly or indirectly, from the
scanned site: URLs, header values, server banners. ReportLab's ``Paragraph``
parses a small XML-like markup language, so unescaped input would at best
corrupt the document and at worst let a scanned site control its own report.
All such text therefore goes through :func:`_text`, and evidence values are
length-capped so a hostile response cannot produce an enormous PDF.
"""

from __future__ import annotations

from datetime import UTC, datetime
from io import BytesIO
from typing import TYPE_CHECKING, Any
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (
    Flowable,
    KeepTogether,
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

from jussiai_scanner.models.findings import Finding, Severity

if TYPE_CHECKING:
    from reportlab.pdfgen.canvas import Canvas

    from jussiai_scanner.scanner.engine import ScanResult

#: Longest evidence value rendered; the rest is elided.
MAX_EVIDENCE_CHARS = 400

SEVERITY_ORDER: tuple[Severity, ...] = (
    Severity.HIGH,
    Severity.MEDIUM,
    Severity.LOW,
    Severity.INFO,
)

SEVERITY_COLOURS: dict[Severity, colors.Color] = {
    Severity.HIGH: colors.HexColor("#b3261e"),
    Severity.MEDIUM: colors.HexColor("#b26a00"),
    Severity.LOW: colors.HexColor("#6b5b00"),
    Severity.INFO: colors.HexColor("#3a5a8c"),
}

_MUTED = colors.HexColor("#5c5c5c")
_LINE = colors.HexColor("#d8d8d8")


def _text(value: object, limit: int | None = None) -> str:
    """Escape ``value`` for inclusion in a ReportLab paragraph."""
    text = str(value)
    if limit is not None and len(text) > limit:
        text = text[:limit] + " […]"
    return escape(text)


def _styles() -> dict[str, ParagraphStyle]:
    base = getSampleStyleSheet()
    body = ParagraphStyle(
        "Body", parent=base["BodyText"], fontSize=9, leading=12.5, alignment=TA_LEFT
    )
    return {
        "title": ParagraphStyle("Title", parent=base["Title"], fontSize=18, spaceAfter=2),
        "subtitle": ParagraphStyle(
            "Subtitle", parent=body, fontSize=9, textColor=_MUTED, spaceAfter=10
        ),
        "h2": ParagraphStyle(
            "H2", parent=base["Heading2"], fontSize=12, spaceBefore=14, spaceAfter=6
        ),
        "body": body,
        "finding": ParagraphStyle("FindingTitle", parent=body, fontSize=10.5, leading=14),
        "meta": ParagraphStyle("Meta", parent=body, fontSize=7.5, textColor=_MUTED),
        "label": ParagraphStyle(
            "Label", parent=body, fontSize=7.5, textColor=_MUTED, spaceBefore=4
        ),
        "mono": ParagraphStyle("Mono", parent=body, fontName="Courier", fontSize=7.5, leading=10),
        "footer": ParagraphStyle("Footer", parent=body, fontSize=7.5, textColor=_MUTED),
    }


def _header_footer(canvas: Canvas, doc: SimpleDocTemplate) -> None:
    """Draw the page number and a standing caveat on every page."""
    canvas.saveState()
    canvas.setFont("Helvetica", 7.5)
    canvas.setFillColor(_MUTED)
    canvas.drawString(
        20 * mm, 12 * mm, "JussiAI Web Security Scanner — findings are produced deterministically"
    )
    canvas.drawRightString(A4[0] - 20 * mm, 12 * mm, f"Page {canvas.getPageNumber()}")
    canvas.setStrokeColor(_LINE)
    canvas.line(20 * mm, 15 * mm, A4[0] - 20 * mm, 15 * mm)
    canvas.restoreState()


def _summary_table(result: ScanResult, style: ParagraphStyle) -> Table:
    generated = datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S UTC")
    rows = [
        ("Requested", _text(result.requested_url)),
        ("Final URL", _text(result.final_url)),
        ("HTTP status", _text(result.status_code)),
        ("Scan duration", _text(f"{result.duration_ms:.0f} ms")),
        ("Generated", _text(generated)),
    ]
    table = Table(
        [[Paragraph(f"<b>{label}</b>", style), Paragraph(value, style)] for label, value in rows],
        colWidths=[32 * mm, None],
        hAlign="LEFT",
    )
    table.setStyle(
        TableStyle(
            [
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
                ("TOPPADDING", (0, 0), (-1, -1), 3),
                ("LINEBELOW", (0, 0), (-1, -2), 0.25, _LINE),
            ]
        )
    )
    return table


def _counts_table(findings: tuple[Finding, ...], style: ParagraphStyle) -> Table:
    counts = {sev: sum(1 for f in findings if f.severity is sev) for sev in SEVERITY_ORDER}
    header = [Paragraph(f"<b>{sev.value.upper()}</b>", style) for sev in SEVERITY_ORDER]
    values = [Paragraph(str(counts[sev]), style) for sev in SEVERITY_ORDER]
    table = Table([header, values], colWidths=[28 * mm] * 4, hAlign="LEFT")
    commands: list[Any] = [
        ("BOX", (0, 0), (-1, -1), 0.25, _LINE),
        ("INNERGRID", (0, 0), (-1, -1), 0.25, _LINE),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]
    commands += [
        ("TEXTCOLOR", (i, 0), (i, 0), SEVERITY_COLOURS[sev]) for i, sev in enumerate(SEVERITY_ORDER)
    ]
    table.setStyle(TableStyle(commands))
    return table


def _finding_block(finding: Finding, styles: dict[str, ParagraphStyle]) -> KeepTogether:
    """Render one finding, kept on a single page where it fits."""
    colour = SEVERITY_COLOURS[finding.severity]
    parts: list[Flowable] = [
        Paragraph(
            f'<font color="{colour.hexval()}"><b>[{finding.severity.value.upper()}]</b></font> '
            f"<b>{_text(finding.title)}</b>",
            styles["finding"],
        ),
        Paragraph(
            f"{_text(finding.check_id)} · confidence: {_text(finding.confidence.value)}",
            styles["meta"],
        ),
    ]
    if finding.description:
        parts.append(Paragraph(_text(finding.description), styles["body"]))
    if finding.remediation:
        parts.append(Paragraph("<b>HOW TO FIX</b>", styles["label"]))
        parts.append(Paragraph(_text(finding.remediation), styles["body"]))
    if finding.evidence:
        parts.append(Paragraph("<b>EVIDENCE</b>", styles["label"]))
        for key, value in finding.evidence.items():
            parts.append(
                Paragraph(
                    f"{_text(key)}: {_text(value, MAX_EVIDENCE_CHARS)}",
                    styles["mono"],
                )
            )
    parts.append(Spacer(1, 8))
    return KeepTogether(parts)


def render_scan_pdf(result: ScanResult) -> bytes:
    """Render ``result`` as a PDF document.

    Args:
        result: A completed scan.

    Returns:
        The PDF file contents.
    """
    styles = _styles()
    buffer = BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        leftMargin=20 * mm,
        rightMargin=20 * mm,
        topMargin=18 * mm,
        bottomMargin=20 * mm,
        title="JussiAI Web Security Scanner report",
        author="JussiAI Web Security Scanner",
        subject=result.final_url,
    )

    story: list[Flowable] = [
        Paragraph("Web Security Scan Report", styles["title"]),
        Paragraph(
            "Non-destructive checks. Findings and remediation are produced "
            "deterministically; no part of this report is generated by a language model.",
            styles["subtitle"],
        ),
        _summary_table(result, styles["body"]),
        Spacer(1, 10),
        _counts_table(result.findings, styles["body"]),
    ]

    if result.notes:
        story.append(Paragraph("Scan notes", styles["h2"]))
        for note in result.notes:
            story.append(Paragraph(f"• {_text(note)}", styles["body"]))

    story.append(Paragraph("Findings", styles["h2"]))
    if not result.findings:
        story.append(Paragraph("No findings were produced.", styles["body"]))
    else:
        ordered = sorted(result.findings, key=lambda f: SEVERITY_ORDER.index(f.severity))
        story.extend(_finding_block(f, styles) for f in ordered)

    story.append(PageBreak())
    story.append(Paragraph("About this report", styles["h2"]))
    story.append(
        Paragraph(
            "Checks are read-only HTTP requests. Nothing was crawled, fuzzed or modified. "
            "The absence of a finding is not evidence that a site is secure: this tool "
            "inspects a small number of transport and header-level properties only.",
            styles["body"],
        )
    )
    story.append(Spacer(1, 6))
    story.append(
        Paragraph(
            "No overall score is shown. A scoring algorithm is not implemented, and any "
            "figure here should not be read as an industry-standard security rating.",
            styles["body"],
        )
    )
    story.append(Spacer(1, 6))
    story.append(
        Paragraph(
            f"Checks run: {_text(', '.join(result.checks_run))}.",
            styles["footer"],
        )
    )

    doc.build(story, onFirstPage=_header_footer, onLaterPages=_header_footer)
    return buffer.getvalue()
