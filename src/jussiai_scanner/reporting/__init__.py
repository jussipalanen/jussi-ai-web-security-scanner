"""Report rendering.

Kept apart from the engine and the API: a report is a presentation of a
:class:`ScanResult`, and the scanner has no opinion about how it is displayed.
"""

from jussiai_scanner.reporting.pdf import render_scan_pdf

__all__ = ["render_scan_pdf"]
