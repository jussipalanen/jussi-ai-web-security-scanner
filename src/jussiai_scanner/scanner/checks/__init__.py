"""Individual security checks.

Each check is a small pure function over :class:`ScanContext` returning findings.
Checks never make network requests and never compute a score.
"""

from jussiai_scanner.scanner.checks.availability import check_availability
from jussiai_scanner.scanner.checks.base import Check
from jussiai_scanner.scanner.checks.disclosure import check_information_disclosure
from jussiai_scanner.scanner.checks.headers import check_security_headers
from jussiai_scanner.scanner.checks.transport import check_transport

#: Registry, in report order. Adding a check means adding it here.
ALL_CHECKS: tuple[Check, ...] = (
    check_availability,
    check_transport,
    check_security_headers,
    check_information_disclosure,
)

__all__ = [
    "ALL_CHECKS",
    "Check",
    "check_availability",
    "check_information_disclosure",
    "check_security_headers",
    "check_transport",
]
