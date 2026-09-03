"""The check contract."""

from __future__ import annotations

from collections.abc import Callable, Sequence

from jussiai_scanner.models.findings import Finding
from jussiai_scanner.scanner.context import ScanContext

#: A check maps the gathered evidence to zero or more findings.
Check = Callable[[ScanContext], Sequence[Finding]]
