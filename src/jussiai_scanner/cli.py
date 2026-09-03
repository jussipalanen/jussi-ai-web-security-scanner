"""Command-line entry point.

Exists so the scanner can be run without FastAPI, which is also the cheapest way
to produce a report file: no server, no HTTP round trip.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from dataclasses import asdict
from pathlib import Path

from jussiai_scanner import __version__
from jussiai_scanner.config import Settings, get_settings
from jussiai_scanner.models.findings import Severity
from jussiai_scanner.reporting import render_scan_pdf
from jussiai_scanner.scanner.engine import Scanner, ScanResult
from jussiai_scanner.scanner.http_client import FetchError
from jussiai_scanner.security.errors import TargetValidationError

EXIT_OK = 0
EXIT_REJECTED = 2
EXIT_UNREACHABLE = 3

_SEVERITY_ORDER = (Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="jussiai-scan",
        description="Scan a public URL and optionally write a PDF or JSON report.",
    )
    parser.add_argument("url", help="Target URL. A bare host is treated as https://host/.")
    parser.add_argument(
        "--pdf",
        metavar="PATH",
        type=Path,
        help="Write a PDF report to PATH. Use - for stdout.",
    )
    parser.add_argument(
        "--json",
        metavar="PATH",
        dest="json_path",
        type=Path,
        help="Write the raw result as JSON to PATH. Use - for stdout.",
    )
    parser.add_argument(
        "-q", "--quiet", action="store_true", help="Suppress the findings summary on stdout."
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return parser


def _print_summary(result: ScanResult) -> None:
    counts = {sev: sum(1 for f in result.findings if f.severity is sev) for sev in _SEVERITY_ORDER}
    print(f"{result.final_url}  ->  HTTP {result.status_code}  ({result.duration_ms:.0f} ms)")
    print("  " + "  ".join(f"{counts[sev]} {sev.value}" for sev in _SEVERITY_ORDER))
    for note in result.notes:
        print(f"  note: {note}")
    print()
    for finding in sorted(result.findings, key=lambda f: _SEVERITY_ORDER.index(f.severity)):
        print(f"[{finding.severity.value:6}] {finding.title}")
        if finding.remediation and finding.remediation != "No action needed.":
            print(f"          fix: {finding.remediation}")


def _write(path: Path, data: bytes, label: str) -> None:
    """Write ``data`` to ``path``, or to stdout when ``path`` is ``-``.

    Streaming to stdout is what makes this usable inside a container whose only
    writable mount is a tmpfs: ``docker cp`` cannot read from tmpfs, but a pipe
    works everywhere.
    """
    if str(path) == "-":
        sys.stdout.buffer.write(data)
        sys.stdout.buffer.flush()
        print(f"{label} written to stdout", file=sys.stderr)
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    print(f"{label} written to {path}", file=sys.stderr)


def run(args: argparse.Namespace, settings: Settings) -> int:
    """Run one scan and write whatever outputs were requested."""
    try:
        result = asyncio.run(Scanner(settings).scan(args.url))
    except TargetValidationError as exc:
        print(f"rejected: {exc.reason}", file=sys.stderr)
        return EXIT_REJECTED
    except FetchError as exc:
        print(f"unreachable: {exc}", file=sys.stderr)
        return EXIT_UNREACHABLE

    if not args.quiet:
        _print_summary(result)
    if args.pdf:
        _write(args.pdf, render_scan_pdf(result), "PDF report")
    if args.json_path:
        payload = asdict(result)
        payload["findings"] = [f.model_dump(mode="json") for f in result.findings]
        _write(args.json_path, json.dumps(payload, indent=2).encode(), "JSON report")
    return EXIT_OK


def main(argv: list[str] | None = None) -> int:
    """Entry point for the ``jussiai-scan`` command."""
    args = build_parser().parse_args(argv)
    return run(args, get_settings())


if __name__ == "__main__":  # pragma: no cover - exercised via __main__.py
    raise SystemExit(main())
