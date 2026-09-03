"""The command-line entry point."""

from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path

import pytest

from jussiai_scanner import cli
from jussiai_scanner.models.findings import Confidence, Finding, Severity
from jussiai_scanner.scanner.engine import ScanResult
from jussiai_scanner.scanner.http_client import FetchError
from jussiai_scanner.security.errors import TargetValidationError
from tests.conftest import build_settings

RESULT = ScanResult(
    requested_url="example.com",
    final_url="https://example.com/",
    status_code=200,
    findings=(
        Finding(
            check_id="headers.csp",
            title="content-security-policy header is missing",
            severity=Severity.MEDIUM,
            confidence=Confidence.HIGH,
            description="Restricts where scripts load from.",
            remediation="Send a Content-Security-Policy header.",
            evidence={"present": "false"},
        ),
    ),
    duration_ms=120.0,
    checks_run=("check_security_headers",),
)


#: Installs a fake engine; pass an exception to make the scan fail that way.
StubScan = Callable[..., None]


@pytest.fixture
def stub_scan(monkeypatch: pytest.MonkeyPatch) -> StubScan:
    """Replace the engine so the CLI is tested without any network access."""

    def factory(outcome: object = RESULT) -> None:
        async def fake_scan(self: object, url: str, **kwargs: object) -> ScanResult:
            if isinstance(outcome, Exception):
                raise outcome
            return RESULT

        monkeypatch.setattr("jussiai_scanner.cli.Scanner.scan", fake_scan)

    return factory


def invoke(argv: list[str]) -> int:
    args = cli.build_parser().parse_args(argv)
    return cli.run(args, build_settings())


def test_scan_prints_summary(stub_scan: StubScan, capsys: pytest.CaptureFixture[str]) -> None:
    stub_scan()
    assert invoke(["example.com"]) == cli.EXIT_OK
    out = capsys.readouterr().out
    assert "https://example.com/" in out
    assert "content-security-policy header is missing" in out
    assert "fix:" in out


def test_quiet_suppresses_the_summary(
    stub_scan: StubScan, capsys: pytest.CaptureFixture[str]
) -> None:
    stub_scan()
    assert invoke(["example.com", "--quiet"]) == cli.EXIT_OK
    assert capsys.readouterr().out == ""


def test_writes_a_pdf(stub_scan: StubScan, tmp_path: Path) -> None:
    stub_scan()
    out = tmp_path / "nested" / "report.pdf"
    assert invoke(["example.com", "--pdf", str(out), "--quiet"]) == cli.EXIT_OK
    assert out.read_bytes().startswith(b"%PDF-"), "parent directories should be created"


def test_writes_json(stub_scan: StubScan, tmp_path: Path) -> None:
    stub_scan()
    out = tmp_path / "report.json"
    assert invoke(["example.com", "--json", str(out), "--quiet"]) == cli.EXIT_OK
    data = json.loads(out.read_text())
    assert data["final_url"] == "https://example.com/"
    assert data["findings"][0]["check_id"] == "headers.csp"
    assert data["findings"][0]["remediation"]


def test_rejected_target_exits_2(stub_scan: StubScan, capsys: pytest.CaptureFixture[str]) -> None:
    stub_scan(TargetValidationError("the target address is a loopback address"))
    assert invoke(["http://127.0.0.1/"]) == cli.EXIT_REJECTED
    assert "loopback" in capsys.readouterr().err


def test_unreachable_target_exits_3(
    stub_scan: StubScan, capsys: pytest.CaptureFixture[str]
) -> None:
    stub_scan(FetchError("the target could not be reached", kind="connection"))
    assert invoke(["example.com"]) == cli.EXIT_UNREACHABLE
    assert "unreachable" in capsys.readouterr().err


def test_no_output_file_is_written_when_the_target_is_rejected(
    stub_scan: StubScan, tmp_path: Path
) -> None:
    stub_scan(TargetValidationError("nope"))
    out = tmp_path / "report.pdf"
    assert invoke(["http://127.0.0.1/", "--pdf", str(out)]) == cli.EXIT_REJECTED
    assert not out.exists()


def test_pdf_can_be_streamed_to_stdout(
    stub_scan: StubScan, capsysbinary: pytest.CaptureFixture[bytes]
) -> None:
    """`--pdf -` is what makes this work inside a read-only container."""
    stub_scan()
    assert invoke(["example.com", "--pdf", "-", "--quiet"]) == cli.EXIT_OK
    assert capsysbinary.readouterr().out.startswith(b"%PDF-")
