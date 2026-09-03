# AGENTS.md

Practical guide for AI agents working in this repository.

`CLAUDE.md` holds the project's rules and constraints and takes precedence over
this file. This one covers how to actually get work done here: commands, layout,
and the invariants that must not be broken.

## Commands

```bash
# Setup. This machine's python3 has no pip or ensurepip, hence the bootstrap.
python3 -m venv --without-pip .venv
curl -LO https://bootstrap.pypa.io/get-pip.py && .venv/bin/python get-pip.py
.venv/bin/python -m pip install -e ".[dev]"

# Quality gate. All four must pass before committing.
.venv/bin/python -m pytest
.venv/bin/python -m ruff check .
.venv/bin/python -m ruff format --check .
.venv/bin/python -m mypy

# Run
.venv/bin/uvicorn jussiai_scanner.api.app:app --reload   # API + /test-url page
.venv/bin/python -m jussiai_scanner example.com --pdf report.pdf

# Docker
./dev up | down | logs | shell | scan <url> | report <url> [file] | test
```

CI runs the same four checks on Python 3.12, 3.13 and 3.14, plus `pip-audit`.

## Layout

```
src/jussiai_scanner/
├── config.py       Frozen Settings, injected - never read as a global
├── models/         Pydantic models shared across layers
├── security/       Validation and SSRF defence (see invariants below)
├── scanner/        Engine, SSRF-safe HTTP client, individual checks
├── reporting/      PDF rendering
├── cli.py          `jussiai-scan` / `python -m jussiai_scanner`
└── api/            Thin FastAPI adapter; no scanning logic lives here
```

The engine must stay usable without FastAPI. If you find yourself importing
`fastapi` outside `api/`, something has gone wrong.

## Invariants

Break these and the project's central claim fails.

1. **All network access goes through `scanner/engine.py`.** Checks are pure
   functions of a `ScanContext`. A check that makes its own request bypasses
   every SSRF control.
2. **Address rules operate on `ipaddress` objects, never strings.** Textual
   matching is trivially defeated (`0177.0.0.1`, `2130706433`,
   `[::ffff:127.0.0.1]` all mean loopback).
3. **Connections are pinned to the validated IP.** Re-resolving a hostname at
   connect time reopens DNS rebinding.
4. **Every redirect hop is revalidated.** Redirects are followed manually for
   exactly this reason; do not switch on `follow_redirects=True`.
5. **The LLM never discovers findings or computes the score.** It may only
   explain findings the Python checks already produced. `Finding.remediation`
   is written in Python and must stay that way.
6. **Scanner output is untrusted.** Header values come from the scanned site.
   The test page renders them with `textContent` only; the PDF escapes them
   before they reach ReportLab's markup parser. Both are covered by tests.
7. **No score exists yet.** Do not add one casually, and never describe output
   as an industry-standard security rating.

## Conventions

- Type hints everywhere; `mypy --strict` must pass, including tests.
- Pydantic models for anything crossing a boundary; frozen where practical.
- Small modules, one concern each. New checks go in `scanner/checks/` and get
  registered in `ALL_CHECKS`.
- Docstrings say *why*, not *what*. Comments explain non-obvious decisions.
- Security-sensitive behaviour needs a test that would fail if it regressed.

## Testing

- Tests make **no real network calls**. Resolvers are injected and transports
  mocked (`httpx.MockTransport`). Verified by running the suite with
  `socket.connect` and `getaddrinfo` patched to raise.
- Never call a real Ollama instance; mock the AI provider when it lands.
- Placeholder hosts are `example.com`; placeholder addresses are `1.1.1.1` and
  `8.8.8.8`. RFC 5737 documentation ranges cannot be used where a target must be
  *accepted* - `ipaddress` reports them as not globally routable, so the scanner
  correctly rejects them.
- Never commit a real IP, host or domain belonging to the project's operator.
  Real targets belong in the Postman environment file, edited locally.

## Working style

`CLAUDE.md` asks for incremental work. Before a significant change: explain the
approach, name the security implications, list affected files, make the smallest
reasonable change, run the gate, and report what changed. Do not add features
outside the MVP without discussing them first.

## Current state

Implemented: validation and SSRF core, SSRF-safe HTTP client, engine, 7 of the
11 MVP checks, `POST /scan`, `/test-url` page, PDF/JSON reports, Docker, CI.

Not implemented: TLS/certificate checks, `robots.txt`, `sitemap.xml`, technology
detection, the deterministic score, and the AI layer.
