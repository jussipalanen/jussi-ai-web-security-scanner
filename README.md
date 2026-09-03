# JussiAI Web Security Scanner

AI-powered, **non-destructive** web security scanner.

The scanner performs safe, read-only checks against public websites. A local LLM
(via Ollama) explains the findings — it never discovers them.

> The score this tool produces is the *JussiAI Web Security Scanner Score*. It is
> a deterministic heuristic defined by this project, not an industry-standard
> security rating.

## Status

Early development. Implemented so far:

- Project skeleton, packaging, tooling
- **Target validation and SSRF protection** (`jussiai_scanner.security`)
- FastAPI application with `/health` and `/validate`
- Shared finding/severity models

Not yet implemented: the scanner engine, the individual checks, scoring, and the
AI layer. See [Roadmap](#roadmap).

## Requirements

- Python 3.12+
- [Ollama](https://ollama.com/) (only once the AI layer lands)

## Setup

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -e ".[dev]"
```

If your Python has no bundled `pip`/`ensurepip` (some minimal distro builds):

```bash
python3 -m venv --without-pip .venv
curl -LO https://bootstrap.pypa.io/get-pip.py && .venv/bin/python get-pip.py
```

Copy `.env.example` to `.env` to override any defaults.

## Running

```bash
.venv/bin/uvicorn jussiai_scanner.api.app:app --reload
```

Interactive API docs: <http://127.0.0.1:8000/docs>

```bash
curl -s localhost:8000/health
curl -s -X POST localhost:8000/validate -H 'content-type: application/json' \
  -d '{"url": "example.com"}'
```

## Quality gate

```bash
.venv/bin/python -m pytest
.venv/bin/python -m ruff check . && .venv/bin/python -m ruff format --check .
.venv/bin/python -m mypy
```

## Architecture

Concerns are kept in separate modules so the scanner engine stays usable without
FastAPI.

```
src/jussiai_scanner/
├── config.py            Immutable settings, injected rather than global
├── models/              Pydantic models shared across layers
│   ├── findings.py      Severity, Confidence, Finding
│   └── scan.py          API request/response shapes
├── security/            Validation and SSRF defence
│   ├── errors.py        TargetValidationError / BlockedAddressError
│   ├── ip_rules.py      Address classification (ipaddress-based)
│   ├── hostnames.py     Hostname policy, IDNA normalisation
│   ├── url_validation.py  Static URL validation (no network)
│   └── resolver.py      DNS resolution + mandatory address validation
└── api/                 Thin FastAPI adapter — no scanning logic
```

### SSRF model

A target must pass two stages before any request is made, and the same pair is
re-applied to **every redirect hop**:

1. **Static validation** (`validate_target_url`) — no network access.
   - `http`/`https` only; other schemes rejected explicitly, not by accident.
   - No embedded credentials (`https://example.com@127.0.0.1/` targets `127.0.0.1`).
   - Port allowlist (default `{80, 443}`).
   - Hostnames normalised and IDNA-encoded; reserved suffixes (`.local`,
     `.internal`, `.localhost`, `.onion`, …) and non-FQDNs rejected.
   - IP literals classified immediately.
2. **Resolution** (`resolve_target`) — every address the name resolves to is
   classified; *one* blocked answer rejects the target.

Address classification (`ip_rules.classify_address`) works on `ipaddress`
objects, never on strings, because textual matching is trivially bypassed
(`0177.0.0.1`, `2130706433`, `[::ffff:127.0.0.1]`, `0::1` all mean loopback). It
blocks loopback, unspecified, private, link-local, multicast, reserved,
carrier-grade NAT, unique-local and site-local addresses, known cloud metadata
endpoints, and IPv4 addresses smuggled inside IPv6 (IPv4-mapped, IPv4-compatible,
6to4, Teredo, NAT64). Anything the standard library does not consider globally
routable is rejected as a backstop.

**DNS rebinding:** the resolver returns the concrete validated addresses so the
HTTP layer can *pin* the connection to an address that was actually checked.
Re-resolving at connect time would reopen the hole.

### AI boundary

The deterministic Python scanner is authoritative. The LLM may **only** explain
findings, describe impact, suggest remediation and write a summary. It never
discovers vulnerabilities, calculates the score, executes commands, or makes
network requests. Evidence attached to a `Finding` is the sole factual basis it
is allowed to describe.

## Roadmap

- [x] Validation & SSRF core
- [ ] SSRF-safe HTTP client (pinned addresses, redirect re-validation, size/time caps)
- [ ] Scanner engine + MVP checks (status, timing, HTTPS, redirects, TLS,
      security headers, information disclosure, `robots.txt`, `sitemap.xml`,
      lightweight tech detection)
- [ ] Deterministic scoring (0–100), documented algorithm
- [ ] AI provider abstraction + Ollama implementation
