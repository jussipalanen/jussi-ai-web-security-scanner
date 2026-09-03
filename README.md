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
- **SSRF-safe HTTP client** with address pinning and per-hop revalidation
- **Scanner engine** and 7 of the 11 MVP checks
- FastAPI application with `/health`, `/validate` and `/scan`
- Browser test page at `/test-url`
- PDF and JSON reports from the command line

Not yet implemented: TLS certificate checks, `robots.txt`, `sitemap.xml`,
technology detection, scoring, and the AI layer. See [Roadmap](#roadmap).

## Testing with Postman

An importable collection lives in [`postman/`](postman/) — 33 requests covering
the scan endpoint and the full SSRF rejection set. See
[postman/README.md](postman/README.md).

## Requirements

- Python 3.12+
- [Ollama](https://ollama.com/) (only once the AI layer lands)

## Docker

A helper script wraps the common operations:

```bash
./dev up              # build, start, wait for the health check
./dev scan example.com   # scan through the container and print findings
./dev logs            # follow the logs
./dev test            # ruff, mypy and pytest in a throwaway container
./dev down            # stop and remove
```

Run `./dev` with no arguments for the full list. Or use compose directly:

```bash
docker compose up --build
```

The API is then on <http://localhost:8000>, with the test page at
<http://localhost:8000/test-url>.

The image is multi-stage, so no build toolchain ships in the runtime layer, and
the container runs as an unprivileged user. The compose service drops all
capabilities, mounts the root filesystem read-only and sets
`no-new-privileges` — the scanner only makes outbound requests and needs no
write access.

Override any setting through the environment (see `.env.example`):

```bash
JUSSIAI_MAX_REDIRECTS=3 docker compose up
```

> A local `uvicorn` already listening on port 8000 will shadow the container:
> requests reach the host process instead, and the container looks stale.
> `./dev up` warns when it detects this. Stop the host process, or use
> `JUSSIAI_PORT=8010 ./dev up` with a matching port in `docker-compose.yml`.

A commented-out `ollama` service is included behind a profile
(`docker compose --profile ai up`) for when the AI layer lands. It does nothing
today.

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
```

## Test page

A minimal browser form for trying the scanner by hand:

```
http://localhost:8000/test-url
```

Enter a host, submit, and the findings render with their descriptions and
remediation steps. It is served by the backend itself, so it is same-origin and
needs no CORS configuration.

A target can also be passed in the query string, which scans it immediately —
useful for bookmarking or linking a scan:

```
http://localhost:8000/test-url?url=https://example.com
```

Submitting the form updates the address bar to match, so a result can be
shared or reloaded, and back/forward move between scans.

The page is static (no build step, no external resources) and locked down with
`default-src 'none'`. It renders header values echoed from scanned sites, so
everything is inserted as text, never as HTML. The `?url=` value is read
client-side and never echoed into the page by the server — the response is
byte-identical whatever the parameter contains.

## Scanning a site

`POST /scan` runs the checks and returns findings. Replace `example.com` with the
host you want to scan.

```bash
curl -s -X POST localhost:8000/scan \
  -H 'content-type: application/json' \
  -d '{"url": "example.com"}'
```

A bare host is fine — it is normalised to `https://` — and so is a full URL with
a path.

### What comes back

```jsonc
{
  "requested_url": "example.com",
  "final_url": "https://example.com/",   // after following redirects
  "status_code": 200,
  "duration_ms": 157.0,
  "counts": { "high": 0, "medium": 3, "low": 3, "info": 5 },
  "findings": [
    {
      "check_id": "headers.content-security-policy",
      "title": "content-security-policy header is missing",
      "severity": "medium",              // info | low | medium | high
      "confidence": "high",
      "description": "This header restricts where scripts, styles and frames may load from ...",
      "remediation": "Roll out in report-only mode first: Content-Security-Policy-Report-Only ...",
      "evidence": { "header": "content-security-policy", "present": "false" }
    }
  ],
  "checks_run": ["check_availability", "check_transport", "..."],
  "notes": []                            // what the scanner could not do, and why
}
```

Every finding carries a `description` (what it means) and a `remediation` (what to
do about it). Both are written by the Python check, so the advice is deterministic
and reviewable — no model generated them. `evidence` holds the raw observed values.

`notes` records anything the scanner skipped, such as port 80 being closed, so a
partial scan is never silently reported as a clean one.

### Just the action items

Pipe the response through `jq` to list only what needs fixing:

```bash
curl -s -X POST localhost:8000/scan \
  -H 'content-type: application/json' \
  -d '{"url": "example.com"}' \
| jq -r '.findings[] | select(.severity != "info")
         | "[\(.severity)] \(.title)\n  -> \(.remediation)\n"'
```

### PDF and JSON reports

The scanner runs from the command line without the API, which is the simplest
way to produce a report file:

```bash
.venv/bin/python -m jussiai_scanner example.com --pdf report.pdf
.venv/bin/python -m jussiai_scanner example.com --json result.json --quiet
```

Installing the package also provides a `jussiai-scan` command. Use `-` as the
path to stream to stdout. Exit codes: `0` scanned, `2` target rejected, `3`
target unreachable.

Through Docker:

```bash
./dev report example.com              # writes report.pdf
./dev report example.com audit.pdf
```

The PDF lists every finding with its description, remediation and evidence,
grouped worst-first. It states plainly that no score is included.

### Checking a URL without scanning it

`POST /validate` answers "is this target allowed?" and sends **no request** to it:

```bash
curl -s -X POST localhost:8000/validate -H 'content-type: application/json' \
  -d '{"url": "example.com"}'
# {"url":"https://example.com/","scheme":"https","host":"example.com","port":443}
```

### Responses you may get

| Status | Meaning |
|---|---|
| `200` | Scan completed |
| `422` | Target refused by validation (private address, bad scheme, disallowed port, unresolvable name) |
| `502` | Target is allowed but could not be reached |

### What it checks today

HTTP status, response time, HTTPS on the final URL, HTTP→HTTPS upgrade, redirect
chain (including HTTPS→HTTP downgrades), six security headers, and
`Server`/`X-Powered-By` information disclosure.

All requests are read-only `GET`s. Nothing is crawled, fuzzed or modified. Only
scan hosts you own or are explicitly authorised to test.

> There is no `score` field yet, and no AI commentary — both are separate
> roadmap items.

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
├── scanner/             Engine, SSRF-safe client, individual checks
│   ├── http_client.py   Pins connections to validated IPs; revalidates each hop
│   ├── engine.py        Owns all network access; runs the check registry
│   └── checks/          One small module per concern
├── reporting/           PDF rendering
├── cli.py               jussiai-scan / python -m jussiai_scanner
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
- [x] SSRF-safe HTTP client (pinned addresses, redirect re-validation, size/time caps)
- [x] Scanner engine + `POST /scan`
- [x] Checks: status, response time, HTTPS, HTTP→HTTPS redirect, redirect chain,
      security headers, information disclosure
- [ ] Checks: TLS/certificate basics, `robots.txt`, `sitemap.xml`, lightweight
      technology detection
- [ ] Deterministic scoring (0–100), documented algorithm
- [ ] AI provider abstraction + Ollama implementation
