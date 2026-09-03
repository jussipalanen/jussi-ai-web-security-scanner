# JussiAI Web Security Scanner

## Project

JussiAI Web Security Scanner is an AI-powered web security scanner.

The application performs safe, non-destructive security checks against
public websites and uses a local LLM through Ollama to explain findings
and provide remediation guidance.

This is a portfolio-quality project. Prioritize security, correctness,
maintainability and clean architecture over speed.

## Technology

Backend:

- Python 3.12+
- FastAPI
- Pydantic
- httpx
- pytest
- Ollama

Do not introduce unnecessary dependencies.

## Architecture

Keep these concerns separated:

- API layer
- Scanner engine
- Individual security checks
- Deterministic scoring
- AI analysis
- Security/validation utilities
- Data models

The scanner must be usable independently from FastAPI where practical.

## AI Architecture

The deterministic Python scanner is authoritative for security findings.

The LLM must NOT:

- discover vulnerabilities independently
- calculate the security score
- execute commands
- modify target websites
- perform arbitrary network requests

The LLM is responsible for:

- explaining findings
- describing potential impact
- suggesting remediation
- generating an overall summary

AI must never invent evidence.

The AI provider must be abstracted so that Ollama can later be replaced
or supplemented by another provider.

## Security Requirements

SSRF protection is critical.

The scanner must protect against:

- localhost
- loopback addresses
- private IPv4 networks
- private IPv6 networks
- link-local addresses
- multicast addresses
- cloud metadata endpoints
- internal hostnames
- redirects to internal/private addresses

Use proper IP/address validation rather than simple string matching.

Consider DNS rebinding and redirect-based SSRF.

Use:

- strict timeouts
- redirect limits
- response size limits
- conservative network access
- limited concurrency

Never implement destructive or intrusive penetration testing.

## Scanner MVP

Initially implement:

1. HTTP status
2. Response time
3. HTTPS detection
4. HTTP → HTTPS redirect
5. Redirect chain
6. TLS/certificate basic checks
7. Security headers
8. Server/X-Powered-By information disclosure
9. robots.txt
10. sitemap.xml
11. Lightweight technology detection

Do not crawl entire websites.

## Security Score

Calculate the JussiAI Web Security Scanner Score deterministically in Python.

Range:

0–100.

The LLM must never calculate the score.

Document the scoring algorithm.

Do not describe the score as an industry-standard security rating.

## Code Quality

Use:

- type hints
- Pydantic models
- small focused modules
- clear naming
- dependency injection where appropriate
- automated tests

Avoid:

- giant files
- duplicated logic
- unnecessary abstractions
- premature complexity
- global mutable state

## Testing

Use pytest.

All security-sensitive functionality must have tests.

Especially test:

- URL validation
- SSRF protection
- private IP detection
- redirects
- malformed URLs
- scanner checks
- scoring
- Ollama failures
- malformed AI responses

Do not make real Ollama calls in automated tests.

Mock the AI provider.

## Development Workflow

IMPORTANT:

Do not implement the entire project in one step.

Work incrementally.

Before implementing a significant architectural change:

1. Explain the proposed approach.
2. Identify security implications.
3. Identify affected files.
4. Implement the smallest reasonable change.
5. Run relevant tests.
6. Report what changed.

If a requirement is ambiguous or potentially insecure,
ask before making assumptions.

Do not add features outside the MVP without discussing them first.

## Current Task

At the beginning of a new development session:

1. Inspect the existing project.
2. Read CLAUDE.md.
3. Check the current implementation and tests.
4. Determine what has already been completed.
5. Do not rebuild existing functionality unnecessarily.

When asked to implement a feature, implement only that feature
unless explicitly instructed otherwise.