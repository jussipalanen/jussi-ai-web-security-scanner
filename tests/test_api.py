"""API layer smoke tests."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient


def test_health(client: TestClient) -> None:
    response = client.get("/health")
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "ok"
    assert body["version"]


def test_validate_accepts_public_url(client: TestClient) -> None:
    response = client.post("/validate", json={"url": "example.com/path"})
    assert response.status_code == 200
    assert response.json()["url"] == "https://example.com/path"


@pytest.mark.parametrize(
    "url",
    [
        "http://127.0.0.1/",
        "http://localhost/",
        "http://169.254.169.254/",
        "file:///etc/passwd",
        "http://example.com:22/",
    ],
)
def test_validate_rejects_unsafe_targets(client: TestClient, url: str) -> None:
    response = client.post("/validate", json={"url": url})
    assert response.status_code == 422
    assert response.json()["detail"]


def test_validate_rejects_unknown_fields(client: TestClient) -> None:
    response = client.post("/validate", json={"url": "example.com", "surprise": 1})
    assert response.status_code == 422


def test_openapi_is_served(client: TestClient) -> None:
    assert client.get("/openapi.json").status_code == 200


def test_scan_rejects_unsafe_target(client: TestClient) -> None:
    """The endpoint refuses before any socket is opened."""
    response = client.post("/scan", json={"url": "http://169.254.169.254/"})
    assert response.status_code == 422
    assert response.json()["detail"]


def test_scan_is_documented(client: TestClient) -> None:
    spec = client.get("/openapi.json").json()
    assert "/scan" in spec["paths"]
    finding = spec["components"]["schemas"]["Finding"]["properties"]
    assert "remediation" in finding
    assert "description" in finding


def test_test_page_is_served(client: TestClient) -> None:
    response = client.get("/test-url")
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/html")
    assert "JussiAI Web Security Scanner" in response.text


def test_test_page_sets_a_strict_csp(client: TestClient) -> None:
    """The page renders values echoed from scanned sites, so it must be locked down."""
    csp = client.get("/test-url").headers["content-security-policy"]
    assert "default-src 'none'" in csp
    assert "'unsafe-inline'" not in csp
    assert client.get("/test-url").headers["x-content-type-options"] == "nosniff"


def test_page_assets_are_served(client: TestClient) -> None:
    for path, content_type in (("/static/app.js", "javascript"), ("/static/styles.css", "css")):
        response = client.get(path)
        assert response.status_code == 200, path
        assert content_type in response.headers["content-type"]


def test_page_uses_no_inline_script_or_external_origin(client: TestClient) -> None:
    """A strict CSP is only useful if the page actually complies with it."""
    html = client.get("/test-url").text
    assert "<script>" not in html, "inline script would be blocked by the CSP"
    assert "http://" not in html and "https://" not in html, "no external resources"


def test_page_never_writes_raw_html(client: TestClient) -> None:
    """Scanner output is attacker-influenced; it must only ever be set as text.

    Matches assignments and HTML-writing calls rather than the bare word, so the
    comment in app.js explaining the rule does not trip the test.
    """
    source = client.get("/static/app.js").text
    for pattern in ("innerHTML =", "outerHTML =", "insertAdjacentHTML", "document.write"):
        assert pattern not in source, f"app.js must not use {pattern}"
    assert "textContent" in source, "rendering should go through textContent"


def test_test_page_is_hidden_from_the_api_schema(client: TestClient) -> None:
    assert "/test-url" not in client.get("/openapi.json").json()["paths"]
