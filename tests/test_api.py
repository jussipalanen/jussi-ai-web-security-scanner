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
