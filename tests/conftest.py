"""Shared test fixtures."""

from __future__ import annotations

from typing import Any

import pytest
from fastapi.testclient import TestClient

from jussiai_scanner.api.app import create_app
from jussiai_scanner.config import Settings


def build_settings(**overrides: Any) -> Settings:
    """Build settings for tests, ignoring any .env file in the working tree."""
    return Settings(_env_file=None, **overrides)  # type: ignore[call-arg]


@pytest.fixture
def settings() -> Settings:
    return build_settings()


@pytest.fixture
def client() -> TestClient:
    return TestClient(create_app())
