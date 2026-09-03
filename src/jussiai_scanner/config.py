"""Application settings.

Settings are immutable and injected rather than read from module-level globals,
so that tests can construct alternative configurations without patching state.
"""

from __future__ import annotations

from functools import lru_cache

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Runtime configuration with conservative, security-oriented defaults."""

    model_config = SettingsConfigDict(
        env_prefix="JUSSIAI_",
        env_file=".env",
        env_file_encoding="utf-8",
        frozen=True,
        extra="ignore",
    )

    # --- Outbound network limits -------------------------------------------------
    request_timeout_seconds: float = Field(default=10.0, gt=0, le=60)
    total_scan_timeout_seconds: float = Field(default=60.0, gt=0, le=300)
    max_redirects: int = Field(default=5, ge=0, le=10)
    max_response_bytes: int = Field(default=1_048_576, gt=0, le=10_485_760)
    max_concurrent_requests: int = Field(default=4, ge=1, le=16)

    # --- Target restrictions -----------------------------------------------------
    allowed_ports: frozenset[int] = Field(default=frozenset({80, 443}))
    max_url_length: int = Field(default=2048, ge=16, le=8192)

    # --- AI provider -------------------------------------------------------------
    ai_enabled: bool = True
    ollama_base_url: str = "http://127.0.0.1:11434"
    ollama_model: str = "llama3.1"
    ollama_timeout_seconds: float = Field(default=60.0, gt=0, le=300)


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Return the process-wide settings instance (cached)."""
    return Settings()
