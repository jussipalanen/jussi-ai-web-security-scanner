"""FastAPI dependency providers."""

from __future__ import annotations

from typing import Annotated

from fastapi import Depends

from jussiai_scanner.config import Settings, get_settings

SettingsDep = Annotated[Settings, Depends(get_settings)]
