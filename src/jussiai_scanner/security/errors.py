"""Exceptions raised by the validation layer."""

from __future__ import annotations


class TargetValidationError(ValueError):
    """The supplied target is not a URL the scanner is allowed to fetch.

    The message is safe to return to API clients: it explains *why* a target was
    rejected without leaking internal network topology.
    """

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


class BlockedAddressError(TargetValidationError):
    """A hostname resolved to an address the scanner must not connect to."""
