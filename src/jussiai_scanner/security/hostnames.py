"""Hostname-level rules applied before any DNS lookup happens."""

from __future__ import annotations

import re
from typing import Final

# Names that are, by convention or RFC, never public internet hosts.
_BLOCKED_SUFFIXES: Final[tuple[str, ...]] = (
    ".local",
    ".localhost",
    ".localdomain",
    ".internal",
    ".intranet",
    ".corp",
    ".home",
    ".home.arpa",
    ".lan",
    ".private",
    ".test",
    ".example",
    ".invalid",
    ".onion",
    ".arpa",
)

_BLOCKED_EXACT: Final[frozenset[str]] = frozenset(
    {"localhost", "localhost.localdomain", "metadata", "metadata.google.internal"}
)

_LABEL_RE: Final = re.compile(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$")

MAX_HOSTNAME_LENGTH: Final = 253


def normalize_hostname(host: str) -> str:
    """Lower-case, strip a trailing dot and IDNA-encode ``host``.

    Raises:
        ValueError: if the name cannot be represented as an ASCII hostname.
    """
    candidate = host.strip().rstrip(".").lower()
    if not candidate:
        raise ValueError("the URL has no hostname")
    try:
        encoded = candidate.encode("idna").decode("ascii")
    except UnicodeError as exc:  # pragma: no cover - message varies by platform
        raise ValueError("the hostname is not a valid international domain name") from exc
    return encoded


def classify_hostname(host: str) -> str | None:
    """Return a rejection reason for ``host``, or ``None`` if it is acceptable.

    ``host`` is expected to already be normalised. This check is deliberately
    independent of DNS: it rejects names that must not even be looked up.
    """
    if len(host) > MAX_HOSTNAME_LENGTH:
        return "the hostname is too long"
    if host in _BLOCKED_EXACT:
        return "the hostname refers to the local machine"
    if any(host.endswith(suffix) for suffix in _BLOCKED_SUFFIXES):
        return "the hostname uses a reserved or internal-only domain suffix"
    labels = host.split(".")
    if len(labels) < 2:
        return "the hostname is not a fully qualified public domain name"
    if any(not _LABEL_RE.match(label) for label in labels):
        return "the hostname contains invalid characters"
    if labels[-1].isdigit():
        return "the hostname has a numeric top-level domain"
    return None
