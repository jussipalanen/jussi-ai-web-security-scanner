"""Validation of user-supplied target URLs.

Validation happens in two stages, both of which must pass before any request is
made:

1. :func:`validate_target_url` - static checks on the URL itself (scheme, port,
   credentials, hostname policy, IP literals). No network access.
2. :func:`jussiai_scanner.security.resolver.resolve_target` - DNS resolution
   followed by :mod:`jussiai_scanner.security.ip_rules` checks on every address
   the name resolves to.

The same pair is re-applied to every redirect hop, so a redirect to an internal
address is rejected exactly like a directly supplied one.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from urllib.parse import urlsplit, urlunsplit

from jussiai_scanner.config import Settings, get_settings
from jussiai_scanner.security.errors import TargetValidationError
from jussiai_scanner.security.hostnames import classify_hostname, normalize_hostname
from jussiai_scanner.security.ip_rules import IPAddress, classify_address

ALLOWED_SCHEMES = frozenset({"http", "https"})
_SCHEME_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.\-]*:")
_DEFAULT_PORTS = {"http": 80, "https": 443}


@dataclass(frozen=True, slots=True)
class ValidatedTarget:
    """A URL that passed static validation.

    Attributes:
        url: The normalised absolute URL.
        scheme: ``http`` or ``https``.
        host: Normalised, IDNA-encoded hostname, or the compressed form of an IP
            literal.
        port: The effective port, defaulted from the scheme when absent.
        ip_literal: The parsed address when the host was given as an IP literal,
            otherwise ``None`` (meaning the host still needs DNS resolution).
    """

    url: str
    scheme: str
    host: str
    port: int
    ip_literal: IPAddress | None = None

    @property
    def is_ip_literal(self) -> bool:
        return self.ip_literal is not None


def _parse_ip_literal(host: str) -> IPAddress | None:
    """Return the address if ``host`` is an IP literal, else ``None``."""
    if host.startswith("[") and host.endswith("]"):
        host = host[1:-1]
    try:
        return ipaddress.ip_address(host)
    except ValueError:
        return None


def validate_target_url(raw_url: str, settings: Settings | None = None) -> ValidatedTarget:
    """Validate and normalise a target URL.

    Args:
        raw_url: The URL as supplied by the caller. A bare host such as
            ``example.com`` is treated as ``https://example.com``.
        settings: Configuration to read limits from; defaults to the process
            settings.

    Returns:
        The normalised target.

    Raises:
        TargetValidationError: If the URL is malformed or points somewhere the
            scanner is not permitted to reach.
    """
    settings = settings or get_settings()

    candidate = raw_url.strip()
    if not candidate:
        raise TargetValidationError("no URL was supplied")
    if len(candidate) > settings.max_url_length:
        raise TargetValidationError("the URL is too long")
    if any(char in candidate for char in ("\n", "\r", "\t", " ")):
        raise TargetValidationError("the URL contains whitespace or control characters")
    # Only prefix a scheme when there is genuinely none. Sniffing for "://"
    # would turn "javascript:alert(1)" into "https://javascript:alert(1)" and
    # reject it for the wrong reason.
    if _SCHEME_RE.match(candidate):
        if not candidate.lower().startswith(("http://", "https://")):
            raise TargetValidationError("only http and https URLs can be scanned")
    else:
        candidate = f"https://{candidate}"

    try:
        parts = urlsplit(candidate)
    except ValueError as exc:
        raise TargetValidationError("the URL could not be parsed") from exc

    scheme = parts.scheme.lower()
    if scheme not in ALLOWED_SCHEMES:
        raise TargetValidationError("only http and https URLs can be scanned")
    if parts.username or parts.password:
        raise TargetValidationError("URLs with embedded credentials are not accepted")

    try:
        raw_host = parts.hostname
        port = parts.port
    except ValueError as exc:
        raise TargetValidationError("the URL has an invalid port") from exc
    if not raw_host:
        raise TargetValidationError("the URL has no hostname")

    ip_literal = _parse_ip_literal(raw_host)
    if ip_literal is not None:
        if (reason := classify_address(ip_literal)) is not None:
            raise TargetValidationError(f"the target address is {reason}")
        host = ip_literal.compressed
        netloc_host = f"[{host}]" if ip_literal.version == 6 else host
    else:
        try:
            host = normalize_hostname(raw_host)
        except ValueError as exc:
            raise TargetValidationError(str(exc)) from exc
        if (reason := classify_hostname(host)) is not None:
            raise TargetValidationError(reason)
        netloc_host = host

    effective_port = port if port is not None else _DEFAULT_PORTS[scheme]
    if effective_port not in settings.allowed_ports:
        raise TargetValidationError(f"port {effective_port} is not allowed")

    netloc = netloc_host
    if port is not None and port != _DEFAULT_PORTS[scheme]:
        netloc = f"{netloc_host}:{port}"

    normalized = urlunsplit((scheme, netloc, parts.path or "/", parts.query, ""))
    return ValidatedTarget(
        url=normalized,
        scheme=scheme,
        host=host,
        port=effective_port,
        ip_literal=ip_literal,
    )
