"""DNS resolution must validate every address a name resolves to."""

from __future__ import annotations

import ipaddress
import socket

import pytest

from jussiai_scanner.config import Settings
from jussiai_scanner.security.errors import BlockedAddressError, TargetValidationError
from jussiai_scanner.security.ip_rules import IPAddress
from jussiai_scanner.security.resolver import (
    Resolver,
    resolve_target,
    resolve_target_async,
    system_resolver,
    validate_addresses,
)
from jussiai_scanner.security.url_validation import validate_target_url
from tests.conftest import build_settings


@pytest.fixture
def settings() -> Settings:
    return build_settings()


def _resolver(*addresses: str) -> Resolver:
    def resolve(host: str, port: int) -> list[IPAddress]:
        return [ipaddress.ip_address(a) for a in addresses]

    return resolve


def test_public_answer_is_accepted(settings: Settings) -> None:
    target = validate_target_url("https://example.com", settings)
    resolved = resolve_target(target, _resolver("93.184.216.34"))
    assert resolved.connect_address == ipaddress.ip_address("93.184.216.34")


def test_private_answer_is_rejected(settings: Settings) -> None:
    target = validate_target_url("https://example.com", settings)
    with pytest.raises(BlockedAddressError, match="private"):
        resolve_target(target, _resolver("10.1.2.3"))


def test_metadata_answer_is_rejected(settings: Settings) -> None:
    """A public-looking name pointing at the metadata service must not resolve."""
    target = validate_target_url("https://attacker-controlled.tld-that-is-public.net", settings)
    with pytest.raises(BlockedAddressError, match="metadata"):
        resolve_target(target, _resolver("169.254.169.254"))


def test_mixed_answer_is_rejected(settings: Settings) -> None:
    """One internal address among several public ones still blocks the target.

    A round-robin or split-horizon record that sometimes answers with an
    internal address is a rebinding primitive, not a safe scan target.
    """
    target = validate_target_url("https://example.com", settings)
    with pytest.raises(BlockedAddressError):
        resolve_target(target, _resolver("93.184.216.34", "127.0.0.1"))


def test_empty_answer_is_rejected(settings: Settings) -> None:
    target = validate_target_url("https://example.com", settings)
    with pytest.raises(TargetValidationError, match="did not resolve"):
        resolve_target(target, _resolver())


def test_ip_literal_target_skips_dns(settings: Settings) -> None:
    def exploding_resolver(host: str, port: int) -> list[IPAddress]:
        raise AssertionError("DNS must not be queried for an IP literal")

    target = validate_target_url("http://93.184.216.34/", settings)
    resolved = resolve_target(target, exploding_resolver)
    assert resolved.addresses == (ipaddress.ip_address("93.184.216.34"),)


def test_addresses_are_pinned_for_the_connection(settings: Settings) -> None:
    """Callers get concrete addresses so connections need not re-resolve."""
    target = validate_target_url("https://example.com", settings)
    resolved = resolve_target(target, _resolver("93.184.216.34", "1.1.1.1"))
    assert resolved.addresses == (
        ipaddress.ip_address("93.184.216.34"),
        ipaddress.ip_address("1.1.1.1"),
    )


def test_resolution_failure_is_reported_as_validation_error(settings: Settings) -> None:
    def failing_resolver(host: str, port: int) -> list[IPAddress]:
        raise socket.gaierror("nope")

    target = validate_target_url("https://example.com", settings)
    with pytest.raises(socket.gaierror):
        resolve_target(target, failing_resolver)


def test_system_resolver_maps_gaierror(monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(*args: object, **kwargs: object) -> None:
        raise socket.gaierror("no such host")

    monkeypatch.setattr(socket, "getaddrinfo", boom)
    with pytest.raises(TargetValidationError, match="could not be resolved"):
        system_resolver("example.invalid", 443)


def test_system_resolver_deduplicates(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_getaddrinfo(*args: object, **kwargs: object) -> list[tuple[object, ...]]:
        return [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443)),
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443)),
            (socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("2606:2800:220:1::1", 443, 0, 0)),
        ]

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)
    assert len(system_resolver("example.com", 443)) == 2


def test_validate_addresses_returns_input_when_all_public() -> None:
    addresses = [ipaddress.ip_address("1.1.1.1"), ipaddress.ip_address("8.8.8.8")]
    assert validate_addresses(addresses) == tuple(addresses)


async def test_async_resolution(settings: Settings) -> None:
    target = validate_target_url("https://example.com", settings)
    resolved = await resolve_target_async(target, _resolver("93.184.216.34"))
    assert resolved.connect_address == ipaddress.ip_address("93.184.216.34")
