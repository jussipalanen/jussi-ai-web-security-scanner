"""Address classification: everything not publicly routable must be rejected."""

from __future__ import annotations

import ipaddress

import pytest

from jussiai_scanner.security.ip_rules import classify_address, is_scannable_address

BLOCKED = [
    # Loopback and unspecified.
    "127.0.0.1",
    "127.1.2.3",
    "0.0.0.0",
    "::1",
    "::",
    # Private IPv4 ranges.
    "10.0.0.1",
    "172.16.5.4",
    "172.31.255.255",
    "192.168.1.1",
    # Link-local and cloud metadata.
    "169.254.1.1",
    "169.254.169.254",
    "fe80::1",
    "100.100.100.200",
    "192.0.0.192",
    "fd00:ec2::254",
    # Carrier-grade NAT.
    "100.64.0.1",
    # Multicast and reserved.
    "224.0.0.1",
    "ff02::1",
    "240.0.0.1",
    # IPv6 private / unique-local.
    "fc00::1",
    "fd12:3456:789a::1",
    # IPv4 smuggled inside IPv6 forms.
    "::ffff:127.0.0.1",
    "::ffff:10.0.0.1",
    "::ffff:169.254.169.254",
    "::127.0.0.1",
    "2002:7f00:1::",  # 6to4 wrapping 127.0.0.1
    "2002:a00:1::",  # 6to4 wrapping 10.0.0.1
    "64:ff9b::7f00:1",  # NAT64 wrapping 127.0.0.1
    "64:ff9b::a9fe:a9fe",  # NAT64 wrapping 169.254.169.254
]

# Publicly routable addresses. RFC 5737 documentation ranges (192.0.2.0/24,
# 198.51.100.0/24, 203.0.113.0/24) cannot be used here: they are not globally
# routable, so the scanner correctly rejects them.
ALLOWED = [
    "1.1.1.1",
    "8.8.8.8",
    "2606:4700:4700::1111",
    "2001:4860:4860::8888",
]


@pytest.mark.parametrize("raw", BLOCKED)
def test_blocked_addresses_are_rejected(raw: str) -> None:
    address = ipaddress.ip_address(raw)
    assert not is_scannable_address(address), f"{raw} should be blocked"
    assert classify_address(address)


@pytest.mark.parametrize("raw", ALLOWED)
def test_public_addresses_are_allowed(raw: str) -> None:
    address = ipaddress.ip_address(raw)
    assert is_scannable_address(address), f"{raw} should be scannable"
    assert classify_address(address) is None


def test_rejection_reason_is_specific_for_metadata_endpoint() -> None:
    reason = classify_address(ipaddress.ip_address("169.254.169.254"))
    assert reason == "cloud instance metadata endpoint"
