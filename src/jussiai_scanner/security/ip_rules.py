"""Classification of IP addresses into "safe to scan" and "blocked".

Rules are expressed against :mod:`ipaddress` objects rather than string matching,
because textual comparison is trivially bypassed (``0177.0.0.1``, ``2130706433``,
``[::ffff:127.0.0.1]``, ``0::1``, and so on all denote loopback).
"""

from __future__ import annotations

import ipaddress
from typing import Final

IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address

# Carrier-grade NAT. Not "private" per :mod:`ipaddress`, but never a legitimate
# scan target, and Alibaba Cloud serves instance metadata from 100.100.100.200.
_CGNAT_V4: Final = ipaddress.ip_network("100.64.0.0/10")

# NAT64 well-known prefix: embeds an IPv4 address in the low 32 bits, so an
# internal IPv4 target can be smuggled through an IPv6 literal.
_NAT64_V6: Final = ipaddress.ip_network("64:ff9b::/96")

# Explicit metadata endpoints. Most are already covered by the link-local or
# unique-local rules; they are listed so rejections carry a precise reason.
_METADATA_ADDRESSES: Final[dict[str, str]] = {
    "169.254.169.254": "cloud instance metadata endpoint",
    "169.254.170.2": "cloud instance metadata endpoint",
    "100.100.100.200": "cloud instance metadata endpoint",
    "192.0.0.192": "cloud instance metadata endpoint",
    "fd00:ec2::254": "cloud instance metadata endpoint",
}


def _unwrap(ip: IPAddress) -> IPAddress | None:
    """Return the IPv4 address embedded in an IPv6 address, if there is one.

    Covers IPv4-mapped (``::ffff:a.b.c.d``), IPv4-compatible, 6to4, Teredo and
    NAT64 forms, each of which can carry a private IPv4 address inside an
    otherwise globally routable-looking IPv6 literal.
    """
    if not isinstance(ip, ipaddress.IPv6Address):
        return None
    if ip.ipv4_mapped is not None:
        return ip.ipv4_mapped
    if ip.sixtofour is not None:
        return ip.sixtofour
    if ip.teredo is not None:
        return ip.teredo[0]
    if ip in _NAT64_V6:
        return ipaddress.IPv4Address(int(ip) & 0xFFFFFFFF)
    # ::a.b.c.d (deprecated IPv4-compatible form), excluding :: and ::1.
    packed = ip.packed
    if packed[:12] == b"\x00" * 12 and int(ip) > 1:
        return ipaddress.IPv4Address(packed[12:])
    return None


def classify_address(ip: IPAddress) -> str | None:
    """Return a rejection reason for ``ip``, or ``None`` if it may be scanned."""
    if (reason := _METADATA_ADDRESSES.get(ip.compressed)) is not None:
        return reason

    embedded = _unwrap(ip)
    if embedded is not None:
        inner = classify_address(embedded)
        if inner is not None:
            return f"IPv6 address embedding an IPv4 address that is {inner}"

    if ip.is_unspecified:
        return "an unspecified address"
    if ip.is_loopback:
        return "a loopback address"
    if ip.is_link_local:
        return "a link-local address"
    if ip.is_multicast:
        return "a multicast address"
    if ip.is_private:
        return "a private address"
    if ip.is_reserved:
        return "a reserved address"
    if isinstance(ip, ipaddress.IPv4Address) and ip in _CGNAT_V4:
        return "a carrier-grade NAT address"
    if isinstance(ip, ipaddress.IPv6Address) and ip.is_site_local:
        return "a site-local address"

    # Backstop: anything the standard library does not consider globally
    # routable is rejected even if no rule above matched it.
    if not ip.is_global:
        return "not a globally routable address"
    return None


def is_scannable_address(ip: IPAddress) -> bool:
    """Return whether ``ip`` is a publicly routable address the scanner may use."""
    return classify_address(ip) is None
