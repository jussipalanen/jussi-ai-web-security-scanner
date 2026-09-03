"""DNS resolution with mandatory address validation.

The resolver returns the concrete addresses a target resolved to so that callers
can *pin* the connection to an address that was actually checked. Re-resolving a
hostname at connect time would reopen a DNS-rebinding hole: a name can return a
public address to the validator and a private one microseconds later.

Every address a name resolves to must be scannable. Rejecting a name because one
of several answers is internal is deliberate - a split-horizon or round-robin
record that sometimes points inside the network is not a safe target.
"""

from __future__ import annotations

import asyncio
import ipaddress
import socket
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass

from jussiai_scanner.security.errors import BlockedAddressError, TargetValidationError
from jussiai_scanner.security.ip_rules import IPAddress, classify_address
from jussiai_scanner.security.url_validation import ValidatedTarget

#: Signature of a name resolver: (host, port) -> addresses.
Resolver = Callable[[str, int], Sequence[IPAddress]]


@dataclass(frozen=True, slots=True)
class ResolvedTarget:
    """A target whose addresses have all been validated."""

    target: ValidatedTarget
    addresses: tuple[IPAddress, ...]

    @property
    def connect_address(self) -> IPAddress:
        """The address a connection should be pinned to."""
        return self.addresses[0]


def system_resolver(host: str, port: int) -> list[IPAddress]:
    """Resolve ``host`` with the system resolver, returning unique addresses."""
    try:
        infos = socket.getaddrinfo(host, port, proto=socket.IPPROTO_TCP)
    except socket.gaierror as exc:
        raise TargetValidationError("the hostname could not be resolved") from exc

    seen: dict[str, IPAddress] = {}
    for info in infos:
        sockaddr = info[4]
        address = ipaddress.ip_address(sockaddr[0])
        seen.setdefault(address.compressed, address)
    if not seen:
        raise TargetValidationError("the hostname did not resolve to any address")
    return list(seen.values())


def validate_addresses(addresses: Iterable[IPAddress]) -> tuple[IPAddress, ...]:
    """Return ``addresses`` unchanged, or raise if any one of them is blocked."""
    resolved = tuple(addresses)
    if not resolved:
        raise TargetValidationError("the hostname did not resolve to any address")
    for address in resolved:
        if (reason := classify_address(address)) is not None:
            raise BlockedAddressError(f"the target resolves to {reason}")
    return resolved


def resolve_target(target: ValidatedTarget, resolver: Resolver = system_resolver) -> ResolvedTarget:
    """Resolve ``target`` and verify every resulting address.

    Args:
        target: A target that already passed :func:`validate_target_url`.
        resolver: Injected name resolver, overridden in tests.

    Raises:
        TargetValidationError: If the name cannot be resolved.
        BlockedAddressError: If any resolved address is not publicly routable.
    """
    if target.ip_literal is not None:
        return ResolvedTarget(target=target, addresses=validate_addresses([target.ip_literal]))
    addresses = validate_addresses(resolver(target.host, target.port))
    return ResolvedTarget(target=target, addresses=addresses)


async def resolve_target_async(
    target: ValidatedTarget, resolver: Resolver = system_resolver
) -> ResolvedTarget:
    """Async wrapper around :func:`resolve_target`; resolution runs in a thread."""
    return await asyncio.to_thread(resolve_target, target, resolver)
