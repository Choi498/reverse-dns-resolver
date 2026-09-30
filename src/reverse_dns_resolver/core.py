"""Core reverse DNS resolution with forward-confirmation.

The standard library's :mod:`socket` module performs reverse lookups via the
operating system resolver, which honours ``/etc/hosts`` and NSS plugins before
querying DNS.  That is convenient but means the answer is not necessarily a real
PTR record.  A PTR can also be ``spoofed'': a zone administrator can publish any
name they like, including one that points at someone else's domain.

This module performs a *forward-confirmed* reverse lookup: it resolves the PTR,
then resolves each returned name forward (A or AAAA), and keeps only the names
whose forward resolution includes the original address.  This is the same check
performed by tools such as ``host -C`` and by mail-server anti-spoofing rules.

Design decisions (stated plainly so the tests can rely on them):

* Resolution goes through :func:`socket.getaddrinfo` rather than a hand-rolled
  DNS client.  We trade precise control over record types for zero third-party
  dependencies and correct handling of the system resolver.
* IPv6 addresses are normalised with :func:`socket.inet_pton` / :func:`socket.inet_ntop`
  before comparison so that ``::1`` and ``0:0:0:0:0:0:0:1`` are recognised as
  the same address (a classic source of false negatives in forward
  confirmation).
* Invalid IP literals raise :class:`ValueError`; that is the caller's bug, not
  a runtime failure.
"""

from __future__ import annotations

import socket
from dataclasses import dataclass, field

__all__ = [
    "ResolutionResult",
    "ReverseDnsResolver",
    "resolve_reverse_dns",
]


def _normalise_ip(address: str) -> str:
    """Return the canonical textual form of ``address``.

    ``socket.gethostbyaddr`` accepts both IPv4 and IPv6 literals, but the
    canonical form matters for forward confirmation: a forward A/AAAA record
    may come back as a compressed IPv6 string while the input was expanded,
    and a naive string compare would wrongly reject a genuine match.
    """
    try:
        packed = socket.inet_pton(socket.AF_INET, address)
        return socket.inet_ntop(socket.AF_INET, packed)
    except OSError:
        # Try IPv6 next; if this also fails we re-raise as ValueError so
        # callers get a single, predictable exception type for bad input.
        try:
            packed = socket.inet_pton(socket.AF_INET6, address)
            return socket.inet_ntop(socket.AF_INET6, packed)
        except OSError as exc:
            raise ValueError(f"not a valid IP literal: {address!r}") from exc


@dataclass
class ResolutionResult:
    """Outcome of a forward-confirmed reverse lookup.

    ``confirmed_names`` is a list of fully-qualified names whose A/AAAA records
    point back at the queried address.  It may be empty when the PTR exists but
    is not forward-confirmed (the common spoofing case).  ``ptr_names`` is the
    raw list returned by the PTR lookup, preserved so callers can audit or log
    unconfirmed names.
    """

    address: str
    ptr_names: list[str] = field(default_factory=list)
    confirmed_names: list[str] = field(default_factory=list)
    error: str | None = None

    @property
    def confirmed(self) -> bool:
        """True if at least one PTR name forward-resolves to the address."""
        return bool(self.confirmed_names)


class ReverseDnsResolver:
    """Stateless wrapper around forward-confirmed reverse DNS resolution.

    The class exists so callers can swap the low-level resolution hooks for
    fakes in tests without monkey-patching :mod:`socket`.  The default hooks
    delegate to the real system resolver.
    """

    def __init__(
        self,
        *,
        resolve_ptr=None,
        resolve_forward=None,
    ) -> None:
        # Defaults are bound here, not in the signature, so that test fakes
        # installed via the constructor never accidentally fall back to the
        # real network.
        self._resolve_ptr = resolve_ptr or self._default_resolve_ptr
        self._resolve_forward = resolve_forward or self._default_resolve_forward

    # -- public API -------------------------------------------------

    def resolve(self, address: str) -> ResolutionResult:
        """Return a :class:`ResolutionResult` for ``address``.

        Never raises for resolution failures; those are captured in
        ``result.error``.  Raises :class:`ValueError` only for addresses that
        are syntactically invalid, since there is nothing useful to return in
        that case.
        """
        normalised = _normalise_ip(address)
        ptr_names = self._resolve_ptr(normalised)
        if not ptr_names:
            return ResolutionResult(address=normalised)

        confirmed: list[str] = []
        for name in ptr_names:
            for forward_addr in self._resolve_forward(name):
                if _normalise_ip(forward_addr) == normalised:
                    if name not in confirmed:
                        confirmed.append(name)
                    break
        return ResolutionResult(
            address=normalised,
            ptr_names=list(ptr_names),
            confirmed_names=confirmed,
        )

    # -- default hooks (real network) ------------------------------

    @staticmethod
    def _default_resolve_ptr(address: str) -> list[str]:
        """Use the OS resolver to obtain PTR names.

        ``gethostbyaddr`` returns a primary name plus a list of aliases.  We
        surface both because some deployments publish the canonical name as an
        alias and vice versa; the forward-confirmation step is what separates
        genuine answers from noise.
        """
        try:
            primary, aliases, _ = socket.gethostbyaddr(address)
        except (socket.herror, socket.gaierror, OSError):
            return []
        # ``aliases`` is the second tuple element; de-duplicate while
        # preserving order for deterministic output.
        seen: set[str] = set()
        names: list[str] = []
        for candidate in (primary, *aliases):
            if candidate and candidate not in seen:
                seen.add(candidate)
                names.append(candidate)
        return names

    @staticmethod
    def _default_resolve_forward(name: str) -> list[str]:
        """Resolve ``name`` to A/AAAA addresses via the OS resolver.

        We iterate over both AF_INET and AF_INET6 so that an IPv4 input can
        still match a name that only has an A record, and vice versa.
        """
        results: list[str] = []
        for family in (socket.AF_INET, socket.AF_INET6):
            try:
                infos = socket.getaddrinfo(name, None, family, socket.SOCK_STREAM)
            except (socket.gaierror, OSError):
                continue
            for info in infos:
                sockaddr = info[4]
                if not sockaddr:
                    continue
                ip = sockaddr[0]
                if ip not in results:
                    results.append(ip)
        return results


# Module-level convenience used by the README example and by tests that prefer
# a function-style call site.
def resolve_reverse_dns(address: str) -> ResolutionResult:
    """Forward-confirmed reverse DNS for ``address``.

    Equivalent to ``ReverseDnsResolver().resolve(address)``; provided as a
    one-shot convenience for scripts that only resolve a single name.
    """
    return ReverseDnsResolver().resolve(address)


# Internal helper exposed under a private name so tests can target it directly
# without going through the public class.
_normalize_ip_internal = _normalise_ip
