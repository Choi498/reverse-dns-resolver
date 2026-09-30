"""Reverse DNS resolver with forward-confirmation of PTR records."""

from reverse_dns_resolver.core import (
    ResolutionResult,
    ReverseDnsResolver,
    resolve_reverse_dns,
)

__all__ = [
    "ResolutionResult",
    "ReverseDnsResolver",
    "resolve_reverse_dns",
]
