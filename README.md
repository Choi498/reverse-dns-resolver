# reverse_dns_resolver

Forward-confirmed reverse DNS lookup for Python: resolve the PTR record for an IP address, then verify each returned name by resolving it forward (A/AAAA) and keeping only names that point back at the original address.

```python
from reverse_dns_resolver import resolve_reverse_dns

result = resolve_reverse_dns("203.0.113.5")
print(result.confirmed_names)   # names whose A/AAAA records include 203.0.113.5
print(result.confirmed)         # True iff at least one name confirmed
```

For control over the underlying resolver (useful in tests or when wrapping a caching resolver), use the class directly:

```python
from reverse_dns_resolver import ReverseDnsResolver

resolver = ReverseDnsResolver(
    resolve_ptr=lambda ip: [],
    resolve_forward=lambda name: [],
)
result = resolver.resolve("203.0.113.5")
```

## Why this exists

A PTR record can name anything the zone administrator likes, including someone else's domain. Mail servers, SSH host-key verification, and log correlators that trust the PTR at face value are therefore spoofable. Forward confirmation — the same check `host -C` performs — filters out PTR entries that do not round-trip through a forward A/AAAA record pointing back at the queried address.

The trade-off: resolution goes through the operating system resolver (`socket.gethostbyaddr` and `socket.getaddrinfo`), not a hand-rolled DNS client. That means `/etc/hosts` and NSS plugins are honoured, and we cannot inspect record TTLs or query specific authoritative servers. In return the library has zero third-party dependencies and behaves correctly under whatever resolver configuration the host already has.

## Edge cases you will hit

- IPv6 literals that compare unequal as strings but denote the same address (`::1` vs `0:0:0:0:0:0:0:1`) are normalised before comparison, so forward confirmation does not produce false negatives on compressed forms.
- A spoofed PTR whose forward record points elsewhere is dropped: `ptr_names` preserves it for auditing, but `confirmed_names` will be empty.
- Invalid IP literals raise `ValueError` before any network lookup; resolution failures (NXDOMAIN, timeout) are captured as empty results rather than exceptions, because the absence of a reverse record is a legitimate answer.

## Exported names

- `ReverseDnsResolver` — class; constructor accepts optional `resolve_ptr` and `resolve_forward` callables for testing.
- `ResolutionResult` — dataclass with `address`, `ptr_names`, `confirmed_names`, `error`, and a `confirmed` property.
- `resolve_reverse_dns(address)` — convenience function delegating to `ReverseDnsResolver().resolve(address)`.
