import socket
import unittest

from reverse_dns_resolver import (
    ResolutionResult,
    ReverseDnsResolver,
    resolve_reverse_dns,
)
from reverse_dns_resolver.core import _normalise_ip


class NormaliseIpTests(unittest.TestCase):
    def test_ipv4_is_canonicalised(self):
        self.assertEqual(_normalise_ip("192.168.1.1"), "192.168.1.1")

    def test_ipv6_compressed_matches_expanded(self):
        self.assertEqual(
            _normalise_ip("::1"),
            _normalise_ip("0:0:0:0:0:0:0:1"),
        )

    def test_invalid_address_raises_value_error(self):
        with self.assertRaises(ValueError):
            _normalise_ip("not.an.ip")


class ResolveTests(unittest.TestCase):
    """Tests using injected fakes so no network access is required."""

    def _make_resolver(self, ptr_map, forward_map):
        return ReverseDnsResolver(
            resolve_ptr=lambda addr: ptr_map.get(addr, []),
            resolve_forward=lambda name: forward_map.get(name, []),
        )

    def test_confirmed_ptr_kept(self):
        resolver = self._make_resolver(
            ptr_map={"203.0.113.5": ["mail.example.test"]},
            forward_map={"mail.example.test": ["203.0.113.5"]},
        )
        result = resolver.resolve("203.0.113.5")
        self.assertEqual(result.ptr_names, ["mail.example.test"])
        self.assertEqual(result.confirmed_names, ["mail.example.test"])
        self.assertTrue(result.confirmed)

    def test_unconfirmed_ptr_dropped(self):
        # PTR points at a name whose A record does not include the original
        # address — the classic spoofed PTR.
        resolver = self._make_resolver(
            ptr_map={"203.0.113.5": ["spoofed.example.test"]},
            forward_map={"spoofed.example.test": ["198.51.100.7"]},
        )
        result = resolver.resolve("203.0.113.5")
        self.assertEqual(result.ptr_names, ["spoofed.example.test"])
        self.assertEqual(result.confirmed_names, [])
        self.assertFalse(result.confirmed)

    def test_multiple_ptrs_one_confirmed(self):
        resolver = self._make_resolver(
            ptr_map={"203.0.113.5": ["a.test", "b.test", "c.test"]},
            forward_map={
                "a.test": ["203.0.113.5"],
                "b.test": ["198.51.100.7"],
                "c.test": ["203.0.113.5", "198.51.100.7"],
            },
        )
        result = resolver.resolve("203.0.113.5")
        self.assertEqual(result.confirmed_names, ["a.test", "c.test"])

    def test_no_ptr_record(self):
        resolver = self._make_resolver(ptr_map={}, forward_map={})
        result = resolver.resolve("203.0.113.5")
        self.assertEqual(result.ptr_names, [])
        self.assertEqual(result.confirmed_names, [])
        self.assertFalse(result.confirmed)

    def test_ipv6_canonicalisation_in_confirmation(self):
        # Input is expanded form, forward record returns compressed form.
        resolver = self._make_resolver(
            ptr_map={"2001:db8::1": ["host.test"]},
            forward_map={"host.test": ["2001:db8:0:0:0:0:0:1"]},
        )
        result = resolver.resolve("2001:db8:0:0:0:0:0:1")
        self.assertEqual(result.confirmed_names, ["host.test"])

    def test_confirmed_names_deduplicated(self):
        # If the PTR lookup returns the same name twice, we must not list it
        # twice in confirmed_names.
        resolver = self._make_resolver(
            ptr_map={"203.0.113.5": ["dup.test", "dup.test"]},
            forward_map={"dup.test": ["203.0.113.5"]},
        )
        result = resolver.resolve("203.0.113.5")
        self.assertEqual(result.confirmed_names, ["dup.test"])

    def test_invalid_address_raises_before_any_lookup(self):
        calls = {"ptr": 0, "forward": 0}

        def fake_ptr(addr):
            calls["ptr"] += 1
            return []

        resolver = ReverseDnsResolver(
            resolve_ptr=fake_ptr,
            resolve_forward=lambda name: [],
        )
        with self.assertRaises(ValueError):
            resolver.resolve("256.0.0.1")
        self.assertEqual(calls["ptr"], 0)


class ModuleFunctionTests(unittest.TestCase):
    def test_resolve_reverse_dns_returns_result(self):
        # Use a fake resolver via monkey-patching the class's hooks is not
        # possible at module level, so instead we verify the function returns
        # a ResolutionResult for a structurally invalid address by wrapping.
        # The function delegates to ReverseDnsResolver; for a valid-shaped but
        # unresolvable address we expect an empty result, not an exception.
        import reverse_dns_resolver.core as core

        original = core.ReverseDnsResolver

        class FakeResolver:
            def __init__(self, **kwargs):
                pass

            def resolve(self, address):
                return ResolutionResult(
                    address=address,
                    ptr_names=[],
                    confirmed_names=[],
                )

        core.ReverseDnsResolver = FakeResolver
        try:
            result = resolve_reverse_dns("203.0.113.9")
        finally:
            core.ReverseDnsResolver = original
        self.assertIsInstance(result, ResolutionResult)
        self.assertEqual(result.address, "203.0.113.9")


if __name__ == "__main__":
    unittest.main()
