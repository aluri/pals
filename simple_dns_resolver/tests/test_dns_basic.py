import unittest
from pathlib import Path
import sys


PROJECT_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_DIR))

from dns_basic import DnsCache, Record, Resolver, Zone  # noqa: E402


def make_resolver(*records, negative_ttl=30):
    zone = Zone([Record.from_dict(record) for record in records])
    return Resolver(zone, cache=DnsCache(), negative_ttl=negative_ttl)


class ResolverTests(unittest.TestCase):
    def test_direct_record_is_cached_and_reused(self):
        resolver = make_resolver(
            {"name": "www.example.com", "type": "A", "value": "93.184.216.34", "ttl": 300}
        )

        first = resolver.resolve("www.example.com", "A", now=100)
        second = resolver.resolve("www.example.com", "A", now=125)

        self.assertEqual(first.status, "NOERROR")
        self.assertEqual(first.source, "zone")
        self.assertEqual(second.source, "cache")
        self.assertEqual(second.answers[0].ttl, 275)
        self.assertEqual(resolver.stats.cache_hits, 1)

    def test_expired_cache_entry_is_re_resolved_from_zone(self):
        resolver = make_resolver(
            {"name": "api.example.com", "type": "A", "value": "192.0.2.10", "ttl": 5}
        )

        resolver.resolve("api.example.com", "A", now=10)
        second = resolver.resolve("api.example.com", "A", now=20)

        self.assertEqual(second.source, "zone")
        self.assertEqual(resolver.stats.expired_entries, 1)

    def test_cname_chain_returns_alias_and_final_answer(self):
        resolver = make_resolver(
            {"name": "blog.example.com", "type": "CNAME", "value": "www.example.com", "ttl": 300},
            {"name": "www.example.com", "type": "A", "value": "93.184.216.34", "ttl": 200},
        )

        result = resolver.resolve("blog.example.com", "A", now=1)

        self.assertEqual(result.status, "NOERROR")
        self.assertEqual([answer.type for answer in result.answers], ["CNAME", "A"])
        self.assertEqual(result.ttl, 200)

    def test_negative_cache_hides_later_zone_change_until_ttl_expires(self):
        resolver = make_resolver(negative_ttl=20)
        first = resolver.resolve("missing.example.com", "A", now=1)
        resolver.zone = Zone(
            [Record.from_dict({"name": "missing.example.com", "type": "A", "value": "192.0.2.55", "ttl": 60})]
        )

        cached = resolver.resolve("missing.example.com", "A", now=10)
        refreshed = resolver.resolve("missing.example.com", "A", now=25)

        self.assertEqual(first.status, "NXDOMAIN")
        self.assertEqual(cached.status, "NXDOMAIN")
        self.assertEqual(cached.source, "cache")
        self.assertEqual(refreshed.status, "NOERROR")
        self.assertEqual(refreshed.source, "zone")

    def test_cname_loop_is_detected_and_cached_negatively(self):
        resolver = make_resolver(
            {"name": "loop1.example.com", "type": "CNAME", "value": "loop2.example.com", "ttl": 60},
            {"name": "loop2.example.com", "type": "CNAME", "value": "loop1.example.com", "ttl": 60},
            negative_ttl=10,
        )

        first = resolver.resolve("loop1.example.com", "A", now=1)
        second = resolver.resolve("loop1.example.com", "A", now=5)

        self.assertEqual(first.status, "CNAME_LOOP")
        self.assertEqual(second.source, "cache")
        self.assertEqual(second.status, "CNAME_LOOP")

    def test_wildcard_record_answers_unknown_host(self):
        resolver = make_resolver(
            {"name": "*.wild.example.com", "type": "A", "value": "203.0.113.10", "ttl": 45}
        )

        result = resolver.resolve("host.wild.example.com", "A", now=1)

        self.assertEqual(result.status, "NOERROR")
        self.assertEqual(result.answers[0].name, "host.wild.example.com")
        self.assertEqual(result.answers[0].value, "203.0.113.10")

    def test_exact_name_prevents_wildcard_substitution(self):
        resolver = make_resolver(
            {"name": "host.wild.example.com", "type": "MX", "value": "mail.example.com", "priority": 10, "ttl": 60},
            {"name": "*.wild.example.com", "type": "A", "value": "203.0.113.10", "ttl": 45},
        )

        result = resolver.resolve("host.wild.example.com", "A", now=1)

        self.assertEqual(result.status, "NXDOMAIN")


if __name__ == "__main__":
    unittest.main()
