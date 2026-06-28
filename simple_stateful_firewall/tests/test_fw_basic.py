import tempfile
import unittest
from pathlib import Path
import sys


PROJECT_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_DIR))

from fw_basic import (  # noqa: E402
    DropLogger,
    Firewall,
    Packet,
    Rule,
    TCP_STATE_CLOSED,
    TCP_STATE_ESTABLISHED,
    TCP_STATE_NEW,
)


def rule(**overrides):
    data = {
        "id": 1,
        "action": "allow",
        "protocol": "tcp",
        "src": "10.0.0.0/24",
        "dst": "any",
        "dst_port": 443,
        "stateful": True,
    }
    data.update(overrides)
    return Rule.from_dict(data)


def packet(**overrides):
    data = {
        "id": 1,
        "timestamp": 1,
        "protocol": "tcp",
        "src_ip": "10.0.0.5",
        "dst_ip": "8.8.8.8",
        "src_port": 54321,
        "dst_port": 443,
        "flags": "SYN",
    }
    data.update(overrides)
    return Packet.from_dict(data, default_timestamp=float(data["id"]))


class FirewallTests(unittest.TestCase):
    def test_first_matching_rule_allows_and_creates_new_session(self):
        firewall = Firewall(
            [
                rule(id=1),
                rule(id=2, action="deny", protocol="any", src="any", dst="any"),
            ]
        )

        decision = firewall.evaluate(packet())

        self.assertEqual(decision.action, "allow")
        self.assertEqual(decision.matched_rule.id, 1)
        self.assertEqual(firewall.stats.rule_hits[1], 1)
        self.assertEqual(next(iter(firewall.sessions.values())).state, TCP_STATE_NEW)

    def test_return_tcp_packet_is_allowed_by_existing_session(self):
        firewall = Firewall(
            [
                rule(id=1),
                rule(id=2, action="deny", protocol="any", src="any", dst="any"),
            ]
        )
        firewall.evaluate(packet(id=1, timestamp=1, flags="SYN"))

        decision = firewall.evaluate(
            packet(
                id=2,
                timestamp=2,
                src_ip="8.8.8.8",
                dst_ip="10.0.0.5",
                src_port=443,
                dst_port=54321,
                flags="SYN-ACK",
            )
        )

        self.assertEqual(decision.action, "allow")
        self.assertEqual(decision.source(), "session return")
        self.assertEqual(decision.session_state_before, TCP_STATE_NEW)
        self.assertEqual(decision.session_state_after, TCP_STATE_ESTABLISHED)
        self.assertEqual(firewall.stats.rule_hits[1], 1)
        self.assertEqual(firewall.stats.session_hits, 1)

    def test_udp_packet_hits_ordered_deny_rule(self):
        firewall = Firewall(
            [
                rule(id=1),
                rule(id=3, action="deny", protocol="any", src="any", dst="any", dst_port="any"),
            ]
        )

        decision = firewall.evaluate(
            packet(
                id=3,
                protocol="udp",
                src_ip="192.168.1.100",
                dst_ip="10.0.0.5",
                src_port=5000,
                dst_port=53,
                flags="",
            )
        )

        self.assertEqual(decision.action, "deny")
        self.assertEqual(decision.matched_rule.id, 3)
        self.assertEqual(firewall.stats.rule_hits[3], 1)

    def test_implicit_deny_when_no_rule_matches(self):
        firewall = Firewall([rule(id=1)])

        decision = firewall.evaluate(packet(id=5, dst_port=22))

        self.assertEqual(decision.action, "deny")
        self.assertTrue(decision.implicit_deny)
        self.assertEqual(firewall.stats.implicit_deny_total, 1)

    def test_fin_closes_session_and_hides_it_from_active_display(self):
        firewall = Firewall([rule(id=1)])
        firewall.evaluate(packet(id=1, timestamp=1, flags="SYN"))
        firewall.evaluate(
            packet(
                id=2,
                timestamp=2,
                src_ip="8.8.8.8",
                dst_ip="10.0.0.5",
                src_port=443,
                dst_port=54321,
                flags="SYN-ACK",
            )
        )

        decision = firewall.evaluate(packet(id=3, timestamp=3, flags="FIN"))

        self.assertEqual(decision.action, "allow")
        self.assertEqual(next(iter(firewall.sessions.values())).state, TCP_STATE_CLOSED)
        self.assertEqual(firewall.sessions_for_display(), [])
        self.assertEqual(len(firewall.sessions_for_display(include_closed=True)), 1)

    def test_session_ages_out_before_late_return_packet(self):
        firewall = Firewall([rule(id=1)], session_timeout=5)
        firewall.evaluate(packet(id=1, timestamp=1, flags="SYN"))

        decision = firewall.evaluate(
            packet(
                id=2,
                timestamp=10,
                src_ip="8.8.8.8",
                dst_ip="10.0.0.5",
                src_port=443,
                dst_port=54321,
                flags="SYN-ACK",
            )
        )

        self.assertEqual(decision.action, "deny")
        self.assertTrue(decision.implicit_deny)

    def test_rate_limit_denies_packet_before_acl(self):
        firewall = Firewall([rule(id=1)], rate_limit=2, rate_window=10)

        firewall.evaluate(packet(id=1, timestamp=1, src_port=54321))
        firewall.evaluate(packet(id=2, timestamp=2, src_port=54322))
        decision = firewall.evaluate(packet(id=3, timestamp=3, src_port=54323))

        self.assertEqual(decision.action, "deny")
        self.assertTrue(decision.rate_limited)
        self.assertEqual(firewall.stats.rate_limited_total, 1)

    def test_drop_logger_rotates(self):
        with tempfile.TemporaryDirectory() as tmp:
            log_path = Path(tmp) / "drops.log"
            firewall = Firewall(
                [rule(id=1, action="deny", protocol="any", src="any", dst="any")],
                drop_logger=DropLogger(log_path, max_bytes=1, backups=2),
            )

            firewall.evaluate(packet(id=1))
            firewall.evaluate(packet(id=2, src_port=54322))

            self.assertTrue(log_path.exists())
            self.assertTrue(log_path.with_name("drops.log.1").exists())
            self.assertEqual(firewall.stats.dropped_logged_total, 2)


if __name__ == "__main__":
    unittest.main()
