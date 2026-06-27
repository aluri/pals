import sys
import unittest
from pathlib import Path


PROJECT_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_DIR))

from l2switch import Frame, Port, VirtualSwitch, Vlan  # noqa: E402


def make_switch() -> VirtualSwitch:
    return VirtualSwitch(
        ports=[
            Port("Gi0/1", "up", "up", "access", vlan=10),
            Port("Gi0/2", "up", "up", "access", vlan=20),
            Port("Gi0/3", "up", "up", "trunk", allowed_vlans=[10, 20]),
            Port("Gi0/4", "up", "up", "access", vlan=10),
            Port("Gi0/5", "down", "down", "access", vlan=10),
        ],
        vlans=[Vlan(10, "DATA"), Vlan(20, "VOICE")],
    )


class VirtualSwitchTests(unittest.TestCase):
    def test_broadcast_floods_only_inside_vlan_and_learns_source(self):
        switch = make_switch()
        decision = switch.process_frame(
            Frame("Gi0/1", "00:11:22:33:44:55", "FF:FF:FF:FF:FF:FF", 10),
            frame_number=1,
        )

        self.assertEqual(decision.action, "flood")
        self.assertEqual(decision.egress_ports, ["Gi0/3", "Gi0/4"])
        self.assertIn((10, "00:11:22:33:44:55"), switch.mac_table)
        self.assertNotIn("Gi0/2", decision.egress_ports)
        self.assertNotIn("Gi0/5", decision.egress_ports)

    def test_known_unicast_forwards_to_single_learned_port(self):
        switch = make_switch()
        switch.process_frame(Frame("Gi0/1", "00:11:22:33:44:55", "FF:FF:FF:FF:FF:FF", 10))

        decision = switch.process_frame(
            Frame("Gi0/4", "00:11:22:33:44:66", "00:11:22:33:44:55", 10)
        )

        self.assertEqual(decision.action, "forward")
        self.assertEqual(decision.egress_ports, ["Gi0/1"])
        self.assertEqual(switch.ports["Gi0/1"].tx_frames, 1)

    def test_unknown_unicast_does_not_cross_vlan_boundary(self):
        switch = make_switch()
        switch.process_frame(Frame("Gi0/1", "00:11:22:33:44:55", "FF:FF:FF:FF:FF:FF", 10))

        decision = switch.process_frame(
            Frame("Gi0/2", "AA:BB:CC:DD:EE:FF", "00:11:22:33:44:55", 20)
        )

        self.assertEqual(decision.action, "flood")
        self.assertEqual(decision.egress_ports, ["Gi0/3"])
        self.assertIn("unknown-unicast flood", decision.reason)

    def test_access_port_rejects_wrong_vlan_tag(self):
        switch = make_switch()

        decision = switch.process_frame(
            Frame("Gi0/1", "00:11:22:33:44:55", "AA:BB:CC:DD:EE:FF", 20)
        )

        self.assertEqual(decision.action, "drop")
        self.assertEqual(decision.egress_ports, [])
        self.assertEqual(switch.ports["Gi0/1"].rx_frames, 1)
        self.assertEqual(switch.ports["Gi0/1"].dropped_frames, 1)
        self.assertEqual(switch.mac_table, {})

    def test_trunk_rejects_disallowed_vlan(self):
        switch = make_switch()

        decision = switch.process_frame(
            Frame("Gi0/3", "00:30:00:30:00:30", "FF:FF:FF:FF:FF:FF", 30)
        )

        self.assertEqual(decision.action, "drop")
        self.assertIn("not in allowed_vlans", decision.reason)

    def test_same_mac_can_exist_in_different_vlans(self):
        switch = make_switch()
        switch.process_frame(Frame("Gi0/1", "00:11:22:33:44:55", "FF:FF:FF:FF:FF:FF", 10))
        switch.process_frame(Frame("Gi0/2", "00:11:22:33:44:55", "FF:FF:FF:FF:FF:FF", 20))

        self.assertEqual(switch.mac_table[(10, "00:11:22:33:44:55")].port, "Gi0/1")
        self.assertEqual(switch.mac_table[(20, "00:11:22:33:44:55")].port, "Gi0/2")


if __name__ == "__main__":
    unittest.main()
