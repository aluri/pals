# Virtual L2 Switch with MAC Learning and VLAN Support

This is a small terminal-based Layer-2 switch simulator. It runs on one system,
uses only the Python standard library, and reads all switch inputs from local
JSON files:

- `ports.json`
- `vlans.json`
- `frames.json`

The simulator demonstrates source MAC learning, known-unicast forwarding,
unknown-unicast flooding, broadcast flooding, VLAN segmentation, access/trunk
tagging behavior, and basic RX/TX/drop counters.

## Quick Start

From this folder:

```bash
python3 l2switch.py demo
```

Useful commands:

```bash
python3 l2switch.py show-ports
python3 l2switch.py show-vlans
python3 l2switch.py show-frames
python3 l2switch.py process-frames --summary
python3 l2switch.py show-mac-table --learn-from-frames
python3 l2switch.py explain-forward 2 --show-mac-table
python3 l2switch.py shell
```

Inside the interactive shell:

```text
switch# show ports
switch# show frames
switch# explain-forward 1
switch# show-mac-table
switch# process-frames
switch# show stats
switch# reset
switch# exit
```

## Design Notes

The switch keeps the MAC table keyed by `(VLAN, MAC address)`, not just MAC
address. This matters because the same MAC can legally appear in different
VLANs, and a Layer-2 switch must not use a VLAN 10 learning event to forward
VLAN 20 traffic.

Ingress rules:

- Access ports accept untagged frames into their configured access VLAN.
- Access ports reject frames tagged for any other VLAN.
- Trunk ports require a VLAN tag and accept only allowed VLANs.
- Frames on undefined VLANs are dropped.

Forwarding rules:

- Known unicast: forward to the learned port in the same VLAN.
- Known unicast learned on the ingress port: filter.
- Unknown unicast: flood to eligible up ports in the same VLAN.
- Broadcast and multicast: flood to eligible up ports in the same VLAN.
- Flooding never sends the frame back out the ingress port.
- Access egress is shown as untagged; trunk egress is shown as tagged.

## Sample Scenario

The included `frames.json` intentionally covers the core behaviors:

- Frame 1 enters `Gi0/1` in VLAN 10 and broadcasts. The switch learns
  `00:11:22:33:44:55` on `Gi0/1` and floods only to VLAN 10 members.
- Frame 2 enters `Gi0/4` in VLAN 10 and targets the learned MAC. The switch
  forwards only to `Gi0/1`.
- Frame 3 enters `Gi0/2` in VLAN 20 and targets a MAC learned in VLAN 10. The
  switch treats it as unknown in VLAN 20 and floods only inside VLAN 20.
- Frame 4 enters trunk `Gi0/3` tagged for VLAN 10 and reaches a known access
  host on `Gi0/4`.
- Frame 5 broadcasts in VLAN 30 from the trunk. The only other VLAN 30 port is
  administratively down, so no egress port is selected.
- Frame 6 arrives on access port `Gi0/1` with VLAN 20 and is dropped because
  the port is configured for access VLAN 10.

## AI Usage, Corrections, and Validation

AI assistance was used to draft the implementation plan, identify the minimum
switch behaviors, and generate the first version of the Python CLI and tests.
The output was corrected in a few important places:

- The prompt example contained stray text (`Cisco Confidential`) inside the
  `vlans.json` example. That was corrected by keeping the JSON files strictly
  valid JSON.
- MAC learning was made VLAN-aware by keying entries as `(VLAN, MAC)`.
- Flooding was constrained to active ports in the same VLAN and excludes the
  ingress port.
- Access and trunk behavior was made explicit. Access ports reject wrong VLAN
  tags, and trunk ports reject VLANs outside `allowed_vlans`.
- The `explain-forward` command primes earlier frames by default so standalone
  explanations can show realistic MAC learning context.

Validation was done with both unit tests and CLI runs:

```bash
python3 -m unittest discover -s tests
python3 l2switch.py demo
python3 l2switch.py explain-forward 3 --show-mac-table
python3 l2switch.py show-mac-table --learn-from-frames
```

The tests cover broadcast flooding, known unicast forwarding, unknown unicast
VLAN isolation, wrong-VLAN access drops, trunk allowed-VLAN enforcement, and
same-MAC learning in separate VLANs.
