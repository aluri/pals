# AI Usage

AI assistance was used to design, implement, correct, and validate this virtual
Layer-2 switch project. The goal was to keep the result small, accurate,
explainable, and runnable on one system with no external dependencies.

## Prompts Used

Initial build prompt:

```text
Virtual L2 Switch with MAC Learning and VLAN Support)

PROBLEM STATEMENT
Build a small virtual Layer-2 switch using AI assistance, then explain how AI was used, corrected, and validated. The solution should run on a single system and simulate a simple L2 switching platform with MAC address learning, VLAN tagging, and basic port statistics. The solution should demonstrate how MAC learning happens, how frames are forwarded or flooded, and how VLAN segmentation works through a switch-style CLI.
The preferred form factor is a CLI or lightweight TUI (Text User Interface). A dashboard is not required. A small, accurate, explainable, and complete solution is essential as the minimum expectation. Bonus points for broader and more ambitious solutions.

Part 1: Build a small terminal program. It can be a command-line tool or a simple text UI processing all inputs, CLIs, or commands.

Part 2: Make the program read port and VLAN configuration from local files: a. ports.json b. vlans.json c. frames.json (simulated incoming frames)

Example ports.json: [ {"name":"Gi0/1","admin_state":"up","oper_state":"up","mode":"access","vlan":10,"rx_frames":0,"tx_frames":0}, {"name":"Gi0/2","admin_state":"up","oper_state":"up","mode":"access","vlan":20,"rx_frames":0,"tx_frames":0}, {"name":"Gi0/3","admin_state":"up","oper_state":"up","mode":"trunk","allowed_vlans":[10,20,30],"rx_frames":0,"tx_frames":0} ]

Example vlans.json: [ Cisco Confidential {"vlan_id":10,"name":"DATA"}, {"vlan_id":20,"name":"VOICE"}, {"vlan_id":30,"name":"MGMT"} ] Example frames.json: [ {"ingress_port":"Gi0/1","src_mac":"00:11:22:33:44:55","dst_mac":"FF:FF:FF:FF:FF:FF","vlan":10}, {"ingress_port":"Gi0/2","src_mac":"AA:BB:CC:DD:EE:FF","dst_mac":"00:11:22:33:44:55","vlan":20} ]

Part 3: Build and maintain a MAC address table populated via source MAC learning.

Part 4: Add a switch-style CLI command such as show-mac-table that prints MAC address, VLAN, port, and age.

Part 5: For a given frame, decide forwarding behavior: Unicast with known destination: forward to single port Unicast with unknown destination: flood within VLAN Broadcast: flood within VLAN Respect VLAN tagging rules (access vs. trunk ports)

Part 6: Add an explain-forward command that prints the forwarding decision, which port(s) were chosen, and why.
```

Implementation prompt used with AI:

```text
Create a dependency-free Python CLI in an isolated virtual_l2_switch folder.
Load ports.json, vlans.json, and frames.json. Model access and trunk ports,
validate VLAN membership, learn source MAC addresses, keep the MAC table keyed
by VLAN and MAC address, and expose demo, process-frames, show-mac-table,
show-ports, show-vlans, show-frames, explain-forward, and shell commands.
```

Correction prompt used with AI:

```text
Make frame-specific commands deterministic even though each CLI invocation
starts fresh. For explain-forward <frame-id>, replay earlier frames by default
so the MAC table has the same context it would have during sequential frame
processing. Add a --no-learn-prior option for isolated inspection.
```

Validation prompt used with AI:

```text
Create focused unit tests for broadcast flooding, known-unicast forwarding,
unknown-unicast VLAN isolation, access-port wrong-VLAN drops, trunk
allowed-VLAN enforcement, and learning the same MAC address separately in
different VLANs.
```

Documentation prompt:

```text
Also generate AI_USAGE.md with all prompts used
```

## AI Corrections Made

- The assignment example included non-JSON text (`Cisco Confidential`) inside
  the VLAN example. The implemented `vlans.json` is valid JSON.
- MAC learning was corrected to use `(VLAN, MAC address)` as the table key so
  learned entries cannot leak forwarding decisions across VLANs.
- Unknown-unicast, broadcast, and multicast flooding were constrained to
  eligible up ports in the same VLAN, excluding the ingress port.
- Access and trunk behavior was made explicit: access ports reject frames
  tagged for the wrong VLAN, while trunks require a VLAN tag and enforce
  `allowed_vlans`.
- `explain-forward` was designed to replay prior frames by default so a
  standalone command can still show realistic MAC learning context.
- Egress behavior was made visible in explanations: access egress is shown as
  untagged and trunk egress is shown as tagged.
- Port counters were kept simple and explainable: RX, TX, and Drops.

## Validation Performed

Validation used unit tests and manual CLI runs:

```bash
python3 -m unittest discover -s tests
python3 -m py_compile l2switch.py tests/test_l2switch.py
python3 l2switch.py demo
python3 l2switch.py explain-forward 3 --show-mac-table
python3 l2switch.py show-mac-table --learn-from-frames
python3 virtual_l2_switch/l2switch.py process-frames --brief --summary
```

The tests verify MAC learning, VLAN-scoped flooding, known-unicast forwarding,
unknown-unicast isolation between VLANs, access-port VLAN drops, trunk
allowed-VLAN enforcement, and support for learning the same MAC in different
VLANs.
