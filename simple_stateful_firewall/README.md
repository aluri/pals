# Simple Stateful Firewall / ACL Evaluator

This is a small terminal firewall simulator. It uses only the Python standard
library, reads local JSON files, evaluates packets against an ordered ACL
ruleset, tracks TCP connection state, and reports firewall-style sessions and
statistics.

## Quick Start

From this folder:

```bash
./fw-basic show-rules --input-dir ./sample
./fw-basic evaluate --packet-id 1 --input-dir ./sample
./fw-basic evaluate --packet-id 2 --input-dir ./sample
./fw-basic explain-decision --packet-id 2 --input-dir ./sample
./fw-basic show-sessions --input-dir ./sample
./fw-basic show-stats --input-dir ./sample
./fw-basic replay-packets --input-dir ./sample --show-stats
```

If the wrapper is not executable on your system, run the same commands as:

```bash
python3 fw_basic.py replay-packets --input-dir ./sample
```

## Input Files

The input directory must contain:

- `acl_rules.json`
- `packets.json`

Rules are evaluated in list order with first-match semantics. If no rule
matches, the packet is denied by the implicit final deny.

Supported rule fields:

- `id`: unique integer
- `action`: `allow` or `deny`
- `protocol`: `tcp`, `udp`, `icmp`, or `any`
- `src`, `dst`: `any`, single IP, or CIDR
- `src_port`, `dst_port`: optional integer, list of integers, or `any`
- `stateful`: optional boolean; creates TCP sessions for allowed TCP packets

Packets support:

- `id`
- `timestamp`: optional numeric time used for session aging and rate limiting
- `protocol`
- `src_ip`, `dst_ip`
- `src_port`, `dst_port` for TCP/UDP
- `flags` for TCP, such as `SYN`, `SYN-ACK`, `ACK`, `FIN`, or `RST`

## Stateful Behavior

For TCP packets, the firewall checks the connection table before ACL rules. A
return packet is allowed when it matches the reverse 5-tuple of an active
session. Forward packets on the same 5-tuple are also allowed while the session
is active.

Session state transitions are intentionally simple:

- Initial `SYN` creates `NEW`.
- Reverse `SYN-ACK` or later `ACK` moves the session to `ESTABLISHED`.
- `FIN` or `RST` moves the session to `CLOSED`.
- Idle sessions are aged out by `--session-timeout`, default `300`.

Commands evaluate from a clean runtime state. Commands that target one packet
replay earlier packets first by default so standalone explanations have the
right connection context. Use `--no-prior-context` to evaluate only the selected
packet.

## Bonus Features

- Session aging: `--session-timeout 30`
- Dynamic rule changes:
  - File-backed: `add-rule` and `remove-rule`
  - In-memory without restart: `./fw-basic shell`, then `add-rule`, `remove-rule`,
    `save-rules`, `reload`, or `reset`
- Drop logging with rotation:
  - Default log path is `INPUT_DIR/dropped_packets.log`
  - Configure with `--drop-log`, `--log-max-bytes`, `--log-backups`, or disable
    with `--no-drop-log`
- Per-source rate limiting:
  - `--rate-limit 10 --rate-window 60`

## Interactive Shell

```text
fw-basic# show rules
fw-basic# replay-packets
fw-basic# show sessions all
fw-basic# add-rule 3 {"id":4,"action":"allow","protocol":"udp","src":"192.168.1.0/24","dst":"10.0.0.5","dst_port":53}
fw-basic# remove-rule 4
fw-basic# save-rules
fw-basic# reset
fw-basic# exit
```

## Validation

```bash
python3 -m unittest discover -s tests
./fw-basic replay-packets --input-dir ./sample --show-stats --no-drop-log
./fw-basic explain-decision --packet-id 2 --input-dir ./sample --no-drop-log
./fw-basic show-sessions --input-dir ./sample --no-drop-log
```
