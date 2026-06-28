# AI Usage

AI assistance was used to design, implement, correct, and validate this project.
The goal was to keep the result small, explainable, and easy to run on one
system.

## Prompts Used

Initial build prompt:

```text
Build a small virtual stateful firewall CLI that reads acl_rules.json and
packets.json, evaluates ordered ACL rules with first-match semantics, implements
an implicit deny, tracks TCP 5-tuple sessions with NEW, ESTABLISHED, and CLOSED
states, and provides show-rules, show-sessions, show-stats, evaluate,
replay-packets, and explain-decision commands.
```

Correction prompt:

```text
Make packet-specific commands deterministic without a background daemon. Replay
earlier packets before the requested packet so a SYN-ACK return packet can be
allowed by the session created by the previous SYN. Add an option to disable
that prior context.
```

Bonus prompt:

```text
Add small bonus features without making the program hard to explain: session
aging with a configurable timeout, dynamic rule add/remove commands, drop-log
rotation, and optional source-IP rate limiting.
```

Validation prompt:

```text
Create focused unit tests for first-match ACL behavior, implicit deny, TCP
return traffic allowed by session state, session closure/aging, rate limiting,
and drop-log rotation.
```

## AI Corrections Made

- The packet example in the assignment text included non-JSON text
  (`Cisco Confidential`). The implementation keeps all sample files valid JSON.
- The session lookup was corrected to check both the original 5-tuple and its
  reverse so return traffic is allowed by connection state.
- Packet-targeted commands were designed to replay prior packets by default.
  That makes `evaluate --packet-id 2` correctly allow a `SYN-ACK` even though
  each CLI command starts as a fresh process.
- ACL evaluation was kept strictly ordered: the first matching rule wins, and a
  final implicit deny is applied when no rule matches.
- Rule hit counts are only incremented for ACL matches. Session hits and
  implicit denies are tracked separately so the statistics remain explainable.
- TCP state transitions were intentionally simplified and documented rather
  than pretending to be a full TCP stack.

## Validation Performed

Validation used unit tests and manual CLI runs:

```bash
python3 -m unittest discover -s tests
./fw-basic show-rules --input-dir ./sample
./fw-basic evaluate --packet-id 1 --input-dir ./sample --no-drop-log
./fw-basic evaluate --packet-id 2 --input-dir ./sample --no-drop-log
./fw-basic explain-decision --packet-id 2 --input-dir ./sample --no-drop-log
./fw-basic show-sessions --input-dir ./sample --all --no-drop-log
./fw-basic show-stats --input-dir ./sample --no-drop-log
./fw-basic replay-packets --input-dir ./sample --show-stats --no-drop-log
```

The tests verify ACL ordering, implicit deny, TCP connection tracking, return
packet handling, session aging, closed sessions, per-rule statistics, drop-log
rotation, and rate limiting.
