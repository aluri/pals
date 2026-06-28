#!/usr/bin/env python3
"""Simple stateful firewall / ACL evaluator.

The program reads ACL rules and packets from JSON files, evaluates traffic with
first-match ACL semantics, tracks TCP connection state, and exposes the result
through a firewall-style CLI.
"""

from __future__ import annotations

import argparse
import cmd
import ipaddress
import json
import re
import shlex
import sys
from collections import defaultdict, deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


DEFAULT_INPUT_DIR = Path(__file__).resolve().parent / "sample"
RULES_FILE = "acl_rules.json"
PACKETS_FILE = "packets.json"

VALID_ACTIONS = {"allow", "deny"}
TCP_STATE_NEW = "NEW"
TCP_STATE_ESTABLISHED = "ESTABLISHED"
TCP_STATE_CLOSED = "CLOSED"


class ConfigError(ValueError):
    """Raised when JSON input or CLI arguments are invalid."""


def load_json_list(path: Path, label: str) -> list[dict[str, Any]]:
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise ConfigError(f"{label} file not found: {path}") from exc
    except json.JSONDecodeError as exc:
        raise ConfigError(f"{label} file is not valid JSON: {path}: {exc}") from exc

    if not isinstance(raw, list):
        raise ConfigError(f"{label} must contain a JSON list: {path}")
    if not all(isinstance(item, dict) for item in raw):
        raise ConfigError(f"{label} must be a list of JSON objects: {path}")
    return raw


def write_json_list(path: Path, rows: list[dict[str, Any]]) -> None:
    path.write_text(json.dumps(rows, indent=2) + "\n", encoding="utf-8")


def normalize_protocol(value: Any, *, allow_any: bool) -> str:
    protocol = str(value or "").strip().lower()
    if not protocol:
        raise ConfigError("protocol is required")
    if protocol == "any" and not allow_any:
        raise ConfigError("packet protocol cannot be 'any'")
    return protocol


def normalize_ip(value: Any, label: str) -> str:
    try:
        return str(ipaddress.ip_address(str(value)))
    except ValueError as exc:
        raise ConfigError(f"{label} is not a valid IP address: {value!r}") from exc


def normalize_port(value: Any, label: str, *, required: bool) -> int | None:
    if value is None or value == "":
        if required:
            raise ConfigError(f"{label} is required")
        return None
    try:
        port = int(value)
    except (TypeError, ValueError) as exc:
        raise ConfigError(f"{label} must be an integer: {value!r}") from exc
    if port < 0 or port > 65535:
        raise ConfigError(f"{label} must be in range 0-65535: {value!r}")
    return port


@dataclass(frozen=True)
class IpMatcher:
    text: str
    network: ipaddress._BaseNetwork | None = None

    @classmethod
    def from_value(cls, value: Any, label: str) -> "IpMatcher":
        text = str(value if value is not None else "any").strip().lower()
        if text == "any":
            return cls(text="any")
        try:
            network = ipaddress.ip_network(text, strict=False)
        except ValueError as exc:
            raise ConfigError(f"{label} must be 'any', IP, or CIDR: {value!r}") from exc
        return cls(text=str(network), network=network)

    def matches(self, value: str) -> bool:
        if self.network is None:
            return True
        return ipaddress.ip_address(value) in self.network


@dataclass(frozen=True)
class PortMatcher:
    text: str
    values: frozenset[int] | None = None

    @classmethod
    def from_value(cls, value: Any, label: str) -> "PortMatcher":
        if value is None or str(value).strip().lower() == "any":
            return cls(text="any")
        if isinstance(value, list):
            ports = frozenset(normalize_port(item, label, required=True) for item in value)
            return cls(text=",".join(str(port) for port in sorted(ports)), values=ports)
        port = normalize_port(value, label, required=True)
        return cls(text=str(port), values=frozenset({port}))

    def matches(self, value: int | None) -> bool:
        if self.values is None:
            return True
        return value in self.values


@dataclass(frozen=True)
class Rule:
    id: int
    action: str
    protocol: str
    src: IpMatcher
    dst: IpMatcher
    src_port: PortMatcher
    dst_port: PortMatcher
    stateful: bool
    raw: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Rule":
        try:
            rule_id = int(data["id"])
        except KeyError as exc:
            raise ConfigError("rule is missing id") from exc
        except (TypeError, ValueError) as exc:
            raise ConfigError(f"rule id must be an integer: {data.get('id')!r}") from exc

        action = str(data.get("action", "")).strip().lower()
        if action not in VALID_ACTIONS:
            raise ConfigError(f"rule {rule_id}: action must be allow or deny")

        return cls(
            id=rule_id,
            action=action,
            protocol=normalize_protocol(data.get("protocol"), allow_any=True),
            src=IpMatcher.from_value(data.get("src", "any"), f"rule {rule_id} src"),
            dst=IpMatcher.from_value(data.get("dst", "any"), f"rule {rule_id} dst"),
            src_port=PortMatcher.from_value(data.get("src_port", "any"), f"rule {rule_id} src_port"),
            dst_port=PortMatcher.from_value(data.get("dst_port", "any"), f"rule {rule_id} dst_port"),
            stateful=bool(data.get("stateful", False)),
            raw=dict(data),
        )

    def matches(self, packet: "Packet") -> bool:
        if self.protocol != "any" and self.protocol != packet.protocol:
            return False
        return (
            self.src.matches(packet.src_ip)
            and self.dst.matches(packet.dst_ip)
            and self.src_port.matches(packet.src_port)
            and self.dst_port.matches(packet.dst_port)
        )

    def summary(self) -> list[str]:
        return [
            str(self.id),
            self.action,
            self.protocol,
            self.src.text,
            self.dst.text,
            self.src_port.text,
            self.dst_port.text,
            "yes" if self.stateful else "no",
        ]


@dataclass(frozen=True)
class Packet:
    id: int
    protocol: str
    src_ip: str
    dst_ip: str
    src_port: int | None
    dst_port: int | None
    flags: str
    timestamp: float
    raw: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: dict[str, Any], default_timestamp: float) -> "Packet":
        try:
            packet_id = int(data["id"])
        except KeyError as exc:
            raise ConfigError("packet is missing id") from exc
        except (TypeError, ValueError) as exc:
            raise ConfigError(f"packet id must be an integer: {data.get('id')!r}") from exc

        protocol = normalize_protocol(data.get("protocol"), allow_any=False)
        ports_required = protocol in {"tcp", "udp"}
        timestamp = data.get("timestamp", default_timestamp)
        try:
            timestamp_value = float(timestamp)
        except (TypeError, ValueError) as exc:
            raise ConfigError(f"packet {packet_id}: timestamp must be numeric") from exc

        return cls(
            id=packet_id,
            protocol=protocol,
            src_ip=normalize_ip(data.get("src_ip"), f"packet {packet_id} src_ip"),
            dst_ip=normalize_ip(data.get("dst_ip"), f"packet {packet_id} dst_ip"),
            src_port=normalize_port(data.get("src_port"), f"packet {packet_id} src_port", required=ports_required),
            dst_port=normalize_port(data.get("dst_port"), f"packet {packet_id} dst_port", required=ports_required),
            flags=str(data.get("flags", "")).strip().upper(),
            timestamp=timestamp_value,
            raw=dict(data),
        )

    @property
    def flag_set(self) -> set[str]:
        return {part for part in re.split(r"[-,|\s]+", self.flags.upper()) if part}

    def flow_key(self) -> "FlowKey":
        return FlowKey(
            self.src_ip,
            self.dst_ip,
            self.src_port,
            self.dst_port,
            self.protocol,
        )


@dataclass(frozen=True)
class FlowKey:
    src_ip: str
    dst_ip: str
    src_port: int | None
    dst_port: int | None
    protocol: str

    def reverse(self) -> "FlowKey":
        return FlowKey(
            self.dst_ip,
            self.src_ip,
            self.dst_port,
            self.src_port,
            self.protocol,
        )

    def display(self) -> str:
        return (
            f"{self.protocol.upper()} "
            f"{self.src_ip}:{port_text(self.src_port)} -> "
            f"{self.dst_ip}:{port_text(self.dst_port)}"
        )


@dataclass
class Session:
    key: FlowKey
    state: str
    created_at: float
    last_seen: float
    packet_count: int = 1

    @property
    def active(self) -> bool:
        return self.state != TCP_STATE_CLOSED


@dataclass
class Stats:
    rule_hits: dict[int, int] = field(default_factory=lambda: defaultdict(int))
    allow_total: int = 0
    deny_total: int = 0
    session_hits: int = 0
    implicit_deny_total: int = 0
    rate_limited_total: int = 0
    dropped_logged_total: int = 0


@dataclass
class Decision:
    packet: Packet
    action: str
    reason: str
    matched_rule: Rule | None = None
    matched_session: Session | None = None
    session_direction: str | None = None
    session_state_before: str | None = None
    session_state_after: str | None = None
    implicit_deny: bool = False
    rate_limited: bool = False
    drop_log_path: Path | None = None

    def source(self) -> str:
        if self.matched_session is not None and self.session_direction != "created":
            return f"session {self.session_direction}"
        if self.matched_rule is not None:
            return f"rule {self.matched_rule.id}"
        if self.matched_session is not None:
            return f"session {self.session_direction}"
        if self.rate_limited:
            return "rate-limit"
        return "implicit-deny"


class DropLogger:
    def __init__(self, path: Path, max_bytes: int, backups: int) -> None:
        self.path = path
        self.max_bytes = max(0, max_bytes)
        self.backups = max(0, backups)

    def log(self, decision: Decision) -> Path:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        row = {
            "packet_id": decision.packet.id,
            "action": decision.action,
            "reason": decision.reason,
            "src_ip": decision.packet.src_ip,
            "dst_ip": decision.packet.dst_ip,
            "protocol": decision.packet.protocol,
            "src_port": decision.packet.src_port,
            "dst_port": decision.packet.dst_port,
            "matched": decision.source(),
        }
        line = json.dumps(row, sort_keys=True) + "\n"
        self._rotate_if_needed(len(line.encode("utf-8")))
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(line)
        return self.path

    def _rotate_if_needed(self, incoming_bytes: int) -> None:
        if self.max_bytes <= 0 or not self.path.exists():
            return
        if self.path.stat().st_size + incoming_bytes <= self.max_bytes:
            return
        if self.backups == 0:
            self.path.write_text("", encoding="utf-8")
            return
        for index in range(self.backups - 1, 0, -1):
            old = self.path.with_name(f"{self.path.name}.{index}")
            new = self.path.with_name(f"{self.path.name}.{index + 1}")
            if old.exists():
                old.replace(new)
        first_backup = self.path.with_name(f"{self.path.name}.1")
        self.path.replace(first_backup)


class Firewall:
    def __init__(
        self,
        rules: list[Rule],
        *,
        session_timeout: float = 300,
        rate_limit: int = 0,
        rate_window: float = 60,
        drop_logger: DropLogger | None = None,
    ) -> None:
        self.rules = self._validate_rule_ids(rules)
        self.session_timeout = float(session_timeout)
        self.rate_limit = max(0, int(rate_limit))
        self.rate_window = float(rate_window)
        self.drop_logger = drop_logger
        self.sessions: dict[FlowKey, Session] = {}
        self.stats = Stats()
        self._rate_buckets: dict[str, deque[float]] = defaultdict(deque)

    @staticmethod
    def _validate_rule_ids(rules: list[Rule]) -> list[Rule]:
        seen: set[int] = set()
        for rule in rules:
            if rule.id in seen:
                raise ConfigError(f"duplicate rule id: {rule.id}")
            seen.add(rule.id)
        return list(rules)

    def reset_runtime(self) -> None:
        self.sessions.clear()
        self.stats = Stats()
        self._rate_buckets.clear()

    def add_rule(self, rule: Rule, position: int | None = None) -> None:
        if any(existing.id == rule.id for existing in self.rules):
            raise ConfigError(f"duplicate rule id: {rule.id}")
        if position is None:
            self.rules.append(rule)
            return
        if position < 1 or position > len(self.rules) + 1:
            raise ConfigError(f"position must be in range 1-{len(self.rules) + 1}")
        self.rules.insert(position - 1, rule)

    def remove_rule(self, rule_id: int) -> Rule:
        for index, rule in enumerate(self.rules):
            if rule.id == rule_id:
                return self.rules.pop(index)
        raise ConfigError(f"rule id not found: {rule_id}")

    def evaluate(self, packet: Packet, *, log_drops: bool = True) -> Decision:
        self._age_sessions(packet.timestamp)

        rate_reason = self._rate_limit_reason(packet)
        if rate_reason is not None:
            decision = Decision(
                packet=packet,
                action="deny",
                reason=rate_reason,
                rate_limited=True,
            )
            self.stats.deny_total += 1
            self.stats.rate_limited_total += 1
            self._maybe_log_drop(decision, log_drops)
            return decision

        if packet.protocol == "tcp":
            session, direction = self._find_active_session(packet)
            if session is not None:
                before = session.state
                self._update_session(session, packet, direction)
                decision = Decision(
                    packet=packet,
                    action="allow",
                    reason=(
                        "packet matches an existing TCP connection tracking "
                        "entry, so it bypasses ACL evaluation"
                    ),
                    matched_session=session,
                    session_direction=direction,
                    session_state_before=before,
                    session_state_after=session.state,
                )
                self.stats.allow_total += 1
                self.stats.session_hits += 1
                return decision

        for rule in self.rules:
            if not rule.matches(packet):
                continue
            self.stats.rule_hits[rule.id] += 1
            if rule.action == "deny":
                decision = Decision(
                    packet=packet,
                    action="deny",
                    reason="first matching ACL rule has action deny",
                    matched_rule=rule,
                )
                self.stats.deny_total += 1
                self._maybe_log_drop(decision, log_drops)
                return decision

            session = None
            state_before = None
            state_after = None
            if packet.protocol == "tcp" and rule.stateful:
                session = self._create_session(packet)
                state_before = session.state
                state_after = session.state
            decision = Decision(
                packet=packet,
                action="allow",
                reason="first matching ACL rule has action allow",
                matched_rule=rule,
                matched_session=session,
                session_direction="created" if session is not None else None,
                session_state_before=state_before,
                session_state_after=state_after,
            )
            self.stats.allow_total += 1
            return decision

        decision = Decision(
            packet=packet,
            action="deny",
            reason="no ACL rule matched, so the implicit deny at the end applied",
            implicit_deny=True,
        )
        self.stats.deny_total += 1
        self.stats.implicit_deny_total += 1
        self._maybe_log_drop(decision, log_drops)
        return decision

    def _maybe_log_drop(self, decision: Decision, enabled: bool) -> None:
        if not enabled or self.drop_logger is None:
            return
        decision.drop_log_path = self.drop_logger.log(decision)
        self.stats.dropped_logged_total += 1

    def _rate_limit_reason(self, packet: Packet) -> str | None:
        if self.rate_limit <= 0:
            return None
        bucket = self._rate_buckets[packet.src_ip]
        cutoff = packet.timestamp - self.rate_window
        while bucket and bucket[0] <= cutoff:
            bucket.popleft()
        bucket.append(packet.timestamp)
        if len(bucket) > self.rate_limit:
            return (
                f"source {packet.src_ip} exceeded rate limit "
                f"{self.rate_limit}/{int(self.rate_window)}s"
            )
        return None

    def _age_sessions(self, now: float) -> None:
        expired = [
            key
            for key, session in self.sessions.items()
            if now - session.last_seen > self.session_timeout
        ]
        for key in expired:
            del self.sessions[key]

    def _find_active_session(self, packet: Packet) -> tuple[Session | None, str | None]:
        key = packet.flow_key()
        session = self.sessions.get(key)
        if session is not None and session.active:
            return session, "forward"
        reverse_session = self.sessions.get(key.reverse())
        if reverse_session is not None and reverse_session.active:
            return reverse_session, "return"
        return None, None

    def _create_session(self, packet: Packet) -> Session:
        key = packet.flow_key()
        session = self.sessions.get(key)
        if session is None:
            session = Session(
                key=key,
                state=self._initial_tcp_state(packet),
                created_at=packet.timestamp,
                last_seen=packet.timestamp,
            )
            self.sessions[key] = session
        else:
            self._update_session(session, packet, "forward")
        return session

    def _initial_tcp_state(self, packet: Packet) -> str:
        flags = packet.flag_set
        if "RST" in flags or "FIN" in flags:
            return TCP_STATE_CLOSED
        if "SYN" in flags and "ACK" not in flags:
            return TCP_STATE_NEW
        return TCP_STATE_ESTABLISHED

    def _update_session(self, session: Session, packet: Packet, direction: str | None) -> None:
        session.packet_count += 1
        session.last_seen = packet.timestamp
        flags = packet.flag_set
        if "RST" in flags or "FIN" in flags:
            session.state = TCP_STATE_CLOSED
            return
        if session.state == TCP_STATE_NEW:
            if direction == "return" and {"SYN", "ACK"}.issubset(flags):
                session.state = TCP_STATE_ESTABLISHED
            elif "ACK" in flags or "SYN" not in flags:
                session.state = TCP_STATE_ESTABLISHED

    def sessions_for_display(self, *, include_closed: bool = False) -> list[Session]:
        sessions = sorted(
            self.sessions.values(),
            key=lambda item: (
                item.key.protocol,
                item.key.src_ip,
                item.key.src_port or -1,
                item.key.dst_ip,
                item.key.dst_port or -1,
            ),
        )
        if include_closed:
            return sessions
        return [session for session in sessions if session.active]


def load_rules(input_dir: Path) -> list[Rule]:
    return [Rule.from_dict(item) for item in load_json_list(input_dir / RULES_FILE, "ACL rules")]


def load_packets(input_dir: Path) -> list[Packet]:
    rows = load_json_list(input_dir / PACKETS_FILE, "packets")
    return [Packet.from_dict(item, default_timestamp=float(index + 1)) for index, item in enumerate(rows)]


def make_firewall(args: argparse.Namespace, *, logging_enabled: bool = True) -> Firewall:
    input_dir = Path(args.input_dir)
    drop_logger = None
    if logging_enabled and not getattr(args, "no_drop_log", False):
        drop_log = getattr(args, "drop_log", None)
        drop_logger = DropLogger(
            Path(drop_log) if drop_log else input_dir / "dropped_packets.log",
            max_bytes=getattr(args, "log_max_bytes", 1_048_576),
            backups=getattr(args, "log_backups", 3),
        )
    return Firewall(
        load_rules(input_dir),
        session_timeout=getattr(args, "session_timeout", 300),
        rate_limit=getattr(args, "rate_limit", 0),
        rate_window=getattr(args, "rate_window", 60),
        drop_logger=drop_logger,
    )


def find_packet(packets: list[Packet], packet_id: int) -> tuple[int, Packet]:
    for index, packet in enumerate(packets):
        if packet.id == packet_id:
            return index, packet
    raise ConfigError(f"packet id not found: {packet_id}")


def evaluate_to_packet(
    firewall: Firewall,
    packets: list[Packet],
    packet_id: int,
    *,
    prior_context: bool = True,
    log_drops: bool = True,
) -> Decision:
    index, target = find_packet(packets, packet_id)
    sequence = packets[: index + 1] if prior_context else [target]
    decision = None
    for packet in sequence:
        decision = firewall.evaluate(packet, log_drops=log_drops)
    if decision is None:
        raise ConfigError("no packet was evaluated")
    return decision


def replay_packets(
    firewall: Firewall,
    packets: list[Packet],
    *,
    through_packet_id: int | None = None,
    log_drops: bool = True,
) -> list[Decision]:
    decisions: list[Decision] = []
    for packet in packets:
        decisions.append(firewall.evaluate(packet, log_drops=log_drops))
        if through_packet_id is not None and packet.id == through_packet_id:
            return decisions
    if through_packet_id is not None:
        raise ConfigError(f"packet id not found: {through_packet_id}")
    return decisions


def port_text(port: int | None) -> str:
    return "*" if port is None else str(port)


def packet_text(packet: Packet) -> str:
    return (
        f"id={packet.id} {packet.protocol.upper()} "
        f"{packet.src_ip}:{port_text(packet.src_port)} -> "
        f"{packet.dst_ip}:{port_text(packet.dst_port)}"
        + (f" flags={packet.flags}" if packet.flags else "")
    )


def render_table(headers: list[str], rows: list[list[Any]]) -> str:
    text_rows = [[str(cell) for cell in row] for row in rows]
    widths = [
        max([len(headers[index])] + [len(row[index]) for row in text_rows])
        for index in range(len(headers))
    ]
    lines = [
        "  ".join(headers[index].ljust(widths[index]) for index in range(len(headers))),
        "  ".join("-" * widths[index] for index in range(len(headers))),
    ]
    for row in text_rows:
        lines.append("  ".join(row[index].ljust(widths[index]) for index in range(len(headers))))
    return "\n".join(lines)


def print_rules(rules: list[Rule]) -> None:
    headers = ["ID", "ACTION", "PROTO", "SRC", "DST", "SRC_PORT", "DST_PORT", "STATEFUL"]
    print(render_table(headers, [rule.summary() for rule in rules]))


def print_decision(decision: Decision) -> None:
    print(render_table(
        ["PACKET", "ACTION", "MATCH", "REASON"],
        [[decision.packet.id, decision.action, decision.source(), decision.reason]],
    ))


def print_explanation(decision: Decision) -> None:
    print("Packet")
    print(f"  {packet_text(decision.packet)}")
    print("")
    print("Decision")
    print(f"  action: {decision.action}")
    print(f"  source: {decision.source()}")
    print(f"  reason: {decision.reason}")
    if decision.matched_rule is not None:
        rule = decision.matched_rule
        print("")
        print("Matched Rule")
        print(f"  id: {rule.id}")
        print(f"  action: {rule.action}")
        print(f"  protocol: {rule.protocol}")
        print(f"  src: {rule.src.text}")
        print(f"  dst: {rule.dst.text}")
        print(f"  src_port: {rule.src_port.text}")
        print(f"  dst_port: {rule.dst_port.text}")
        print(f"  stateful: {'yes' if rule.stateful else 'no'}")
    if decision.matched_session is not None:
        session = decision.matched_session
        print("")
        print("Session")
        print(f"  key: {session.key.display()}")
        print(f"  direction: {decision.session_direction}")
        print(f"  state_before: {decision.session_state_before}")
        print(f"  state_after: {decision.session_state_after}")
        print(f"  packets_seen: {session.packet_count}")
    if decision.drop_log_path is not None:
        print("")
        print(f"Drop Log: {decision.drop_log_path}")


def print_replay(decisions: list[Decision]) -> None:
    rows = []
    for decision in decisions:
        rows.append([
            decision.packet.id,
            decision.packet.protocol,
            f"{decision.packet.src_ip}:{port_text(decision.packet.src_port)}",
            f"{decision.packet.dst_ip}:{port_text(decision.packet.dst_port)}",
            decision.action,
            decision.source(),
        ])
    print(render_table(["ID", "PROTO", "SRC", "DST", "ACTION", "MATCH"], rows))


def print_sessions(firewall: Firewall, *, include_closed: bool = False) -> None:
    sessions = firewall.sessions_for_display(include_closed=include_closed)
    if not sessions:
        print("No sessions.")
        return
    rows = [
        [
            session.key.display(),
            session.state,
            compact_number(session.created_at),
            compact_number(session.last_seen),
            session.packet_count,
        ]
        for session in sessions
    ]
    print(render_table(["FLOW", "STATE", "CREATED", "LAST_SEEN", "PACKETS"], rows))


def print_stats(firewall: Firewall) -> None:
    rows = []
    for rule in firewall.rules:
        rows.append([rule.id, rule.action, rule.protocol, firewall.stats.rule_hits.get(rule.id, 0)])
    print("Rule Hits")
    print(render_table(["ID", "ACTION", "PROTO", "HITS"], rows))
    print("")
    totals = [
        ["allowed", firewall.stats.allow_total],
        ["denied", firewall.stats.deny_total],
        ["session_hits", firewall.stats.session_hits],
        ["implicit_denies", firewall.stats.implicit_deny_total],
        ["rate_limited", firewall.stats.rate_limited_total],
        ["drops_logged", firewall.stats.dropped_logged_total],
    ]
    print("Totals")
    print(render_table(["COUNTER", "VALUE"], totals))


def compact_number(value: float) -> str:
    return str(int(value)) if value.is_integer() else f"{value:.3f}"


def cmd_show_rules(args: argparse.Namespace) -> None:
    print_rules(load_rules(Path(args.input_dir)))


def cmd_evaluate(args: argparse.Namespace) -> None:
    firewall = make_firewall(args)
    packets = load_packets(Path(args.input_dir))
    decision = evaluate_to_packet(
        firewall,
        packets,
        args.packet_id,
        prior_context=not args.no_prior_context,
    )
    print_decision(decision)


def cmd_explain_decision(args: argparse.Namespace) -> None:
    firewall = make_firewall(args, logging_enabled=False)
    packets = load_packets(Path(args.input_dir))
    decision = evaluate_to_packet(
        firewall,
        packets,
        args.packet_id,
        prior_context=not args.no_prior_context,
    )
    print_explanation(decision)


def cmd_replay_packets(args: argparse.Namespace) -> None:
    firewall = make_firewall(args)
    packets = load_packets(Path(args.input_dir))
    decisions = replay_packets(firewall, packets)
    print_replay(decisions)
    if args.show_stats:
        print("")
        print_stats(firewall)


def cmd_show_sessions(args: argparse.Namespace) -> None:
    firewall = make_firewall(args, logging_enabled=False)
    packets = load_packets(Path(args.input_dir))
    replay_packets(firewall, packets, through_packet_id=args.through_packet_id)
    print_sessions(firewall, include_closed=args.all)


def cmd_show_stats(args: argparse.Namespace) -> None:
    firewall = make_firewall(args, logging_enabled=False)
    packets = load_packets(Path(args.input_dir))
    replay_packets(firewall, packets, through_packet_id=args.through_packet_id)
    print_stats(firewall)


def cmd_add_rule(args: argparse.Namespace) -> None:
    input_dir = Path(args.input_dir)
    rows = load_json_list(input_dir / RULES_FILE, "ACL rules")
    rule_data = parse_rule_json(args.rule_json)
    rule = Rule.from_dict(rule_data)
    firewall = Firewall([Rule.from_dict(item) for item in rows])
    firewall.add_rule(rule, position=args.position)
    updated = [item.raw for item in firewall.rules]
    write_json_list(input_dir / RULES_FILE, updated)
    print(f"Added rule {rule.id} to {input_dir / RULES_FILE}")


def cmd_remove_rule(args: argparse.Namespace) -> None:
    input_dir = Path(args.input_dir)
    rows = load_json_list(input_dir / RULES_FILE, "ACL rules")
    firewall = Firewall([Rule.from_dict(item) for item in rows])
    removed = firewall.remove_rule(args.rule_id)
    write_json_list(input_dir / RULES_FILE, [item.raw for item in firewall.rules])
    print(f"Removed rule {removed.id} from {input_dir / RULES_FILE}")


def parse_rule_json(text: str) -> dict[str, Any]:
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ConfigError(f"rule JSON is invalid: {exc}") from exc
    if not isinstance(data, dict):
        raise ConfigError("rule JSON must be a single object")
    return data


class FirewallShell(cmd.Cmd):
    intro = "Stateful firewall shell. Type 'help' for commands."
    prompt = "fw-basic# "

    def __init__(self, args: argparse.Namespace) -> None:
        super().__init__()
        self.identchars += "-"
        self.args = args
        self.input_dir = Path(args.input_dir)
        self.firewall = make_firewall(args)
        self.packets = load_packets(self.input_dir)

    def parseline(self, line: str) -> tuple[str | None, str | None, str]:
        command_name, arg, original = super().parseline(line)
        if command_name is not None:
            command_name = command_name.replace("-", "_")
        return command_name, arg, original

    def do_show(self, line: str) -> None:
        """show rules | sessions [all] | stats"""
        words = shlex.split(line)
        if not words:
            print("usage: show rules | sessions [all] | stats")
            return
        if words[0] == "rules":
            print_rules(self.firewall.rules)
        elif words[0] == "sessions":
            print_sessions(self.firewall, include_closed=("all" in words[1:]))
        elif words[0] == "stats":
            print_stats(self.firewall)
        else:
            print("usage: show rules | sessions [all] | stats")

    def do_replay_packets(self, line: str) -> None:
        """replay-packets"""
        if line.strip():
            print("usage: replay-packets")
            return
        decisions = replay_packets(self.firewall, self.packets)
        print_replay(decisions)

    def do_evaluate(self, line: str) -> None:
        """evaluate PACKET_ID"""
        packet_id = parse_shell_packet_id(line, "evaluate")
        if packet_id is None:
            return
        decision = evaluate_to_packet(self.firewall, self.packets, packet_id, prior_context=False)
        print_decision(decision)

    def do_explain_decision(self, line: str) -> None:
        """explain-decision PACKET_ID"""
        packet_id = parse_shell_packet_id(line, "explain-decision")
        if packet_id is None:
            return
        decision = evaluate_to_packet(self.firewall, self.packets, packet_id, prior_context=False)
        print_explanation(decision)

    def do_add_rule(self, line: str) -> None:
        """add-rule [POSITION] '{"id":4,"action":"allow",...}'"""
        try:
            position, rule_json = parse_shell_rule_add(line)
            rule = Rule.from_dict(parse_rule_json(rule_json))
            self.firewall.add_rule(rule, position=position)
        except ConfigError as exc:
            print(f"error: {exc}")
            return
        if position is None:
            print(f"added in-memory rule {rule.id}")
        else:
            print(f"added in-memory rule {rule.id} at position {position}")

    def do_remove_rule(self, line: str) -> None:
        """remove-rule RULE_ID"""
        try:
            rule_id = int(line.strip())
            removed = self.firewall.remove_rule(rule_id)
        except (ValueError, ConfigError) as exc:
            print(f"error: {exc}")
            return
        print(f"removed in-memory rule {removed.id}")

    def do_save_rules(self, line: str) -> None:
        """save-rules"""
        if line.strip():
            print("usage: save-rules")
            return
        write_json_list(self.input_dir / RULES_FILE, [rule.raw for rule in self.firewall.rules])
        print(f"saved {self.input_dir / RULES_FILE}")

    def do_reset(self, line: str) -> None:
        """reset runtime sessions, stats, and rate counters"""
        if line.strip():
            print("usage: reset")
            return
        self.firewall.reset_runtime()
        print("runtime state reset")

    def do_reload(self, line: str) -> None:
        """reload rules and packets from disk"""
        if line.strip():
            print("usage: reload")
            return
        self.firewall = make_firewall(self.args)
        self.packets = load_packets(self.input_dir)
        print("reloaded rules and packets")

    def do_exit(self, line: str) -> bool:
        """exit"""
        return True

    def do_EOF(self, line: str) -> bool:
        print("")
        return True


def parse_shell_packet_id(line: str, command: str) -> int | None:
    words = shlex.split(line)
    if len(words) != 1:
        print(f"usage: {command} PACKET_ID")
        return None
    try:
        return int(words[0])
    except ValueError:
        print("packet id must be an integer")
        return None


def parse_shell_rule_add(line: str) -> tuple[int | None, str]:
    text = line.strip()
    if not text:
        raise ConfigError("usage: add-rule [POSITION] JSON")
    if text.startswith("{"):
        return None, text
    first, sep, rest = text.partition(" ")
    if not sep:
        raise ConfigError("usage: add-rule [POSITION] JSON")
    try:
        position = int(first)
    except ValueError as exc:
        raise ConfigError("position must be an integer when provided") from exc
    return position, rest.strip()


def cmd_shell(args: argparse.Namespace) -> None:
    FirewallShell(args).cmdloop()


def add_common_runtime_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--input-dir", default=str(DEFAULT_INPUT_DIR), help="directory containing acl_rules.json and packets.json")
    parser.add_argument("--session-timeout", type=float, default=300, help="TCP session idle timeout in seconds/ticks")
    parser.add_argument("--rate-limit", type=int, default=0, help="max packets per source IP in the rate window; 0 disables")
    parser.add_argument("--rate-window", type=float, default=60, help="rate-limit window in seconds/ticks")
    parser.add_argument("--drop-log", default=None, help="path for dropped-packet log; default is INPUT_DIR/dropped_packets.log")
    parser.add_argument("--log-max-bytes", type=int, default=1_048_576, help="rotate drop log after this many bytes")
    parser.add_argument("--log-backups", type=int, default=3, help="number of rotated drop logs to retain")
    parser.add_argument("--no-drop-log", action="store_true", help="disable dropped-packet logging")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="fw-basic",
        description="Simple stateful firewall / ACL evaluator",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    show_rules = subparsers.add_parser("show-rules", help="display ACL rules")
    show_rules.add_argument("--input-dir", default=str(DEFAULT_INPUT_DIR))
    show_rules.set_defaults(func=cmd_show_rules)

    evaluate = subparsers.add_parser("evaluate", help="evaluate one packet by id")
    add_common_runtime_args(evaluate)
    evaluate.add_argument("--packet-id", type=int, required=True)
    evaluate.add_argument("--no-prior-context", action="store_true", help="do not replay earlier packets before the target")
    evaluate.set_defaults(func=cmd_evaluate)

    explain = subparsers.add_parser("explain-decision", help="explain one packet decision")
    add_common_runtime_args(explain)
    explain.add_argument("--packet-id", type=int, required=True)
    explain.add_argument("--no-prior-context", action="store_true", help="do not replay earlier packets before the target")
    explain.set_defaults(func=cmd_explain_decision)

    replay = subparsers.add_parser("replay-packets", help="evaluate all packets in order")
    add_common_runtime_args(replay)
    replay.add_argument("--show-stats", action="store_true", help="print statistics after replay")
    replay.set_defaults(func=cmd_replay_packets)

    sessions = subparsers.add_parser("show-sessions", help="display active TCP sessions after replay")
    add_common_runtime_args(sessions)
    sessions.add_argument("--through-packet-id", type=int, default=None, help="stop replay after this packet id")
    sessions.add_argument("--all", action="store_true", help="include CLOSED sessions")
    sessions.set_defaults(func=cmd_show_sessions)

    stats = subparsers.add_parser("show-stats", help="display rule hit counts and totals after replay")
    add_common_runtime_args(stats)
    stats.add_argument("--through-packet-id", type=int, default=None, help="stop replay after this packet id")
    stats.set_defaults(func=cmd_show_stats)

    add_rule = subparsers.add_parser("add-rule", help="append or insert a rule in acl_rules.json")
    add_rule.add_argument("--input-dir", default=str(DEFAULT_INPUT_DIR))
    add_rule.add_argument("--rule-json", required=True, help="JSON object for the new rule")
    add_rule.add_argument("--position", type=int, default=None, help="1-based insertion position")
    add_rule.set_defaults(func=cmd_add_rule)

    remove_rule = subparsers.add_parser("remove-rule", help="remove a rule from acl_rules.json")
    remove_rule.add_argument("--input-dir", default=str(DEFAULT_INPUT_DIR))
    remove_rule.add_argument("--rule-id", type=int, required=True)
    remove_rule.set_defaults(func=cmd_remove_rule)

    shell = subparsers.add_parser("shell", help="interactive firewall shell with live rule changes")
    add_common_runtime_args(shell)
    shell.set_defaults(func=cmd_shell)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        args.func(args)
    except ConfigError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
