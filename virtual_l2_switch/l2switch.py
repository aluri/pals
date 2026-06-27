#!/usr/bin/env python3
"""A small virtual Layer-2 switch simulator.

The simulator loads port, VLAN, and frame data from local JSON files. It learns
source MAC addresses, maintains a per-VLAN MAC table, and explains forwarding
decisions for access and trunk ports.
"""

from __future__ import annotations

import argparse
import json
import re
import shlex
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


DEFAULT_DIR = Path(__file__).resolve().parent
BROADCAST_MAC = "FF:FF:FF:FF:FF:FF"
MAC_RE = re.compile(r"^[0-9A-F]{2}(:[0-9A-F]{2}){5}$")


class ConfigError(ValueError):
    """Raised when input JSON is missing required switch fields."""


def normalize_mac(value: str) -> str:
    mac = str(value).strip().upper().replace("-", ":")
    if not MAC_RE.match(mac):
        raise ConfigError(f"invalid MAC address: {value!r}")
    return mac


def normalize_vlan(value: Any, *, required: bool = True) -> int | None:
    if value is None:
        if required:
            raise ConfigError("VLAN is required")
        return None
    try:
        vlan = int(value)
    except (TypeError, ValueError) as exc:
        raise ConfigError(f"invalid VLAN value: {value!r}") from exc
    if vlan < 1 or vlan > 4094:
        raise ConfigError(f"VLAN must be in range 1-4094: {value!r}")
    return vlan


def is_multicast_mac(mac: str) -> bool:
    return bool(int(mac.split(":")[0], 16) & 1)


def is_broadcast_mac(mac: str) -> bool:
    return mac == BROADCAST_MAC


@dataclass
class Port:
    name: str
    admin_state: str
    oper_state: str
    mode: str
    vlan: int | None = None
    allowed_vlans: list[int] = field(default_factory=list)
    rx_frames: int = 0
    tx_frames: int = 0
    dropped_frames: int = 0

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Port":
        name = str(data.get("name", "")).strip()
        if not name:
            raise ConfigError("port is missing a non-empty name")

        admin_state = str(data.get("admin_state", "down")).lower()
        oper_state = str(data.get("oper_state", "down")).lower()
        mode = str(data.get("mode", "")).lower()

        if admin_state not in {"up", "down"}:
            raise ConfigError(f"{name}: admin_state must be up or down")
        if oper_state not in {"up", "down"}:
            raise ConfigError(f"{name}: oper_state must be up or down")
        if mode not in {"access", "trunk"}:
            raise ConfigError(f"{name}: mode must be access or trunk")

        vlan = normalize_vlan(data.get("vlan"), required=(mode == "access"))
        allowed_vlans = [
            normalize_vlan(item) for item in data.get("allowed_vlans", [])
        ]

        if mode == "trunk" and not allowed_vlans:
            raise ConfigError(f"{name}: trunk port requires allowed_vlans")

        return cls(
            name=name,
            admin_state=admin_state,
            oper_state=oper_state,
            mode=mode,
            vlan=vlan,
            allowed_vlans=sorted(set(v for v in allowed_vlans if v is not None)),
            rx_frames=int(data.get("rx_frames", 0)),
            tx_frames=int(data.get("tx_frames", 0)),
            dropped_frames=int(data.get("dropped_frames", 0)),
        )

    @property
    def is_up(self) -> bool:
        return self.admin_state == "up" and self.oper_state == "up"

    def allows_vlan(self, vlan: int) -> bool:
        if self.mode == "access":
            return self.vlan == vlan
        return vlan in self.allowed_vlans

    def vlan_summary(self) -> str:
        if self.mode == "access":
            return str(self.vlan)
        return ",".join(str(vlan) for vlan in self.allowed_vlans)

    def egress_description(self, vlan: int) -> str:
        if self.mode == "access":
            return f"untagged access VLAN {vlan}"
        return f"tagged trunk VLAN {vlan}"


@dataclass(frozen=True)
class Vlan:
    vlan_id: int
    name: str

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Vlan":
        vlan_id = normalize_vlan(data.get("vlan_id"))
        name = str(data.get("name", "")).strip() or f"VLAN{vlan_id}"
        if vlan_id is None:
            raise ConfigError("vlan_id is required")
        return cls(vlan_id=vlan_id, name=name)


@dataclass(frozen=True)
class Frame:
    ingress_port: str
    src_mac: str
    dst_mac: str
    vlan: int | None

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Frame":
        ingress_port = str(data.get("ingress_port", "")).strip()
        if not ingress_port:
            raise ConfigError("frame is missing ingress_port")
        return cls(
            ingress_port=ingress_port,
            src_mac=normalize_mac(data.get("src_mac", "")),
            dst_mac=normalize_mac(data.get("dst_mac", "")),
            vlan=normalize_vlan(data.get("vlan"), required=False),
        )


@dataclass
class MacEntry:
    mac: str
    vlan: int
    port: str
    first_seen_tick: int
    last_seen_tick: int


@dataclass
class ForwardDecision:
    frame_number: int | None
    ingress_port: str
    src_mac: str
    dst_mac: str
    vlan: int | None
    action: str
    egress_ports: list[str]
    reason: str
    learning: str
    egress_tagging: dict[str, str] = field(default_factory=dict)


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


class VirtualSwitch:
    def __init__(self, ports: list[Port], vlans: list[Vlan]) -> None:
        self.ports = self._index_ports(ports)
        self.vlans = self._index_vlans(vlans)
        self.mac_table: dict[tuple[int, str], MacEntry] = {}
        self.clock = 0

        for port in self.ports.values():
            for vlan in self.port_vlans(port):
                if vlan not in self.vlans:
                    raise ConfigError(f"{port.name}: references undefined VLAN {vlan}")

    @classmethod
    def from_files(cls, ports_path: Path, vlans_path: Path) -> "VirtualSwitch":
        ports = [Port.from_dict(item) for item in load_json_list(ports_path, "ports")]
        vlans = [Vlan.from_dict(item) for item in load_json_list(vlans_path, "vlans")]
        return cls(ports=ports, vlans=vlans)

    @staticmethod
    def load_frames(frames_path: Path) -> list[Frame]:
        return [Frame.from_dict(item) for item in load_json_list(frames_path, "frames")]

    @staticmethod
    def _index_ports(ports: list[Port]) -> dict[str, Port]:
        indexed: dict[str, Port] = {}
        for port in ports:
            if port.name in indexed:
                raise ConfigError(f"duplicate port name: {port.name}")
            indexed[port.name] = port
        return indexed

    @staticmethod
    def _index_vlans(vlans: list[Vlan]) -> dict[int, Vlan]:
        indexed: dict[int, Vlan] = {}
        for vlan in vlans:
            if vlan.vlan_id in indexed:
                raise ConfigError(f"duplicate VLAN id: {vlan.vlan_id}")
            indexed[vlan.vlan_id] = vlan
        return indexed

    @staticmethod
    def port_vlans(port: Port) -> list[int]:
        if port.mode == "access":
            return [port.vlan] if port.vlan is not None else []
        return port.allowed_vlans

    def process_frame(
        self, frame: Frame, frame_number: int | None = None
    ) -> ForwardDecision:
        ingress = self.ports.get(frame.ingress_port)
        if ingress is None:
            return ForwardDecision(
                frame_number=frame_number,
                ingress_port=frame.ingress_port,
                src_mac=frame.src_mac,
                dst_mac=frame.dst_mac,
                vlan=frame.vlan,
                action="drop",
                egress_ports=[],
                reason=f"ingress port {frame.ingress_port} does not exist",
                learning="source MAC was not learned",
            )

        if not ingress.is_up:
            ingress.dropped_frames += 1
            return ForwardDecision(
                frame_number=frame_number,
                ingress_port=frame.ingress_port,
                src_mac=frame.src_mac,
                dst_mac=frame.dst_mac,
                vlan=frame.vlan,
                action="drop",
                egress_ports=[],
                reason=f"ingress port {frame.ingress_port} is not up",
                learning="source MAC was not learned",
            )

        ingress.rx_frames += 1
        vlan, ingress_reason = self._resolve_ingress_vlan(ingress, frame)
        if vlan is None:
            ingress.dropped_frames += 1
            return ForwardDecision(
                frame_number=frame_number,
                ingress_port=frame.ingress_port,
                src_mac=frame.src_mac,
                dst_mac=frame.dst_mac,
                vlan=frame.vlan,
                action="drop",
                egress_ports=[],
                reason=ingress_reason,
                learning="source MAC was not learned",
            )

        if vlan not in self.vlans:
            ingress.dropped_frames += 1
            return ForwardDecision(
                frame_number=frame_number,
                ingress_port=frame.ingress_port,
                src_mac=frame.src_mac,
                dst_mac=frame.dst_mac,
                vlan=vlan,
                action="drop",
                egress_ports=[],
                reason=f"VLAN {vlan} is not configured on the switch",
                learning="source MAC was not learned",
            )

        self.clock += 1
        learning = self._learn_source(frame.src_mac, vlan, ingress.name)

        if is_broadcast_mac(frame.dst_mac):
            egress_ports = self._flood_ports(vlan, ingress.name)
            reason = (
                f"destination is broadcast, so the frame is flooded only within "
                f"VLAN {vlan}; {ingress.name} is excluded"
            )
            action = "flood"
        elif is_multicast_mac(frame.dst_mac):
            egress_ports = self._flood_ports(vlan, ingress.name)
            reason = (
                f"destination is multicast, so the frame is flooded only within "
                f"VLAN {vlan}; {ingress.name} is excluded"
            )
            action = "flood"
        else:
            entry = self.mac_table.get((vlan, frame.dst_mac))
            if entry is None:
                egress_ports = self._flood_ports(vlan, ingress.name)
                reason = (
                    f"destination {frame.dst_mac} is unknown in VLAN {vlan}, "
                    "so this is an unknown-unicast flood within that VLAN"
                )
                action = "flood"
            elif entry.port == ingress.name:
                egress_ports = []
                reason = (
                    f"destination {frame.dst_mac} is already learned on ingress "
                    f"port {ingress.name}, so the frame is filtered"
                )
                action = "filter"
            elif not self._can_egress(entry.port, vlan):
                egress_ports = []
                reason = (
                    f"destination {frame.dst_mac} is learned on {entry.port}, "
                    f"but that port cannot currently carry VLAN {vlan}"
                )
                action = "drop"
            else:
                egress_ports = [entry.port]
                reason = (
                    f"destination {frame.dst_mac} is known in VLAN {vlan} on "
                    f"{entry.port}, so the frame is unicasted to that port"
                )
                action = "forward"

        for port_name in egress_ports:
            self.ports[port_name].tx_frames += 1

        egress_tagging = {
            port_name: self.ports[port_name].egress_description(vlan)
            for port_name in egress_ports
        }
        return ForwardDecision(
            frame_number=frame_number,
            ingress_port=frame.ingress_port,
            src_mac=frame.src_mac,
            dst_mac=frame.dst_mac,
            vlan=vlan,
            action=action,
            egress_ports=egress_ports,
            reason=f"{ingress_reason}; {reason}",
            learning=learning,
            egress_tagging=egress_tagging,
        )

    def _resolve_ingress_vlan(self, port: Port, frame: Frame) -> tuple[int | None, str]:
        if port.mode == "access":
            if frame.vlan is None:
                return port.vlan, f"{port.name} is an access port; untagged frame uses VLAN {port.vlan}"
            if frame.vlan == port.vlan:
                return frame.vlan, f"{port.name} is an access port and frame VLAN {frame.vlan} matches"
            return (
                None,
                f"{port.name} is access VLAN {port.vlan}, but received VLAN {frame.vlan}",
            )

        if frame.vlan is None:
            return None, f"{port.name} is a trunk port and requires a VLAN tag"
        if frame.vlan not in port.allowed_vlans:
            allowed = ",".join(str(vlan) for vlan in port.allowed_vlans)
            return (
                None,
                f"{port.name} is a trunk port but VLAN {frame.vlan} is not in allowed_vlans [{allowed}]",
            )
        return frame.vlan, f"{port.name} is a trunk port and allows VLAN {frame.vlan}"

    def _learn_source(self, src_mac: str, vlan: int, port_name: str) -> str:
        if is_multicast_mac(src_mac):
            return f"source {src_mac} is multicast/broadcast and was not learned"

        key = (vlan, src_mac)
        previous = self.mac_table.get(key)
        if previous is None:
            self.mac_table[key] = MacEntry(
                mac=src_mac,
                vlan=vlan,
                port=port_name,
                first_seen_tick=self.clock,
                last_seen_tick=self.clock,
            )
            return f"learned {src_mac} in VLAN {vlan} on {port_name}"

        old_port = previous.port
        previous.port = port_name
        previous.last_seen_tick = self.clock
        if old_port == port_name:
            return f"refreshed {src_mac} in VLAN {vlan} on {port_name}"
        return f"moved {src_mac} in VLAN {vlan} from {old_port} to {port_name}"

    def _can_egress(self, port_name: str, vlan: int) -> bool:
        port = self.ports.get(port_name)
        return bool(port and port.is_up and port.allows_vlan(vlan))

    def _flood_ports(self, vlan: int, ingress_port: str) -> list[str]:
        return [
            port.name
            for port in self.ports.values()
            if port.name != ingress_port and port.is_up and port.allows_vlan(vlan)
        ]

    def render_mac_table(self) -> str:
        rows = []
        for entry in sorted(self.mac_table.values(), key=lambda item: (item.vlan, item.mac)):
            rows.append(
                [
                    str(entry.vlan),
                    entry.mac,
                    entry.port,
                    str(self.clock - entry.last_seen_tick),
                    str(entry.last_seen_tick),
                ]
            )
        return render_table(
            ["VLAN", "MAC Address", "Port", "Age(frames)", "Last Seen(frame)"],
            rows,
            empty="MAC table is empty",
        )

    def render_ports(self, *, stats_only: bool = False) -> str:
        rows = []
        for port in self.ports.values():
            if stats_only:
                rows.append(
                    [
                        port.name,
                        str(port.rx_frames),
                        str(port.tx_frames),
                        str(port.dropped_frames),
                    ]
                )
            else:
                rows.append(
                    [
                        port.name,
                        port.admin_state,
                        port.oper_state,
                        port.mode,
                        port.vlan_summary(),
                        str(port.rx_frames),
                        str(port.tx_frames),
                        str(port.dropped_frames),
                    ]
                )

        if stats_only:
            return render_table(["Port", "RX", "TX", "Drops"], rows)
        return render_table(
            ["Port", "Admin", "Oper", "Mode", "VLANs", "RX", "TX", "Drops"], rows
        )

    def render_vlans(self) -> str:
        rows = [[str(vlan.vlan_id), vlan.name] for vlan in self.vlans.values()]
        return render_table(["VLAN", "Name"], rows)


def render_frames(frames: list[Frame]) -> str:
    rows = [
        [
            str(index),
            frame.ingress_port,
            frame.src_mac,
            frame.dst_mac,
            str(frame.vlan) if frame.vlan is not None else "untagged",
        ]
        for index, frame in enumerate(frames, start=1)
    ]
    return render_table(["ID", "Ingress", "Source", "Destination", "VLAN"], rows)


def render_table(headers: list[str], rows: list[list[str]], *, empty: str = "") -> str:
    if not rows:
        return empty or "(none)"
    widths = [
        max(len(str(header)), *(len(str(row[index])) for row in rows))
        for index, header in enumerate(headers)
    ]
    header_line = "  ".join(header.ljust(widths[index]) for index, header in enumerate(headers))
    rule = "  ".join("-" * width for width in widths)
    row_lines = [
        "  ".join(str(value).ljust(widths[index]) for index, value in enumerate(row))
        for row in rows
    ]
    return "\n".join([header_line, rule, *row_lines])


def format_decision(decision: ForwardDecision) -> str:
    frame_label = f"Frame {decision.frame_number}" if decision.frame_number is not None else "Frame"
    vlan = str(decision.vlan) if decision.vlan is not None else "unknown"
    egress = ", ".join(decision.egress_ports) if decision.egress_ports else "none"
    lines = [
        f"{frame_label}: {decision.src_mac} -> {decision.dst_mac}",
        f"Ingress: {decision.ingress_port}  VLAN: {vlan}",
        f"Action: {decision.action.upper()}",
        f"Egress ports: {egress}",
        f"Learning: {decision.learning}",
        f"Reason: {decision.reason}",
    ]
    if decision.egress_tagging:
        lines.append("Egress tagging:")
        for port_name in decision.egress_ports:
            lines.append(f"  {port_name}: {decision.egress_tagging[port_name]}")
    return "\n".join(lines)


def load_switch_and_frames(args: argparse.Namespace) -> tuple[VirtualSwitch, list[Frame]]:
    switch = VirtualSwitch.from_files(Path(args.ports), Path(args.vlans))
    frames = VirtualSwitch.load_frames(Path(args.frames))
    return switch, frames


def process_all_frames(switch: VirtualSwitch, frames: list[Frame], *, print_decisions: bool) -> None:
    for index, frame in enumerate(frames, start=1):
        decision = switch.process_frame(frame, frame_number=index)
        if print_decisions:
            print(format_decision(decision))
            print()


def cmd_demo(args: argparse.Namespace) -> int:
    switch, frames = load_switch_and_frames(args)
    print("Virtual L2 Switch Demo")
    print()
    print("Configured VLANs")
    print(switch.render_vlans())
    print()
    print("Configured Ports")
    print(switch.render_ports())
    print()
    print("Input Frames")
    print(render_frames(frames))
    print()
    print("Forwarding Decisions")
    process_all_frames(switch, frames, print_decisions=True)
    print("MAC Address Table")
    print(switch.render_mac_table())
    print()
    print("Port Statistics")
    print(switch.render_ports(stats_only=True))
    return 0


def cmd_process_frames(args: argparse.Namespace) -> int:
    switch, frames = load_switch_and_frames(args)
    process_all_frames(switch, frames, print_decisions=not args.brief)
    if args.brief:
        print(f"processed {len(frames)} frame(s)")
    if args.summary:
        print()
        print("MAC Address Table")
        print(switch.render_mac_table())
        print()
        print("Port Statistics")
        print(switch.render_ports(stats_only=True))
    return 0


def cmd_explain_forward(args: argparse.Namespace) -> int:
    switch, frames = load_switch_and_frames(args)
    frame_id = args.frame_id
    if frame_id < 1 or frame_id > len(frames):
        raise ConfigError(f"frame id must be between 1 and {len(frames)}")

    if args.learn_prior:
        for index in range(1, frame_id):
            switch.process_frame(frames[index - 1], frame_number=index)
        if frame_id > 1:
            print(f"Primed MAC table with frame(s) 1-{frame_id - 1}.")
            print()

    decision = switch.process_frame(frames[frame_id - 1], frame_number=frame_id)
    print(format_decision(decision))
    if args.show_mac_table:
        print()
        print("MAC Address Table")
        print(switch.render_mac_table())
    return 0


def cmd_show_mac_table(args: argparse.Namespace) -> int:
    switch, frames = load_switch_and_frames(args)
    if args.learn_from_frames:
        process_all_frames(switch, frames, print_decisions=False)
    print(switch.render_mac_table())
    return 0


def cmd_show_ports(args: argparse.Namespace) -> int:
    switch, _frames = load_switch_and_frames(args)
    print(switch.render_ports())
    return 0


def cmd_show_vlans(args: argparse.Namespace) -> int:
    switch, _frames = load_switch_and_frames(args)
    print(switch.render_vlans())
    return 0


def cmd_show_frames(args: argparse.Namespace) -> int:
    _switch, frames = load_switch_and_frames(args)
    print(render_frames(frames))
    return 0


def cmd_shell(args: argparse.Namespace) -> int:
    switch, frames = load_switch_and_frames(args)
    print("Virtual L2 Switch CLI. Type 'help' for commands, 'exit' to quit.")
    while True:
        try:
            line = input("switch# ").strip()
        except EOFError:
            print()
            return 0

        if not line:
            continue
        try:
            tokens = shlex.split(line)
        except ValueError as exc:
            print(f"parse error: {exc}")
            continue

        command = " ".join(token.lower() for token in tokens)
        verb = tokens[0].lower()

        try:
            if command in {"exit", "quit"}:
                return 0
            if command == "help":
                print(shell_help())
            elif command in {"show ports", "show-ports"}:
                print(switch.render_ports())
            elif command in {"show vlans", "show-vlans"}:
                print(switch.render_vlans())
            elif command in {"show frames", "show-frames"}:
                print(render_frames(frames))
            elif command in {"show stats", "show-stats"}:
                print(switch.render_ports(stats_only=True))
            elif command in {"show mac-table", "show-mac-table", "show mac table"}:
                print(switch.render_mac_table())
            elif command in {"process frames", "process-frames"}:
                process_all_frames(switch, frames, print_decisions=True)
            elif verb in {"send-frame", "process-frame", "explain-forward"}:
                if len(tokens) != 2 or not tokens[1].isdigit():
                    print(f"usage: {verb} <frame-id>")
                    continue
                frame_id = int(tokens[1])
                if frame_id < 1 or frame_id > len(frames):
                    print(f"frame id must be between 1 and {len(frames)}")
                    continue
                decision = switch.process_frame(frames[frame_id - 1], frame_number=frame_id)
                print(format_decision(decision))
            elif command == "reset":
                switch, frames = load_switch_and_frames(args)
                print("switch state reloaded from JSON files")
            else:
                print(f"unknown command: {line}")
        except ConfigError as exc:
            print(f"error: {exc}")


def shell_help() -> str:
    return "\n".join(
        [
            "Commands:",
            "  show ports",
            "  show vlans",
            "  show frames",
            "  show mac-table",
            "  show stats",
            "  explain-forward <frame-id>",
            "  send-frame <frame-id>",
            "  process-frames",
            "  reset",
            "  exit",
        ]
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Virtual L2 switch with MAC learning and VLANs")
    parser.add_argument("--ports", default=str(DEFAULT_DIR / "ports.json"), help="path to ports.json")
    parser.add_argument("--vlans", default=str(DEFAULT_DIR / "vlans.json"), help="path to vlans.json")
    parser.add_argument("--frames", default=str(DEFAULT_DIR / "frames.json"), help="path to frames.json")

    subparsers = parser.add_subparsers(dest="command")

    demo = subparsers.add_parser("demo", help="run a complete demonstration")
    demo.set_defaults(func=cmd_demo)

    process_frames = subparsers.add_parser("process-frames", help="process all frames from frames.json")
    process_frames.add_argument("--brief", action="store_true", help="suppress per-frame explanations")
    process_frames.add_argument("--summary", action="store_true", help="print MAC table and stats after processing")
    process_frames.set_defaults(func=cmd_process_frames)

    explain = subparsers.add_parser("explain-forward", help="explain forwarding for one frame id")
    explain.add_argument("frame_id", type=int, help="1-based frame id from frames.json")
    explain.add_argument(
        "--no-learn-prior",
        action="store_false",
        dest="learn_prior",
        help="do not pre-process earlier frames before explaining this frame",
    )
    explain.add_argument(
        "--show-mac-table",
        action="store_true",
        help="print MAC table after the explained frame",
    )
    explain.set_defaults(func=cmd_explain_forward, learn_prior=True)

    show_mac = subparsers.add_parser("show-mac-table", help="print the MAC address table")
    show_mac.add_argument(
        "--learn-from-frames",
        action="store_true",
        help="process frames.json before printing the table",
    )
    show_mac.set_defaults(func=cmd_show_mac_table)

    show_ports = subparsers.add_parser("show-ports", help="print port configuration and counters")
    show_ports.set_defaults(func=cmd_show_ports)

    show_vlans = subparsers.add_parser("show-vlans", help="print VLAN configuration")
    show_vlans.set_defaults(func=cmd_show_vlans)

    show_frames = subparsers.add_parser("show-frames", help="print simulated input frames")
    show_frames.set_defaults(func=cmd_show_frames)

    shell = subparsers.add_parser("shell", help="start an interactive switch-style CLI")
    shell.set_defaults(func=cmd_shell)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not hasattr(args, "func"):
        if sys.stdin.isatty():
            args.func = cmd_shell
        else:
            args.func = cmd_demo

    try:
        return args.func(args)
    except ConfigError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
