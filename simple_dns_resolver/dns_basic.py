#!/usr/bin/env python3
"""Small virtual DNS resolver with TTL cache and DNS-style CLI."""

from __future__ import annotations

import argparse
import json
import shlex
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


DEFAULT_INPUT_DIR = Path(__file__).resolve().parent / "sample"
ZONE_FILE = "zone_records.json"
QUERIES_FILE = "queries.json"
STATE_FILE = ".dns_basic_state.json"
SUPPORTED_TYPES = {"A", "AAAA", "CNAME", "MX", "NS"}


class ConfigError(ValueError):
    """Raised when local input files or CLI arguments are invalid."""


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


def normalize_name(value: Any, *, allow_wildcard: bool = False) -> str:
    name = str(value or "").strip().lower().rstrip(".")
    if not name:
        raise ConfigError("DNS name cannot be empty")
    labels = name.split(".")
    if any(label == "" for label in labels):
        raise ConfigError(f"invalid DNS name: {value!r}")
    if "*" in labels:
        if not allow_wildcard or labels[0] != "*" or labels.count("*") != 1:
            raise ConfigError(f"wildcard must be the left-most label: {value!r}")
    return name


def normalize_type(value: Any) -> str:
    qtype = str(value or "").strip().upper()
    if qtype not in SUPPORTED_TYPES:
        supported = ", ".join(sorted(SUPPORTED_TYPES))
        raise ConfigError(f"record type must be one of {supported}: {value!r}")
    return qtype


def positive_int(value: Any, label: str, *, allow_zero: bool = True) -> int:
    try:
        number = int(value)
    except (TypeError, ValueError) as exc:
        raise ConfigError(f"{label} must be an integer: {value!r}") from exc
    minimum = 0 if allow_zero else 1
    if number < minimum:
        raise ConfigError(f"{label} must be >= {minimum}: {value!r}")
    return number


@dataclass(frozen=True)
class Record:
    name: str
    type: str
    value: str
    ttl: int
    priority: int | None = None
    wildcard: bool = False

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Record":
        name = normalize_name(data.get("name"), allow_wildcard=True)
        rtype = normalize_type(data.get("type"))
        if "value" not in data:
            raise ConfigError(f"{name} {rtype}: value is required")

        raw_value = str(data.get("value", "")).strip()
        if not raw_value:
            raise ConfigError(f"{name} {rtype}: value cannot be empty")
        value = (
            normalize_name(raw_value)
            if rtype in {"CNAME", "MX", "NS"}
            else raw_value
        )

        ttl = positive_int(data.get("ttl"), f"{name} {rtype} ttl")
        priority = None
        if rtype == "MX":
            if "priority" not in data:
                raise ConfigError(f"{name} MX: priority is required")
            priority = positive_int(data.get("priority"), f"{name} MX priority")

        return cls(
            name=name,
            type=rtype,
            value=value,
            ttl=ttl,
            priority=priority,
            wildcard=name.startswith("*."),
        )

    def answer(self, owner_name: str | None = None) -> "Answer":
        return Answer(
            name=owner_name or self.name,
            type=self.type,
            value=self.value,
            ttl=self.ttl,
            priority=self.priority,
        )

    def sort_key(self) -> tuple[int, str, str]:
        return (self.priority if self.priority is not None else 0, self.value, self.name)


@dataclass(frozen=True)
class Query:
    id: int
    qname: str
    qtype: str

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Query":
        try:
            query_id = int(data["id"])
        except KeyError as exc:
            raise ConfigError("query is missing id") from exc
        except (TypeError, ValueError) as exc:
            raise ConfigError(f"query id must be an integer: {data.get('id')!r}") from exc
        return cls(
            id=query_id,
            qname=normalize_name(data.get("qname")),
            qtype=normalize_type(data.get("qtype")),
        )


@dataclass(frozen=True)
class Answer:
    name: str
    type: str
    value: str
    ttl: int
    priority: int | None = None

    def with_ttl(self, ttl: int) -> "Answer":
        return Answer(
            name=self.name,
            type=self.type,
            value=self.value,
            ttl=max(0, int(ttl)),
            priority=self.priority,
        )

    def to_dict(self) -> dict[str, Any]:
        row: dict[str, Any] = {
            "name": self.name,
            "type": self.type,
            "value": self.value,
            "ttl": self.ttl,
        }
        if self.priority is not None:
            row["priority"] = self.priority
        return row

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Answer":
        return cls(
            name=normalize_name(data.get("name"), allow_wildcard=True),
            type=normalize_type(data.get("type")),
            value=str(data.get("value", "")).strip(),
            ttl=positive_int(data.get("ttl", 0), "cached answer ttl"),
            priority=(
                positive_int(data.get("priority"), "cached MX priority")
                if data.get("priority") is not None
                else None
            ),
        )

    def short(self) -> str:
        if self.priority is None:
            return f"{self.name} {self.type} {self.value}"
        return f"{self.name} {self.type} {self.priority} {self.value}"


@dataclass
class CacheEntry:
    qname: str
    qtype: str
    status: str
    answers: list[Answer]
    reason: str
    cached_at: float
    expires_at: float
    negative: bool = False

    def is_valid(self, now: float) -> bool:
        return self.expires_at > now

    def remaining_ttl(self, now: float) -> int:
        return max(0, int(self.expires_at - now))

    def to_dict(self) -> dict[str, Any]:
        return {
            "qname": self.qname,
            "qtype": self.qtype,
            "status": self.status,
            "answers": [answer.to_dict() for answer in self.answers],
            "reason": self.reason,
            "cached_at": self.cached_at,
            "expires_at": self.expires_at,
            "negative": self.negative,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "CacheEntry":
        return cls(
            qname=normalize_name(data.get("qname")),
            qtype=normalize_type(data.get("qtype")),
            status=str(data.get("status", "")).strip().upper() or "NXDOMAIN",
            answers=[Answer.from_dict(item) for item in data.get("answers", [])],
            reason=str(data.get("reason", "")).strip(),
            cached_at=float(data.get("cached_at", 0)),
            expires_at=float(data.get("expires_at", 0)),
            negative=bool(data.get("negative", False)),
        )


@dataclass
class CacheStats:
    resolutions: int = 0
    cache_hits: int = 0
    cache_misses: int = 0
    expired_entries: int = 0
    zone_lookups: int = 0
    nxdomain: int = 0
    cname_loops: int = 0

    def to_dict(self) -> dict[str, int]:
        return {
            "resolutions": self.resolutions,
            "cache_hits": self.cache_hits,
            "cache_misses": self.cache_misses,
            "expired_entries": self.expired_entries,
            "zone_lookups": self.zone_lookups,
            "nxdomain": self.nxdomain,
            "cname_loops": self.cname_loops,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "CacheStats":
        return cls(
            resolutions=int(data.get("resolutions", 0)),
            cache_hits=int(data.get("cache_hits", 0)),
            cache_misses=int(data.get("cache_misses", 0)),
            expired_entries=int(data.get("expired_entries", 0)),
            zone_lookups=int(data.get("zone_lookups", 0)),
            nxdomain=int(data.get("nxdomain", 0)),
            cname_loops=int(data.get("cname_loops", 0)),
        )


@dataclass
class ResolutionResult:
    qname: str
    qtype: str
    status: str
    answers: list[Answer]
    source: str
    reason: str
    ttl: int
    steps: list[str] = field(default_factory=list)

    @property
    def is_negative(self) -> bool:
        return self.status != "NOERROR"

    def with_cache_ttl(self, remaining_ttl: int, steps: list[str]) -> "ResolutionResult":
        return ResolutionResult(
            qname=self.qname,
            qtype=self.qtype,
            status=self.status,
            answers=[answer.with_ttl(remaining_ttl) for answer in self.answers],
            source="cache",
            reason=self.reason,
            ttl=remaining_ttl,
            steps=steps,
        )


class Zone:
    def __init__(self, records: list[Record]) -> None:
        self.records = list(records)
        self.index: dict[tuple[str, str], list[Record]] = {}
        self.exact_names: set[str] = set()
        for record in self.records:
            self.index.setdefault((record.name, record.type), []).append(record)
            if not record.wildcard:
                self.exact_names.add(record.name)
        for records_for_key in self.index.values():
            records_for_key.sort(key=lambda item: item.sort_key())

    @classmethod
    def from_file(cls, path: Path) -> "Zone":
        return cls([Record.from_dict(item) for item in load_json_list(path, "zone_records")])

    def lookup(self, qname: str, qtype: str) -> tuple[list[tuple[Record, str]], str]:
        exact = self.index.get((qname, qtype), [])
        if exact:
            return [(record, qname) for record in exact], "exact"

        if qname in self.exact_names:
            return [], "none"

        for wildcard_name in wildcard_candidates(qname):
            wildcard = self.index.get((wildcard_name, qtype), [])
            if wildcard:
                return [(record, qname) for record in wildcard], f"wildcard {wildcard_name}"
        return [], "none"


class DnsCache:
    def __init__(self, entries: list[CacheEntry] | None = None) -> None:
        self.entries: dict[tuple[str, str], CacheEntry] = {}
        for entry in entries or []:
            self.entries[(entry.qname, entry.qtype)] = entry

    def get(self, qname: str, qtype: str) -> CacheEntry | None:
        return self.entries.get((qname, qtype))

    def set(self, entry: CacheEntry) -> None:
        self.entries[(entry.qname, entry.qtype)] = entry

    def delete(self, qname: str, qtype: str) -> None:
        self.entries.pop((qname, qtype), None)

    def clear(self) -> None:
        self.entries.clear()

    def prune_expired(self, now: float) -> int:
        expired_keys = [
            key for key, entry in self.entries.items() if not entry.is_valid(now)
        ]
        for key in expired_keys:
            del self.entries[key]
        return len(expired_keys)

    def valid_entries(self, now: float) -> list[CacheEntry]:
        self.prune_expired(now)
        return sorted(self.entries.values(), key=lambda item: (item.qname, item.qtype))

    def to_list(self) -> list[dict[str, Any]]:
        return [entry.to_dict() for entry in self.entries.values()]


class Resolver:
    def __init__(
        self,
        zone: Zone,
        *,
        cache: DnsCache | None = None,
        stats: CacheStats | None = None,
        negative_ttl: int = 60,
        max_cname_depth: int = 16,
    ) -> None:
        self.zone = zone
        self.cache = cache or DnsCache()
        self.stats = stats or CacheStats()
        self.negative_ttl = max(0, int(negative_ttl))
        self.max_cname_depth = max(1, int(max_cname_depth))

    def resolve(self, qname: str, qtype: str, *, now: float | None = None) -> ResolutionResult:
        resolved_now = current_time(now)
        normalized_name = normalize_name(qname)
        normalized_type = normalize_type(qtype)
        self.stats.resolutions += 1
        steps: list[str] = []
        result = self._resolve(
            normalized_name,
            normalized_type,
            now=resolved_now,
            steps=steps,
            seen=[],
        )
        result.steps[:] = steps
        if result.status == "NXDOMAIN":
            self.stats.nxdomain += 1
        elif result.status == "CNAME_LOOP":
            self.stats.cname_loops += 1
        return result

    def _resolve(
        self,
        qname: str,
        qtype: str,
        *,
        now: float,
        steps: list[str],
        seen: list[str],
    ) -> ResolutionResult:
        if qname in seen:
            chain = " -> ".join([*seen, qname])
            steps.append(f"CNAME loop detected before cache lookup: {chain}")
            return ResolutionResult(
                qname=qname,
                qtype=qtype,
                status="CNAME_LOOP",
                answers=[],
                source="resolver",
                reason=f"CNAME loop detected: {chain}",
                ttl=self.negative_ttl,
            )

        entry = self.cache.get(qname, qtype)
        if entry is not None and entry.is_valid(now):
            remaining = entry.remaining_ttl(now)
            self.stats.cache_hits += 1
            steps.append(f"Cache check for {qname} {qtype}: HIT ({remaining}s remaining)")
            return ResolutionResult(
                qname=qname,
                qtype=qtype,
                status=entry.status,
                answers=entry.answers,
                source="cache",
                reason=entry.reason,
                ttl=remaining,
            ).with_cache_ttl(remaining, steps)

        if entry is not None:
            self.cache.delete(qname, qtype)
            self.stats.expired_entries += 1
            steps.append(f"Cache check for {qname} {qtype}: EXPIRED")
        else:
            steps.append(f"Cache check for {qname} {qtype}: MISS")
        self.stats.cache_misses += 1

        self.stats.zone_lookups += 1
        result = self._resolve_from_zone(qname, qtype, now=now, steps=steps, seen=seen)
        ttl = result.ttl if result.status == "NOERROR" else self.negative_ttl
        if ttl > 0:
            self.cache.set(
                CacheEntry(
                    qname=qname,
                    qtype=qtype,
                    status=result.status,
                    answers=result.answers,
                    reason=result.reason,
                    cached_at=now,
                    expires_at=now + ttl,
                    negative=result.status != "NOERROR",
                )
            )
            steps.append(f"Cache store for {qname} {qtype}: {ttl}s TTL")
        else:
            steps.append(f"Cache store for {qname} {qtype}: skipped because TTL is 0")

        result.source = "zone"
        result.ttl = ttl
        return result

    def _resolve_from_zone(
        self,
        qname: str,
        qtype: str,
        *,
        now: float,
        steps: list[str],
        seen: list[str],
    ) -> ResolutionResult:
        if len(seen) >= self.max_cname_depth:
            chain = " -> ".join([*seen, qname])
            steps.append(f"CNAME chain exceeded {self.max_cname_depth} hops: {chain}")
            return ResolutionResult(
                qname=qname,
                qtype=qtype,
                status="CNAME_LOOP",
                answers=[],
                source="zone",
                reason=f"CNAME chain exceeded {self.max_cname_depth} hops",
                ttl=self.negative_ttl,
            )

        direct_records, direct_source = self.zone.lookup(qname, qtype)
        if direct_records:
            answers = [record.answer(owner_name) for record, owner_name in direct_records]
            ttl = min(answer.ttl for answer in answers)
            source_text = "zone lookup" if direct_source == "exact" else f"zone lookup via {direct_source}"
            steps.append(f"{source_text} for {qname} {qtype}: found {len(answers)} answer(s)")
            return ResolutionResult(
                qname=qname,
                qtype=qtype,
                status="NOERROR",
                answers=answers,
                source="zone",
                reason=f"found {len(answers)} {qtype} record(s)",
                ttl=ttl,
            )

        steps.append(f"Zone lookup for {qname} {qtype}: no direct answer")
        if qtype == "CNAME":
            return ResolutionResult(
                qname=qname,
                qtype=qtype,
                status="NXDOMAIN",
                answers=[],
                source="zone",
                reason=f"no CNAME record found for {qname}",
                ttl=self.negative_ttl,
            )

        cname_records, cname_source = self.zone.lookup(qname, "CNAME")
        if not cname_records:
            steps.append(f"CNAME lookup for {qname}: no CNAME answer")
            return ResolutionResult(
                qname=qname,
                qtype=qtype,
                status="NXDOMAIN",
                answers=[],
                source="zone",
                reason=f"no {qtype} record or CNAME found for {qname}",
                ttl=self.negative_ttl,
            )

        cname_record, owner_name = cname_records[0]
        cname_answer = cname_record.answer(owner_name)
        target = normalize_name(cname_record.value)
        source_text = "zone lookup" if cname_source == "exact" else f"zone lookup via {cname_source}"
        steps.append(f"{source_text} for {qname} CNAME: {owner_name} -> {target}")
        if target in seen or target == qname:
            chain = " -> ".join([*seen, qname, target])
            steps.append(f"CNAME loop detected: {chain}")
            return ResolutionResult(
                qname=qname,
                qtype=qtype,
                status="CNAME_LOOP",
                answers=[cname_answer],
                source="zone",
                reason=f"CNAME loop detected: {chain}",
                ttl=min(cname_answer.ttl, self.negative_ttl) if self.negative_ttl else cname_answer.ttl,
            )

        child = self._resolve(
            target,
            qtype,
            now=now,
            steps=steps,
            seen=[*seen, qname],
        )
        answers = [cname_answer, *child.answers]
        if child.status == "NOERROR":
            ttl = min(answer.ttl for answer in answers)
            return ResolutionResult(
                qname=qname,
                qtype=qtype,
                status="NOERROR",
                answers=answers,
                source="zone",
                reason=f"resolved through CNAME {qname} -> {target}",
                ttl=ttl,
            )

        return ResolutionResult(
            qname=qname,
            qtype=qtype,
            status=child.status,
            answers=answers,
            source="zone",
            reason=f"CNAME target {target} returned {child.status}: {child.reason}",
            ttl=self.negative_ttl,
        )


def wildcard_candidates(qname: str) -> list[str]:
    labels = qname.split(".")
    return ["*." + ".".join(labels[index:]) for index in range(1, len(labels))]


def current_time(now: float | None = None) -> float:
    return time.time() if now is None else float(now)


def load_queries(path: Path) -> list[Query]:
    return [Query.from_dict(item) for item in load_json_list(path, "queries")]


def state_path_for(args: argparse.Namespace) -> Path:
    if getattr(args, "state_file", None):
        return Path(args.state_file)
    return Path(args.input_dir) / STATE_FILE


def load_state(path: Path, now: float) -> tuple[DnsCache, CacheStats]:
    if not path.exists():
        return DnsCache(), CacheStats()
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ConfigError(f"cache state is not valid JSON: {path}: {exc}") from exc

    entries = [CacheEntry.from_dict(item) for item in raw.get("cache", [])]
    cache = DnsCache(entries)
    cache.prune_expired(now)
    stats = CacheStats.from_dict(raw.get("stats", {}))
    return cache, stats


def save_state(path: Path, cache: DnsCache, stats: CacheStats, now: float) -> None:
    cache.prune_expired(now)
    path.parent.mkdir(parents=True, exist_ok=True)
    state = {
        "cache": cache.to_list(),
        "stats": stats.to_dict(),
        "saved_at": now,
    }
    path.write_text(json.dumps(state, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def load_resolver(args: argparse.Namespace, now: float) -> tuple[Resolver, Path | None]:
    input_dir = Path(args.input_dir)
    zone = Zone.from_file(input_dir / ZONE_FILE)
    state_path = None if args.no_persist_cache else state_path_for(args)
    if state_path is None:
        cache, stats = DnsCache(), CacheStats()
    else:
        cache, stats = load_state(state_path, now)
    resolver = Resolver(
        zone,
        cache=cache,
        stats=stats,
        negative_ttl=args.negative_ttl,
        max_cname_depth=args.max_cname_depth,
    )
    return resolver, state_path


def maybe_save(args: argparse.Namespace, resolver: Resolver, state_path: Path | None, now: float) -> None:
    if state_path is not None:
        save_state(state_path, resolver.cache, resolver.stats, now)


def render_table(headers: list[str], rows: list[list[str]], *, empty: str = "(none)") -> str:
    if not rows:
        return empty
    widths = [
        max(len(str(header)), *(len(str(row[index])) for row in rows))
        for index, header in enumerate(headers)
    ]
    header_line = "  ".join(str(header).ljust(widths[index]) for index, header in enumerate(headers))
    rule = "  ".join("-" * width for width in widths)
    row_lines = [
        "  ".join(str(value).ljust(widths[index]) for index, value in enumerate(row))
        for row in rows
    ]
    return "\n".join([header_line, rule, *row_lines])


def format_answers(answers: list[Answer]) -> str:
    rows = []
    for answer in answers:
        rows.append(
            [
                answer.name,
                answer.type,
                str(answer.priority) if answer.priority is not None else "-",
                answer.value,
                str(answer.ttl),
            ]
        )
    return render_table(["Name", "Type", "Priority", "Value", "TTL"], rows, empty="(no answers)")


def format_result(result: ResolutionResult) -> str:
    lines = [
        f"Query: {result.qname} {result.qtype}",
        f"Status: {result.status}",
        f"Source: {result.source}",
    ]
    if result.reason:
        lines.append(f"Reason: {result.reason}")
    if result.answers:
        lines.append("Answers:")
        lines.append(format_answers(result.answers))
    return "\n".join(lines)


def format_cache(cache: DnsCache, now: float) -> str:
    rows = []
    for entry in cache.valid_entries(now):
        if entry.answers:
            detail = "; ".join(answer.short() for answer in entry.answers)
        else:
            detail = entry.reason
        rows.append(
            [
                entry.qname,
                entry.qtype,
                entry.status,
                "yes" if entry.negative else "no",
                str(entry.remaining_ttl(now)),
                detail,
            ]
        )
    return render_table(["Name", "Type", "Status", "Negative", "TTL", "Detail"], rows, empty="Cache is empty")


def format_stats(stats: CacheStats) -> str:
    rows = [
        ["resolutions", str(stats.resolutions)],
        ["cache_hits", str(stats.cache_hits)],
        ["cache_misses", str(stats.cache_misses)],
        ["expired_entries", str(stats.expired_entries)],
        ["zone_lookups", str(stats.zone_lookups)],
        ["nxdomain", str(stats.nxdomain)],
        ["cname_loops", str(stats.cname_loops)],
    ]
    return render_table(["Metric", "Value"], rows)


def cmd_resolve(args: argparse.Namespace) -> int:
    now = current_time(args.now)
    resolver, state_path = load_resolver(args, now)
    result = resolver.resolve(args.name, args.type, now=now)
    print(format_result(result))
    maybe_save(args, resolver, state_path, now)
    return 0


def cmd_explain_resolution(args: argparse.Namespace) -> int:
    now = current_time(args.now)
    resolver, state_path = load_resolver(args, now)
    result = resolver.resolve(args.name, args.type, now=now)
    print(format_result(result))
    print()
    print("Resolution Steps")
    for index, step in enumerate(result.steps, start=1):
        print(f"{index}. {step}")
    maybe_save(args, resolver, state_path, now)
    return 0


def cmd_show_cache(args: argparse.Namespace) -> int:
    now = current_time(args.now)
    resolver, state_path = load_resolver(args, now)
    print(format_cache(resolver.cache, now))
    maybe_save(args, resolver, state_path, now)
    return 0


def cmd_flush_cache(args: argparse.Namespace) -> int:
    now = current_time(args.now)
    resolver, state_path = load_resolver(args, now)
    resolver.cache.clear()
    maybe_save(args, resolver, state_path, now)
    print("Cache flushed")
    return 0


def cmd_show_stats(args: argparse.Namespace) -> int:
    now = current_time(args.now)
    resolver, state_path = load_resolver(args, now)
    print(format_stats(resolver.stats))
    maybe_save(args, resolver, state_path, now)
    return 0


def cmd_replay_queries(args: argparse.Namespace) -> int:
    base_now = current_time(args.now)
    resolver, state_path = load_resolver(args, base_now)
    queries = load_queries(Path(args.input_dir) / QUERIES_FILE)
    for index, query in enumerate(queries):
        query_now = base_now + (index * args.step_seconds)
        result = resolver.resolve(query.qname, query.qtype, now=query_now)
        print(f"[{query.id}] {query.qname} {query.qtype}")
        print(format_result(result))
        if args.explain:
            print("Resolution Steps")
            for step_index, step in enumerate(result.steps, start=1):
                print(f"{step_index}. {step}")
        if index != len(queries) - 1:
            print()

    final_now = base_now + (max(0, len(queries) - 1) * args.step_seconds)
    if args.show_cache:
        print()
        print("Cache")
        print(format_cache(resolver.cache, final_now))
    if args.show_stats:
        print()
        print("Stats")
        print(format_stats(resolver.stats))
    maybe_save(args, resolver, state_path, final_now)
    return 0


def cmd_shell(args: argparse.Namespace) -> int:
    now = current_time(args.now)
    resolver, state_path = load_resolver(args, now)
    shell = DnsShell(args, resolver, state_path, now)
    shell.cmdloop()
    maybe_save(args, resolver, state_path, shell.now)
    return 0


class DnsShell:
    prompt = "dns-basic# "

    def __init__(
        self,
        args: argparse.Namespace,
        resolver: Resolver,
        state_path: Path | None,
        now: float,
    ) -> None:
        import cmd

        class _Shell(cmd.Cmd):
            intro = "DNS resolver shell. Type help or ? to list commands."
            prompt = DnsShell.prompt

        self._cmd = _Shell()
        self.args = args
        self.resolver = resolver
        self.state_path = state_path
        self.now = now
        self._install_commands()

    def cmdloop(self) -> None:
        self._cmd.cmdloop()

    def _install_commands(self) -> None:
        self._cmd.do_resolve = self._wrap_resolve  # type: ignore[attr-defined]
        self._cmd.do_explain_resolution = self._wrap_explain  # type: ignore[attr-defined]
        self._cmd.do_show_cache = self._wrap_show_cache  # type: ignore[attr-defined]
        self._cmd.do_flush_cache = self._wrap_flush_cache  # type: ignore[attr-defined]
        self._cmd.do_show_stats = self._wrap_show_stats  # type: ignore[attr-defined]
        self._cmd.do_advance_time = self._wrap_advance_time  # type: ignore[attr-defined]
        self._cmd.do_exit = self._wrap_exit  # type: ignore[attr-defined]
        self._cmd.do_quit = self._wrap_exit  # type: ignore[attr-defined]
        self._cmd.do_EOF = self._wrap_exit  # type: ignore[attr-defined]
        self._cmd.default = self._wrap_default  # type: ignore[method-assign]

    def _wrap_resolve(self, line: str) -> None:
        parts = shlex.split(line)
        if len(parts) != 2:
            print("usage: resolve <name> <type>")
            return
        try:
            result = self.resolver.resolve(parts[0], parts[1], now=self.now)
            print(format_result(result))
        except ConfigError as exc:
            print(f"error: {exc}")

    def _wrap_explain(self, line: str) -> None:
        parts = shlex.split(line)
        if len(parts) != 2:
            print("usage: explain_resolution <name> <type>")
            return
        try:
            result = self.resolver.resolve(parts[0], parts[1], now=self.now)
            print(format_result(result))
            print()
            for index, step in enumerate(result.steps, start=1):
                print(f"{index}. {step}")
        except ConfigError as exc:
            print(f"error: {exc}")

    def _wrap_show_cache(self, _line: str) -> None:
        print(format_cache(self.resolver.cache, self.now))

    def _wrap_flush_cache(self, _line: str) -> None:
        self.resolver.cache.clear()
        print("Cache flushed")

    def _wrap_show_stats(self, _line: str) -> None:
        print(format_stats(self.resolver.stats))

    def _wrap_advance_time(self, line: str) -> None:
        parts = shlex.split(line)
        if len(parts) != 1:
            print("usage: advance_time <seconds>")
            return
        try:
            seconds = float(parts[0])
        except ValueError:
            print("error: seconds must be numeric")
            return
        self.now += seconds
        expired = self.resolver.cache.prune_expired(self.now)
        print(f"advanced time by {seconds:g}s; expired {expired} cache entrie(s)")

    def _wrap_default(self, line: str) -> None:
        parts = shlex.split(line)
        if not parts:
            return
        aliases = {
            "explain-resolution": self._wrap_explain,
            "show-cache": self._wrap_show_cache,
            "flush-cache": self._wrap_flush_cache,
            "show-stats": self._wrap_show_stats,
            "advance-time": self._wrap_advance_time,
        }
        handler = aliases.get(parts[0])
        if handler is None:
            print(f"unknown command: {parts[0]}")
            return
        handler(" ".join(shlex.quote(part) for part in parts[1:]))

    def _wrap_exit(self, _line: str) -> bool:
        maybe_save(self.args, self.resolver, self.state_path, self.now)
        return True


def add_common_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--input-dir", default=str(DEFAULT_INPUT_DIR), help="directory containing zone_records.json and queries.json")
    parser.add_argument("--now", type=float, default=None, help="override current time as a numeric timestamp")
    parser.add_argument("--negative-ttl", type=int, default=60, help="TTL for cached NXDOMAIN/CNAME_LOOP responses")
    parser.add_argument("--max-cname-depth", type=int, default=16, help="maximum CNAME hops before loop/depth failure")
    parser.add_argument("--state-file", default=None, help="cache/stat state file for repeated CLI commands")
    parser.add_argument("--no-persist-cache", action="store_true", help="disable CLI state persistence")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Simple DNS resolver with TTL cache")
    subparsers = parser.add_subparsers(dest="command", required=True)

    resolve = subparsers.add_parser("resolve", help="resolve one DNS-style query")
    resolve.add_argument("name")
    resolve.add_argument("type")
    add_common_options(resolve)
    resolve.set_defaults(func=cmd_resolve)

    explain = subparsers.add_parser("explain-resolution", help="show each lookup step")
    explain.add_argument("name")
    explain.add_argument("type")
    add_common_options(explain)
    explain.set_defaults(func=cmd_explain_resolution)

    show_cache = subparsers.add_parser("show-cache", help="dump valid cache entries")
    add_common_options(show_cache)
    show_cache.set_defaults(func=cmd_show_cache)

    flush_cache = subparsers.add_parser("flush-cache", help="clear cache entries")
    add_common_options(flush_cache)
    flush_cache.set_defaults(func=cmd_flush_cache)

    show_stats = subparsers.add_parser("show-stats", help="show resolver counters")
    add_common_options(show_stats)
    show_stats.set_defaults(func=cmd_show_stats)

    replay = subparsers.add_parser("replay-queries", help="resolve every query in queries.json")
    replay.add_argument("--step-seconds", type=float, default=0, help="advance simulated time between queries")
    replay.add_argument("--explain", action="store_true", help="print lookup steps for each query")
    replay.add_argument("--show-cache", action="store_true", help="print cache after replay")
    replay.add_argument("--show-stats", action="store_true", help="print stats after replay")
    add_common_options(replay)
    replay.set_defaults(func=cmd_replay_queries)

    shell = subparsers.add_parser("shell", help="run an interactive in-memory resolver shell")
    add_common_options(shell)
    shell.set_defaults(func=cmd_shell)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except BrokenPipeError:
        return 1
    except ConfigError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
