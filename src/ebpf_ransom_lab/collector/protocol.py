"""Versioned, JSON-safe records emitted by the live collector."""

from __future__ import annotations

import base64
import json
import unicodedata
from dataclasses import asdict, dataclass
from typing import Any


PROTOCOL_VERSION = 1
LINUX_O_CREAT = 0x40
SYSCALL_OPERATIONS = frozenset({"open", "openat", "unlink", "unlinkat"})


def _unsigned(name: str, value: int, bits: int, *, positive: bool = False) -> None:
    lower = 1 if positive else 0
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"{name} must be an integer")
    if not lower <= value < 2**bits:
        qualifier = "positive " if positive else "unsigned "
        raise ValueError(f"{name} must be a {qualifier}{bits}-bit integer")


def safe_filename_display(raw: bytes) -> str:
    """Return readable text with undecodable or unsafe characters escaped.

    The original bytes remain available separately.  HTML metacharacters are
    escaped even though consumers should still render this value as text.
    """

    decoded = raw.decode("utf-8", errors="surrogateescape")
    displayed: list[str] = []
    for character in decoded:
        codepoint = ord(character)
        category = unicodedata.category(character)
        if 0xDC80 <= codepoint <= 0xDCFF:
            displayed.append(f"\\x{codepoint - 0xDC00:02x}")
        elif character == "\\":
            displayed.append("\\\\")
        elif character in "<>&":
            displayed.append(f"\\x{codepoint:02x}")
        elif category in {"Cc", "Cf", "Cs", "Zl", "Zp"}:
            if codepoint <= 0xFF:
                displayed.append(f"\\x{codepoint:02x}")
            elif codepoint <= 0xFFFF:
                displayed.append(f"\\u{codepoint:04x}")
            else:
                displayed.append(f"\\U{codepoint:08x}")
        else:
            displayed.append(character)
    return "".join(displayed)


@dataclass(frozen=True)
class FilenameBytes:
    raw: bytes
    display: str
    truncated: bool = False

    def __post_init__(self) -> None:
        if not isinstance(self.raw, bytes):
            raise ValueError("filename raw value must be bytes")
        if self.display != safe_filename_display(self.raw):
            raise ValueError("filename display must be derived from its raw bytes")
        if type(self.truncated) is not bool:
            raise ValueError("filename truncated flag must be a boolean")

    @classmethod
    def from_bytes(cls, raw: bytes, *, truncated: bool = False) -> FilenameBytes:
        if not isinstance(raw, bytes):
            raise TypeError("filename must be bytes")
        return cls(raw=raw, display=safe_filename_display(raw), truncated=truncated)

    def to_dict(self) -> dict[str, Any]:
        return {
            "raw_base64": base64.b64encode(self.raw).decode("ascii"),
            "display": self.display,
            "truncated": self.truncated,
        }


@dataclass(frozen=True)
class ProcessIdentity:
    boot_id: str
    tgid: int
    start_time_ns: int

    def __post_init__(self) -> None:
        if not isinstance(self.boot_id, str) or not self.boot_id.strip():
            raise ValueError("boot_id must be non-empty")
        _unsigned("tgid", self.tgid, 32, positive=True)
        _unsigned("start_time_ns", self.start_time_ns, 64)

    def to_dict(self) -> dict[str, Any]:
        return {
            "boot_id": self.boot_id,
            "tgid": self.tgid,
            "start_time_ns": self.start_time_ns,
        }


@dataclass(frozen=True)
class OperationAttempt:
    name: str
    create_intent: bool

    def to_dict(self) -> dict[str, Any]:
        return {"name": self.name, "create_intent": self.create_intent}


@dataclass(frozen=True)
class SyscallResult:
    return_value: int
    succeeded: bool

    @classmethod
    def from_return_value(cls, return_value: int) -> SyscallResult:
        if isinstance(return_value, bool) or not isinstance(return_value, int):
            raise ValueError("return_value must be an integer")
        if not -(2**63) <= return_value < 2**63:
            raise ValueError("return_value must be a signed 64-bit integer")
        return cls(return_value=return_value, succeeded=return_value >= 0)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class NormalizedEvent:
    run_id: str
    sequence: int
    monotonic_ns: int
    identity: ProcessIdentity
    tid: int
    event_type: str
    attempt: OperationAttempt | None
    result: SyscallResult | None
    filename: FilenameBytes | None

    def __post_init__(self) -> None:
        if not isinstance(self.run_id, str) or not self.run_id.strip():
            raise ValueError("run_id must be non-empty")
        _unsigned("sequence", self.sequence, 64, positive=True)
        _unsigned("monotonic_ns", self.monotonic_ns, 64)
        _unsigned("tid", self.tid, 32, positive=True)
        if self.event_type not in {"syscall", "process_exit"}:
            raise ValueError(f"unsupported event type: {self.event_type}")
        if self.event_type == "syscall":
            if self.attempt is None or self.result is None or self.filename is None:
                raise ValueError("syscall events require attempt, result, and filename")
        elif any(item is not None for item in (self.attempt, self.result, self.filename)):
            raise ValueError("process-exit events cannot contain syscall data")

    @classmethod
    def syscall(
        cls,
        *,
        run_id: str,
        sequence: int,
        monotonic_ns: int,
        identity: ProcessIdentity,
        tid: int,
        operation: str,
        return_value: int,
        open_flags: int,
        filename: FilenameBytes,
    ) -> NormalizedEvent:
        if operation not in SYSCALL_OPERATIONS:
            raise ValueError(f"unsupported operation: {operation}")
        _unsigned("open_flags", open_flags, 32)
        create_intent = operation in {"open", "openat"} and bool(
            open_flags & LINUX_O_CREAT
        )
        return cls(
            run_id=run_id,
            sequence=sequence,
            monotonic_ns=monotonic_ns,
            identity=identity,
            tid=tid,
            event_type="syscall",
            attempt=OperationAttempt(operation, create_intent),
            result=SyscallResult.from_return_value(return_value),
            filename=filename,
        )

    @classmethod
    def process_exit(
        cls,
        *,
        run_id: str,
        sequence: int,
        monotonic_ns: int,
        identity: ProcessIdentity,
        tid: int,
    ) -> NormalizedEvent:
        return cls(
            run_id=run_id,
            sequence=sequence,
            monotonic_ns=monotonic_ns,
            identity=identity,
            tid=tid,
            event_type="process_exit",
            attempt=None,
            result=None,
            filename=None,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": PROTOCOL_VERSION,
            "record_type": "event",
            "run_id": self.run_id,
            "collector_sequence": self.sequence,
            "monotonic_ns": self.monotonic_ns,
            "process": self.identity.to_dict(),
            "tid": self.tid,
            "event_type": self.event_type,
            "attempt": None if self.attempt is None else self.attempt.to_dict(),
            "result": None if self.result is None else self.result.to_dict(),
            "filename": None if self.filename is None else self.filename.to_dict(),
        }

    def to_json_line(self) -> str:
        return json.dumps(
            self.to_dict(), ensure_ascii=False, sort_keys=True, separators=(",", ":")
        ) + "\n"

    def to_contract_event(self):
        """Convert a syscall to the shared O/C/D feature-stream contract."""

        from .adapter import to_contract_event

        return to_contract_event(self)


@dataclass(frozen=True)
class LossCounters:
    ring_buffer_reservation_failures: int = 0
    pending_map_update_failures: int = 0
    filename_read_failures: int = 0
    identity_read_failures: int = 0
    consumer_decode_errors: int = 0
    consumer_queue_drops: int = 0

    def __post_init__(self) -> None:
        for name, value in asdict(self).items():
            _unsigned(name, value, 64)

    @property
    def total(self) -> int:
        return sum(asdict(self).values())

    def to_dict(self) -> dict[str, int]:
        return asdict(self)


@dataclass(frozen=True)
class CollectorHealth:
    run_id: str
    connected: bool
    monotonic_ns: int
    counters: LossCounters

    def __post_init__(self) -> None:
        if not isinstance(self.run_id, str) or not self.run_id.strip():
            raise ValueError("run_id must be non-empty")
        _unsigned("monotonic_ns", self.monotonic_ns, 64)
        if type(self.connected) is not bool:
            raise ValueError("connected must be a boolean")

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": PROTOCOL_VERSION,
            "record_type": "collector_health",
            "run_id": self.run_id,
            "monotonic_ns": self.monotonic_ns,
            "connected": self.connected,
            "loss_counters": self.counters.to_dict(),
            "loss_total": self.counters.total,
            "telemetry_complete": self.counters.total == 0,
        }

    def to_json_line(self) -> str:
        return json.dumps(
            self.to_dict(), ensure_ascii=False, sort_keys=True, separators=(",", ":")
        ) + "\n"
