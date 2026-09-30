"""Versioned, immutable records shared by collection, replay, and inference."""

from __future__ import annotations

import base64
import binascii
from dataclasses import dataclass
import hashlib
import json
from typing import Any, Mapping, TypeAlias


CONTRACT_VERSION = 1
FEATURE_VERSION = 2
OPERATIONS = ("O", "C", "D")
TELEMETRY_QUALITIES = frozenset(("complete", "degraded"))


def _text(value: object, name: str) -> None:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{name} must be a non-empty string")


def _integer(
    value: object, name: str, *, minimum: int = 0, maximum_exclusive: int | None = None
) -> None:
    if type(value) is not int or value < minimum or (
        maximum_exclusive is not None and value >= maximum_exclusive
    ):
        upper = "" if maximum_exclusive is None else f" and < {maximum_exclusive}"
        raise ValueError(f"{name} must be an integer >= {minimum}{upper}")


def _version(value: object, name: str, expected: int) -> None:
    if type(value) is not int or value != expected:
        raise ValueError(f"unsupported {name} version {value!r}; expected {expected}")


@dataclass(frozen=True, slots=True)
class ProcessIdentity:
    """A Linux process identity that remains safe across PID reuse."""

    boot_id: str
    tgid: int
    start_time_ns: int
    schema_version: int = CONTRACT_VERSION

    def __post_init__(self) -> None:
        _version(self.schema_version, "schema", CONTRACT_VERSION)
        _text(self.boot_id, "boot_id")
        _integer(self.tgid, "tgid", minimum=1, maximum_exclusive=2**32)
        _integer(self.start_time_ns, "start_time_ns", maximum_exclusive=2**64)

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": "process_identity",
            "schema_version": self.schema_version,
            "boot_id": self.boot_id,
            "tgid": self.tgid,
            "start_time_ns": self.start_time_ns,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> ProcessIdentity:
        data = _plain_mapping(value)
        if data.pop("type", None) != "process_identity":
            raise ValueError("invalid process identity record type")
        _version(data.get("schema_version"), "schema", CONTRACT_VERSION)
        try:
            return cls(**data)
        except TypeError as error:
            raise ValueError(f"invalid process identity: {error}") from error


@dataclass(frozen=True, slots=True)
class RunStart:
    """Capture metadata that freezes window alignment before telemetry arrives."""

    run_id: str
    capture_start_ns: int
    source: str
    schema_version: int = CONTRACT_VERSION

    def __post_init__(self) -> None:
        _version(self.schema_version, "schema", CONTRACT_VERSION)
        _text(self.run_id, "run_id")
        _integer(self.capture_start_ns, "capture_start_ns", maximum_exclusive=2**64)
        if self.source not in {"live", "replay", "controlled-workload"}:
            raise ValueError("unsupported run source")

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": "run_start",
            "schema_version": self.schema_version,
            "run_id": self.run_id,
            "capture_start_ns": self.capture_start_ns,
            "source": self.source,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> RunStart:
        try:
            return cls(**_record_payload(value, "run_start"))
        except TypeError as error:
            raise ValueError(f"invalid run start: {error}") from error


@dataclass(frozen=True, slots=True)
class RunEnd:
    """A terminal marker emitted only after a collector finishes cleanly."""

    run_id: str
    collector_sequence: int
    timestamp_ns: int
    status: str = "complete"
    total_lost_events: int = 0
    schema_version: int = CONTRACT_VERSION

    def __post_init__(self) -> None:
        _version(self.schema_version, "schema", CONTRACT_VERSION)
        _text(self.run_id, "run_id")
        _integer(self.collector_sequence, "collector_sequence", maximum_exclusive=2**64)
        _integer(self.timestamp_ns, "timestamp_ns", maximum_exclusive=2**64)
        if self.status not in {"complete", "failed"}:
            raise ValueError("run end status must be complete or failed")
        _integer(self.total_lost_events, "total_lost_events", maximum_exclusive=2**64)

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": "run_end",
            "schema_version": self.schema_version,
            "run_id": self.run_id,
            "collector_sequence": self.collector_sequence,
            "timestamp_ns": self.timestamp_ns,
            "status": self.status,
            "total_lost_events": self.total_lost_events,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> RunEnd:
        try:
            return cls(**_record_payload(value, "run_end"))
        except TypeError as error:
            raise ValueError(f"invalid run end: {error}") from error


@dataclass(frozen=True, slots=True)
class Event:
    """One normalized file-operation event in collector emission order."""

    run_id: str
    collector_sequence: int
    timestamp_ns: int
    process: ProcessIdentity
    tid: int
    operation: str
    result: int | None = None
    filename: str = ""
    filename_bytes_b64: str | None = None
    telemetry_quality: str = "complete"
    lost_events: int = 0
    schema_version: int = CONTRACT_VERSION

    def __post_init__(self) -> None:
        _version(self.schema_version, "schema", CONTRACT_VERSION)
        _text(self.run_id, "run_id")
        _integer(self.collector_sequence, "collector_sequence", maximum_exclusive=2**64)
        _integer(self.timestamp_ns, "timestamp_ns", maximum_exclusive=2**64)
        if not isinstance(self.process, ProcessIdentity):
            raise ValueError("process must be a ProcessIdentity")
        _integer(self.tid, "tid", minimum=1, maximum_exclusive=2**32)
        if self.operation not in OPERATIONS:
            raise ValueError("operation must be O, C, or D")
        if self.result is not None and (
            type(self.result) is not int or not -(2**63) <= self.result < 2**63
        ):
            raise ValueError("result must be a signed 64-bit integer or null")
        if not isinstance(self.filename, str):
            raise ValueError("filename must be a string")
        if self.filename_bytes_b64 is not None and not isinstance(self.filename_bytes_b64, str):
            raise ValueError("filename_bytes_b64 must be a string or null")
        if self.filename_bytes_b64 is not None:
            try:
                base64.b64decode(self.filename_bytes_b64.encode("ascii"), validate=True)
            except (binascii.Error, UnicodeEncodeError) as error:
                raise ValueError("filename_bytes_b64 must contain valid base64") from error
        if self.telemetry_quality not in TELEMETRY_QUALITIES:
            raise ValueError("telemetry_quality must be complete or degraded")
        _integer(self.lost_events, "lost_events", maximum_exclusive=2**64)

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": "event",
            "schema_version": self.schema_version,
            "run_id": self.run_id,
            "collector_sequence": self.collector_sequence,
            "timestamp_ns": self.timestamp_ns,
            "process": self.process.to_dict(),
            "tid": self.tid,
            "operation": self.operation,
            "result": self.result,
            "filename": self.filename,
            "filename_bytes_b64": self.filename_bytes_b64,
            "telemetry_quality": self.telemetry_quality,
            "lost_events": self.lost_events,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> Event:
        data = _record_payload(value, "event")
        process = data.get("process")
        if not isinstance(process, Mapping):
            raise ValueError("event process must be an object")
        data["process"] = ProcessIdentity.from_dict(process)
        try:
            return cls(**data)
        except TypeError as error:
            raise ValueError(f"invalid event: {error}") from error


@dataclass(frozen=True, slots=True)
class Heartbeat:
    """A collector watermark, optionally carrying newly observed event loss."""

    run_id: str
    collector_sequence: int
    timestamp_ns: int
    lost_events: int = 0
    schema_version: int = CONTRACT_VERSION

    def __post_init__(self) -> None:
        _version(self.schema_version, "schema", CONTRACT_VERSION)
        _text(self.run_id, "run_id")
        _integer(self.collector_sequence, "collector_sequence", maximum_exclusive=2**64)
        _integer(self.timestamp_ns, "timestamp_ns", maximum_exclusive=2**64)
        _integer(self.lost_events, "lost_events", maximum_exclusive=2**64)

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": "heartbeat",
            "schema_version": self.schema_version,
            "run_id": self.run_id,
            "collector_sequence": self.collector_sequence,
            "timestamp_ns": self.timestamp_ns,
            "lost_events": self.lost_events,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> Heartbeat:
        try:
            return cls(**_record_payload(value, "heartbeat"))
        except TypeError as error:
            raise ValueError(f"invalid heartbeat: {error}") from error


@dataclass(frozen=True, slots=True)
class ProcessExit:
    """A lifecycle record that preserves a process boundary without a fake operation."""

    run_id: str
    collector_sequence: int
    timestamp_ns: int
    process: ProcessIdentity
    tid: int
    schema_version: int = CONTRACT_VERSION

    def __post_init__(self) -> None:
        _version(self.schema_version, "schema", CONTRACT_VERSION)
        _text(self.run_id, "run_id")
        _integer(self.collector_sequence, "collector_sequence", maximum_exclusive=2**64)
        _integer(self.timestamp_ns, "timestamp_ns", maximum_exclusive=2**64)
        if not isinstance(self.process, ProcessIdentity):
            raise ValueError("process must be a ProcessIdentity")
        _integer(self.tid, "tid", minimum=1, maximum_exclusive=2**32)

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": "process_exit",
            "schema_version": self.schema_version,
            "run_id": self.run_id,
            "collector_sequence": self.collector_sequence,
            "timestamp_ns": self.timestamp_ns,
            "process": self.process.to_dict(),
            "tid": self.tid,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> ProcessExit:
        data = _record_payload(value, "process_exit")
        process = data.get("process")
        if not isinstance(process, Mapping):
            raise ValueError("process exit process must be an object")
        data["process"] = ProcessIdentity.from_dict(process)
        try:
            return cls(**data)
        except TypeError as error:
            raise ValueError(f"invalid process exit: {error}") from error


@dataclass(frozen=True, slots=True)
class FeatureWindow:
    """An immutable view of one process's features in one fixed time window.

    A late event creates a replacement record with the same ``window_id`` and
    a larger ``late_event_count``. Consumers should upsert on ``window_id``.
    """

    run_id: str
    process: ProcessIdentity
    start_ns: int
    end_ns: int
    feature_names: tuple[str, ...]
    values: tuple[int, ...]
    partial: bool = False
    loss_count: int = 0
    late_event_count: int = 0
    feature_version: int = FEATURE_VERSION
    schema_version: int = CONTRACT_VERSION

    def __post_init__(self) -> None:
        _version(self.schema_version, "schema", CONTRACT_VERSION)
        _version(self.feature_version, "feature", FEATURE_VERSION)
        _text(self.run_id, "run_id")
        if not isinstance(self.process, ProcessIdentity):
            raise ValueError("process must be a ProcessIdentity")
        _integer(self.start_ns, "start_ns")
        _integer(self.end_ns, "end_ns")
        if self.end_ns <= self.start_ns:
            raise ValueError("end_ns must be greater than start_ns")
        if type(self.partial) is not bool:
            raise ValueError("partial must be a boolean")
        if not isinstance(self.feature_names, tuple) or not all(
            isinstance(name, str) and name for name in self.feature_names
        ):
            raise ValueError("feature_names must be a tuple of non-empty strings")
        if len(set(self.feature_names)) != len(self.feature_names):
            raise ValueError("feature_names must be unique")
        if not isinstance(self.values, tuple) or len(self.feature_names) != len(self.values):
            raise ValueError("feature names and values must have equal lengths")
        if any(type(value) is not int or value < 0 for value in self.values):
            raise ValueError("feature values must be non-negative integers")
        _integer(self.loss_count, "loss_count")
        _integer(self.late_event_count, "late_event_count")

    @property
    def window_id(self) -> str:
        identity = (
            self.run_id,
            self.process.boot_id,
            self.process.tgid,
            self.process.start_time_ns,
            self.start_ns,
            self.end_ns,
            self.feature_version,
        )
        payload = json.dumps(identity, separators=(",", ":"), ensure_ascii=True)
        return hashlib.sha256(payload.encode("ascii")).hexdigest()

    @property
    def feature_map(self) -> dict[str, int]:
        return dict(zip(self.feature_names, self.values, strict=True))

    @property
    def quality(self) -> tuple[str, ...]:
        flags = (
            *(("partial",) if self.partial else ()),
            *(("loss",) if self.loss_count else ()),
            *(("late",) if self.late_event_count else ()),
        )
        return flags or ("complete",)

    @property
    def complete(self) -> bool:
        return not self.partial and not self.loss_count

    @property
    def classifiable(self) -> bool:
        return self.complete and not self.late_event_count

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": "feature_window",
            "schema_version": self.schema_version,
            "feature_version": self.feature_version,
            "window_id": self.window_id,
            "run_id": self.run_id,
            "process": self.process.to_dict(),
            "start_ns": self.start_ns,
            "end_ns": self.end_ns,
            "feature_names": list(self.feature_names),
            "values": list(self.values),
            "partial": self.partial,
            "loss_count": self.loss_count,
            "late_event_count": self.late_event_count,
            "quality": list(self.quality),
            "complete": self.complete,
            "classifiable": self.classifiable,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> FeatureWindow:
        data = _record_payload(value, "feature_window")
        supplied_id = data.pop("window_id", None)
        for derived in ("quality", "complete", "classifiable"):
            data.pop(derived, None)
        process = data.get("process")
        if not isinstance(process, Mapping):
            raise ValueError("feature window process must be an object")
        data["process"] = ProcessIdentity.from_dict(process)
        if isinstance(data.get("feature_names"), list):
            data["feature_names"] = tuple(data["feature_names"])
        if isinstance(data.get("values"), list):
            data["values"] = tuple(data["values"])
        try:
            window = cls(**data)
        except TypeError as error:
            raise ValueError(f"invalid feature window: {error}") from error
        if supplied_id is not None and supplied_id != window.window_id:
            raise ValueError("feature window_id does not match its identity fields")
        return window


StreamRecord: TypeAlias = Event | Heartbeat | ProcessExit
SerializableRecord: TypeAlias = ProcessIdentity | RunStart | RunEnd | Event | Heartbeat | ProcessExit | FeatureWindow


def _plain_mapping(value: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise ValueError("record must be an object")
    return dict(value)


def _record_payload(value: Mapping[str, Any], expected_type: str) -> dict[str, Any]:
    data = _plain_mapping(value)
    record_type = data.pop("type", None)
    if record_type != expected_type:
        raise ValueError(f"record type must be {expected_type}")
    _version(data.get("schema_version"), "schema", CONTRACT_VERSION)
    return data


def record_from_dict(value: Mapping[str, Any]) -> SerializableRecord:
    """Decode one contract record and reject unknown/incompatible versions."""

    data = _plain_mapping(value)
    _version(data.get("schema_version"), "schema", CONTRACT_VERSION)
    record_type = data.get("type")
    classes = {
        "process_identity": ProcessIdentity,
        "run_start": RunStart,
        "run_end": RunEnd,
        "event": Event,
        "heartbeat": Heartbeat,
        "process_exit": ProcessExit,
        "feature_window": FeatureWindow,
    }
    record_class = classes.get(record_type)
    if record_class is None:
        raise ValueError(f"unknown record type {record_type!r}")
    return record_class.from_dict(data)


def record_to_dict(record: SerializableRecord) -> dict[str, Any]:
    if not isinstance(record, (ProcessIdentity, RunStart, RunEnd, Event, Heartbeat, ProcessExit, FeatureWindow)):
        raise ValueError(f"unsupported record {type(record).__name__}")
    return record.to_dict()
