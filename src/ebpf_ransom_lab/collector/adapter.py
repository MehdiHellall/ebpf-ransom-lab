"""Adapters from collector records to the shared replay/feature contracts."""

from __future__ import annotations

import base64
from dataclasses import dataclass

from ebpf_ransom_lab.contracts import (
    Event,
    Heartbeat,
    ProcessExit,
    ProcessIdentity as ContractProcessIdentity,
)

from .protocol import CollectorHealth, LossCounters, NormalizedEvent


def _contract_identity(event: NormalizedEvent) -> ContractProcessIdentity:
    return ContractProcessIdentity(
        boot_id=event.identity.boot_id,
        tgid=event.identity.tgid,
        start_time_ns=event.identity.start_time_ns,
    )


def to_contract_event(event: NormalizedEvent) -> Event:
    """Convert one correlated syscall to the O/C/D shared feature contract."""

    if not isinstance(event, NormalizedEvent):
        raise ValueError("collector event must be a NormalizedEvent")
    if event.event_type == "process_exit":
        raise ValueError("process exit cannot be converted to a file-operation event")
    if event.attempt is None or event.result is None or event.filename is None:
        raise ValueError("collector syscall is missing normalized fields")
    if event.attempt.name in {"open", "openat"}:
        operation = "C" if event.attempt.create_intent else "O"
    elif event.attempt.name in {"unlink", "unlinkat"}:
        operation = "D"
    else:  # Defensive even though NormalizedEvent validates the operation.
        raise ValueError(f"unsupported collector operation: {event.attempt.name}")
    return Event(
        run_id=event.run_id,
        collector_sequence=event.sequence,
        timestamp_ns=event.monotonic_ns,
        process=_contract_identity(event),
        tid=event.tid,
        operation=operation,
        result=event.result.return_value,
        filename=event.filename.display,
        filename_bytes_b64=base64.b64encode(event.filename.raw).decode("ascii"),
        telemetry_quality="complete",
        lost_events=0,
    )


@dataclass(frozen=True, slots=True)
class ProcessExitNotice:
    """Lifecycle notice used to close, but never classify, a process window."""

    run_id: str
    collector_sequence: int
    timestamp_ns: int
    process: ContractProcessIdentity
    tid: int

    @classmethod
    def from_event(cls, event: NormalizedEvent) -> ProcessExitNotice:
        if not isinstance(event, NormalizedEvent) or event.event_type != "process_exit":
            raise ValueError("process exit notice requires a process-exit event")
        return cls(
            run_id=event.run_id,
            collector_sequence=event.sequence,
            timestamp_ns=event.monotonic_ns,
            process=_contract_identity(event),
            tid=event.tid,
        )

    def to_contract_record(self) -> ProcessExit:
        return ProcessExit(
            run_id=self.run_id,
            collector_sequence=self.collector_sequence,
            timestamp_ns=self.timestamp_ns,
            process=self.process,
            tid=self.tid,
        )


@dataclass(frozen=True, slots=True)
class _AdapterState:
    run_id: str | None = None
    counters: LossCounters = LossCounters()


class CollectorProtocolAdapter:
    """Convert cumulative health snapshots into loss-delta heartbeats."""

    def __init__(self) -> None:
        self._state = _AdapterState()

    def health_to_heartbeat(
        self, health: CollectorHealth, *, collector_sequence: int
    ) -> Heartbeat:
        if not isinstance(health, CollectorHealth):
            raise ValueError("health must be a CollectorHealth record")
        if self._state.run_id is not None and health.run_id != self._state.run_id:
            raise ValueError("collector health run changed; use a new adapter")
        previous = self._state.counters.to_dict()
        current = health.counters.to_dict()
        if any(current[name] < previous[name] for name in current):
            raise ValueError("collector loss counters regressed")
        delta = sum(current[name] - previous[name] for name in current)
        heartbeat = Heartbeat(
            run_id=health.run_id,
            collector_sequence=collector_sequence,
            timestamp_ns=health.monotonic_ns,
            lost_events=delta,
        )
        self._state = _AdapterState(health.run_id, health.counters)
        return heartbeat
