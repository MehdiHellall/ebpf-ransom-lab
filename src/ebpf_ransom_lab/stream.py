"""Shared fail-closed validation for normalized collector streams."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

from ebpf_ransom_lab.contracts import (
    Event,
    Heartbeat,
    ProcessExit,
    RunEnd,
    RunStart,
    SerializableRecord,
    StreamRecord,
)


@dataclass(frozen=True, slots=True)
class ValidatedStream:
    """A complete stream whose envelope, ordering, and loss totals agree."""

    start: RunStart
    records: tuple[StreamRecord, ...]
    end: RunEnd

    @property
    def total_lost_events(self) -> int:
        return self.end.total_lost_events


def validate_stream(
    records: Iterable[SerializableRecord],
    *,
    capture_start_ns: int | None = None,
    capture_end_ns: int | None = None,
    require_lossless: bool = True,
    require_results: bool = True,
) -> ValidatedStream:
    """Validate one complete RunStart/telemetry/RunEnd stream.

    Collector sequences cover every telemetry record and the terminal record,
    starting at one. Timestamps may arrive late, but they must remain inside
    the declared run boundary.
    """

    materialized = tuple(records)
    if len(materialized) < 2 or not isinstance(materialized[0], RunStart):
        raise ValueError("stream must begin with exactly one run-start record")
    if not isinstance(materialized[-1], RunEnd):
        raise ValueError("stream must end with exactly one run-end record")
    if sum(isinstance(record, RunStart) for record in materialized) != 1:
        raise ValueError("stream must begin with exactly one run-start record")
    if sum(isinstance(record, RunEnd) for record in materialized) != 1:
        raise ValueError("stream must end with exactly one run-end record")

    start = materialized[0]
    end = materialized[-1]
    assert isinstance(start, RunStart) and isinstance(end, RunEnd)
    telemetry = materialized[1:-1]
    if not all(isinstance(record, (Event, Heartbeat, ProcessExit)) for record in telemetry):
        raise ValueError("stream contains a non-telemetry record inside its envelope")
    stream_records = tuple(telemetry)

    if end.status != "complete":
        raise ValueError("stream terminal status is not complete")
    if end.run_id != start.run_id or any(
        record.run_id != start.run_id for record in stream_records
    ):
        raise ValueError("stream run ID changed")
    if capture_start_ns is not None and capture_start_ns != start.capture_start_ns:
        raise ValueError("capture_start_ns does not match recorded run start")
    if capture_end_ns is not None and capture_end_ns != end.timestamp_ns:
        raise ValueError("capture_end_ns does not match recorded run end")

    sequenced = (*stream_records, end)
    sequences = tuple(record.collector_sequence for record in sequenced)
    if sequences != tuple(range(1, len(sequenced) + 1)):
        raise ValueError("collector sequence is not contiguous from one")
    if end.timestamp_ns < start.capture_start_ns or any(
        record.timestamp_ns < start.capture_start_ns
        or record.timestamp_ns > end.timestamp_ns
        for record in stream_records
    ):
        raise ValueError("stream timestamp is outside the run boundary")

    observed_loss = sum(
        record.lost_events
        for record in stream_records
        if isinstance(record, (Event, Heartbeat))
    )
    if observed_loss != end.total_lost_events:
        raise ValueError("stream loss telemetry total does not match run end")
    if require_lossless and observed_loss:
        raise ValueError("stream contains lost events")
    if require_lossless and any(
        isinstance(record, Event) and record.telemetry_quality != "complete"
        for record in stream_records
    ):
        raise ValueError("stream contains degraded telemetry")
    if require_results and any(
        isinstance(record, Event) and record.result is None for record in stream_records
    ):
        raise ValueError("stream event is missing its syscall result")

    return ValidatedStream(start, stream_records, end)
