"""Replay normalized records through the shared feature engine."""

from __future__ import annotations

from pathlib import Path
from typing import Iterable

from ebpf_ransom_lab.contracts import Event, FeatureWindow, Heartbeat, ProcessExit, RunEnd, RunStart, StreamRecord
from ebpf_ransom_lab.features import WindowFeatureEngine
from ebpf_ransom_lab.recording import read_jsonl


def replay_records(
    records: Iterable[StreamRecord], *, capture_start_ns: int | None = None,
    capture_end_ns: int | None = None, chunk_sizes: Iterable[int] | None = None,
) -> tuple[FeatureWindow, ...]:
    """Return final window views independent of input batch boundaries."""

    materialized = tuple(records)
    starts = tuple(record for record in materialized if isinstance(record, RunStart))
    if len(starts) > 1:
        raise ValueError("recording has multiple run-start records")
    if starts and (not materialized or materialized[0] is not starts[0]):
        raise ValueError("run start must be the first recording record")
    ends = tuple(record for record in materialized if isinstance(record, RunEnd))
    if len(ends) > 1:
        raise ValueError("recording has multiple run-end records")
    if ends and materialized[-1] is not ends[0]:
        raise ValueError("run end must be the final recording record")
    stream_records = tuple(
        record for record in materialized if not isinstance(record, (RunStart, RunEnd))
    )
    if not all(isinstance(record, (Event, Heartbeat, ProcessExit)) for record in stream_records):
        raise ValueError("replay accepts only a run start plus Event, Heartbeat, and ProcessExit records")
    if starts and any(record.run_id != starts[0].run_id for record in stream_records):
        raise ValueError("run-start ID does not match stream records")
    if ends and (
        (starts and ends[0].run_id != starts[0].run_id)
        or any(record.run_id != ends[0].run_id for record in stream_records)
    ):
        raise ValueError("run-end ID does not match stream records")
    if ends and ends[0].status != "complete":
        raise ValueError("cannot replay a failed capture")
    if capture_start_ns is None:
        if starts:
            capture_start_ns = starts[0].capture_start_ns
        else:
            raise ValueError("capture_start_ns is required for reproducible window alignment")
    if starts and capture_start_ns != starts[0].capture_start_ns:
        raise ValueError("capture_start_ns does not match recorded run start")
    engine = WindowFeatureEngine(capture_start_ns)
    for chunk in _chunks(stream_records, chunk_sizes):
        engine.feed(chunk)
    if capture_end_ns is None and ends:
        capture_end_ns = ends[0].timestamp_ns
    elif capture_end_ns is not None and ends and capture_end_ns != ends[0].timestamp_ns:
        raise ValueError("capture_end_ns does not match recorded run end")
    if capture_end_ns is None:
        capture_end_ns = max(
            (record.timestamp_ns for record in stream_records), default=capture_start_ns
        )
    engine.finish(capture_end_ns)
    return engine.windows


def replay_file(
    path: Path, *, capture_start_ns: int | None = None,
    capture_end_ns: int | None = None, chunk_sizes: Iterable[int] | None = None,
) -> tuple[FeatureWindow, ...]:
    records = read_jsonl(Path(path))
    return replay_records(
        records, capture_start_ns=capture_start_ns,
        capture_end_ns=capture_end_ns, chunk_sizes=chunk_sizes,
    )


def _chunks(
    records: tuple[StreamRecord, ...], chunk_sizes: Iterable[int] | None
) -> tuple[tuple[StreamRecord, ...], ...]:
    if chunk_sizes is None:
        return (records,) if records else ()
    chunks = []
    offset = 0
    for size in chunk_sizes:
        if type(size) is not int or size < 0:
            raise ValueError("chunk sizes must be non-negative integers")
        chunks.append(records[offset:offset + size])
        offset += size
        if offset > len(records):
            raise ValueError("chunk sizes exceed the number of records")
    if offset < len(records):
        chunks.append(records[offset:])
    return tuple(chunks)
