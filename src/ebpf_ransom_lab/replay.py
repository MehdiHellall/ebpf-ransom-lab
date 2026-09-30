"""Replay normalized records through the shared feature engine."""

from __future__ import annotations

from pathlib import Path
from typing import Iterable

from ebpf_ransom_lab.contracts import FeatureWindow, SerializableRecord
from ebpf_ransom_lab.features import WindowFeatureEngine
from ebpf_ransom_lab.recording import read_jsonl
from ebpf_ransom_lab.stream import validate_stream


def replay_records(
    records: Iterable[SerializableRecord], *, capture_start_ns: int | None = None,
    capture_end_ns: int | None = None, chunk_sizes: Iterable[int] | None = None,
) -> tuple[FeatureWindow, ...]:
    """Return final windows from a complete, lossless normalized stream."""

    validated = validate_stream(
        records,
        capture_start_ns=capture_start_ns,
        capture_end_ns=capture_end_ns,
    )
    engine = WindowFeatureEngine(validated.start.capture_start_ns)
    for chunk in _chunks(validated.records, chunk_sizes):
        engine.feed(chunk)
    engine.finish(validated.end.timestamp_ns)
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
