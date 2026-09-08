"""Stable JSON Lines serialization for normalized recordings."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Iterable

from ebpf_ransom_lab.contracts import SerializableRecord, record_from_dict, record_to_dict


class RecordingLineError(ValueError):
    """A malformed JSONL record, annotated with its source line."""


class RecordingBudgetExceeded(RuntimeError):
    """Writing the next complete JSONL record would exceed the byte budget."""

    def __init__(self, max_bytes: int, written_bytes: int, next_line_bytes: int):
        self.max_bytes = max_bytes
        self.written_bytes = written_bytes
        self.next_line_bytes = next_line_bytes
        super().__init__(
            "recording byte budget exceeded: "
            f"limit={max_bytes}, written={written_bytes}, next_line={next_line_bytes}"
        )


def read_jsonl(path: Path) -> tuple[SerializableRecord, ...]:
    """Read a whole recording, reporting malformed data with an exact line."""

    source = Path(path)
    records = []
    with source.open("rb") as stream:
        for line_number, raw_line in enumerate(stream, start=1):
            try:
                line = raw_line.decode("utf-8")
            except UnicodeDecodeError as error:
                raise RecordingLineError(
                    f"{source}:{line_number}: invalid UTF-8: {error}"
                ) from error
            if not line.strip():
                raise RecordingLineError(f"{source}:{line_number}: blank JSONL record")
            try:
                value = json.loads(line)
            except json.JSONDecodeError as error:
                raise RecordingLineError(
                    f"{source}:{line_number}: invalid JSON: {error.msg}"
                ) from error
            if not isinstance(value, dict):
                raise RecordingLineError(f"{source}:{line_number}: JSON record must be an object")
            try:
                records.append(record_from_dict(value))
            except ValueError as error:
                raise RecordingLineError(f"{source}:{line_number}: {error}") from error
    return tuple(records)


def encode_jsonl_record(record: SerializableRecord) -> bytes:
    """Encode one complete canonical JSONL line before any file write occurs."""

    text = json.dumps(
        record_to_dict(record), ensure_ascii=False, sort_keys=True,
        separators=(",", ":"), allow_nan=False,
    )
    return (text + "\n").encode("utf-8")


def write_jsonl(
    path: Path, records: Iterable[SerializableRecord], *, max_bytes: int | None = None
) -> None:
    """Write complete JSONL records, stopping cleanly at ``max_bytes``."""

    if max_bytes is not None and (type(max_bytes) is not int or max_bytes < 0):
        raise ValueError("max_bytes must be a non-negative integer or null")

    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    written_bytes = 0
    with destination.open("wb") as stream:
        for record in records:
            line = encode_jsonl_record(record)
            if max_bytes is not None and written_bytes + len(line) > max_bytes:
                raise RecordingBudgetExceeded(max_bytes, written_bytes, len(line))
            stream.write(line)
            written_bytes += len(line)
        stream.flush()
