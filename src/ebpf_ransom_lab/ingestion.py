"""Unprivileged streaming ingestion for collector pipes and replay fixtures."""
from __future__ import annotations

import json
from dataclasses import dataclass
from typing import TextIO

from ebpf_ransom_lab.contracts import RunEnd, RunStart, record_from_dict
from ebpf_ransom_lab.detection import RuleScorer
from ebpf_ransom_lab.replay import replay_records
from ebpf_ransom_lab.storage import Store
from ebpf_ransom_lab.stream import validate_stream


@dataclass(frozen=True, slots=True)
class IngestionSummary:
    run_id: str
    records: int
    windows: int
    alerts: int


def ingest_jsonl_stream(
    stream: TextIO, store: Store, *, capture_start_ns: int | None = None, threshold: float = 4.0,
) -> IngestionSummary:
    """Validate a complete stream, then commit all derived state atomically."""
    scorer = RuleScorer(threshold)
    materialized = []
    lost_events = 0
    telemetry_records = 0
    observed_start_ns: int | None = None
    last_timestamp_ns = 0
    try:
        for line_number, line in enumerate(stream, start=1):
            if not line.strip():
                raise ValueError(f"invalid collector line {line_number}: blank JSONL record")
            try:
                raw = json.loads(line)
                if not isinstance(raw, dict):
                    raise ValueError("JSON record must be an object")
                record = record_from_dict(raw)
            except (ValueError, json.JSONDecodeError) as error:
                raise ValueError(f"invalid collector line {line_number}: {error}") from error
            materialized.append(record)
            lost_events += getattr(record, "lost_events", 0)
            if isinstance(record, RunStart) and len(materialized) == 1:
                observed_start_ns = record.capture_start_ns
                last_timestamp_ns = observed_start_ns
            elif observed_start_ns is not None and not isinstance(record, RunEnd):
                telemetry_records += 1
                last_timestamp_ns = max(
                    last_timestamp_ns, getattr(record, "timestamp_ns", last_timestamp_ns)
                )
                elapsed = max(1, last_timestamp_ns - observed_start_ns)
                store.update_health(
                    connected=True,
                    event_rate=telemetry_records * 1_000_000_000 / elapsed,
                    lost_events=lost_events,
                    recording=True,
                    error=None,
                )
        validated = validate_stream(materialized, capture_start_ns=capture_start_ns)
        windows = replay_records(materialized, capture_start_ns=capture_start_ns)
        predictions = tuple(scorer.predict(window) for window in windows)
        store.replace_run_analysis(
            validated.start.run_id,
            source=validated.start.source,
            started_ns=validated.start.capture_start_ns,
            windows=windows,
            predictions=predictions,
        )
        alerts = sum(prediction.suspicious is True for prediction in predictions)
        store.update_health(
            connected=False, event_rate=0.0,
            lost_events=validated.total_lost_events, recording=False, error=None,
        )
        return IngestionSummary(
            validated.start.run_id, len(validated.records), len(windows), alerts
        )
    except Exception as error:
        store.update_health(connected=False, event_rate=0.0, lost_events=lost_events, recording=False, error=str(error))
        raise
