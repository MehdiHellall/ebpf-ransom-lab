"""Unprivileged streaming ingestion for collector pipes and replay fixtures."""
from __future__ import annotations

import json
from dataclasses import dataclass
from typing import TextIO

from ebpf_ransom_lab.contracts import Event, Heartbeat, ProcessExit, RunEnd, RunStart, record_from_dict
from ebpf_ransom_lab.detection import RuleScorer
from ebpf_ransom_lab.features import WindowFeatureEngine
from ebpf_ransom_lab.storage import Store


@dataclass(frozen=True, slots=True)
class IngestionSummary:
    run_id: str
    records: int
    windows: int
    alerts: int


def ingest_jsonl_stream(
    stream: TextIO, store: Store, *, capture_start_ns: int | None = None, threshold: float = 4.0,
) -> IngestionSummary:
    """Consume one strict core JSONL stream and persist rule results incrementally."""
    engine = None if capture_start_ns is None else WindowFeatureEngine(capture_start_ns)
    scorer = RuleScorer(threshold)
    run_id: str | None = None
    last_timestamp = capture_start_ns or 0
    records = windows = alerts = lost_events = 0
    has_run_start = ended = False
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
            if ended:
                raise ValueError(f"invalid collector line {line_number}: record follows run end")
            if isinstance(record, RunStart):
                if run_id is not None:
                    raise ValueError(f"invalid collector line {line_number}: run start must be first")
                if capture_start_ns is not None and capture_start_ns != record.capture_start_ns:
                    raise ValueError(f"invalid collector line {line_number}: capture start disagrees with CLI")
                capture_start_ns = record.capture_start_ns
                engine = WindowFeatureEngine(capture_start_ns)
                run_id = record.run_id
                has_run_start = True
                last_timestamp = capture_start_ns
                store.upsert_run(run_id, source="live", started_ns=capture_start_ns, status="collecting")
                continue
            if isinstance(record, RunEnd):
                if run_id is None or engine is None or capture_start_ns is None:
                    raise ValueError(f"invalid collector line {line_number}: run end has no run start")
                if record.run_id != run_id or record.status != "complete":
                    raise ValueError(f"invalid collector line {line_number}: unsuccessful run end")
                if record.total_lost_events != lost_events:
                    raise ValueError(f"invalid collector line {line_number}: loss total mismatch")
                added_windows, added_alerts = _persist(
                    engine.finish(record.timestamp_ns), store, scorer
                )
                windows += added_windows
                alerts += added_alerts
                last_timestamp = record.timestamp_ns
                ended = True
                store.upsert_run(
                    run_id, source="live", started_ns=capture_start_ns, status="complete"
                )
                store.update_health(
                    connected=False, event_rate=0.0, lost_events=lost_events,
                    recording=False, error=None,
                )
                continue
            if not isinstance(record, (Event, Heartbeat, ProcessExit)):
                raise ValueError(f"invalid collector line {line_number}: record is not a stream event")
            if engine is None or capture_start_ns is None:
                raise ValueError(f"invalid collector line {line_number}: missing run-start metadata")
            if run_id is None:
                run_id = record.run_id
                store.upsert_run(run_id, source="live", started_ns=capture_start_ns, status="collecting")
            elif record.run_id != run_id:
                raise ValueError(f"invalid collector line {line_number}: run ID changed")
            emitted = engine.feed((record,))
            records += 1
            last_timestamp = max(last_timestamp, record.timestamp_ns)
            lost_events += getattr(record, "lost_events", 0)
            added_windows, added_alerts = _persist(emitted, store, scorer)
            windows += added_windows
            alerts += added_alerts
            elapsed = max(1, last_timestamp - capture_start_ns)
            store.update_health(
                connected=True, event_rate=records * 1_000_000_000 / elapsed,
                lost_events=lost_events, recording=True, error=None,
            )
        if run_id is None or engine is None or capture_start_ns is None:
            raise ValueError("collector stream contains no records")
        if has_run_start and not ended:
            raise ValueError("collector stream is missing its terminal run-end record")
        if not ended:
            added_windows, added_alerts = _persist(engine.finish(last_timestamp), store, scorer)
            windows += added_windows
            alerts += added_alerts
            store.upsert_run(run_id, source="live", started_ns=capture_start_ns, status="complete")
            store.update_health(
                connected=False, event_rate=0.0, lost_events=lost_events,
                recording=False, error=None,
            )
        return IngestionSummary(run_id, records, windows, alerts)
    except Exception as error:
        store.update_health(connected=False, event_rate=0.0, lost_events=lost_events, recording=False, error=str(error))
        raise


def _persist(windows, store: Store, scorer: RuleScorer) -> tuple[int, int]:
    alerts = 0
    for window in windows:
        prediction = scorer.predict(window)
        store.upsert_window(window)
        store.upsert_prediction(prediction)
        if prediction.suspicious:
            store.create_alert(prediction, window)
            alerts += 1
    return len(windows), alerts
