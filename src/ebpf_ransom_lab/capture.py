"""Fail-closed acceptance gate for controlled experiment captures."""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Mapping

from ebpf_ransom_lab.contracts import Event, Heartbeat, ProcessExit, RunEnd, RunStart
from ebpf_ransom_lab.dataset import load_workload_manifest
from ebpf_ransom_lab.recording import read_jsonl
from ebpf_ransom_lab.workloads import build_experiment_manifest


NSEC_PER_SECOND = 1_000_000_000
MAX_CAPTURE_OVERRUN_NS = 2 * NSEC_PER_SECOND


@dataclass(frozen=True, slots=True)
class CaptureAcceptance:
    run_id: str
    raw_sha256: str
    raw_bytes: int
    runtime_manifest_sha256: str
    experiment_plan_sha256: str
    capture_start_ns: int
    capture_end_ns: int
    duration_ns: int
    record_count: int
    event_count: int
    heartbeat_count: int
    process_exit_count: int
    tracked_event_count: int
    total_lost_events: int = 0
    schema_version: int = 1
    status: str = "accepted"

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


def validate_capture_file(
    capture_path: Path, runtime_manifest_path: Path, experiment_plan_path: Path
) -> CaptureAcceptance:
    """Validate raw evidence and return immutable acceptance metadata."""

    capture = Path(capture_path)
    manifest_path = Path(runtime_manifest_path)
    plan_path = Path(experiment_plan_path)
    plan = _load_exact_plan(plan_path)
    manifest = load_workload_manifest(manifest_path)
    planned_run = next(
        (item for item in plan["runs"] if item["run_id"] == manifest.run_id), None
    )
    if planned_run is None:
        raise ValueError("runtime manifest run is absent from the experiment plan")
    if (
        planned_run["scenario"] != manifest.scenario
        or planned_run["seed"] != manifest.seed
        or planned_run["split"] != manifest.split
        or planned_run["behavior_label"] != manifest.behavior_label
        or planned_run["plan_sha256"] != manifest.plan_sha256
    ):
        raise ValueError("runtime manifest does not match its experiment-plan run")

    records = read_jsonl(capture)
    start_indexes = [index for index, record in enumerate(records) if isinstance(record, RunStart)]
    end_indexes = [index for index, record in enumerate(records) if isinstance(record, RunEnd)]
    if start_indexes != [0]:
        raise ValueError("capture must contain exactly one first run-start record")
    if end_indexes != [len(records) - 1]:
        raise ValueError("capture must contain exactly one final run-end record")

    start = records[0]
    end = records[-1]
    assert isinstance(start, RunStart) and isinstance(end, RunEnd)
    telemetry = records[1:-1]
    if not telemetry or any(
        not isinstance(record, (Event, Heartbeat, ProcessExit)) for record in telemetry
    ):
        raise ValueError("capture contains invalid or empty telemetry")
    if start.source != "live" or start.run_id != manifest.run_id:
        raise ValueError("capture run start does not match the runtime manifest")
    if end.run_id != manifest.run_id or end.status != "complete":
        raise ValueError("capture does not have a successful terminal record")
    if any(record.run_id != manifest.run_id for record in telemetry):
        raise ValueError("capture telemetry run ID changed")

    sequenced = (*telemetry, end)
    sequences = tuple(record.collector_sequence for record in sequenced)
    if sequences != tuple(range(1, len(sequenced) + 1)):
        raise ValueError("capture collector sequence is not contiguous")
    if any(
        record.timestamp_ns < start.capture_start_ns or record.timestamp_ns > end.timestamp_ns
        for record in sequenced
    ):
        raise ValueError("capture telemetry timestamp is outside the run boundary")

    planned_duration_ns = int(float(planned_run["capture_duration_seconds"]) * NSEC_PER_SECOND)
    duration_ns = end.timestamp_ns - start.capture_start_ns
    if not planned_duration_ns <= duration_ns <= planned_duration_ns + MAX_CAPTURE_OVERRUN_NS:
        raise ValueError("capture duration does not match the experiment plan")

    deltas = sum(
        record.lost_events for record in telemetry if isinstance(record, (Event, Heartbeat))
    )
    if deltas != end.total_lost_events:
        raise ValueError("capture loss telemetry totals are inconsistent")
    if end.total_lost_events:
        raise ValueError("capture has event loss and is invalid for experiment data")
    if any(
        isinstance(record, Event) and record.telemetry_quality != "complete"
        for record in telemetry
    ):
        raise ValueError("capture contains degraded telemetry")

    tracked = frozenset(manifest.tracked_processes)
    tracked_event_count = sum(
        isinstance(record, Event) and record.process in tracked for record in telemetry
    )
    exited = frozenset(
        record.process for record in telemetry if isinstance(record, ProcessExit)
    )
    if tracked_event_count < 1:
        raise ValueError("capture contains no event for the tracked workload process")
    if not tracked.issubset(exited):
        raise ValueError("capture is missing the tracked workload process exit")

    return CaptureAcceptance(
        run_id=manifest.run_id,
        raw_sha256=_sha256_file(capture),
        raw_bytes=capture.stat().st_size,
        runtime_manifest_sha256=_sha256_file(manifest_path),
        experiment_plan_sha256=_canonical_sha256(plan),
        capture_start_ns=start.capture_start_ns,
        capture_end_ns=end.timestamp_ns,
        duration_ns=duration_ns,
        record_count=len(records),
        event_count=sum(isinstance(record, Event) for record in telemetry),
        heartbeat_count=sum(isinstance(record, Heartbeat) for record in telemetry),
        process_exit_count=sum(isinstance(record, ProcessExit) for record in telemetry),
        tracked_event_count=tracked_event_count,
        total_lost_events=end.total_lost_events,
    )


def write_capture_acceptance(path: Path, acceptance: CaptureAcceptance) -> None:
    if not isinstance(acceptance, CaptureAcceptance):
        raise ValueError("capture acceptance is required")
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    with destination.open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(acceptance.to_dict(), stream, indent=2, sort_keys=True)
        stream.write("\n")


def _load_exact_plan(path: Path) -> dict[str, object]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ValueError("invalid experiment plan") from error
    expected = build_experiment_manifest()
    if not isinstance(value, dict) or value != expected:
        raise ValueError("experiment plan does not match the frozen 40-run design")
    return value


def _canonical_sha256(value: Mapping[str, object]) -> str:
    encoded = json.dumps(
        value, ensure_ascii=True, sort_keys=True, separators=(",", ":")
    ).encode("ascii")
    return hashlib.sha256(encoded).hexdigest()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()
