"""Build trainable rows only from explicitly labeled controlled captures."""
from __future__ import annotations

import json
import math
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping, Sequence

from ebpf_ransom_lab.contracts import FeatureWindow, ProcessIdentity
from ebpf_ransom_lab.modeling import LabeledWindow
from ebpf_ransom_lab.recording import read_jsonl
from ebpf_ransom_lab.workloads import (
    EXPERIMENT_WORKLOAD_HOLD_SECONDS,
    MAX_WORKLOAD_BYTES,
    MAX_WORKLOAD_FILES,
    MAX_WORKLOAD_SECONDS,
    SCENARIOS,
    plan_sha256,
    plan_workload,
    split_for_seed,
)


_LABELS = {"benign": 0, "suspicious": 1}
_SPLITS = {"training", "validation", "test"}


@dataclass(frozen=True, slots=True)
class WorkloadLabelManifest:
    run_id: str
    scenario: str
    seed: int
    split: str
    behavior_label: str
    plan_sha256: str
    tracked_processes: tuple[ProcessIdentity, ...]
    label_provenance: str
    background_activity: str
    status: str
    workload_hold_seconds: float

    @property
    def label(self) -> int:
        return _LABELS[self.behavior_label]


def load_workload_manifest(source: Mapping[str, object] | Path) -> WorkloadLabelManifest:
    if isinstance(source, Path):
        try:
            raw = json.loads(source.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as error:
            raise ValueError("invalid workload manifest") from error
    else:
        raw = dict(source)
    if not isinstance(raw, dict) or raw.get("schema_version") != 1:
        raise ValueError("unsupported workload manifest")
    run_id = raw.get("run_id")
    scenario = raw.get("scenario")
    seed = raw.get("seed")
    split = raw.get("split")
    behavior = raw.get("behavior_label")
    plan_digest = raw.get("plan_sha256")
    provenance = raw.get("label_provenance")
    background = raw.get("background_activity")
    status = raw.get("status")
    duration = raw.get("workload_hold_seconds")
    process_scope_policy = raw.get("process_scope_policy")
    limits = raw.get("limits")
    processes = raw.get("tracked_processes")
    if not isinstance(run_id, str) or not run_id:
        raise ValueError("workload manifest needs a run ID")
    if scenario not in SCENARIOS:
        raise ValueError("workload manifest has an unknown scenario")
    if type(seed) is not int:
        raise ValueError("workload manifest has an invalid seed")
    expected_run_id = f"controlled-{scenario}-seed-{seed}"
    if run_id != expected_run_id:
        raise ValueError("workload manifest run ID does not match scenario and seed")
    expected_split = split_for_seed(seed)
    if split not in _SPLITS:
        raise ValueError("workload manifest has an invalid split")
    if split != expected_split:
        raise ValueError("workload manifest split does not match the fixed seed policy")
    if behavior not in _LABELS:
        raise ValueError("workload manifest has an unknown behavior label")
    if behavior != SCENARIOS[scenario]:
        raise ValueError("workload manifest behavior label does not match scenario")
    expected_plan = plan_sha256(plan_workload(scenario, seed))
    if plan_digest != expected_plan:
        raise ValueError("workload manifest plan hash does not match the fixed workload plan")
    if provenance != "controlled_workload":
        raise ValueError("workload manifest lacks controlled label provenance")
    if status != "completed":
        raise ValueError("workload manifest must describe a completed workload")
    if (
        isinstance(duration, bool)
        or not isinstance(duration, (int, float))
        or not math.isfinite(duration)
        or float(duration) != float(EXPERIMENT_WORKLOAD_HOLD_SECONDS)
    ):
        raise ValueError(
            "workload manifest hold duration must be "
            f"{EXPERIMENT_WORKLOAD_HOLD_SECONDS:g} seconds"
        )
    if background != "unlabeled":
        raise ValueError("background activity must remain unlabeled")
    if process_scope_policy != "root_process_only":
        raise ValueError("workload manifest must label only the exact root process")
    expected_limits = {
        "max_seconds": MAX_WORKLOAD_SECONDS,
        "max_files": MAX_WORKLOAD_FILES,
        "max_bytes": MAX_WORKLOAD_BYTES,
    }
    if limits != expected_limits:
        raise ValueError("workload manifest does not use the fixed experiment limits")
    if not isinstance(processes, list) or len(processes) != 1:
        raise ValueError("workload manifest must track exactly one root process")
    identities = []
    for value in processes:
        if not isinstance(value, Mapping):
            raise ValueError("tracked process must be an object")
        try:
            identities.append(ProcessIdentity(
                boot_id=value["boot_id"], tgid=value["tgid"], start_time_ns=value["start_time_ns"],
            ))
        except (KeyError, ValueError) as error:
            raise ValueError("invalid tracked process identity") from error
    if len(set(identities)) != len(identities):
        raise ValueError("duplicate tracked process identity")
    return WorkloadLabelManifest(
        run_id=run_id, scenario=scenario, seed=seed, split=split, behavior_label=behavior,
        plan_sha256=plan_digest, tracked_processes=tuple(identities),
        label_provenance=provenance, background_activity=background,
        status=status, workload_hold_seconds=float(duration),
    )


def read_feature_windows(path: Path) -> tuple[FeatureWindow, ...]:
    records = read_jsonl(path)
    if not records or any(not isinstance(record, FeatureWindow) for record in records):
        raise ValueError("feature input must contain only feature-window records")
    return tuple(records)


def build_labeled_windows(
    windows: Sequence[FeatureWindow], manifest: WorkloadLabelManifest, *, capture_hash: str
) -> tuple[LabeledWindow, ...]:
    if not isinstance(manifest, WorkloadLabelManifest):
        raise ValueError("invalid workload label manifest")
    if len(capture_hash) != 64 or any(character not in "0123456789abcdef" for character in capture_hash):
        raise ValueError("capture hash must be lowercase SHA-256")
    if any(window.run_id != manifest.run_id for window in windows):
        raise ValueError("feature window run ID does not match manifest")
    tracked = frozenset(manifest.tracked_processes)
    return tuple(
        LabeledWindow(
            window_id=window.window_id,
            capture_id=manifest.run_id,
            capture_hash=capture_hash,
            split=manifest.split,
            label=manifest.label,
            feature_version=window.feature_version,
            feature_names=window.feature_names,
            features=tuple(float(value) for value in window.values),
            complete=True,
            quality="good",
        )
        for window in windows
        if window.process in tracked and window.classifiable
    )


def write_labeled_windows(path: Path, rows: Sequence[LabeledWindow]) -> None:
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.exists():
        raise FileExistsError(f"refusing to overwrite {destination}")
    with destination.open("w", encoding="utf-8", newline="\n") as stream:
        for row in rows:
            stream.write(json.dumps(row.as_dict(), sort_keys=True, separators=(",", ":")) + "\n")
