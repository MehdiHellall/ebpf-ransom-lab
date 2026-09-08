"""Build trainable rows only from explicitly labeled controlled captures."""
from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping, Sequence

from ebpf_ransom_lab.contracts import FeatureWindow, ProcessIdentity
from ebpf_ransom_lab.modeling import LabeledWindow
from ebpf_ransom_lab.recording import read_jsonl


_LABELS = {"benign": 0, "suspicious": 1}
_SPLITS = {"training", "validation", "test"}


@dataclass(frozen=True, slots=True)
class WorkloadLabelManifest:
    run_id: str
    split: str
    behavior_label: str
    tracked_processes: tuple[ProcessIdentity, ...]
    label_provenance: str
    background_activity: str

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
    split = raw.get("split")
    behavior = raw.get("behavior_label")
    provenance = raw.get("label_provenance")
    background = raw.get("background_activity")
    processes = raw.get("tracked_processes")
    if not isinstance(run_id, str) or not run_id:
        raise ValueError("workload manifest needs a run ID")
    if split not in _SPLITS:
        raise ValueError("workload manifest has an invalid split")
    if behavior not in _LABELS:
        raise ValueError("workload manifest has an unknown behavior label")
    if provenance != "controlled_workload":
        raise ValueError("workload manifest lacks controlled label provenance")
    if background != "unlabeled":
        raise ValueError("background activity must remain unlabeled")
    if not isinstance(processes, list) or not processes:
        raise ValueError("workload manifest needs tracked processes")
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
        run_id=run_id, split=split, behavior_label=behavior,
        tracked_processes=tuple(identities), label_provenance=provenance,
        background_activity=background,
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
