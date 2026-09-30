"""Build trainable rows only from explicitly labeled controlled captures."""
from __future__ import annotations

import json
import hashlib
import math
import shutil
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping, Sequence

from ebpf_ransom_lab.contracts import FeatureWindow, ProcessIdentity
from ebpf_ransom_lab.features import FEATURE_NAMES, FEATURE_VERSION
from ebpf_ransom_lab.modeling import LabeledWindow, load_dataset
from ebpf_ransom_lab.recording import read_jsonl
from ebpf_ransom_lab.workloads import (
    EXPERIMENT_WORKLOAD_HOLD_SECONDS,
    MAX_WORKLOAD_BYTES,
    MAX_WORKLOAD_FILES,
    MAX_WORKLOAD_SECONDS,
    SCENARIOS,
    build_experiment_manifest,
    plan_sha256,
    plan_workload,
    split_for_seed,
)


_LABELS = {"benign": 0, "suspicious": 1}
_SPLITS = {"training", "validation", "test"}
DATASET_MANIFEST_VERSION = 1
DATASET_FILENAMES = {
    "all": "all.jsonl",
    "selection": "selection.jsonl",
    "test": "test.jsonl",
}


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


def assemble_experiment_dataset(
    input_directory: Path, experiment_plan_path: Path, output_directory: Path
) -> dict[str, object]:
    """Assemble all 40 per-run files and bind every output byte and row."""

    source = Path(input_directory)
    destination = Path(output_directory)
    if destination.exists():
        raise FileExistsError(f"refusing to overwrite {destination}")
    plan = _load_exact_experiment_plan(Path(experiment_plan_path))
    planned_runs = tuple(plan["runs"])
    expected_names = {f"{run['run_id']}.jsonl" for run in planned_runs}
    actual_names = {path.name for path in source.glob("*.jsonl") if path.is_file()}
    missing = sorted(expected_names - actual_names)
    unexpected = sorted(actual_names - expected_names)
    if missing or unexpected:
        raise ValueError(
            f"per-run dataset files do not match the 40-run plan; "
            f"missing={missing}, unexpected={unexpected}"
        )

    all_rows: list[LabeledWindow] = []
    captures: list[dict[str, object]] = []
    seen_window_ids: set[str] = set()
    seen_capture_hashes: set[str] = set()
    for planned in planned_runs:
        run_id = str(planned["run_id"])
        path = source / f"{run_id}.jsonl"
        with path.open(encoding="utf-8") as stream:
            rows = load_dataset(stream)
        if not rows or any(row.capture_id != run_id for row in rows):
            raise ValueError(f"dataset {run_id} does not contain only its planned capture")
        expected_label = _LABELS[str(planned["behavior_label"])]
        expected_split = str(planned["split"])
        if any(row.label != expected_label or row.split != expected_split for row in rows):
            raise ValueError(f"dataset {run_id} label or split disagrees with the plan")
        capture_hashes = {row.capture_hash for row in rows}
        if len(capture_hashes) != 1:
            raise ValueError(f"dataset {run_id} contains multiple raw capture hashes")
        capture_hash = next(iter(capture_hashes))
        if capture_hash in seen_capture_hashes:
            raise ValueError("the same raw capture hash is assigned to multiple planned runs")
        seen_capture_hashes.add(capture_hash)
        ordered = tuple(sorted(rows, key=lambda row: row.window_id))
        for row in ordered:
            if row.window_id in seen_window_ids:
                raise ValueError(f"duplicate window ID in aggregate dataset: {row.window_id}")
            seen_window_ids.add(row.window_id)
        all_rows.extend(ordered)
        captures.append({
            "run_id": run_id,
            "scenario": planned["scenario"],
            "seed": planned["seed"],
            "split": expected_split,
            "label": expected_label,
            "capture_sha256": capture_hash,
            "row_count": len(ordered),
            "row_content_sha256": labeled_rows_sha256(ordered),
        })

    grouped = {
        "all": tuple(all_rows),
        "selection": tuple(row for row in all_rows if row.split != "test"),
        "test": tuple(row for row in all_rows if row.split == "test"),
    }
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = Path(tempfile.mkdtemp(prefix=f".{destination.name}-", dir=destination.parent))
    try:
        datasets: dict[str, object] = {}
        for role, rows in grouped.items():
            filename = DATASET_FILENAMES[role]
            path = temporary / filename
            write_labeled_windows(path, rows)
            datasets[role] = {
                "filename": filename,
                "sha256": _sha256_file(path),
                "row_content_sha256": labeled_rows_sha256(rows),
                "row_count": len(rows),
                "splits": sorted({row.split for row in rows}),
            }
        manifest = {
            "schema_version": DATASET_MANIFEST_VERSION,
            "experiment": plan["experiment"],
            "experiment_plan_sha256": _canonical_sha256(plan),
            "feature_version": FEATURE_VERSION,
            "feature_names": list(FEATURE_NAMES),
            "expected_run_count": len(planned_runs),
            "row_count": len(all_rows),
            "row_content_sha256": labeled_rows_sha256(all_rows),
            "datasets": datasets,
            "captures": captures,
        }
        (temporary / "manifest.json").write_text(
            json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        temporary.rename(destination)
    except Exception:
        shutil.rmtree(temporary, ignore_errors=True)
        raise
    return manifest


def load_manifest_bound_dataset(
    dataset_path: Path, manifest_path: Path, *, role: str
) -> tuple[tuple[LabeledWindow, ...], str]:
    """Load a dataset only when its exact bytes and full rows match its manifest."""

    if role not in DATASET_FILENAMES:
        raise ValueError("unknown aggregate dataset role")
    manifest_file = Path(manifest_path)
    try:
        manifest = json.loads(manifest_file.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ValueError("invalid aggregate dataset manifest") from error
    _validate_dataset_manifest(manifest)
    entry = manifest["datasets"][role]
    dataset = Path(dataset_path)
    if dataset.name != entry["filename"]:
        raise ValueError(f"dataset filename does not match manifest role {role}")
    if _sha256_file(dataset) != entry["sha256"]:
        raise ValueError("dataset byte hash does not match aggregate manifest")
    with dataset.open(encoding="utf-8") as stream:
        rows = load_dataset(stream)
    if len(rows) != entry["row_count"]:
        raise ValueError("dataset row count does not match aggregate manifest")
    if labeled_rows_sha256(rows) != entry["row_content_sha256"]:
        raise ValueError("dataset row content does not match aggregate manifest")
    if sorted({row.split for row in rows}) != entry["splits"]:
        raise ValueError("dataset splits do not match aggregate manifest")
    included_splits = set(entry["splits"])
    expected_captures = {
        capture["run_id"]: capture
        for capture in manifest["captures"]
        if capture["split"] in included_splits
    }
    actual_captures = {row.capture_id for row in rows}
    if actual_captures != set(expected_captures):
        raise ValueError("dataset does not contain every capture required by its role")
    for run_id, capture in expected_captures.items():
        capture_rows = tuple(row for row in rows if row.capture_id == run_id)
        if (
            len(capture_rows) != capture["row_count"]
            or labeled_rows_sha256(capture_rows) != capture["row_content_sha256"]
            or {row.capture_hash for row in capture_rows} != {capture["capture_sha256"]}
            or {row.label for row in capture_rows} != {capture["label"]}
            or {row.split for row in capture_rows} != {capture["split"]}
        ):
            raise ValueError(f"dataset capture content does not match manifest: {run_id}")
    if role == "all" and labeled_rows_sha256(rows) != manifest["row_content_sha256"]:
        raise ValueError("all-dataset content does not match aggregate row hash")
    return rows, _sha256_file(manifest_file)


def labeled_rows_sha256(rows: Sequence[LabeledWindow]) -> str:
    """Hash complete canonical row content independent of file ordering."""

    ordered = sorted(
        (row.as_dict() for row in rows),
        key=lambda row: (str(row["capture_id"]), str(row["window_id"])),
    )
    encoded = json.dumps(
        ordered, ensure_ascii=True, sort_keys=True, separators=(",", ":")
    ).encode("ascii")
    return hashlib.sha256(encoded).hexdigest()


def _load_exact_experiment_plan(path: Path) -> dict[str, object]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ValueError("invalid experiment plan") from error
    expected = build_experiment_manifest()
    if not isinstance(value, dict) or value != expected:
        raise ValueError("experiment plan does not match the frozen 40-run design")
    return value


def _validate_dataset_manifest(value: object) -> None:
    if not isinstance(value, dict) or set(value) != {
        "schema_version", "experiment", "experiment_plan_sha256",
        "feature_version", "feature_names", "expected_run_count", "row_count",
        "row_content_sha256", "datasets", "captures",
    }:
        raise ValueError("invalid aggregate dataset manifest fields")
    if value["schema_version"] != DATASET_MANIFEST_VERSION:
        raise ValueError("unsupported aggregate dataset manifest version")
    expected_plan = build_experiment_manifest()
    if (
        value["experiment"] != expected_plan["experiment"]
        or value["experiment_plan_sha256"] != _canonical_sha256(expected_plan)
        or value["feature_version"] != FEATURE_VERSION
        or tuple(value["feature_names"]) != FEATURE_NAMES
        or value["expected_run_count"] != len(expected_plan["runs"])
    ):
        raise ValueError("aggregate dataset manifest is incompatible with the experiment")
    _validate_digest(value["row_content_sha256"], "aggregate row content")
    datasets = value["datasets"]
    if not isinstance(datasets, dict) or set(datasets) != set(DATASET_FILENAMES):
        raise ValueError("invalid aggregate dataset entries")
    expected_splits = {
        "all": ["test", "training", "validation"],
        "selection": ["training", "validation"],
        "test": ["test"],
    }
    for role, filename in DATASET_FILENAMES.items():
        entry = datasets[role]
        if not isinstance(entry, dict) or set(entry) != {
            "filename", "sha256", "row_content_sha256", "row_count", "splits"
        }:
            raise ValueError("invalid aggregate dataset entry")
        if entry["filename"] != filename or entry["splits"] != expected_splits[role]:
            raise ValueError("aggregate dataset role metadata is invalid")
        _validate_digest(entry["sha256"], f"{role} dataset")
        _validate_digest(entry["row_content_sha256"], f"{role} row content")
        if type(entry["row_count"]) is not int or entry["row_count"] < 1:
            raise ValueError("aggregate dataset row count is invalid")
    captures = value["captures"]
    planned = expected_plan["runs"]
    if not isinstance(captures, list) or len(captures) != len(planned):
        raise ValueError("aggregate manifest must contain all 40 captures")
    total_rows = 0
    for actual, expected in zip(captures, planned, strict=True):
        if not isinstance(actual, dict) or set(actual) != {
            "run_id", "scenario", "seed", "split", "label", "capture_sha256",
            "row_count", "row_content_sha256",
        }:
            raise ValueError("invalid aggregate capture entry")
        if (
            actual["run_id"] != expected["run_id"]
            or actual["scenario"] != expected["scenario"]
            or actual["seed"] != expected["seed"]
            or actual["split"] != expected["split"]
            or actual["label"] != _LABELS[expected["behavior_label"]]
        ):
            raise ValueError("aggregate capture entry disagrees with the experiment plan")
        _validate_digest(actual["capture_sha256"], "raw capture")
        _validate_digest(actual["row_content_sha256"], "capture row content")
        if type(actual["row_count"]) is not int or actual["row_count"] < 1:
            raise ValueError("capture row count is invalid")
        total_rows += actual["row_count"]
    if type(value["row_count"]) is not int or value["row_count"] != total_rows:
        raise ValueError("aggregate row count does not match capture entries")
    if datasets["all"]["row_count"] != total_rows:
        raise ValueError("all-dataset row count does not match aggregate rows")
    if datasets["all"]["row_content_sha256"] != value["row_content_sha256"]:
        raise ValueError("all-dataset hash does not match aggregate row hash")
    capture_hashes = [capture["capture_sha256"] for capture in captures]
    if len(set(capture_hashes)) != len(capture_hashes):
        raise ValueError("aggregate manifest repeats a raw capture hash")
    expected_selection_rows = sum(
        capture["row_count"] for capture in captures if capture["split"] != "test"
    )
    expected_test_rows = sum(
        capture["row_count"] for capture in captures if capture["split"] == "test"
    )
    if (
        datasets["selection"]["row_count"] != expected_selection_rows
        or datasets["test"]["row_count"] != expected_test_rows
    ):
        raise ValueError("split dataset row counts do not match capture entries")


def _canonical_sha256(value: object) -> str:
    encoded = json.dumps(
        value, ensure_ascii=True, sort_keys=True, separators=(",", ":")
    ).encode("ascii")
    return hashlib.sha256(encoded).hexdigest()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _validate_digest(value: object, name: str) -> None:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise ValueError(f"invalid {name} hash")
