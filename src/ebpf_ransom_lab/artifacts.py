"""Strict, versioned model artifacts using skops instead of pickle/joblib."""

from __future__ import annotations

import hashlib
import json
import math
from dataclasses import dataclass
from importlib.metadata import version
from pathlib import Path
from typing import Mapping, Sequence

import numpy as np
import skops.io

from ebpf_ransom_lab.features import FEATURE_NAMES, FEATURE_SEMANTICS, FEATURE_VERSION
from ebpf_ransom_lab.modeling import LabeledWindow, TrainingResult


ARTIFACT_VERSION = "model-artifact-v3"
MODEL_FILENAME = "model.skops"
MANIFEST_FILENAME = "manifest.json"
EVALUATION_FILENAME = "test-evaluation.json"
SCORE_SEMANTICS = "decision score; not a calibrated probability"
PUBLISHED_DATA_REASON = (
    "The published training labels do not establish benign ground truth."
)
_RATE_METRICS = frozenset(("precision", "recall", "f1"))
_COUNT_METRICS = frozenset(
    ("true_negatives", "false_positives", "false_negatives", "true_positives")
)
_MODEL_NAMES = frozenset(("rule", "rbf_svm", "random_forest"))
_DEPENDENCIES = frozenset(("numpy", "scikit-learn", "skops"))


@dataclass(frozen=True, slots=True)
class LoadedArtifact:
    model_name: str
    threshold: float
    estimator: object | None
    feature_names: tuple[str, ...]
    feature_version: int
    selection_manifest_hash: str
    experiment_dataset_manifest_sha256: str
    selection_dataset_sha256: str

    def score(self, samples: Sequence[LabeledWindow]) -> tuple[float, ...]:
        for sample in samples:
            if (
                sample.feature_version != self.feature_version
                or sample.feature_names != self.feature_names
            ):
                raise ValueError("incompatible feature schema or order")
            if len(sample.features) != len(self.feature_names) or any(
                not math.isfinite(value) for value in sample.features
            ):
                raise ValueError("invalid numeric feature vector")
        matrix = np.asarray([sample.features for sample in samples], dtype=float)
        if self.model_name == "rule":
            create_index = self.feature_names.index("C_sum")
            delete_index = self.feature_names.index("D_sum")
            values = (matrix[:, create_index] + matrix[:, delete_index]) / 10.0
        elif self.model_name == "rbf_svm":
            values = self.estimator.decision_function(matrix)
        elif self.model_name == "random_forest":
            values = self.estimator.predict_proba(matrix)[:, 1]
        else:  # Validated manifests cannot reach this branch.
            raise ValueError("unsupported model")
        return tuple(float(value) for value in values)


def save_artifact(target: Path, result: TrainingResult) -> None:
    target = Path(target)
    if target.exists():
        raise FileExistsError(f"artifact directory already exists: {target}")
    target.mkdir(parents=True)
    model_hash = None
    model_format = "builtin-rule"
    if result.estimator is not None:
        model_path = target / MODEL_FILENAME
        skops.io.dump(result.estimator, model_path)
        model_hash = _sha256(model_path)
        model_format = "skops"
    manifest = {
        "artifact_version": ARTIFACT_VERSION,
        "feature_version": result.feature_version,
        "feature_names": list(result.feature_names),
        "feature_semantics": FEATURE_SEMANTICS,
        "model_name": result.selected_name,
        "model_format": model_format,
        "model_sha256": model_hash,
        "threshold": result.threshold,
        "score_semantics": SCORE_SEMANTICS,
        "random_seed": result.random_seed,
        "selection_manifest_hash": result.selection_manifest_hash,
        "experiment_dataset_manifest_sha256": (
            result.experiment_dataset_manifest_sha256
        ),
        "selection_dataset_sha256": result.selection_dataset_sha256,
        "selection_captures": list(result.selection_captures),
        "dependencies": {name: version(name) for name in sorted(_DEPENDENCIES)},
        "validation_metrics": {
            name: dict(values) for name, values in result.validation_metrics.items()
        },
        "report_sections": _plain(result.report_sections),
    }
    _validate_manifest(manifest)
    (target / MANIFEST_FILENAME).write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )


def load_artifact_metadata(target: Path) -> dict[str, object]:
    target = Path(target)
    if target.is_symlink() or not target.is_dir():
        raise ValueError("artifact must be a non-symlink directory")
    manifest_path = target / MANIFEST_FILENAME
    if manifest_path.is_symlink():
        raise ValueError("artifact manifest cannot be a symlink")
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ValueError("invalid artifact manifest") from error
    _validate_manifest(manifest)

    allowed_files = {MANIFEST_FILENAME, EVALUATION_FILENAME}
    if manifest["model_format"] == "skops":
        allowed_files.add(MODEL_FILENAME)
    unexpected = sorted(path.name for path in target.iterdir() if path.name not in allowed_files)
    if unexpected:
        raise ValueError(f"artifact contains unexpected files: {unexpected}")
    if manifest["model_format"] == "builtin-rule" and (target / MODEL_FILENAME).exists():
        raise ValueError("builtin rule artifact cannot contain a model file")
    return manifest


def load_artifact(target: Path) -> LoadedArtifact:
    target = Path(target)
    manifest = load_artifact_metadata(target)
    estimator = None
    if manifest["model_format"] == "skops":
        model_path = target / MODEL_FILENAME
        if (
            model_path.is_symlink()
            or not model_path.is_file()
            or _sha256(model_path) != manifest["model_sha256"]
        ):
            raise ValueError("model file checksum mismatch")
        untrusted = skops.io.get_untrusted_types(file=model_path)
        if untrusted:
            raise ValueError("artifact contains unapproved serialized types")
        estimator = skops.io.load(model_path, trusted=[])
    return LoadedArtifact(
        model_name=str(manifest["model_name"]),
        threshold=float(manifest["threshold"]),
        estimator=estimator,
        feature_names=tuple(manifest["feature_names"]),
        feature_version=int(manifest["feature_version"]),
        selection_manifest_hash=str(manifest["selection_manifest_hash"]),
        experiment_dataset_manifest_sha256=str(
            manifest["experiment_dataset_manifest_sha256"]
        ),
        selection_dataset_sha256=str(manifest["selection_dataset_sha256"]),
    )


def save_test_evaluation(
    target: Path,
    *,
    dataset_sha256: str,
    experiment_dataset_manifest_sha256: str,
    metrics: Mapping[str, float | int],
) -> None:
    """Persist the one allowed held-out evaluation without rewriting the artifact."""

    artifact = Path(target)
    loaded = load_artifact(artifact)
    _validate_digest(dataset_sha256, "test dataset")
    _validate_digest(
        experiment_dataset_manifest_sha256, "experiment dataset manifest"
    )
    if (
        experiment_dataset_manifest_sha256
        != loaded.experiment_dataset_manifest_sha256
    ):
        raise ValueError("test dataset manifest does not match the selected artifact")
    plain_metrics = _validated_metrics(metrics, "test metrics")
    destination = artifact / EVALUATION_FILENAME
    artifact_manifest_sha256 = _sha256(artifact / MANIFEST_FILENAME)
    with destination.open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(
            {
                "schema_version": 2,
                "split": "test",
                "dataset_sha256": dataset_sha256,
                "experiment_dataset_manifest_sha256": (
                    experiment_dataset_manifest_sha256
                ),
                "artifact_manifest_sha256": artifact_manifest_sha256,
                "metrics": plain_metrics,
            },
            stream,
            indent=2,
            sort_keys=True,
        )
        stream.write("\n")


def load_test_evaluation(target: Path) -> dict[str, object]:
    artifact = Path(target)
    path = artifact / EVALUATION_FILENAME
    if path.is_symlink():
        raise ValueError("test evaluation cannot be a symlink")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ValueError("held-out test has not been evaluated exactly once") from error
    if (
        not isinstance(value, dict)
        or set(value) != {
            "schema_version", "split", "dataset_sha256",
            "experiment_dataset_manifest_sha256", "artifact_manifest_sha256",
            "metrics",
        }
        or value.get("schema_version") != 2
        or value.get("split") != "test"
    ):
        raise ValueError("invalid test evaluation record")
    _validate_digest(value.get("dataset_sha256"), "test dataset")
    _validate_digest(
        value.get("experiment_dataset_manifest_sha256"),
        "experiment dataset manifest",
    )
    _validate_digest(value.get("artifact_manifest_sha256"), "artifact manifest")
    if value["artifact_manifest_sha256"] != _sha256(artifact / MANIFEST_FILENAME):
        raise ValueError("test evaluation belongs to a different artifact")
    metadata = load_artifact_metadata(artifact)
    if (
        value["experiment_dataset_manifest_sha256"]
        != metadata["experiment_dataset_manifest_sha256"]
    ):
        raise ValueError("test evaluation uses a different experiment dataset manifest")
    value["metrics"] = _validated_metrics(value.get("metrics"), "test metrics")
    return value


def _validate_manifest(manifest: object) -> None:
    if not isinstance(manifest, dict):
        raise ValueError("artifact manifest must be an object")
    if set(manifest) != {
        "artifact_version", "feature_version", "feature_names", "feature_semantics",
        "model_name", "model_format", "model_sha256", "threshold",
        "score_semantics", "random_seed", "selection_manifest_hash",
        "experiment_dataset_manifest_sha256", "selection_dataset_sha256",
        "selection_captures", "dependencies", "validation_metrics",
        "report_sections",
    }:
        raise ValueError("artifact manifest has unexpected or missing fields")
    if manifest.get("artifact_version") != ARTIFACT_VERSION:
        raise ValueError("unsupported artifact version")
    if (
        manifest.get("feature_version") != FEATURE_VERSION
        or tuple(manifest.get("feature_names", ())) != FEATURE_NAMES
        or manifest.get("feature_semantics") != FEATURE_SEMANTICS
    ):
        raise ValueError("incompatible feature schema, order, or semantics")
    if manifest.get("model_name") not in _MODEL_NAMES:
        raise ValueError("unsupported model")
    expected_format = "builtin-rule" if manifest["model_name"] == "rule" else "skops"
    if manifest.get("model_format") != expected_format:
        raise ValueError("incompatible model format")
    model_hash = manifest.get("model_sha256")
    if expected_format == "builtin-rule":
        if model_hash is not None:
            raise ValueError("builtin rule cannot declare a serialized model hash")
    else:
        _validate_digest(model_hash, "model")
    threshold = manifest.get("threshold")
    if (
        isinstance(threshold, bool)
        or not isinstance(threshold, (int, float))
        or not math.isfinite(threshold)
    ):
        raise ValueError("invalid model threshold")
    if manifest.get("score_semantics") != SCORE_SEMANTICS:
        raise ValueError("invalid score semantics")
    random_seed = manifest.get("random_seed")
    if type(random_seed) is not int or not 0 <= random_seed < 2**64:
        raise ValueError("invalid model random seed")
    _validate_digest(manifest.get("selection_manifest_hash"), "selection manifest")
    _validate_digest(
        manifest.get("experiment_dataset_manifest_sha256"),
        "experiment dataset manifest",
    )
    _validate_digest(manifest.get("selection_dataset_sha256"), "selection dataset")
    captures = manifest.get("selection_captures")
    if (
        not isinstance(captures, list)
        or not captures
        or any(not isinstance(item, str) or not item for item in captures)
        or captures != sorted(set(captures))
    ):
        raise ValueError("invalid selection capture list")
    dependencies = manifest.get("dependencies")
    if (
        not isinstance(dependencies, dict)
        or set(dependencies) != _DEPENDENCIES
        or any(dependencies.get(name) != version(name) for name in _DEPENDENCIES)
    ):
        raise ValueError("incompatible dependency versions")

    metrics = manifest.get("validation_metrics")
    if not isinstance(metrics, dict) or set(metrics) != _MODEL_NAMES:
        raise ValueError("invalid validation metric sets")
    validated_metrics = {
        name: _validated_metrics(value, f"validation metrics for {name}")
        for name, value in metrics.items()
    }
    sample_counts = {
        sum(int(values[key]) for key in _COUNT_METRICS)
        for values in validated_metrics.values()
    }
    if len(sample_counts) != 1 or next(iter(sample_counts)) < 1:
        raise ValueError("validation metrics do not cover the same nonempty sample set")
    sections = manifest.get("report_sections")
    if not isinstance(sections, dict) or set(sections) != {
        "controlled_workloads", "published_data"
    }:
        raise ValueError("invalid report sections")
    controlled = sections["controlled_workloads"]
    if (
        not isinstance(controlled, dict)
        or set(controlled) != {"status", "selected_model", "validation"}
        or controlled.get("status") != "selected_not_tested"
        or controlled.get("selected_model") != manifest["model_name"]
        or controlled.get("validation") != validated_metrics[manifest["model_name"]]
    ):
        raise ValueError("controlled-workload report section is inconsistent")
    published = sections["published_data"]
    if (
        not isinstance(published, dict)
        or set(published) != {"status", "reason"}
        or published.get("status") != "blocked_label_provenance"
        or published.get("reason") != PUBLISHED_DATA_REASON
    ):
        raise ValueError("published-data report section is invalid")


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
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


def _validated_metrics(value: object, name: str) -> dict[str, float | int]:
    if not isinstance(value, Mapping):
        raise ValueError(f"invalid {name}")
    metrics = dict(value)
    if set(metrics) != _RATE_METRICS | _COUNT_METRICS | {"mcc"}:
        raise ValueError(f"invalid {name}")
    if any(
        isinstance(metrics[key], bool)
        or not isinstance(metrics[key], (int, float))
        or not math.isfinite(float(metrics[key]))
        or not 0 <= float(metrics[key]) <= 1
        for key in _RATE_METRICS
    ):
        raise ValueError(f"invalid {name}")
    if (
        isinstance(metrics["mcc"], bool)
        or not isinstance(metrics["mcc"], (int, float))
        or not math.isfinite(float(metrics["mcc"]))
        or not -1 <= float(metrics["mcc"]) <= 1
    ):
        raise ValueError(f"invalid {name}")
    if any(
        isinstance(metrics[key], bool)
        or not isinstance(metrics[key], int)
        or metrics[key] < 0
        for key in _COUNT_METRICS
    ):
        raise ValueError(f"invalid {name}")
    expected = _metrics_from_counts(metrics)
    if any(
        not math.isclose(
            float(metrics[key]), expected[key], rel_tol=1e-12, abs_tol=1e-12
        )
        for key in (*_RATE_METRICS, "mcc")
    ):
        raise ValueError(f"{name} do not agree with their confusion counts")
    return metrics


def _metrics_from_counts(metrics: Mapping[str, float | int]) -> dict[str, float]:
    tn = int(metrics["true_negatives"])
    fp = int(metrics["false_positives"])
    fn = int(metrics["false_negatives"])
    tp = int(metrics["true_positives"])
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    denominator = math.sqrt((tp + fp) * (tp + fn) * (tn + fp) * (tn + fn))
    mcc = (tp * tn - fp * fn) / denominator if denominator else 0.0
    return {"precision": precision, "recall": recall, "f1": f1, "mcc": mcc}


def _plain(value: object) -> object:
    if hasattr(value, "items"):
        return {str(key): _plain(item) for key, item in value.items()}
    if isinstance(value, (tuple, list)):
        return [_plain(item) for item in value]
    return value
