"""Safe, versioned model artifacts using skops instead of pickle/joblib."""
from __future__ import annotations

import hashlib
import json
import math
from dataclasses import dataclass
from importlib.metadata import version
from pathlib import Path
from typing import Sequence

import numpy as np
import skops.io

from ebpf_ransom_lab.features import FEATURE_NAMES, FEATURE_VERSION
from ebpf_ransom_lab.modeling import LabeledWindow, TrainingResult


ARTIFACT_VERSION = "model-artifact-v1"
MODEL_FILENAME = "model.skops"
MANIFEST_FILENAME = "manifest.json"


@dataclass(frozen=True, slots=True)
class LoadedArtifact:
    model_name: str
    threshold: float
    estimator: object | None
    feature_names: tuple[str, ...]
    feature_version: int
    training_manifest_hash: str

    def score(self, samples: Sequence[LabeledWindow]) -> tuple[float, ...]:
        for sample in samples:
            if sample.feature_version != self.feature_version or sample.feature_names != self.feature_names:
                raise ValueError("incompatible feature schema or order")
            if len(sample.features) != len(self.feature_names) or any(not math.isfinite(value) for value in sample.features):
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
        else:
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
        "model_name": result.selected_name,
        "model_format": model_format,
        "model_sha256": model_hash,
        "threshold": result.threshold,
        "score_semantics": "decision score; not a calibrated probability",
        "random_seed": result.random_seed,
        "training_manifest_hash": result.training_manifest_hash,
        "training_captures": list(result.training_captures),
        "dependencies": {
            name: version(name) for name in ("numpy", "scikit-learn", "skops")
        },
        "validation_metrics": {name: dict(values) for name, values in result.validation_metrics.items()},
        "test_metrics": dict(result.test_metrics),
        "report_sections": _plain(result.report_sections),
    }
    (target / MANIFEST_FILENAME).write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )


def load_artifact(target: Path) -> LoadedArtifact:
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

    estimator = None
    if manifest["model_format"] == "skops":
        model_path = target / MODEL_FILENAME
        if model_path.is_symlink() or _sha256(model_path) != manifest["model_sha256"]:
            raise ValueError("model file checksum mismatch")
        untrusted = skops.io.get_untrusted_types(file=model_path)
        if untrusted:
            raise ValueError("artifact contains unapproved serialized types")
        estimator = skops.io.load(model_path, trusted=[])
    return LoadedArtifact(
        model_name=manifest["model_name"],
        threshold=float(manifest["threshold"]),
        estimator=estimator,
        feature_names=tuple(manifest["feature_names"]),
        feature_version=manifest["feature_version"],
        training_manifest_hash=manifest["training_manifest_hash"],
    )


def _validate_manifest(manifest: object) -> None:
    if not isinstance(manifest, dict):
        raise ValueError("artifact manifest must be an object")
    if manifest.get("artifact_version") != ARTIFACT_VERSION:
        raise ValueError("unsupported artifact version")
    if manifest.get("feature_version") != FEATURE_VERSION or tuple(manifest.get("feature_names", ())) != FEATURE_NAMES:
        raise ValueError("incompatible feature schema or order")
    if manifest.get("model_name") not in {"rule", "rbf_svm", "random_forest"}:
        raise ValueError("unsupported model")
    expected_format = "builtin-rule" if manifest["model_name"] == "rule" else "skops"
    if manifest.get("model_format") != expected_format:
        raise ValueError("incompatible model format")
    threshold = manifest.get("threshold")
    if isinstance(threshold, bool) or not isinstance(threshold, (int, float)) or not math.isfinite(threshold):
        raise ValueError("invalid model threshold")
    digest = manifest.get("training_manifest_hash")
    if not isinstance(digest, str) or len(digest) != 64 or any(character not in "0123456789abcdef" for character in digest):
        raise ValueError("invalid training manifest hash")
    dependencies = manifest.get("dependencies")
    if not isinstance(dependencies, dict) or any(dependencies.get(name) != version(name) for name in ("numpy", "scikit-learn", "skops")):
        raise ValueError("incompatible dependency versions")


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _plain(value: object) -> object:
    if hasattr(value, "items"):
        return {str(key): _plain(item) for key, item in value.items()}
    if isinstance(value, (tuple, list)):
        return [_plain(item) for item in value]
    return value
