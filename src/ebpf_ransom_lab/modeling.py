"""Leakage-resistant model selection for controlled-workload windows."""
from __future__ import annotations

import hashlib
import json
import math
from dataclasses import dataclass
from types import MappingProxyType
from typing import Iterable, Mapping, Sequence

import numpy as np
from sklearn.base import clone
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import confusion_matrix, f1_score, matthews_corrcoef, precision_score, recall_score
from sklearn.model_selection import StratifiedGroupKFold
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.svm import SVC

from ebpf_ransom_lab.features import FEATURE_NAMES, FEATURE_VERSION


SPLITS = frozenset(("training", "validation", "test"))
MODEL_COMPLEXITY = {"rule": 0, "rbf_svm": 1, "random_forest": 2}


@dataclass(frozen=True, slots=True)
class LabeledWindow:
    window_id: str
    capture_id: str
    capture_hash: str
    split: str
    label: int | None
    feature_version: int
    feature_names: tuple[str, ...]
    features: tuple[float, ...]
    complete: bool
    quality: str

    def as_dict(self) -> dict[str, object]:
        return {
            "window_id": self.window_id,
            "capture_id": self.capture_id,
            "capture_hash": self.capture_hash,
            "split": self.split,
            "label": self.label,
            "feature_version": self.feature_version,
            "feature_names": self.feature_names,
            "features": self.features,
            "complete": self.complete,
            "quality": self.quality,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, object]) -> "LabeledWindow":
        expected = set(cls.__dataclass_fields__)
        if set(value) != expected:
            raise ValueError("unexpected labeled-window fields")
        return cls(
            window_id=str(value["window_id"]),
            capture_id=str(value["capture_id"]),
            capture_hash=str(value["capture_hash"]),
            split=str(value["split"]),
            label=value["label"] if value["label"] is None else int(value["label"]),
            feature_version=int(value["feature_version"]),
            feature_names=tuple(str(item) for item in value["feature_names"]),
            features=tuple(float(item) for item in value["features"]),
            complete=value["complete"] is True,
            quality=str(value["quality"]),
        )


@dataclass(frozen=True, slots=True)
class TrainingResult:
    selected_name: str
    threshold: float
    estimator: object | None
    feature_names: tuple[str, ...]
    feature_version: int
    random_seed: int
    training_manifest_hash: str
    training_captures: tuple[str, ...]
    validation_metrics: Mapping[str, Mapping[str, float | int]]
    test_metrics: Mapping[str, float | int]
    report_sections: Mapping[str, Mapping[str, object]]

    def score(self, samples: Sequence[LabeledWindow]) -> tuple[float, ...]:
        _validate_feature_compatibility(samples, self.feature_version, self.feature_names)
        matrix = np.asarray([sample.features for sample in samples], dtype=float)
        return tuple(float(value) for value in _score(self.selected_name, self.estimator, matrix, self.feature_names))


def validate_dataset(samples: Sequence[LabeledWindow]) -> None:
    if not samples:
        raise ValueError("dataset is empty")
    _validate_feature_compatibility(samples, FEATURE_VERSION, FEATURE_NAMES)
    capture_splits: dict[str, str] = {}
    hash_splits: dict[str, str] = {}
    for sample in samples:
        if sample.split not in SPLITS:
            raise ValueError("unknown split")
        if sample.label not in (0, 1):
            raise ValueError("unlabeled windows cannot be used for training")
        if not sample.complete or sample.quality != "good":
            raise ValueError("only complete good-quality windows can be trained")
        if not sample.window_id or not sample.capture_id:
            raise ValueError("window and capture identifiers are required")
        if len(sample.capture_hash) != 64 or any(character not in "0123456789abcdef" for character in sample.capture_hash):
            raise ValueError("capture hash must be lowercase SHA-256")
        prior = capture_splits.setdefault(sample.capture_id, sample.split)
        if prior != sample.split:
            raise ValueError("capture appears across splits")
        hash_prior = hash_splits.setdefault(sample.capture_hash, sample.split)
        if hash_prior != sample.split:
            raise ValueError("capture hash appears across splits")


def load_dataset(lines: Iterable[str]) -> tuple[LabeledWindow, ...]:
    samples: list[LabeledWindow] = []
    for line_number, line in enumerate(lines, start=1):
        if not line.strip():
            continue
        try:
            value = json.loads(line)
            if not isinstance(value, dict):
                raise ValueError("row must be an object")
            samples.append(LabeledWindow.from_dict(value))
        except (TypeError, ValueError, json.JSONDecodeError) as error:
            raise ValueError(f"invalid dataset line {line_number}: {error}") from error
    result = tuple(samples)
    validate_dataset(result)
    return result


def train_and_select(samples: Sequence[LabeledWindow], *, random_seed: int = 37) -> TrainingResult:
    """Tune only on training groups, select on validation, and test once."""
    samples = tuple(samples)
    validate_dataset(samples)
    by_split = {name: tuple(sample for sample in samples if sample.split == name) for name in SPLITS}
    if any(not by_split[name] for name in SPLITS):
        raise ValueError("training, validation, and test samples are required")

    training = by_split["training"]
    train_x, train_y, groups = _arrays(training)
    _validate_cv_groups(train_y, groups)
    finalists: dict[str, object | None] = {"rule": None}
    finalists["rbf_svm"] = _fit_best_svm(train_x, train_y, groups, random_seed)
    finalists["random_forest"] = _fit_best_forest(train_x, train_y, groups, random_seed)

    validation = by_split["validation"]
    validation_x, validation_y, _ = _arrays(validation)
    evaluations: dict[str, tuple[float, Mapping[str, float | int]]] = {}
    for name, estimator in finalists.items():
        scores = _score(name, estimator, validation_x, FEATURE_NAMES)
        threshold, metrics = _choose_threshold(scores, validation_y)
        evaluations[name] = (threshold, metrics)

    selected_name = min(
        finalists,
        key=lambda name: (
            -float(evaluations[name][1]["f1"]),
            int(evaluations[name][1]["false_positives"]),
            MODEL_COMPLEXITY[name],
        ),
    )
    threshold = evaluations[selected_name][0]
    test = by_split["test"]
    test_x, test_y, _ = _arrays(test)
    test_scores = _score(selected_name, finalists[selected_name], test_x, FEATURE_NAMES)
    test_metrics = _metrics(test_y, test_scores >= threshold)
    manifest_hash = _training_manifest_hash(training)
    validation_metrics = MappingProxyType({
        name: MappingProxyType(dict(metrics)) for name, (_, metrics) in evaluations.items()
    })
    immutable_test = MappingProxyType(dict(test_metrics))
    report_sections = MappingProxyType({
        "controlled_workloads": MappingProxyType({
            "status": "evaluated",
            "selected_model": selected_name,
            "validation": validation_metrics[selected_name],
            "test": immutable_test,
        }),
        "published_data": MappingProxyType({
            "status": "blocked_label_provenance",
            "reason": "The published training labels do not establish benign ground truth.",
        }),
    })
    return TrainingResult(
        selected_name=selected_name,
        threshold=float(threshold),
        estimator=finalists[selected_name],
        feature_names=FEATURE_NAMES,
        feature_version=FEATURE_VERSION,
        random_seed=random_seed,
        training_manifest_hash=manifest_hash,
        training_captures=tuple(sorted({sample.capture_id for sample in training})),
        validation_metrics=validation_metrics,
        test_metrics=immutable_test,
        report_sections=report_sections,
    )


def evaluate_loaded_artifact(artifact: object, samples: Sequence[LabeledWindow]) -> dict[str, float | int]:
    """Evaluate a previously validated artifact without fitting or selecting again."""
    samples = tuple(samples)
    validate_dataset(samples)
    if not samples:
        raise ValueError("evaluation dataset is empty")
    score = getattr(artifact, "score", None)
    threshold = getattr(artifact, "threshold", None)
    if not callable(score) or isinstance(threshold, bool) or not isinstance(threshold, (int, float)):
        raise ValueError("invalid loaded artifact")
    values = np.asarray(score(samples), dtype=float)
    if len(values) != len(samples) or not np.isfinite(values).all():
        raise ValueError("artifact returned invalid scores")
    labels = np.asarray([sample.label for sample in samples], dtype=int)
    return _metrics(labels, values >= float(threshold))


def _validate_feature_compatibility(samples: Sequence[LabeledWindow], version: int, names: tuple[str, ...]) -> None:
    for sample in samples:
        if sample.feature_version != version or sample.feature_names != names:
            raise ValueError("incompatible feature schema or order")
        if len(sample.features) != len(names) or any(not math.isfinite(value) for value in sample.features):
            raise ValueError("invalid numeric feature vector")


def _arrays(samples: Sequence[LabeledWindow]) -> tuple[np.ndarray, np.ndarray, np.ndarray]:
    return (
        np.asarray([sample.features for sample in samples], dtype=float),
        np.asarray([sample.label for sample in samples], dtype=int),
        np.asarray([sample.capture_id for sample in samples], dtype=object),
    )


def _validate_cv_groups(labels: np.ndarray, groups: np.ndarray) -> None:
    for label in (0, 1):
        if len(set(groups[labels == label])) < 3:
            raise ValueError("three independent training captures per class are required")


def _cv_score(estimator: object, matrix: np.ndarray, labels: np.ndarray, groups: np.ndarray, seed: int) -> float:
    splitter = StratifiedGroupKFold(n_splits=3, shuffle=True, random_state=seed)
    values = []
    for train_indexes, validation_indexes in splitter.split(matrix, labels, groups):
        fitted = clone(estimator)
        fitted.fit(matrix[train_indexes], labels[train_indexes])
        predictions = fitted.predict(matrix[validation_indexes])
        values.append(f1_score(labels[validation_indexes], predictions, zero_division=0))
    return float(sum(values) / len(values))


def _fit_best_svm(matrix: np.ndarray, labels: np.ndarray, groups: np.ndarray, seed: int) -> Pipeline:
    candidates = tuple(
        Pipeline((("scale", StandardScaler()), ("model", SVC(kernel="rbf", C=c, gamma=gamma))))
        for c in (0.5, 1.0) for gamma in ("scale", 0.1)
    )
    winner = max(candidates, key=lambda item: (_cv_score(item, matrix, labels, groups, seed), -float(item["model"].C)))
    winner.fit(matrix, labels)
    return winner


def _fit_best_forest(matrix: np.ndarray, labels: np.ndarray, groups: np.ndarray, seed: int) -> RandomForestClassifier:
    candidates = tuple(
        RandomForestClassifier(n_estimators=trees, max_depth=depth, random_state=seed, n_jobs=1)
        for trees in (40, 80) for depth in (4, None)
    )
    winner = max(candidates, key=lambda item: (_cv_score(item, matrix, labels, groups, seed), -item.n_estimators, -(item.max_depth or 10_000)))
    winner.fit(matrix, labels)
    return winner


def _score(name: str, estimator: object | None, matrix: np.ndarray, names: tuple[str, ...]) -> np.ndarray:
    if name == "rule":
        create_index, delete_index = names.index("C_sum"), names.index("D_sum")
        return (matrix[:, create_index] + matrix[:, delete_index]) / 10.0
    if name == "rbf_svm":
        return np.asarray(estimator.decision_function(matrix), dtype=float)
    if name == "random_forest":
        return np.asarray(estimator.predict_proba(matrix)[:, 1], dtype=float)
    raise ValueError("unsupported model")


def _choose_threshold(scores: np.ndarray, labels: np.ndarray) -> tuple[float, Mapping[str, float | int]]:
    epsilon = np.finfo(float).eps
    candidates = tuple(sorted({float(score) for score in scores})) + (float(max(scores) + epsilon),)
    evaluated = tuple((threshold, _metrics(labels, scores >= threshold)) for threshold in candidates)
    return min(evaluated, key=lambda item: (-float(item[1]["f1"]), int(item[1]["false_positives"]), -item[0]))


def _metrics(labels: np.ndarray, predictions: np.ndarray) -> dict[str, float | int]:
    matrix = confusion_matrix(labels, predictions, labels=(0, 1))
    true_negative, false_positive, false_negative, true_positive = (int(value) for value in matrix.ravel())
    return {
        "precision": float(precision_score(labels, predictions, zero_division=0)),
        "recall": float(recall_score(labels, predictions, zero_division=0)),
        "f1": float(f1_score(labels, predictions, zero_division=0)),
        "mcc": float(matthews_corrcoef(labels, predictions)),
        "true_negatives": true_negative,
        "false_positives": false_positive,
        "false_negatives": false_negative,
        "true_positives": true_positive,
    }


def _training_manifest_hash(samples: Sequence[LabeledWindow]) -> str:
    captures = sorted({(sample.capture_id, sample.capture_hash, sample.split) for sample in samples})
    encoded = json.dumps(captures, separators=(",", ":"), ensure_ascii=True).encode("ascii")
    return hashlib.sha256(encoded).hexdigest()
