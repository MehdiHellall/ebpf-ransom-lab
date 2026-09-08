"""Transparent baseline scoring shared by replay and the live service."""
from __future__ import annotations

import math
from dataclasses import dataclass

from ebpf_ransom_lab.contracts import FeatureWindow
from ebpf_ransom_lab.features import FEATURE_NAMES


RULE_VERSION = "rule-count-rate-v1"


@dataclass(frozen=True, slots=True)
class Prediction:
    window_id: str
    model_version: str
    score: float | None
    threshold: float
    suspicious: bool | None
    quality: str
    supporting_features: tuple[tuple[str, int], ...]


@dataclass(frozen=True, slots=True)
class RuleScorer:
    """Score create/delete attempts per second in a ten-second window."""

    threshold: float = 4.0
    model_version: str = RULE_VERSION

    def __post_init__(self) -> None:
        if isinstance(self.threshold, bool) or not math.isfinite(self.threshold) or self.threshold < 0:
            raise ValueError("rule threshold must be a finite non-negative number")

    def predict(self, window: FeatureWindow) -> Prediction:
        if window.feature_names != FEATURE_NAMES:
            raise ValueError("incompatible feature order")
        features = window.feature_map
        supporting = (("C_sum", features["C_sum"]), ("D_sum", features["D_sum"]))
        if not window.classifiable:
            return Prediction(
                window.window_id, self.model_version, None, self.threshold, None,
                ",".join(window.quality), supporting,
            )
        score = (features["C_sum"] + features["D_sum"]) / 10.0
        return Prediction(
            window.window_id, self.model_version, score, self.threshold,
            score >= self.threshold, "complete", supporting,
        )
