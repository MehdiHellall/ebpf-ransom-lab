import json
import tempfile
import unittest
from pathlib import Path

from ebpf_ransom_lab.artifacts import load_artifact, save_artifact
from ebpf_ransom_lab.features import FEATURE_NAMES, FEATURE_VERSION
from ebpf_ransom_lab.modeling import LabeledWindow, train_and_select


def make_samples(feature_name="D_sum"):
    rows = []
    for label, stem, value in ((0, "benign", 1), (1, "suspicious", 10)):
        for split, count in (("training", 3), ("validation", 1), ("test", 1)):
            for group in range(count):
                capture = f"{stem}-{split}-{group}"
                features = tuple(float(value + group if name == feature_name else 0) for name in FEATURE_NAMES)
                rows.append(LabeledWindow(
                    window_id=f"{capture}:0", capture_id=capture,
                    capture_hash=(capture.encode().hex() + "0" * 64)[:64],
                    split=split, label=label, feature_version=FEATURE_VERSION,
                    feature_names=FEATURE_NAMES, features=features,
                    complete=True, quality="good",
                ))
    return tuple(rows)


class ArtifactTests(unittest.TestCase):
    def test_round_trip_preserves_scores_and_metadata(self):
        result = train_and_select(make_samples(), random_seed=23)
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "model"
            save_artifact(target, result)
            loaded = load_artifact(target)

            sample = make_samples()[-1]
            self.assertEqual(result.selected_name, loaded.model_name)
            self.assertEqual(result.threshold, loaded.threshold)
            self.assertEqual(FEATURE_NAMES, loaded.feature_names)
            self.assertEqual(result.score((sample,))[0], loaded.score((sample,))[0])

    def test_rejects_tampered_or_incompatible_artifact(self):
        result = train_and_select(make_samples(), random_seed=23)
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "model"
            save_artifact(target, result)
            manifest_path = target / "manifest.json"
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            manifest["feature_names"] = list(reversed(manifest["feature_names"]))
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            with self.assertRaises(ValueError):
                load_artifact(target)

    def test_safe_skops_model_round_trip_and_checksum(self):
        result = train_and_select(make_samples("O_sum"), random_seed=23)
        self.assertEqual("rbf_svm", result.selected_name)
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "model"
            save_artifact(target, result)
            loaded = load_artifact(target)
            self.assertEqual(result.score(make_samples()[:1]), loaded.score(make_samples()[:1]))
            model_path = target / "model.skops"
            model_path.write_bytes(model_path.read_bytes() + b"tamper")
            with self.assertRaisesRegex(ValueError, "checksum"):
                load_artifact(target)


if __name__ == "__main__":
    unittest.main()
