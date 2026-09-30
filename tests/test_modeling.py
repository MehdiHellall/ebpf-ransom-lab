import io
import json
import unittest

from ebpf_ransom_lab.features import FEATURE_NAMES, FEATURE_VERSION
from ebpf_ransom_lab.modeling import LabeledWindow, load_dataset, train_and_select, validate_dataset


def sample(capture, split, label, value, index=0):
    values = tuple(
        float(value if name in {"C_sum", "D_sum"} else 0)
        for name in FEATURE_NAMES
    )
    return LabeledWindow(
        window_id=f"{capture}:{index}",
        capture_id=capture,
        capture_hash=(capture.encode().hex() + "0" * 64)[:64],
        split=split,
        label=label,
        feature_version=FEATURE_VERSION,
        feature_names=FEATURE_NAMES,
        features=values,
        complete=True,
        quality="good",
    )


class DatasetValidationTests(unittest.TestCase):
    def test_rejects_capture_or_hash_crossing_splits(self):
        with self.assertRaisesRegex(ValueError, "capture appears across splits"):
            validate_dataset((
                sample("same", "training", 0, 1, 0),
                sample("same", "test", 0, 1, 1),
            ))

        first = sample("one", "training", 0, 1)
        second = sample("two", "test", 0, 1)
        second = LabeledWindow(**{**second.as_dict(), "capture_hash": first.capture_hash})
        with self.assertRaisesRegex(ValueError, "capture hash is assigned"):
            validate_dataset((first, second))

    def test_rejects_unknown_partial_and_incompatible_samples(self):
        base = sample("one", "training", 0, 1)
        cases = (
            {"label": None},
            {"complete": False},
            {"quality": "incomplete"},
            {"feature_version": "future"},
            {"feature_names": tuple(reversed(FEATURE_NAMES))},
        )
        for changes in cases:
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                validate_dataset((LabeledWindow(**{**base.as_dict(), **changes}),))

    def test_feature_version_survives_json_round_trip_as_schema_integer(self):
        rows = []
        for split, capture in (("training", "train-0"), ("validation", "validation-0"), ("test", "test-0")):
            rows.append(sample(capture, split, 0, 1))
        encoded = "".join(json.dumps(row.as_dict()) + "\n" for row in rows)

        loaded = load_dataset(io.StringIO(encoded))

        self.assertEqual((FEATURE_VERSION, FEATURE_VERSION, FEATURE_VERSION), tuple(row.feature_version for row in loaded))


class TrainingTests(unittest.TestCase):
    def test_training_is_grouped_repeatable_and_does_not_touch_held_out_data(self):
        samples = []
        for label, stem, low, high in ((0, "benign", 0, 1), (1, "suspicious", 9, 12)):
            for group_index in range(3):
                capture = f"{stem}-train-{group_index}"
                samples.extend(sample(capture, "training", label, low + group_index, i) for i in range(2))
            samples.extend(sample(f"{stem}-validation", "validation", label, high, i) for i in range(2))
            samples.extend(sample(f"{stem}-test", "test", label, high, i) for i in range(2))

        selection = tuple(sample for sample in samples if sample.split != "test")
        kwargs = {
            "random_seed": 37,
            "experiment_dataset_manifest_sha256": "a" * 64,
            "selection_dataset_sha256": "b" * 64,
        }
        first = train_and_select(selection, **kwargs)
        second = train_and_select(selection, **kwargs)

        self.assertEqual(first.selected_name, second.selected_name)
        self.assertEqual(first.threshold, second.threshold)
        self.assertEqual({"rule", "rbf_svm", "random_forest"}, set(first.validation_metrics))
        self.assertEqual({"controlled_workloads", "published_data"}, set(first.report_sections))
        self.assertEqual("selected_not_tested", first.report_sections["controlled_workloads"]["status"])
        self.assertEqual("blocked_label_provenance", first.report_sections["published_data"]["status"])

        with self.assertRaisesRegex(ValueError, "withheld"):
            train_and_select(tuple(samples), **kwargs)

        changed = list(selection)
        changed[0] = LabeledWindow(**{
            **changed[0].as_dict(),
            "features": (changed[0].features[0] + 1.0, *changed[0].features[1:]),
        })
        changed_result = train_and_select(tuple(changed), **kwargs)
        self.assertNotEqual(
            first.selection_manifest_hash, changed_result.selection_manifest_hash
        )


if __name__ == "__main__":
    unittest.main()
