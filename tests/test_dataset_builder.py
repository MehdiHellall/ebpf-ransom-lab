import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from ebpf_ransom_lab.contracts import FeatureWindow, ProcessIdentity
from ebpf_ransom_lab.dataset import build_labeled_windows, load_workload_manifest
from ebpf_ransom_lab.features import FEATURE_NAMES
from ebpf_ransom_lab.recording import write_jsonl


class DatasetBuilderTests(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.TemporaryDirectory()
        self.addCleanup(self.root.cleanup)
        self.path = Path(self.root.name)
        self.identity = ProcessIdentity("boot", 42, 100)
        self.background = ProcessIdentity("boot", 99, 200)
        values = tuple(1 if name == "D_sum" else 0 for name in FEATURE_NAMES)
        self.windows = (
            FeatureWindow("controlled-copying-seed-11", self.identity, 0, 10_000_000_000, FEATURE_NAMES, values),
            FeatureWindow("controlled-copying-seed-11", self.background, 0, 10_000_000_000, FEATURE_NAMES, values),
        )

    def manifest(self, **changes):
        document = {
            "schema_version": 1,
            "run_id": "controlled-copying-seed-11",
            "split": "training",
            "behavior_label": "benign",
            "label_provenance": "controlled_workload",
            "tracked_processes": [{
                "boot_id": "boot", "tgid": 42, "start_time_ns": 100,
            }],
            "background_activity": "unlabeled",
        }
        document.update(changes)
        return document

    def test_only_manifest_tracked_complete_windows_become_labeled_rows(self):
        source = self.path / "features.jsonl"
        write_jsonl(source, self.windows)
        manifest = load_workload_manifest(self.manifest())
        rows = build_labeled_windows(self.windows, manifest, capture_hash=hashlib.sha256(source.read_bytes()).hexdigest())
        self.assertEqual(1, len(rows))
        self.assertEqual(0, rows[0].label)
        self.assertEqual("training", rows[0].split)
        self.assertEqual("controlled-copying-seed-11", rows[0].capture_id)

    def test_manifest_rejects_missing_identity_unknown_label_and_wrong_run(self):
        for changes in (
            {"tracked_processes": []},
            {"behavior_label": "unknown"},
            {"run_id": "other"},
        ):
            with self.subTest(changes=changes):
                if changes == {"run_id": "other"}:
                    manifest = load_workload_manifest(self.manifest(**changes))
                    with self.assertRaisesRegex(ValueError, "run ID"):
                        build_labeled_windows(self.windows, manifest, capture_hash="a" * 64)
                else:
                    with self.assertRaises(ValueError):
                        load_workload_manifest(self.manifest(**changes))

    def test_json_manifest_is_canonical_input(self):
        path = self.path / "run-manifest.json"
        path.write_text(json.dumps(self.manifest()), encoding="utf-8")
        self.assertEqual("training", load_workload_manifest(path).split)


if __name__ == "__main__":
    unittest.main()
