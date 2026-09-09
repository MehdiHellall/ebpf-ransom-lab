import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from ebpf_ransom_lab.contracts import FeatureWindow, ProcessIdentity
from ebpf_ransom_lab.dataset import build_labeled_windows, load_workload_manifest
from ebpf_ransom_lab.features import FEATURE_NAMES
from ebpf_ransom_lab.recording import write_jsonl
from ebpf_ransom_lab.workloads import (
    EXPERIMENT_WORKLOAD_HOLD_SECONDS,
    MAX_WORKLOAD_BYTES,
    MAX_WORKLOAD_FILES,
    MAX_WORKLOAD_SECONDS,
    plan_sha256,
    plan_workload,
)


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
        scenario = "copying"
        seed = 11
        document = {
            "schema_version": 1,
            "run_id": f"controlled-{scenario}-seed-{seed}",
            "scenario": scenario,
            "seed": seed,
            "split": "training",
            "behavior_label": "benign",
            "plan_sha256": plan_sha256(plan_workload(scenario, seed)),
            "label_provenance": "controlled_workload",
            "status": "completed",
            "workload_hold_seconds": EXPERIMENT_WORKLOAD_HOLD_SECONDS,
            "process_scope_policy": "root_process_only",
            "limits": {
                "max_seconds": MAX_WORKLOAD_SECONDS,
                "max_files": MAX_WORKLOAD_FILES,
                "max_bytes": MAX_WORKLOAD_BYTES,
            },
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
            {"tracked_processes": [
                {"boot_id": "boot", "tgid": 42, "start_time_ns": 100},
                {"boot_id": "boot", "tgid": 43, "start_time_ns": 101},
            ]},
            {"behavior_label": "unknown"},
            {"run_id": "other"},
        ):
            with self.subTest(changes=changes):
                with self.assertRaises(ValueError):
                    load_workload_manifest(self.manifest(**changes))

    def test_manifest_must_match_the_fixed_completed_capture_plan(self):
        for changes, reason in (
            ({"scenario": "bulk-editing"}, "run ID"),
            ({"seed": 41}, "run ID"),
            ({"split": "test"}, "split"),
            ({"plan_sha256": "0" * 64}, "plan"),
            ({"status": "failed"}, "completed"),
            ({"workload_hold_seconds": 0}, "50 seconds"),
            ({"process_scope_policy": "match numeric PID"}, "root process"),
            ({"limits": {"max_seconds": 1, "max_files": 1, "max_bytes": 1}}, "limits"),
        ):
            with self.subTest(changes=changes):
                with self.assertRaisesRegex(ValueError, reason):
                    load_workload_manifest(self.manifest(**changes))

    def test_json_manifest_is_canonical_input(self):
        path = self.path / "run-manifest.json"
        path.write_text(json.dumps(self.manifest()), encoding="utf-8")
        self.assertEqual("training", load_workload_manifest(path).split)


if __name__ == "__main__":
    unittest.main()
