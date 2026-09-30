import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from ebpf_ransom_lab.contracts import FeatureWindow, ProcessIdentity
from ebpf_ransom_lab.dataset import (
    assemble_experiment_dataset,
    build_labeled_windows,
    load_manifest_bound_dataset,
    load_workload_manifest,
    write_labeled_windows,
)
from ebpf_ransom_lab.features import FEATURE_NAMES, FEATURE_VERSION
from ebpf_ransom_lab.modeling import LabeledWindow
from ebpf_ransom_lab.recording import write_jsonl
from ebpf_ransom_lab.workloads import (
    EXPERIMENT_WORKLOAD_HOLD_SECONDS,
    MAX_WORKLOAD_BYTES,
    MAX_WORKLOAD_FILES,
    MAX_WORKLOAD_SECONDS,
    plan_sha256,
    plan_workload,
    build_experiment_manifest,
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

    def test_aggregate_manifest_requires_and_binds_all_forty_runs(self):
        inputs = self.path / "per-run"
        inputs.mkdir()
        plan_document = build_experiment_manifest()
        plan_path = self.path / "plan.json"
        plan_path.write_text(json.dumps(plan_document), encoding="utf-8")
        for index, planned in enumerate(plan_document["runs"]):
            run_id = planned["run_id"]
            row = LabeledWindow(
                window_id=f"window-{index}",
                capture_id=run_id,
                capture_hash=hashlib.sha256(run_id.encode()).hexdigest(),
                split=planned["split"],
                label=0 if planned["behavior_label"] == "benign" else 1,
                feature_version=FEATURE_VERSION,
                feature_names=FEATURE_NAMES,
                features=tuple(float(index) for _ in FEATURE_NAMES),
                complete=True,
                quality="good",
            )
            write_labeled_windows(inputs / f"{run_id}.jsonl", (row,))

        output = self.path / "aggregate"
        manifest = assemble_experiment_dataset(inputs, plan_path, output)
        self.assertEqual(40, manifest["expected_run_count"])
        self.assertEqual(40, manifest["row_count"])
        selection, manifest_hash = load_manifest_bound_dataset(
            output / "selection.jsonl", output / "manifest.json", role="selection"
        )
        test, same_manifest_hash = load_manifest_bound_dataset(
            output / "test.jsonl", output / "manifest.json", role="test"
        )
        self.assertEqual(32, len(selection))
        self.assertEqual(8, len(test))
        self.assertEqual(manifest_hash, same_manifest_hash)

        with (output / "selection.jsonl").open("a", encoding="utf-8") as stream:
            stream.write("\n")
        with self.assertRaisesRegex(ValueError, "byte hash"):
            load_manifest_bound_dataset(
                output / "selection.jsonl", output / "manifest.json", role="selection"
            )

    def test_aggregate_manifest_rejects_a_missing_planned_run(self):
        inputs = self.path / "per-run"
        inputs.mkdir()
        plan = self.path / "plan.json"
        plan.write_text(json.dumps(build_experiment_manifest()), encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "missing"):
            assemble_experiment_dataset(inputs, plan, self.path / "aggregate")


if __name__ == "__main__":
    unittest.main()
