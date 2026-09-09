import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from ebpf_ransom_lab.contracts import ProcessIdentity
from ebpf_ransom_lab.workloads import (
    MAX_WORKLOAD_BYTES,
    MAX_WORKLOAD_FILES,
    MAX_WORKLOAD_SECONDS,
    SCENARIOS,
    Action,
    WorkloadLimits,
    WorkloadPlan,
    execute_plan,
    plan_workload,
    run_workload,
    workload_run_manifest,
)


EXPECTED_SCENARIOS = {
    "copying": "benign",
    "archiving": "benign",
    "compression": "benign",
    "small-build": "benign",
    "bulk-editing": "benign",
    "rapid-generated-file-replacement": "suspicious",
    "create-delete-churn": "suspicious",
    "paced-replacement": "suspicious",
}


class WorkloadTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.approved_root = Path(self.temp.name) / "approved"
        self.approved_root.mkdir()

    def test_exact_scenario_catalog_and_labels(self):
        self.assertEqual(EXPECTED_SCENARIOS, SCENARIOS)

    def test_plans_are_reproducible_and_confined_to_relative_paths(self):
        for scenario in SCENARIOS:
            with self.subTest(scenario=scenario):
                first = plan_workload(scenario, 23)
                second = plan_workload(scenario, 23)
                self.assertEqual(first, second)
                self.assertTrue(first.actions)
                for action in first.actions:
                    for relative_path in action.paths:
                        path = Path(relative_path)
                        self.assertFalse(path.is_absolute())
                        self.assertNotIn("..", path.parts)

        self.assertNotEqual(
            plan_workload("copying", 11), plan_workload("copying", 23)
        )
        with self.assertRaisesRegex(ValueError, "unsupported workload seed"):
            plan_workload("copying", 7)
        with self.assertRaisesRegex(ValueError, "unknown workload scenario"):
            plan_workload("unknown", 11)

    def test_each_scenario_runs_in_a_fresh_generated_workspace(self):
        limits = WorkloadLimits(max_seconds=10, max_files=100, max_bytes=2_000_000)
        runs = [
            run_workload(scenario, 11, self.approved_root, limits=limits)
            for scenario in SCENARIOS
        ]

        self.assertEqual(8, len({run.workspace for run in runs}))
        for run in runs:
            self.assertEqual(self.approved_root.resolve(), run.workspace.parent)
            self.assertTrue(run.workspace.name.startswith("workload-"))
            self.assertEqual("completed", run.status)
            self.assertEqual(
                f"controlled-{run.scenario}-seed-{run.seed}", run.run_id
            )
            self.assertEqual("training", run.split)
            self.assertEqual(SCENARIOS[run.scenario], run.behavior_label)
            self.assertEqual(64, len(run.plan_sha256))
            self.assertGreater(run.files_created, 0)
            self.assertGreater(run.bytes_written, 0)
            self.assertEqual("process", run.label_scope.kind)
            self.assertEqual(run.process_identity, run.label_scope.root_identity)
            self.assertFalse(run.label_scope.include_descendants)
            self.assertEqual("unlabeled", run.label_scope.background_activity)
            self.assertIsInstance(run.process_identity, ProcessIdentity)
            self.assertGreater(run.process_identity.tgid, 0)
            self.assertNotEqual(os.getpid(), run.process_identity.tgid)

    def test_each_plan_executes_through_the_direct_safety_boundary(self):
        limits = WorkloadLimits(max_seconds=10, max_files=100, max_bytes=2_000_000)
        for index, scenario in enumerate(SCENARIOS):
            with self.subTest(scenario=scenario):
                workspace = self.approved_root / f"workload-direct-{index}"
                workspace.mkdir()
                stats = execute_plan(
                    plan_workload(scenario, 37),
                    self.approved_root,
                    workspace,
                    limits,
                )
                self.assertGreater(stats.files_created, 0)
                self.assertGreater(stats.bytes_written, 0)
                self.assertLessEqual(stats.files_created, limits.max_files)
                self.assertLessEqual(stats.bytes_written, limits.max_bytes)

    def test_runtime_manifest_carries_the_only_allowed_label_identity(self):
        result = run_workload(
            "copying", 11, self.approved_root,
            limits=WorkloadLimits(max_seconds=10, max_files=100, max_bytes=2_000_000),
        )
        manifest = workload_run_manifest(result)
        self.assertEqual("controlled_workload", manifest["label_provenance"])
        self.assertEqual("unlabeled", manifest["background_activity"])
        self.assertEqual("training", manifest["split"])
        self.assertEqual([{
            "boot_id": result.process_identity.boot_id,
            "tgid": result.process_identity.tgid,
            "start_time_ns": result.process_identity.start_time_ns,
        }], manifest["tracked_processes"])

    def test_rejects_symlink_root_and_symlink_ancestor(self):
        target = Path(self.temp.name) / "target"
        target.mkdir()
        link = Path(self.temp.name) / "link"
        try:
            link.symlink_to(target, target_is_directory=True)
        except (OSError, NotImplementedError):
            self.skipTest("directory symlinks are unavailable")

        with self.assertRaisesRegex(ValueError, "symlink"):
            run_workload("copying", 11, link)

        real_child = target / "child"
        real_child.mkdir()
        linked_child = link / "child"
        with self.assertRaisesRegex(ValueError, "symlink"):
            run_workload("copying", 11, linked_child)

    def test_rejects_escaped_and_symlinked_action_paths(self):
        workspace = self.approved_root / "workload-manual"
        workspace.mkdir()
        escaped = WorkloadPlan(
            scenario="copying",
            seed=11,
            actions=(Action("write", "../escape.txt", data=b"no"),),
        )
        with self.assertRaisesRegex(ValueError, "unsafe workload path"):
            execute_plan(escaped, self.approved_root, workspace)

        outside = self.approved_root / "outside.txt"
        outside.write_bytes(b"safe")
        link = workspace / "linked.txt"
        try:
            link.symlink_to(outside)
        except (OSError, NotImplementedError):
            self.skipTest("file symlinks are unavailable")
        linked = WorkloadPlan(
            scenario="copying",
            seed=11,
            actions=(Action("write", "linked.txt", data=b"no"),),
        )
        with self.assertRaisesRegex(ValueError, "symlink"):
            execute_plan(linked, self.approved_root, workspace)
        self.assertEqual(b"safe", outside.read_bytes())

    def test_enforces_file_and_byte_limits_before_writing(self):
        plan = WorkloadPlan(
            scenario="copying",
            seed=11,
            actions=(
                Action("write", "one.txt", data=b"1234"),
                Action("write", "two.txt", data=b"5678"),
            ),
        )
        workspace = self.approved_root / "workload-limits"
        workspace.mkdir()

        with self.assertRaisesRegex(RuntimeError, "file-count limit"):
            execute_plan(
                plan,
                self.approved_root,
                workspace,
                WorkloadLimits(max_seconds=5, max_files=1, max_bytes=100),
            )
        self.assertFalse((workspace / "two.txt").exists())

        workspace2 = self.approved_root / "workload-bytes"
        workspace2.mkdir()
        with self.assertRaisesRegex(RuntimeError, "byte limit"):
            execute_plan(
                plan,
                self.approved_root,
                workspace2,
                WorkloadLimits(max_seconds=5, max_files=10, max_bytes=7),
            )
        self.assertFalse((workspace2 / "two.txt").exists())

    def test_enforces_elapsed_time_limit(self):
        plan = WorkloadPlan(
            scenario="paced-replacement",
            seed=11,
            actions=(Action("pause", delay_seconds=0.02),),
        )
        workspace = self.approved_root / "workload-time"
        workspace.mkdir()

        with self.assertRaisesRegex(RuntimeError, "time limit"):
            execute_plan(
                plan,
                self.approved_root,
                workspace,
                WorkloadLimits(max_seconds=0.001, max_files=1, max_bytes=1),
            )

    def test_limits_must_be_positive(self):
        for limits in (
            WorkloadLimits(max_seconds=0, max_files=1, max_bytes=1),
            WorkloadLimits(max_seconds=1, max_files=0, max_bytes=1),
            WorkloadLimits(max_seconds=1, max_files=1, max_bytes=0),
        ):
            with self.subTest(limits=limits), self.assertRaises(ValueError):
                limits.validate()

    def test_limits_cannot_disable_or_raise_hard_ceilings(self):
        invalid = (
            WorkloadLimits(max_seconds=float("nan"), max_files=1, max_bytes=1),
            WorkloadLimits(max_seconds=MAX_WORKLOAD_SECONDS + 1, max_files=1, max_bytes=1),
            WorkloadLimits(max_seconds=1, max_files=MAX_WORKLOAD_FILES + 1, max_bytes=1),
            WorkloadLimits(max_seconds=1, max_files=1, max_bytes=MAX_WORKLOAD_BYTES + 1),
        )
        for limits in invalid:
            with self.subTest(limits=limits), self.assertRaises(ValueError):
                limits.validate()

    def test_live_capture_hold_is_bounded_separately_from_file_operation_limits(self):
        with self.assertRaisesRegex(ValueError, "hold_seconds"):
            run_workload("copying", 11, self.approved_root, hold_seconds=60.1)

    def test_root_is_rejected_before_workspace_or_child_process_creation(self):
        before = tuple(self.approved_root.iterdir())
        with patch("ebpf_ransom_lab.workloads._effective_uid", return_value=0), \
             patch("ebpf_ransom_lab.workloads.subprocess.Popen") as launch:
            with self.assertRaisesRegex(PermissionError, "ordinary user"):
                run_workload("copying", 11, self.approved_root)
        launch.assert_not_called()
        self.assertEqual(before, tuple(self.approved_root.iterdir()))

    def test_seed_changes_observable_workload_structure_not_only_file_bytes(self):
        def signature(scenario, seed):
            return tuple(
                (action.operation, action.path, action.source, action.sources, action.delay_seconds)
                for action in plan_workload(scenario, seed).actions
            )

        for scenario in SCENARIOS:
            with self.subTest(scenario=scenario):
                self.assertEqual(
                    len({signature(scenario, seed) for seed in (11, 23, 37, 41, 53)}),
                    5,
                )

    def test_rejects_invalid_actions_and_workspace_boundaries(self):
        workspace = self.approved_root / "workload-invalid"
        workspace.mkdir()
        invalid = WorkloadPlan(
            scenario="copying",
            seed=11,
            actions=(Action("execute-command", "file.txt"),),
        )
        with self.assertRaisesRegex(ValueError, "unsupported workload action"):
            execute_plan(invalid, self.approved_root, workspace)

        outside = Path(self.temp.name) / "workload-outside"
        outside.mkdir()
        with self.assertRaisesRegex(ValueError, "escaped approved root"):
            execute_plan(plan_workload("copying", 11), self.approved_root, outside)

        not_generated = self.approved_root / "ordinary-directory"
        not_generated.mkdir()
        with self.assertRaisesRegex(ValueError, "escaped approved root"):
            execute_plan(
                plan_workload("copying", 11), self.approved_root, not_generated
            )

        missing_root = Path(self.temp.name) / "missing"
        with self.assertRaisesRegex(ValueError, "does not exist"):
            run_workload("copying", 11, missing_root)

    def test_rejects_negative_pause_and_missing_sources(self):
        workspace = self.approved_root / "workload-bad-source"
        workspace.mkdir()
        missing = WorkloadPlan(
            scenario="copying",
            seed=11,
            actions=(Action("copy", "copy.txt", source="missing.txt"),),
        )
        with self.assertRaisesRegex(ValueError, "not a regular file"):
            execute_plan(missing, self.approved_root, workspace)

        negative_pause = WorkloadPlan(
            scenario="copying",
            seed=11,
            actions=(Action("pause", delay_seconds=-1),),
        )
        with self.assertRaisesRegex(ValueError, "delay cannot be negative"):
            execute_plan(negative_pause, self.approved_root, workspace)

    def test_archive_budget_is_checked_before_allocating_the_archive(self):
        workspace = self.approved_root / "workload-archive-budget"
        workspace.mkdir()
        (workspace / "one.txt").write_bytes(b"1")
        (workspace / "two.txt").write_bytes(b"2")
        plan = WorkloadPlan(
            scenario="archiving",
            seed=11,
            actions=(
                Action(
                    "archive",
                    "bundle.tar",
                    sources=("one.txt", "two.txt"),
                ),
            ),
        )

        with patch("ebpf_ransom_lab.workloads.tarfile.open") as archive_open:
            with self.assertRaisesRegex(RuntimeError, "byte limit"):
                execute_plan(
                    plan,
                    self.approved_root,
                    workspace,
                    WorkloadLimits(max_seconds=5, max_files=1, max_bytes=1),
                )
        archive_open.assert_not_called()


if __name__ == "__main__":
    unittest.main()
