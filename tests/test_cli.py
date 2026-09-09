import io
import hashlib
import json
from dataclasses import replace
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from ebpf_ransom_lab.cli import run
from ebpf_ransom_lab.contracts import Event, Heartbeat, ProcessExit, ProcessIdentity, RunEnd, RunStart
from ebpf_ransom_lab.features import WINDOW_NS
from ebpf_ransom_lab.recording import read_jsonl, write_jsonl
from ebpf_ransom_lab.doctor import DoctorContext
from ebpf_ransom_lab.collector.protocol import CollectorHealth, LossCounters
from ebpf_ransom_lab.reference import FileVerification, VerificationReport
from ebpf_ransom_lab.workloads import (
    EXPERIMENT_WORKLOAD_HOLD_SECONDS,
    MAX_WORKLOAD_BYTES,
    MAX_WORKLOAD_FILES,
    MAX_WORKLOAD_SECONDS,
    build_experiment_manifest,
    plan_sha256,
    plan_workload,
)


class CliTests(unittest.TestCase):
    COMMIT = "a" * 40

    def test_audit_cli_reports_output_and_exit_status(self):
        output = io.StringIO()
        with patch('ebpf_ransom_lab.cli.audit_checkout', return_value={'ok': False}), \
             patch('ebpf_ransom_lab.cli.write_report') as writer:
            code = run(['audit', 'reference', '--output', 'var/audit'], stdout=output)
        self.assertEqual(1, code)
        writer.assert_called_once()
        self.assertIn('audit.json', output.getvalue())

    def test_audit_cli_handles_output_failure(self):
        output = io.StringIO()
        with patch('ebpf_ransom_lab.cli.audit_checkout', return_value={'ok': True}), \
             patch('ebpf_ransom_lab.cli.write_report', side_effect=OSError('unwritable')):
            code = run(['audit', 'reference'], stdout=output)
        self.assertEqual(2, code)
        self.assertIn('unwritable', output.getvalue())

    def test_doctor_json_returns_success_for_application_scope(self):
        context = DoctorContext(
            system="Windows",
            python_version=(3, 12, 0),
            kernel_release="",
            effective_uid=None,
            free_bytes=10 * 1024**3,
            available_modules=frozenset(),
            existing_paths=frozenset(),
            data_directory_writable=True,
        )
        output = io.StringIO()

        exit_code = run(
            ["doctor", "--scope", "app", "--json"],
            stdout=output,
            doctor_context=context,
        )

        payload = json.loads(output.getvalue())
        self.assertEqual(0, exit_code)
        self.assertEqual("pass", payload["summary"])
        self.assertEqual("app", payload["scope"])

    def test_doctor_text_returns_failure_for_collector_on_windows(self):
        context = DoctorContext(
            system="Windows",
            python_version=(3, 12, 0),
            kernel_release="11",
            effective_uid=None,
            free_bytes=10 * 1024**3,
            available_modules=frozenset(),
            existing_paths=frozenset(),
            data_directory_writable=True,
        )
        output = io.StringIO()

        exit_code = run(
            ["doctor", "--scope", "collector"],
            stdout=output,
            doctor_context=context,
        )

        self.assertEqual(1, exit_code)
        self.assertIn("Environment: FAIL", output.getvalue())
        self.assertIn("collector_platform", output.getvalue())

    def test_reference_json_renders_verification_report(self):
        report = VerificationReport(
            repository="https://example.test/upstream.git",
            expected_commit=self.COMMIT,
            actual_commit=self.COMMIT,
            commit_status="match",
            files=(
                FileVerification(
                    path="data/example.txt",
                    status="match",
                    expected_sha256="0" * 64,
                    actual_sha256="0" * 64,
                ),
            ),
        )
        with tempfile.TemporaryDirectory() as directory:
            manifest = Path(directory) / "manifest.json"
            manifest.write_text(
                json.dumps(
                    {
                    "schema_version": 1,
                    "repository": report.repository,
                    "commit": self.COMMIT,
                    "license": "MIT",
                        "files": [
                            {
                                "path": "data/example.txt",
                                "sha256": "0" * 64,
                                "size": 1,
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )
            output = io.StringIO()
            with patch("ebpf_ransom_lab.cli.verify_reference", return_value=report):
                exit_code = run(
                    [
                        "reference",
                        "verify",
                        directory,
                        "--manifest",
                        str(manifest),
                        "--json",
                    ],
                    stdout=output,
                )

        self.assertEqual(0, exit_code)
        self.assertTrue(json.loads(output.getvalue())["ok"])

    def test_features_and_replay_drive_the_portable_dashboard_database(self):
        identity = ProcessIdentity("boot", 9, 10)
        records = (
            Event("demo", 1, 0, identity, 9, "C"),
            Event("demo", 2, 1, identity, 9, "D"),
            Heartbeat("demo", 3, WINDOW_NS),
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            input_path = root / "recording.jsonl"
            features_path = root / "features.jsonl"
            database = root / "runs.sqlite"
            write_jsonl(input_path, records)
            output = io.StringIO()

            self.assertEqual(0, run([
                "features", str(input_path), "--capture-start-ns", "0",
                "--capture-end-ns", str(WINDOW_NS), "--output", str(features_path),
            ], stdout=output))
            self.assertEqual(1, len(read_jsonl(features_path)))
            self.assertEqual(0, run([
                "replay", str(input_path), "--capture-start-ns", "0",
                "--capture-end-ns", str(WINDOW_NS), "--database", str(database),
            ], stdout=output))
            self.assertTrue(database.exists())
            self.assertIn("Replay complete", output.getvalue())

    def test_features_refuses_to_overwrite_existing_output(self):
        identity = ProcessIdentity("boot", 9, 10)
        records = (
            Event("demo", 1, 0, identity, 9, "C"),
            Heartbeat("demo", 2, WINDOW_NS),
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            input_path = root / "recording.jsonl"
            features_path = root / "features.jsonl"
            write_jsonl(input_path, records)
            features_path.write_text("keep me\n", encoding="utf-8")

            output = io.StringIO()
            self.assertEqual(2, run([
                "features", str(input_path), "--capture-start-ns", "0",
                "--capture-end-ns", str(WINDOW_NS), "--output", str(features_path),
            ], stdout=output))

            self.assertEqual("keep me\n", features_path.read_text(encoding="utf-8"))
            self.assertIn("refusing to overwrite", output.getvalue())

    def test_workload_plan_writes_the_fixed_forty_run_manifest(self):
        with tempfile.TemporaryDirectory() as directory:
            output_path = Path(directory) / "experiment.json"
            output = io.StringIO()
            self.assertEqual(0, run([
                "workload", "plan", "--output", str(output_path),
            ], stdout=output))
            self.assertEqual(40, len(json.loads(output_path.read_text(encoding="utf-8"))["runs"]))

    def test_dataset_command_rejects_untracked_background_by_construction(self):
        identity = ProcessIdentity("boot", 9, 10)
        records = (
            RunStart("controlled-copying-seed-11", 0, "live"),
            Event("controlled-copying-seed-11", 1, 1, identity, 9, "C"),
            Heartbeat("controlled-copying-seed-11", 2, WINDOW_NS),
            ProcessExit("controlled-copying-seed-11", 3, 50 * 1_000_000_000, identity, 9),
            Heartbeat("controlled-copying-seed-11", 4, 60 * 1_000_000_000 - 1),
            RunEnd("controlled-copying-seed-11", 5, 60 * 1_000_000_000),
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            recording = root / "recording.jsonl"
            features = root / "features.jsonl"
            manifest = root / "run-manifest.json"
            dataset = root / "dataset.jsonl"
            plan = root / "plan.json"
            acceptance = root / "capture.accepted.json"
            write_jsonl(recording, records)
            plan.write_text(json.dumps(build_experiment_manifest()), encoding="utf-8")
            scenario = "copying"
            seed = 11
            manifest.write_text(json.dumps({
                "schema_version": 1, "run_id": "controlled-copying-seed-11",
                "scenario": scenario, "seed": seed,
                "split": "training", "behavior_label": "benign",
                "plan_sha256": plan_sha256(plan_workload(scenario, seed)),
                "label_provenance": "controlled_workload", "background_activity": "unlabeled",
                "status": "completed", "workload_hold_seconds": EXPERIMENT_WORKLOAD_HOLD_SECONDS,
                "process_scope_policy": "root_process_only",
                "limits": {
                    "max_seconds": MAX_WORKLOAD_SECONDS,
                    "max_files": MAX_WORKLOAD_FILES,
                    "max_bytes": MAX_WORKLOAD_BYTES,
                },
                "tracked_processes": [{"boot_id": "boot", "tgid": 9, "start_time_ns": 10}],
            }), encoding="utf-8")
            output = io.StringIO()
            self.assertEqual(0, run([
                "capture", "validate", str(recording), str(manifest),
                "--plan", str(plan), "--output", str(acceptance),
            ], stdout=output))
            self.assertTrue(acceptance.exists())
            self.assertEqual(0, run([
                "features", str(recording), "--output", str(features),
            ], stdout=output))
            self.assertEqual(0, run([
                "dataset", "build", str(features), str(manifest),
                "--capture", str(recording), "--plan", str(plan), "--output", str(dataset),
            ], stdout=output))
            row = json.loads(dataset.read_text(encoding="utf-8"))
            self.assertEqual(0, row["label"])
            self.assertEqual("training", row["split"])
            self.assertEqual(hashlib.sha256(recording.read_bytes()).hexdigest(), row["capture_hash"])

            tampered = root / "tampered-features.jsonl"
            feature_records = read_jsonl(features)
            changed_values = (feature_records[0].values[0] + 1, *feature_records[0].values[1:])
            write_jsonl(tampered, (replace(feature_records[0], values=changed_values), *feature_records[1:]))
            self.assertEqual(2, run([
                "dataset", "build", str(tampered), str(manifest),
                "--capture", str(recording), "--plan", str(plan),
                "--output", str(root / "tampered-dataset.jsonl"),
            ], stdout=output))
            self.assertIn("does not exactly match", output.getvalue())

    def test_collect_command_is_present_and_fails_closed_without_linux_root(self):
        output = io.StringIO()
        with patch("ebpf_ransom_lab.cli.os.name", "nt"):
            self.assertEqual(2, run(["collect", "--run-id", "demo"], stdout=output))
        self.assertEqual("", output.getvalue())

    def test_collect_rejects_unsafe_run_id_before_starting_collector(self):
        output = io.StringIO()
        stderr = io.StringIO()
        with patch("ebpf_ransom_lab.cli.sys.stderr", stderr):
            self.assertEqual(2, run(["collect", "--run-id", "../demo"], stdout=output))
        self.assertEqual("", output.getvalue())
        self.assertIn("run-id", stderr.getvalue())

    def test_collect_emits_terminal_success_only_when_final_loss_is_readable(self):
        class FakeCollector:
            fail_health = False

            def __init__(self, consumer):
                self.consumer = consumer

            def start(self):
                return None

            def poll(self, *, timeout_ms):
                return None

            def health(self, *, monotonic_ns):
                if self.fail_health:
                    raise RuntimeError("loss telemetry unreadable")
                return CollectorHealth(
                    self.consumer.run_id, True, monotonic_ns, LossCounters()
                )

            def stop(self):
                return None

        def collect(collector):
            output = io.StringIO()
            stderr = io.StringIO()
            with patch("ebpf_ransom_lab.cli.os.name", "posix"), \
                 patch("ebpf_ransom_lab.cli.os.geteuid", return_value=0, create=True), \
                 patch("ebpf_ransom_lab.collector.runtime.read_boot_id", return_value="boot"), \
                 patch("ebpf_ransom_lab.collector.runtime.BccCollector", collector), \
                 patch("ebpf_ransom_lab.cli.time.monotonic_ns", side_effect=(100, 102, 103)), \
                 patch("ebpf_ransom_lab.cli.sys.stderr", stderr):
                code = run([
                    "collect", "--run-id", "run", "--duration-seconds", "0.000000001",
                ], stdout=output)
            return code, tuple(json.loads(line) for line in output.getvalue().splitlines())

        code, records = collect(FakeCollector)
        self.assertEqual(0, code)
        self.assertEqual("run_start", records[0]["type"])
        self.assertEqual("run_end", records[-1]["type"])
        self.assertGreaterEqual(records[-1]["timestamp_ns"] - records[0]["capture_start_ns"], 1)

        class FailingCollector(FakeCollector):
            fail_health = True

        code, records = collect(FailingCollector)
        self.assertEqual(2, code)
        self.assertFalse(any(record["type"] == "run_end" for record in records))

    def test_train_evaluate_and_report_are_exposed_as_safe_commands(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            dataset = root / "dataset.jsonl"
            dataset.write_text("{}\n", encoding="utf-8")
            output = io.StringIO()
            with patch("ebpf_ransom_lab.cli.load_dataset", return_value=(object(),)), \
                 patch("ebpf_ransom_lab.cli.train_and_select") as trainer, \
                 patch("ebpf_ransom_lab.cli.save_artifact") as saver:
                trainer.return_value = type("Result", (), {
                    "selected_name": "rule", "threshold": 4.0,
                    "test_metrics": {"f1": 1.0},
                })()
                self.assertEqual(0, run(["train", str(dataset), "--output", str(root / "artifact")], stdout=output))
                saver.assert_called_once()

            with patch("ebpf_ransom_lab.cli.load_artifact") as loader, \
                 patch("ebpf_ransom_lab.cli.load_dataset", return_value=()), \
                 patch("ebpf_ransom_lab.cli.evaluate_loaded_artifact", return_value={"f1": 1.0}), \
                 patch("ebpf_ransom_lab.cli.save_test_evaluation"):
                loader.return_value = object()
                self.assertEqual(0, run(["evaluate", str(root / "artifact"), str(dataset)], stdout=output))
            self.assertIn("f1", output.getvalue())

    def test_report_combines_selection_metadata_with_the_one_test_evaluation(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            artifact = root / "artifact"
            artifact.mkdir()
            (artifact / "manifest.json").write_text(json.dumps({
                "artifact_version": "model-artifact-v2",
                "model_name": "rule",
                "selection_manifest_hash": "a" * 64,
                "validation_metrics": {"rule": {"f1": 1.0}},
                "report_sections": {
                    "controlled_workloads": {"status": "selected_not_tested"},
                    "published_data": {"status": "blocked_label_provenance"},
                },
            }), encoding="utf-8")
            output_path = root / "report.json"
            with patch("ebpf_ransom_lab.cli.load_artifact"), \
                 patch("ebpf_ransom_lab.cli.load_test_evaluation", return_value={
                     "dataset_sha256": "b" * 64,
                     "metrics": {"f1": 1.0},
                 }):
                self.assertEqual(0, run([
                    "report", str(artifact), "--output", str(output_path),
                ], stdout=io.StringIO()))

            report = json.loads(output_path.read_text(encoding="utf-8"))
            self.assertEqual("evaluated", report["report_sections"]["controlled_workloads"]["status"])
            self.assertEqual({"f1": 1.0}, report["test_metrics"])


if __name__ == "__main__":
    unittest.main()
