import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from ebpf_ransom_lab.cli import run
from ebpf_ransom_lab.contracts import Event, Heartbeat, ProcessIdentity
from ebpf_ransom_lab.features import WINDOW_NS
from ebpf_ransom_lab.recording import read_jsonl, write_jsonl
from ebpf_ransom_lab.doctor import DoctorContext
from ebpf_ransom_lab.reference import FileVerification, VerificationReport


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
            Event("controlled-copying-seed-11", 1, 0, identity, 9, "C"),
            Event("controlled-copying-seed-11", 2, 1, identity, 9, "D"),
            Heartbeat("controlled-copying-seed-11", 3, WINDOW_NS),
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            recording = root / "recording.jsonl"
            features = root / "features.jsonl"
            manifest = root / "run-manifest.json"
            dataset = root / "dataset.jsonl"
            write_jsonl(recording, records)
            manifest.write_text(json.dumps({
                "schema_version": 1, "run_id": "controlled-copying-seed-11",
                "split": "training", "behavior_label": "benign",
                "label_provenance": "controlled_workload", "background_activity": "unlabeled",
                "tracked_processes": [{"boot_id": "boot", "tgid": 9, "start_time_ns": 10}],
            }), encoding="utf-8")
            output = io.StringIO()
            self.assertEqual(0, run([
                "features", str(recording), "--capture-start-ns", "0",
                "--capture-end-ns", str(WINDOW_NS), "--output", str(features),
            ], stdout=output))
            self.assertEqual(0, run([
                "dataset", "build", str(features), str(manifest), "--output", str(dataset),
            ], stdout=output))
            row = json.loads(dataset.read_text(encoding="utf-8"))
            self.assertEqual(0, row["label"])
            self.assertEqual("training", row["split"])

    def test_collect_command_is_present_and_fails_closed_without_linux_root(self):
        output = io.StringIO()
        with patch("ebpf_ransom_lab.cli.os.name", "nt"):
            self.assertEqual(2, run(["collect", "--run-id", "demo"], stdout=output))
        self.assertEqual("", output.getvalue())

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
                 patch("ebpf_ransom_lab.cli.evaluate_loaded_artifact", return_value={"f1": 1.0}):
                loader.return_value = object()
                self.assertEqual(0, run(["evaluate", str(root / "artifact"), str(dataset)], stdout=output))
            self.assertIn("f1", output.getvalue())


if __name__ == "__main__":
    unittest.main()
