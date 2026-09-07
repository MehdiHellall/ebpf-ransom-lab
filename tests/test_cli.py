import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from ebpf_ransom_lab.cli import run
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


if __name__ == "__main__":
    unittest.main()
