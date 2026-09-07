import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from ebpf_ransom_lab.reference import load_manifest, read_git_commit, verify_reference


class ReferenceVerificationTests(unittest.TestCase):
    COMMIT = "a" * 40

    def write_manifest(self, root: Path, digest: str) -> Path:
        manifest_path = root / "manifest.json"
        manifest_path.write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "repository": "https://example.test/upstream.git",
                    "commit": self.COMMIT,
                    "license": "MIT",
                    "files": [
                        {
                            "path": "data/example.txt",
                            "sha256": digest,
                            "size": 8,
                        }
                    ],
                }
            ),
            encoding="utf-8",
        )
        return manifest_path

    def test_valid_reference_matches_manifest_and_commit(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            evidence = root / "checkout" / "data" / "example.txt"
            evidence.parent.mkdir(parents=True)
            evidence.write_bytes(b"evidence")
            digest = hashlib.sha256(b"evidence").hexdigest()
            manifest = load_manifest(self.write_manifest(root, digest))

            report = verify_reference(
                root / "checkout", manifest, commit_reader=lambda _: self.COMMIT
            )

            self.assertTrue(report.ok)
            self.assertEqual("match", report.commit_status)
            self.assertEqual("match", report.files[0].status)

    def test_changed_file_fails_verification(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            evidence = root / "checkout" / "data" / "example.txt"
            evidence.parent.mkdir(parents=True)
            evidence.write_bytes(b"changed")
            expected = hashlib.sha256(b"evidence").hexdigest()
            manifest = load_manifest(self.write_manifest(root, expected))

            report = verify_reference(
                root / "checkout", manifest, commit_reader=lambda _: self.COMMIT
            )

            self.assertFalse(report.ok)
            self.assertEqual("mismatch", report.files[0].status)

    def test_missing_file_and_wrong_commit_are_both_reported(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            expected = hashlib.sha256(b"evidence").hexdigest()
            manifest = load_manifest(self.write_manifest(root, expected))

            report = verify_reference(
                root / "checkout", manifest, commit_reader=lambda _: "other"
            )

            self.assertFalse(report.ok)
            self.assertEqual("mismatch", report.commit_status)
            self.assertEqual("missing", report.files[0].status)

    def test_manifest_rejects_unsafe_relative_paths(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest_path = self.write_manifest(root, "0" * 64)
            document = json.loads(manifest_path.read_text(encoding="utf-8"))
            document["files"][0]["path"] = "../escape.txt"
            manifest_path.write_text(json.dumps(document), encoding="utf-8")

            with self.assertRaises(ValueError):
                load_manifest(manifest_path)

    def test_git_commit_reader_returns_commit(self):
        completed = type(
            "Completed",
            (),
            {"stdout": "abc123\n"},
        )()
        with patch("ebpf_ransom_lab.reference.subprocess.run", return_value=completed) as run:
            commit = read_git_commit(Path("C:/reference checkout"))

        self.assertEqual("abc123", commit)
        command = run.call_args.args[0]
        self.assertEqual("safe.directory=C:/reference checkout", command[2])

    def test_git_commit_reader_handles_missing_git(self):
        with patch(
            "ebpf_ransom_lab.reference.subprocess.run",
            side_effect=FileNotFoundError,
        ):
            self.assertIsNone(read_git_commit(Path("missing")))

    def test_manifest_rejects_invalid_hash_and_size(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest_path = self.write_manifest(root, "0" * 64)
            document = json.loads(manifest_path.read_text(encoding="utf-8"))
            document["files"][0]["sha256"] = "not-a-hash"
            manifest_path.write_text(json.dumps(document), encoding="utf-8")
            with self.assertRaises(ValueError):
                load_manifest(manifest_path)

            document["files"][0]["sha256"] = "0" * 64
            document["files"][0]["size"] = -1
            manifest_path.write_text(json.dumps(document), encoding="utf-8")
            with self.assertRaises(ValueError):
                load_manifest(manifest_path)

    def test_manifest_rejects_unsafe_repository_and_short_commit(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest_path = self.write_manifest(root, "0" * 64)
            document = json.loads(manifest_path.read_text(encoding="utf-8"))
            document["repository"] = "git@example.test:upstream.git"
            manifest_path.write_text(json.dumps(document), encoding="utf-8")
            with self.assertRaises(ValueError):
                load_manifest(manifest_path)

            document["repository"] = "https://example.test/upstream.git"
            document["commit"] = "abc123"
            manifest_path.write_text(json.dumps(document), encoding="utf-8")
            with self.assertRaises(ValueError):
                load_manifest(manifest_path)


if __name__ == "__main__":
    unittest.main()
