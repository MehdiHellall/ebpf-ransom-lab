import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from ebpf_ransom_lab.capture import validate_capture_file, write_capture_acceptance
from ebpf_ransom_lab.contracts import Event, Heartbeat, ProcessExit, ProcessIdentity, RunEnd, RunStart
from ebpf_ransom_lab.recording import write_jsonl
from ebpf_ransom_lab.workloads import (
    EXPERIMENT_CAPTURE_SECONDS,
    EXPERIMENT_WORKLOAD_HOLD_SECONDS,
    MAX_WORKLOAD_BYTES,
    MAX_WORKLOAD_FILES,
    MAX_WORKLOAD_SECONDS,
    build_experiment_manifest,
    plan_sha256,
    plan_workload,
)


class CaptureValidationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.identity = ProcessIdentity("boot", 42, 100)
        self.run_id = "controlled-copying-seed-11"
        self.manifest = self.root / "run.json"
        self.plan = self.root / "plan.json"
        self.capture = self.root / "capture.jsonl"
        self.manifest.write_text(json.dumps({
            "schema_version": 1,
            "run_id": self.run_id,
            "scenario": "copying",
            "seed": 11,
            "split": "training",
            "behavior_label": "benign",
            "plan_sha256": plan_sha256(plan_workload("copying", 11)),
            "label_provenance": "controlled_workload",
            "tracked_processes": [{
                "boot_id": self.identity.boot_id,
                "tgid": self.identity.tgid,
                "start_time_ns": self.identity.start_time_ns,
            }],
            "process_scope_policy": "root_process_only",
            "background_activity": "unlabeled",
            "status": "completed",
            "workload_hold_seconds": EXPERIMENT_WORKLOAD_HOLD_SECONDS,
            "limits": {
                "max_seconds": MAX_WORKLOAD_SECONDS,
                "max_files": MAX_WORKLOAD_FILES,
                "max_bytes": MAX_WORKLOAD_BYTES,
            },
        }), encoding="utf-8")
        self.plan.write_text(json.dumps(build_experiment_manifest()), encoding="utf-8")

    def records(self, *, event_loss=0, heartbeat_loss=0, end_loss=0, status="complete"):
        end_ns = int(EXPERIMENT_CAPTURE_SECONDS * 1_000_000_000)
        return (
            RunStart(self.run_id, 0, source="live"),
            Event(self.run_id, 1, 1, self.identity, 42, "C", lost_events=event_loss),
            ProcessExit(self.run_id, 2, int(EXPERIMENT_WORKLOAD_HOLD_SECONDS * 1_000_000_000), self.identity, 42),
            Heartbeat(self.run_id, 3, end_ns - 1, lost_events=heartbeat_loss),
            RunEnd(self.run_id, 4, end_ns, status=status, total_lost_events=end_loss),
        )

    def validate(self, records=None):
        write_jsonl(self.capture, records or self.records())
        return validate_capture_file(self.capture, self.manifest, self.plan)

    def test_valid_capture_binds_plan_manifest_and_raw_sha256(self):
        acceptance = self.validate()

        self.assertEqual(self.run_id, acceptance.run_id)
        self.assertEqual(hashlib.sha256(self.capture.read_bytes()).hexdigest(), acceptance.raw_sha256)
        self.assertEqual(self.capture.stat().st_size, acceptance.raw_bytes)
        self.assertEqual(1, acceptance.tracked_event_count)
        self.assertEqual(0, acceptance.total_lost_events)

        output = self.root / "accepted.json"
        write_capture_acceptance(output, acceptance)
        saved = json.loads(output.read_text(encoding="utf-8"))
        self.assertEqual("accepted", saved["status"])
        with self.assertRaises(FileExistsError):
            write_capture_acceptance(output, acceptance)

    def test_any_loss_or_degraded_telemetry_invalidates_the_whole_run(self):
        cases = (
            self.records(event_loss=1, end_loss=1),
            self.records(heartbeat_loss=1, end_loss=1),
            self.records(end_loss=1),
            (
                self.records()[0],
                Event(self.run_id, 1, 1, self.identity, 42, "C", telemetry_quality="degraded"),
                *self.records()[2:],
            ),
        )
        for records in cases:
            with self.subTest(records=records), self.assertRaisesRegex(ValueError, "loss|degraded"):
                self.validate(records)

    def test_truncation_sequence_errors_and_missing_tracked_lifecycle_are_rejected(self):
        valid = self.records()
        foreign = ProcessIdentity("boot", 99, 200)
        cases = (
            valid[:-1],
            (valid[0], valid[2], valid[1], valid[3], valid[4]),
            (valid[0], Event(self.run_id, 2, 1, self.identity, 42, "C"), *valid[2:]),
            (RunStart(self.run_id, 0, "live"), Event(self.run_id, 1, 1, foreign, 99, "C"),
             ProcessExit(self.run_id, 2, 2, foreign, 99), valid[3], valid[4]),
        )
        for records in cases:
            with self.subTest(records=records), self.assertRaises(ValueError):
                self.validate(records)

    def test_capture_must_reach_planned_duration_and_match_frozen_plan(self):
        records = (
            *self.records()[:3],
            Heartbeat(self.run_id, 3, 59_000_000_000 - 1),
            RunEnd(self.run_id, 4, 59_000_000_000),
        )
        with self.assertRaisesRegex(ValueError, "duration"):
            self.validate(records)

        plan = json.loads(self.plan.read_text(encoding="utf-8"))
        plan["runs"][0]["split"] = "test"
        self.plan.write_text(json.dumps(plan), encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "experiment plan"):
            self.validate()
