import dataclasses
import unittest

from ebpf_ransom_lab.contracts import (
    CONTRACT_VERSION,
    Event,
    FeatureWindow,
    Heartbeat,
    ProcessIdentity,
    ProcessExit,
    RunStart,
    record_from_dict,
)


class ContractTests(unittest.TestCase):
    def setUp(self):
        self.process = ProcessIdentity("boot-a", 42, 1_234)

    def test_records_are_immutable_and_versioned(self):
        event = Event("run-a", 3, 5_000, self.process, 43, "O")
        self.assertEqual(CONTRACT_VERSION, event.schema_version)
        self.assertEqual(CONTRACT_VERSION, self.process.schema_version)
        with self.assertRaises(dataclasses.FrozenInstanceError):
            event.operation = "D"
        with self.assertRaises(dataclasses.FrozenInstanceError):
            self.process.tgid = 99

    def test_event_round_trip_is_stable(self):
        event = Event(
            "run-a", 3, 5_000, self.process, 43, "C", result=-13,
            filename="bad-\ufffd-name", filename_bytes_b64="YmFkLWZm",
            telemetry_quality="degraded", lost_events=2,
        )
        encoded = event.to_dict()
        self.assertEqual("event", encoded["type"])
        self.assertEqual(event, record_from_dict(encoded))
        self.assertEqual(encoded, record_from_dict(encoded).to_dict())

    def test_heartbeat_round_trip(self):
        heartbeat = Heartbeat("run-a", 4, 10_000, lost_events=7)
        self.assertEqual(heartbeat, record_from_dict(heartbeat.to_dict()))

    def test_process_exit_round_trip_preserves_lifecycle_identity(self):
        process_exit = ProcessExit("run", 7, 123, ProcessIdentity("boot", 3, 4), 3)
        self.assertEqual(process_exit, record_from_dict(process_exit.to_dict()))

    def test_run_start_round_trip_freezes_capture_alignment(self):
        record = RunStart("run", 123, source="live")
        self.assertEqual(record, record_from_dict(record.to_dict()))

    def test_window_has_deterministic_identity_feature_mapping_and_quality(self):
        window = FeatureWindow(
            "run-a", self.process, 0, 10, ("a", "b"), (2, 3),
            partial=True, loss_count=4, late_event_count=1,
        )
        same = FeatureWindow(
            "run-a", self.process, 0, 10, ("a", "b"), (9, 8),
            partial=True, loss_count=4, late_event_count=2,
        )
        self.assertEqual(window.window_id, same.window_id)
        self.assertEqual({"a": 2, "b": 3}, window.feature_map)
        self.assertEqual(("partial", "loss", "late"), window.quality)
        self.assertFalse(window.complete)
        self.assertFalse(window.classifiable)
        self.assertEqual(window, FeatureWindow.from_dict(window.to_dict()))

    def test_complete_window_quality(self):
        window = FeatureWindow("run-a", self.process, 0, 10, ("a",), (0,))
        self.assertEqual(("complete",), window.quality)
        self.assertTrue(window.complete)
        self.assertTrue(window.classifiable)

    def test_contract_validation_rejects_ambiguous_or_invalid_values(self):
        invalid = (
            lambda: ProcessIdentity("", 1, 0),
            lambda: ProcessIdentity("boot", True, 0),
            lambda: ProcessIdentity("boot", 1, 0, schema_version=True),
            lambda: ProcessIdentity("boot", 2**32, 0),
            lambda: ProcessIdentity("boot", 1, 2**64),
            lambda: Event("run", 0, 0, self.process, 1, "X"),
            lambda: Event("run", -1, 0, self.process, 1, "O"),
            lambda: Event("run", 2**64, 0, self.process, 1, "O"),
            lambda: Event("run", 0, 0, self.process, 1, "O", lost_events=-1),
            lambda: Event("run", 0, 0, self.process, 1, "O", filename_bytes_b64="not b64"),
            lambda: Heartbeat("run", 0, -1),
            lambda: FeatureWindow("run", self.process, 10, 10, (), ()),
            lambda: FeatureWindow("run", self.process, 0, 10, ("a",), ()),
            lambda: FeatureWindow("run", self.process, 0, 10, ("a", "a"), (0, 0)),
            lambda: FeatureWindow("run", self.process, 0, 10, ("a",), (0,), feature_version=1.0),
        )
        for make in invalid:
            with self.subTest(make=make), self.assertRaises(ValueError):
                make()

    def test_unknown_or_incompatible_record_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "record type"):
            record_from_dict({"type": "mystery", "schema_version": CONTRACT_VERSION})
        with self.assertRaisesRegex(ValueError, "schema version"):
            record_from_dict({"type": "heartbeat", "schema_version": 99})

    def test_nested_process_identity_requires_explicit_type_and_version(self):
        encoded = self.process.to_dict()
        for missing in ("type", "schema_version"):
            with self.subTest(missing=missing), self.assertRaises(ValueError):
                ProcessIdentity.from_dict({key: value for key, value in encoded.items() if key != missing})


if __name__ == "__main__":
    unittest.main()
