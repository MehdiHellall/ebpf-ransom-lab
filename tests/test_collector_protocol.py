import base64
import json
import unittest

from ebpf_ransom_lab.collector.protocol import (
    CollectorHealth,
    FilenameBytes,
    LossCounters,
    NormalizedEvent,
    ProcessIdentity,
    PROTOCOL_VERSION,
)


class CollectorProtocolTests(unittest.TestCase):
    def setUp(self):
        self.identity = ProcessIdentity(
            boot_id="89bd29e1-49d3-4bb4-a9f4-4cf74737d67c",
            tgid=412,
            start_time_ns=9_876_543,
        )

    def test_filename_preserves_bytes_and_escapes_unsafe_display_characters(self):
        raw = b"report-\xff\n<script>&\\.txt"

        filename = FilenameBytes.from_bytes(raw, truncated=True)

        self.assertEqual(raw, filename.raw)
        self.assertEqual(
            r"report-\xff\x0a\x3cscript\x3e\x26\\.txt",
            filename.display,
        )
        record = filename.to_dict()
        self.assertEqual(raw, base64.b64decode(record["raw_base64"], validate=True))
        self.assertTrue(record["truncated"])

    def test_valid_utf8_filename_remains_readable(self):
        filename = FilenameBytes.from_bytes("données/été.txt".encode("utf-8"))

        self.assertEqual("données/été.txt", filename.display)

    def test_syscall_record_separates_attempt_from_failed_result(self):
        event = NormalizedEvent.syscall(
            run_id="run-1",
            sequence=7,
            monotonic_ns=12_345,
            identity=self.identity,
            tid=417,
            operation="openat",
            return_value=-13,
            open_flags=0x40,
            filename=FilenameBytes.from_bytes(b"locked"),
        )

        record = event.to_dict()
        self.assertEqual(PROTOCOL_VERSION, record["schema_version"])
        self.assertEqual(
            {"name": "openat", "create_intent": True}, record["attempt"]
        )
        self.assertEqual(
            {"return_value": -13, "succeeded": False}, record["result"]
        )
        self.assertEqual(self.identity.to_dict(), record["process"])
        self.assertEqual(417, record["tid"])
        self.assertNotIn("filename", record["process"])
        self.assertEqual(record, json.loads(event.to_json_line()))

    def test_create_intent_is_never_inferred_for_unlink(self):
        event = NormalizedEvent.syscall(
            run_id="run-1",
            sequence=8,
            monotonic_ns=12_346,
            identity=self.identity,
            tid=417,
            operation="unlinkat",
            return_value=0,
            open_flags=0x40,
            filename=FilenameBytes.from_bytes(b"gone"),
        )

        self.assertFalse(event.to_dict()["attempt"]["create_intent"])
        self.assertTrue(event.to_dict()["result"]["succeeded"])

    def test_process_exit_has_identity_but_no_fake_syscall_result(self):
        event = NormalizedEvent.process_exit(
            run_id="run-1",
            sequence=9,
            monotonic_ns=12_347,
            identity=self.identity,
            tid=412,
        )

        record = event.to_dict()
        self.assertEqual("process_exit", record["event_type"])
        self.assertIsNone(record["attempt"])
        self.assertIsNone(record["result"])
        self.assertIsNone(record["filename"])

    def test_visible_health_record_includes_every_loss_counter(self):
        counters = LossCounters(
            ring_buffer_reservation_failures=2,
            pending_map_update_failures=3,
            filename_read_failures=11,
            identity_read_failures=13,
            consumer_decode_errors=5,
            consumer_queue_drops=7,
        )

        health = CollectorHealth(
            run_id="run-1", connected=True, monotonic_ns=100, counters=counters
        ).to_dict()

        self.assertEqual(41, health["loss_total"])
        self.assertFalse(health["telemetry_complete"])
        self.assertEqual(counters.to_dict(), health["loss_counters"])

    def test_protocol_rejects_invalid_boundaries(self):
        with self.assertRaises(ValueError):
            ProcessIdentity(boot_id="", tgid=1, start_time_ns=1)
        with self.assertRaises(ValueError):
            ProcessIdentity(boot_id="boot", tgid=2**32, start_time_ns=1)
        with self.assertRaises(ValueError):
            LossCounters(consumer_queue_drops=-1)
        with self.assertRaises(ValueError):
            FilenameBytes(raw=b"safe", display="different")
        with self.assertRaises(ValueError):
            NormalizedEvent.syscall(
                run_id="run",
                sequence=0,
                monotonic_ns=1,
                identity=self.identity,
                tid=1,
                operation="rename",
                return_value=0,
                open_flags=0,
                filename=FilenameBytes.from_bytes(b"x"),
            )


if __name__ == "__main__":
    unittest.main()
