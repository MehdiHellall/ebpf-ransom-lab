import json
import tempfile
import unittest
from pathlib import Path

from ebpf_ransom_lab.contracts import Event, Heartbeat, ProcessIdentity, RunEnd, RunStart
from ebpf_ransom_lab.features import WINDOW_NS
from ebpf_ransom_lab.recording import (
    RecordingBudgetExceeded,
    RecordingLineError,
    encode_jsonl_record,
    read_jsonl,
    write_jsonl,
)
from ebpf_ransom_lab.replay import replay_file, replay_records


class ReplayTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.origin = 1_000_000_000
        process = ProcessIdentity("boot", 7, 50)
        self.telemetry = (
            Event("run", 1, self.origin, process, 7, "O", result=3),
            Event("run", 2, self.origin + 1, process, 7, "C", result=4),
            Heartbeat("run", 3, self.origin + WINDOW_NS),
            Event("run", 4, self.origin + 2, process, 7, "D", result=0),
            Event("run", 5, self.origin + WINDOW_NS, process, 7, "O", result=5),
            Heartbeat("run", 6, self.origin + 2 * WINDOW_NS),
        )
        self.records = (
            RunStart("run", self.origin, source="replay"),
            *self.telemetry,
            RunEnd("run", 7, self.origin + 2 * WINDOW_NS),
        )

    def test_jsonl_round_trip_and_trailing_newline(self):
        path = self.root / "recording.jsonl"
        write_jsonl(path, self.records)
        self.assertEqual(self.records, read_jsonl(path))
        self.assertTrue(path.read_bytes().endswith(b"\n"))

    def test_recording_budget_accepts_exact_complete_line(self):
        path = self.root / "bounded.jsonl"
        expected = encode_jsonl_record(self.records[0])
        write_jsonl(path, (self.records[0],), max_bytes=len(expected))
        self.assertEqual(expected, path.read_bytes())

    def test_recording_budget_stops_before_partial_line_and_closes_file(self):
        path = self.root / "bounded.jsonl"
        first = encode_jsonl_record(self.records[0])
        with self.assertRaisesRegex(RecordingBudgetExceeded, "recording byte budget"):
            write_jsonl(path, self.records[:2], max_bytes=len(first))
        self.assertEqual(first, path.read_bytes())
        # The writer's context has closed the file even on the error path.
        path.rename(self.root / "closed.jsonl")

    def test_recording_budget_rejects_first_line_without_writing_bytes(self):
        path = self.root / "bounded.jsonl"
        required = len(encode_jsonl_record(self.records[0]))
        with self.assertRaises(RecordingBudgetExceeded):
            write_jsonl(path, (self.records[0],), max_bytes=required - 1)
        self.assertEqual(b"", path.read_bytes())

    def test_batch_and_arbitrary_chunks_have_identical_final_windows(self):
        batch = replay_records(self.records, capture_start_ns=self.origin)
        one_by_one = replay_records(
            self.records, capture_start_ns=self.origin, chunk_sizes=(1, 1, 1, 1, 1, 1)
        )
        arbitrary = replay_records(
            self.records, capture_start_ns=self.origin, chunk_sizes=(2, 3, 1)
        )
        with_empty_chunks = replay_records(
            self.records, capture_start_ns=self.origin, chunk_sizes=(0, 2, 0, 4, 0)
        )
        self.assertEqual(batch, one_by_one)
        self.assertEqual(batch, arbitrary)
        self.assertEqual(batch, with_empty_chunks)
        self.assertEqual(2, len(batch))
        self.assertEqual(1, batch[0].late_event_count)
        self.assertEqual(1, batch[0].feature_map["OCD"])

    def test_replay_file_uses_same_path(self):
        path = self.root / "recording.jsonl"
        write_jsonl(path, self.records)
        self.assertEqual(
            replay_records(self.records, capture_start_ns=self.origin),
            replay_file(path, capture_start_ns=self.origin, chunk_sizes=(2, 1, 3)),
        )

    def test_json_errors_identify_path_and_line(self):
        path = self.root / "bad.jsonl"
        path.write_text(
            json.dumps(self.records[0].to_dict()) + "\n{not json}\n",
            encoding="utf-8",
        )
        with self.assertRaisesRegex(RecordingLineError, r"bad\.jsonl:2: invalid JSON"):
            read_jsonl(path)

    def test_blank_unknown_and_invalid_records_identify_line(self):
        path = self.root / "bad.jsonl"
        for text, line, reason in (
            ("\n", 1, "blank"),
            (json.dumps({"type": "unknown", "schema_version": 1}) + "\n", 1, "record type"),
            (json.dumps(self.records[0].to_dict()) + "\n[]\n", 2, "object"),
        ):
            with self.subTest(text=text):
                path.write_text(text, encoding="utf-8")
                with self.assertRaises(RecordingLineError) as raised:
                    read_jsonl(path)
                self.assertIn(f":{line}:", str(raised.exception))
                self.assertIn(reason, str(raised.exception))

    def test_replay_always_needs_a_complete_stream_envelope(self):
        with self.assertRaisesRegex(ValueError, "run-start"):
            replay_records((), capture_start_ns=self.origin)
        with self.assertRaisesRegex(ValueError, "run-start"):
            replay_records(())
        with self.assertRaisesRegex(ValueError, "run-start"):
            replay_records(self.telemetry, capture_start_ns=self.origin)

    def test_recorded_run_start_is_a_reproducible_capture_alignment(self):
        self.assertEqual(replay_records(self.records), replay_records(
            self.records, capture_start_ns=self.origin
        ))
        with self.assertRaisesRegex(ValueError, "does not match"):
            replay_records(self.records, capture_start_ns=self.origin + 1)

    def test_terminal_run_end_supplies_capture_end_without_becoming_a_feature_record(self):
        complete = self.records
        invalid = (
            (*complete, complete[-1]),
            (complete[-1], *complete[:-1]),
            (*complete[:-1], RunEnd("other", 7, self.origin + 2 * WINDOW_NS)),
        )
        for records in invalid:
            with self.subTest(records=records), self.assertRaises(ValueError):
                replay_records(records)

    def test_replay_rejects_loss_degraded_events_and_sequence_gaps(self):
        base = self.records
        lossy = (
            base[0],
            Event("run", 1, self.origin, base[1].process, 7, "O", result=3, lost_events=1),
            *base[2:-1],
            RunEnd("run", 7, self.origin + 2 * WINDOW_NS, total_lost_events=1),
        )
        degraded = (
            base[0],
            Event(
                "run", 1, self.origin, base[1].process, 7, "O", result=3,
                telemetry_quality="degraded",
            ),
            *base[2:],
        )
        gap = (base[0], base[1], *base[3:])
        for records, reason in ((lossy, "lost"), (degraded, "degraded"), (gap, "sequence")):
            with self.subTest(reason=reason), self.assertRaisesRegex(ValueError, reason):
                replay_records(records)


if __name__ == "__main__":
    unittest.main()
