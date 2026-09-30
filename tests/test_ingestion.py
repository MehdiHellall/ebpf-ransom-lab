import io
import json
import tempfile
import unittest
from pathlib import Path

from ebpf_ransom_lab.contracts import Event, Heartbeat, ProcessIdentity, RunEnd, RunStart
from ebpf_ransom_lab.features import WINDOW_NS
from ebpf_ransom_lab.ingestion import ingest_jsonl_stream
from ebpf_ransom_lab.storage import Store


class IngestionTests(unittest.TestCase):
    def test_pipe_ingestion_uses_the_same_window_rule_and_health_path(self):
        identity = ProcessIdentity("boot", 8, 9)
        records = (
            RunStart("run", 0, source="live"),
            Event("run", 1, 0, identity, 8, "C", result=0),
            Event("run", 2, 1, identity, 8, "D", result=0),
            Heartbeat("run", 3, WINDOW_NS),
            RunEnd("run", 4, WINDOW_NS),
        )
        stream = io.StringIO("".join(json.dumps(record.to_dict()) + "\n" for record in records))
        with tempfile.TemporaryDirectory() as directory:
            store = Store(Path(directory) / "runs.sqlite")
            store.initialize()
            summary = ingest_jsonl_stream(stream, store, capture_start_ns=0, threshold=0.1)
            self.assertEqual("run", summary.run_id)
            self.assertEqual(1, summary.windows)
            self.assertEqual(1, summary.alerts)
            self.assertFalse(store.health()["collector_connected"])
            self.assertEqual(1, store.metrics()["active_alerts"])

    def test_malformed_pipe_line_is_a_visible_disconnected_error(self):
        with tempfile.TemporaryDirectory() as directory:
            store = Store(Path(directory) / "runs.sqlite")
            store.initialize()
            with self.assertRaisesRegex(ValueError, "line 1"):
                ingest_jsonl_stream(io.StringIO("not-json\n"), store, capture_start_ns=0)
            self.assertIn("line 1", store.health()["error"])

    def test_live_run_start_can_supply_the_required_capture_alignment(self):
        identity = ProcessIdentity("boot", 8, 9)
        records = (
            RunStart("run", 0, source="live"),
            Event("run", 1, 0, identity, 8, "O", result=3),
            Heartbeat("run", 2, WINDOW_NS),
            RunEnd("run", 3, WINDOW_NS),
        )
        stream = io.StringIO("".join(json.dumps(record.to_dict()) + "\n" for record in records))
        with tempfile.TemporaryDirectory() as directory:
            store = Store(Path(directory) / "runs.sqlite")
            store.initialize()
            summary = ingest_jsonl_stream(stream, store)
            self.assertEqual(1, summary.windows)

    def test_invalid_terminal_stream_leaves_no_partial_run_data(self):
        identity = ProcessIdentity("boot", 8, 9)
        records = (
            RunStart("run", 0, source="live"),
            Event("run", 1, 0, identity, 8, "C", result=3),
            Heartbeat("run", 3, WINDOW_NS),
            RunEnd("run", 4, WINDOW_NS),
        )
        stream = io.StringIO("".join(json.dumps(record.to_dict()) + "\n" for record in records))
        with tempfile.TemporaryDirectory() as directory:
            store = Store(Path(directory) / "runs.sqlite")
            store.initialize()
            with self.assertRaisesRegex(ValueError, "sequence"):
                ingest_jsonl_stream(stream, store)
            self.assertEqual((), store.list_runs(limit=10, offset=0))
            self.assertEqual(0, store.metrics()["windows"])

    def test_lossy_stream_is_rejected_without_persisting_alerts(self):
        identity = ProcessIdentity("boot", 8, 9)
        records = (
            RunStart("run", 0, source="live"),
            Event("run", 1, 0, identity, 8, "D", result=0, lost_events=1),
            RunEnd("run", 2, WINDOW_NS, total_lost_events=1),
        )
        stream = io.StringIO("".join(json.dumps(record.to_dict()) + "\n" for record in records))
        with tempfile.TemporaryDirectory() as directory:
            store = Store(Path(directory) / "runs.sqlite")
            store.initialize()
            with self.assertRaisesRegex(ValueError, "lost events"):
                ingest_jsonl_stream(stream, store, threshold=0.0)
            self.assertEqual(0, store.metrics()["active_alerts"])


if __name__ == "__main__":
    unittest.main()
