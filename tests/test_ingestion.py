import io
import json
import tempfile
import unittest
from pathlib import Path

from ebpf_ransom_lab.contracts import Event, Heartbeat, ProcessIdentity, RunStart
from ebpf_ransom_lab.features import WINDOW_NS
from ebpf_ransom_lab.ingestion import ingest_jsonl_stream
from ebpf_ransom_lab.storage import Store


class IngestionTests(unittest.TestCase):
    def test_pipe_ingestion_uses_the_same_window_rule_and_health_path(self):
        identity = ProcessIdentity("boot", 8, 9)
        records = (
            Event("run", 1, 0, identity, 8, "C"),
            Event("run", 2, 1, identity, 8, "D"),
            Heartbeat("run", 3, WINDOW_NS),
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
            Event("run", 1, 0, identity, 8, "O"),
            Heartbeat("run", 2, WINDOW_NS),
        )
        stream = io.StringIO("".join(json.dumps(record.to_dict()) + "\n" for record in records))
        with tempfile.TemporaryDirectory() as directory:
            store = Store(Path(directory) / "runs.sqlite")
            store.initialize()
            summary = ingest_jsonl_stream(stream, store)
            self.assertEqual(1, summary.windows)


if __name__ == "__main__":
    unittest.main()
