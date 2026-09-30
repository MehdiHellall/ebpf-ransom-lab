import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from ebpf_ransom_lab.contracts import FeatureWindow, ProcessIdentity
from ebpf_ransom_lab.detection import RuleScorer
from ebpf_ransom_lab.features import FEATURE_NAMES
from ebpf_ransom_lab.storage import Store


class StoreTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.store = Store(Path(self.directory.name) / "runs.sqlite")
        self.store.initialize()
        self.store.upsert_run("run-1", source="replay", started_ns=0, status="complete")
        values = tuple(50 if name == "D_sum" else 0 for name in FEATURE_NAMES)
        self.window = FeatureWindow(
            "run-1", ProcessIdentity("boot", 7, 11), 0, 10_000_000_000,
            FEATURE_NAMES, values,
        )

    def tearDown(self):
        self.directory.cleanup()

    def test_window_prediction_alert_and_pagination_round_trip(self):
        prediction = RuleScorer(threshold=4.0).predict(self.window)
        self.store.upsert_window(self.window)
        self.store.upsert_prediction(prediction)
        self.store.create_alert(prediction, self.window)

        self.assertEqual("run-1", self.store.list_runs(limit=1, offset=0)[0]["run_id"])
        self.assertEqual("7", self.store.list_processes(limit=10, offset=0)[0]["tgid"])
        self.assertEqual(self.window.window_id, self.store.list_windows(limit=10, offset=0)[0]["window_id"])
        self.assertEqual(1, len(self.store.list_alerts(limit=10, offset=0)))
        self.assertEqual(1, self.store.metrics()["suspicious_windows"])
        self.assertEqual((), self.store.list_runs(limit=1, offset=1))

    def test_health_defaults_to_disconnected_and_can_be_updated(self):
        self.assertFalse(self.store.health()["collector_connected"])
        self.store.update_health(connected=True, event_rate=3.5, lost_events=2, recording=True, error=None)
        health = self.store.health()
        self.assertTrue(health["collector_connected"])
        self.assertEqual(2, health["lost_events"])

    def test_foreign_keys_reject_orphan_windows(self):
        orphan = FeatureWindow(
            "missing", self.window.process, self.window.start_ns, self.window.end_ns,
            self.window.feature_names, self.window.values,
        )
        with self.assertRaises(Exception):
            self.store.upsert_window(orphan)

    def test_negative_rescore_invalidates_and_positive_rescore_reactivates_alert(self):
        positive = RuleScorer(threshold=4.0).predict(self.window)
        self.store.upsert_window(self.window)
        self.store.upsert_prediction(positive)
        self.store.create_alert(positive, self.window)
        self.assertEqual(1, self.store.metrics()["active_alerts"])

        negative = RuleScorer(threshold=100.0).predict(self.window)
        self.store.upsert_prediction(negative)
        self.assertEqual(0, self.store.metrics()["active_alerts"])

        self.store.upsert_prediction(positive)
        self.store.create_alert(positive, self.window)
        self.assertEqual(1, self.store.metrics()["active_alerts"])
        self.assertTrue(self.store.list_alerts(limit=10, offset=0)[0]["valid"])

    def test_run_analysis_rolls_back_as_one_transaction(self):
        prediction = RuleScorer(threshold=4.0).predict(self.window)
        self.store.replace_run_analysis(
            "run-1",
            source="replay",
            started_ns=0,
            windows=(self.window,),
            predictions=(prediction,),
        )
        with patch(
            "ebpf_ransom_lab.storage._upsert_prediction",
            side_effect=RuntimeError("forced write failure"),
        ):
            with self.assertRaisesRegex(RuntimeError, "forced write failure"):
                self.store.replace_run_analysis(
                    "run-1",
                    source="replay",
                    started_ns=1,
                    windows=(self.window,),
                    predictions=(prediction,),
                )

        self.assertEqual(1, self.store.metrics()["windows"])
        self.assertEqual(1, self.store.metrics()["active_alerts"])
        self.assertEqual("0", self.store.list_runs(limit=1, offset=0)[0]["started_ns"])


if __name__ == "__main__":
    unittest.main()
