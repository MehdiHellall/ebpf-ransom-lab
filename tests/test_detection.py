import unittest

from ebpf_ransom_lab.contracts import FeatureWindow, ProcessIdentity
from ebpf_ransom_lab.detection import RuleScorer
from ebpf_ransom_lab.features import FEATURE_NAMES


def window(**changes):
    values = tuple(50 if name == "D_sum" else 0 for name in FEATURE_NAMES)
    fields = {
        "run_id": "run-1",
        "process": ProcessIdentity("boot", 123, 456),
        "start_ns": 0,
        "end_ns": 10_000_000_000,
        "feature_names": FEATURE_NAMES,
        "values": values,
    }
    fields.update(changes)
    return FeatureWindow(**fields)


class RuleScorerTests(unittest.TestCase):
    def test_transparent_rule_scores_complete_windows(self):
        prediction = RuleScorer(threshold=4.0).predict(window())
        self.assertEqual(5.0, prediction.score)
        self.assertTrue(prediction.suspicious)
        self.assertEqual((("C_sum", 0), ("D_sum", 50)), prediction.supporting_features)

    def test_partial_loss_and_late_windows_abstain(self):
        cases = (window(partial=True), window(loss_count=2), window(late_event_count=1))
        for item in cases:
            with self.subTest(quality=item.quality):
                prediction = RuleScorer().predict(item)
                self.assertIsNone(prediction.score)
                self.assertIsNone(prediction.suspicious)
                self.assertNotEqual("complete", prediction.quality)


if __name__ == "__main__":
    unittest.main()
