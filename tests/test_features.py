import unittest

from ebpf_ransom_lab.contracts import Event, Heartbeat, ProcessIdentity, ProcessExit
from ebpf_ransom_lab.features import (
    FEATURE_NAMES,
    SEQUENCE_NAMES,
    WINDOW_NS,
    WindowFeatureEngine,
)


class WindowFeatureTests(unittest.TestCase):
    def setUp(self):
        self.origin = 100_000_000_000
        self.p1 = ProcessIdentity("boot", 10, 100)
        self.p2 = ProcessIdentity("boot", 11, 200)

    def event(self, seq, offset, operation, process=None, lost=0):
        process = process or self.p1
        return Event(
            "run", seq, self.origin + offset, process, process.tgid,
            operation, lost_events=lost,
        )

    def values(self, window):
        return window.feature_map

    def test_feature_schema_is_fixed_to_counts_maxima_and_all_triples(self):
        self.assertEqual(27, len(SEQUENCE_NAMES))
        self.assertEqual("OOO", SEQUENCE_NAMES[0])
        self.assertEqual("DDD", SEQUENCE_NAMES[-1])
        self.assertEqual(33, len(FEATURE_NAMES))
        self.assertEqual(
            ("O_sum", "C_sum", "D_sum", "O_max_1s", "C_max_1s", "D_max_1s"),
            FEATURE_NAMES[:6],
        )
        self.assertEqual(SEQUENCE_NAMES, FEATURE_NAMES[6:])

    def test_counts_maxima_and_overlapping_sequences(self):
        engine = WindowFeatureEngine(self.origin)
        records = (
            self.event(4, 100_000_000, "O"),
            self.event(1, 200_000_000, "O"),
            self.event(3, 1_100_000_000, "D"),
            self.event(2, 1_200_000_000, "C"),
        )
        emitted = engine.feed(records)
        emitted += engine.feed((Heartbeat("run", 5, self.origin + WINDOW_NS),))
        self.assertEqual(1, len(emitted))
        values = self.values(emitted[0])
        self.assertEqual((2, 1, 1), tuple(values[name] for name in FEATURE_NAMES[:3]))
        self.assertEqual((2, 1, 1), tuple(values[name] for name in FEATURE_NAMES[3:6]))
        # Collector order is O,C,D,O even though input and timestamps differ.
        self.assertEqual(1, values["OCD"])
        self.assertEqual(1, values["CDO"])
        self.assertEqual(0, values["ODC"])

    def test_sequences_do_not_cross_process_or_window_boundaries(self):
        engine = WindowFeatureEngine(self.origin)
        engine.feed((
            self.event(0, 0, "O"),
            self.event(1, 1, "C", self.p2),
            self.event(2, WINDOW_NS - 1, "D"),
            self.event(3, WINDOW_NS, "O"),
            self.event(4, WINDOW_NS + 1, "C"),
        ))
        engine.finish(self.origin + 2 * WINDOW_NS)
        windows = engine.windows
        by_key = {(window.process, window.start_ns): window for window in windows}
        self.assertEqual(0, sum(by_key[(self.p1, self.origin)].feature_map[name] for name in SEQUENCE_NAMES))
        self.assertEqual(0, sum(by_key[(self.p2, self.origin)].feature_map[name] for name in SEQUENCE_NAMES))
        self.assertEqual(0, sum(by_key[(self.p1, self.origin + WINDOW_NS)].feature_map[name] for name in SEQUENCE_NAMES))

    def test_boundary_event_advances_and_closes_previous_window(self):
        engine = WindowFeatureEngine(self.origin)
        self.assertEqual((), engine.feed((self.event(0, 0, "O"),)))
        emitted = engine.feed((self.event(1, WINDOW_NS, "C"),))
        self.assertEqual(1, len(emitted))
        self.assertEqual(self.origin, emitted[0].start_ns)
        self.assertTrue(emitted[0].complete)
        remaining = engine.finish(self.origin + WINDOW_NS + 1)
        self.assertEqual(self.origin + WINDOW_NS, remaining[0].start_ns)
        self.assertTrue(remaining[0].partial)

    def test_heartbeat_watermark_closes_quiet_window(self):
        engine = WindowFeatureEngine(self.origin)
        engine.feed((self.event(0, 1, "O"),))
        windows = engine.feed((Heartbeat("run", 1, self.origin + WINDOW_NS),))
        self.assertEqual(1, len(windows))
        self.assertEqual(1, windows[0].feature_map["O_sum"])
        self.assertFalse(windows[0].partial)

    def test_late_event_returns_replacement_with_same_id(self):
        engine = WindowFeatureEngine(self.origin)
        engine.feed((self.event(0, 0, "O"),))
        original = engine.feed((Heartbeat("run", 1, self.origin + WINDOW_NS),))[0]
        replacement = engine.feed((self.event(2, 1, "C"),))[0]
        self.assertEqual(original.window_id, replacement.window_id)
        self.assertEqual(1, replacement.late_event_count)
        self.assertEqual(("late",), replacement.quality)
        self.assertFalse(replacement.classifiable)
        self.assertEqual(1, replacement.feature_map["C_sum"])
        self.assertEqual(0, original.feature_map["C_sum"])

    def test_first_event_for_process_in_closed_interval_is_late(self):
        engine = WindowFeatureEngine(self.origin)
        engine.feed((Heartbeat("run", 0, self.origin + WINDOW_NS),))
        late = engine.feed((self.event(1, 1, "O"),))[0]
        self.assertEqual(1, late.late_event_count)
        self.assertEqual(("late",), late.quality)
        self.assertEqual(1, late.feature_map["O_sum"])

    def test_loss_is_retained_as_quality_and_prevents_classification(self):
        engine = WindowFeatureEngine(self.origin)
        engine.feed((self.event(0, 0, "O", lost=3),))
        window = engine.feed((Heartbeat("run", 1, self.origin + WINDOW_NS),))[0]
        self.assertEqual(3, window.loss_count)
        self.assertEqual(("loss",), window.quality)
        self.assertFalse(window.complete)
        self.assertFalse(window.classifiable)

    def test_loss_watermark_applies_to_a_process_seen_later_in_same_window(self):
        engine = WindowFeatureEngine(self.origin)
        engine.feed((Heartbeat("run", 0, self.origin + 1, lost_events=5),))
        engine.feed((self.event(1, 2, "O"),))
        window = engine.feed((Heartbeat("run", 2, self.origin + WINDOW_NS),))[0]
        self.assertEqual(5, window.loss_count)
        self.assertEqual(("loss",), window.quality)

    def test_event_loss_returns_replacements_for_already_closed_process_windows(self):
        engine = WindowFeatureEngine(self.origin)
        engine.feed((self.event(0, 0, "O"), self.event(1, 0, "O", self.p2)))
        originals = engine.feed((Heartbeat("run", 2, self.origin + WINDOW_NS),))
        emitted = engine.feed((self.event(3, 1, "C", lost=4),))
        latest = {window.window_id: window for window in (*originals, *emitted)}
        self.assertEqual(2, len(latest))
        self.assertEqual({4}, {window.loss_count for window in latest.values()})
        self.assertTrue(all(not window.classifiable for window in latest.values()))

    def test_finish_and_process_exit_preserve_partial_windows(self):
        engine = WindowFeatureEngine(self.origin)
        engine.feed((self.event(0, 1, "O"), self.event(1, 2, "C", self.p2)))
        exited = engine.close_process(self.p1, self.origin + 3)
        self.assertEqual(1, len(exited))
        self.assertTrue(exited[0].partial)
        final = engine.finish(self.origin + 4)
        self.assertEqual(1, len(final))
        self.assertEqual(self.p2, final[0].process)
        self.assertTrue(final[0].partial)

    def test_lifecycle_process_exit_record_closes_the_matching_window(self):
        event = self.event(1, 1, "O")
        exit_record = ProcessExit("run", 2, self.origin + 2, event.process, event.tid)
        engine = WindowFeatureEngine(self.origin)
        engine.feed((event,))
        emitted = engine.feed((exit_record,))
        self.assertEqual(1, len(emitted))
        self.assertTrue(emitted[0].partial)
        final = engine.finish(self.origin + 4)
        self.assertEqual((), final)

    def test_run_and_timestamp_validation(self):
        engine = WindowFeatureEngine(self.origin)
        engine.feed((self.event(0, 1, "O"),))
        with self.assertRaisesRegex(ValueError, "run"):
            engine.feed((Event("other", 1, self.origin + 2, self.p1, 10, "O"),))
        with self.assertRaisesRegex(ValueError, "capture start"):
            WindowFeatureEngine(self.origin).feed((self.event(0, -1, "O"),))
        duplicate = WindowFeatureEngine(self.origin)
        duplicate.feed((self.event(7, 0, "O"),))
        with self.assertRaisesRegex(ValueError, "collector sequence"):
            duplicate.feed((self.event(7, 1, "C"),))


if __name__ == "__main__":
    unittest.main()
