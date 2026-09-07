import dataclasses
import unittest

from ebpf_ransom_lab.legacy import Event, FeatureTable, reconstruct


class LegacyReconstructionTests(unittest.TestCase):
    def test_empty_input(self):
        self.assertEqual(FeatureTable(("PID", "P_max", "P_sum"), ()), reconstruct(()))
        self.assertEqual(reconstruct(()), reconstruct(((), ())))

    def test_observed_columns_are_sorted_and_missing_types_are_zero(self):
        table = reconstruct(((Event(0, 9, "O", 0), Event(0, 2, "C", 1)),))
        self.assertEqual(("PID", "C_max", "C_sum", "O_max", "O_sum", "P_max", "P_sum"), table.columns)
        self.assertEqual(((2, 1, 1, 0, 0, 1, 1), (9, 0, 0, 1, 1, 0, 0)), table.rows)

    def test_pattern_max_sums_per_type_peaks_in_different_periods(self):
        table = reconstruct(((
            Event(0, 1, "O", 2), Event(1, 1, "O", 1),
            Event(1_000_000_000, 1, "C", 4), Event(2_000_000_000, 1, "O", 1),
        ),))
        self.assertEqual(("PID", "C_max", "C_sum", "O_max", "O_sum", "P_max", "P_sum", "OCO", "OOC"), table.columns)
        self.assertEqual(((1, 1, 1, 2, 3, 7, 8, 1, 1),), table.rows)

    def test_global_origin_and_negative_time_truncate_toward_zero(self):
        table = reconstruct(((
            Event(2_000_000_000, 1, "O", 0),
            Event(1_500_000_000, 2, "O", 0),
            Event(2_500_000_000, 2, "O", 0),
            Event(1_000_000_000, 2, "O", 0),
        ),))
        self.assertEqual(((1, 1, 1, 0, 0, 0), (2, 2, 3, 0, 0, 1)), table.rows)

    def test_offset_retains_collision_and_sequence_crossing_capture_boundary(self):
        table = reconstruct((
            (Event(0, 10001, "O", 0), Event(0, 10001, "C", 0)),
            (Event(0, 1, "D", 1),),
        ))
        self.assertEqual(("PID", "C_max", "C_sum", "D_max", "D_sum", "O_max", "O_sum", "P_max", "P_sum", "OCD"), table.columns)
        self.assertEqual(((10001, 1, 1, 1, 1, 1, 1, 1, 1, 1),), table.rows)

    def test_empty_capture_still_occupies_offset_index(self):
        table = reconstruct(((), (Event(0, 7, "E", 0),)))
        self.assertEqual(((10007, 1, 1, 0, 0),), table.rows)

    def test_sequences_follow_input_order_not_timestamp_order(self):
        table = reconstruct(((Event(3, 1, "O", 0), Event(1, 2, "E", 0), Event(2, 1, "D", 0), Event(1, 1, "C", 0)),))
        self.assertEqual("ODC", table.columns[-1])
        self.assertEqual((1, 0), tuple(row[-1] for row in table.rows))

    def test_sequence_counts_overlap(self):
        table = reconstruct(((Event(0, 1, "O", 0),) * 5,))
        self.assertEqual(((1, 5, 5, 0, 0, 3),), table.rows)

    def test_integer_bucket_boundaries_and_large_origin(self):
        origin = 9_007_199_254_740_993
        table = reconstruct(((
            Event(origin, 1, "O", 0),
            Event(origin + 999_999_999, 1, "O", 0),
            Event(origin + 1_000_000_000, 1, "O", 0),
            Event(origin - 999_999_999, 1, "O", 0),
            Event(origin - 1_000_000_000, 1, "O", 0),
        ),))
        self.assertEqual(((1, 3, 5, 0, 0, 3),), table.rows)

    def test_negative_pattern_max_includes_missing_bucket_zero(self):
        table = reconstruct(((
            Event(0, 1, "O", -2),
            Event(1_000_000_000, 1, "C", -1),
        ),))
        self.assertEqual(((1, 1, 1, 1, 1, 0, -3),), table.rows)

    def test_negative_pattern_max_does_not_add_unobserved_bucket(self):
        table = reconstruct(((Event(0, 1, "O", -2),),))
        self.assertEqual(((1, 1, 1, -2, -2),), table.rows)

    def test_records_are_immutable(self):
        with self.assertRaises(dataclasses.FrozenInstanceError):
            Event(0, 1, "O", 0).pid = 2
        with self.assertRaises(dataclasses.FrozenInstanceError):
            FeatureTable((), ()).columns = ("PID",)

    def test_invalid_events_are_rejected(self):
        for event in (Event(0, 1, "X", 0), Event(0.5, 1, "O", 0), Event(0, True, "O", 0), Event(0, 1, "O", "1")):
            with self.subTest(event=event), self.assertRaises(ValueError):
                reconstruct(((event,),))


if __name__ == "__main__":
    unittest.main()
