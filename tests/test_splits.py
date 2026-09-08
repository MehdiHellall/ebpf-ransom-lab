import unittest

from ebpf_ransom_lab.workloads import (
    RUN_SEEDS,
    SCENARIOS,
    SPLIT_BY_SEED,
    build_experiment_manifest,
    split_for_seed,
)


class ControlledWorkloadSplitTests(unittest.TestCase):
    def test_seed_assignments_are_fixed_before_training(self):
        self.assertEqual((11, 23, 37, 41, 53), RUN_SEEDS)
        self.assertEqual(
            {11: "training", 23: "training", 37: "training", 41: "validation", 53: "test"},
            SPLIT_BY_SEED,
        )
        self.assertEqual("validation", split_for_seed(41))
        with self.assertRaisesRegex(ValueError, "unsupported workload seed"):
            split_for_seed(99)

    def test_manifest_has_one_run_per_scenario_and_seed(self):
        manifest = build_experiment_manifest()
        runs = manifest["runs"]

        self.assertEqual(1, manifest["schema_version"])
        self.assertEqual(40, len(runs))
        self.assertEqual(40, len({run["run_id"] for run in runs}))
        self.assertEqual(
            {(scenario, seed) for scenario in SCENARIOS for seed in RUN_SEEDS},
            {(run["scenario"], run["seed"]) for run in runs},
        )

    def test_manifest_split_counts_and_process_tree_label_scope(self):
        runs = build_experiment_manifest()["runs"]

        self.assertEqual(24, sum(run["split"] == "training" for run in runs))
        self.assertEqual(8, sum(run["split"] == "validation" for run in runs))
        self.assertEqual(8, sum(run["split"] == "test" for run in runs))
        for run in runs:
            self.assertEqual(SPLIT_BY_SEED[run["seed"]], run["split"])
            self.assertEqual(60, run["capture_duration_seconds"])
            self.assertEqual("controlled_workload", run["label_provenance"])
            self.assertEqual(64, len(run["plan_sha256"]))
            self.assertEqual(
                {
                    "kind": "process_tree",
                    "root_identity": "recorded_at_workload_start",
                    "include_descendants": True,
                    "background_activity": "unlabeled",
                },
                run["label_scope"],
            )

    def test_manifest_is_deterministic_and_returns_fresh_objects(self):
        first = build_experiment_manifest()
        second = build_experiment_manifest()

        self.assertEqual(first, second)
        first["runs"][0]["split"] = "test"
        self.assertNotEqual(first, build_experiment_manifest())


if __name__ == "__main__":
    unittest.main()
