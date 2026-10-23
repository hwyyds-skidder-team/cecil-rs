"""Regression checks for the strict comparison gate, without running timings."""
import copy
import unittest

import report


def measurements():
    inputs = [{"name": name, "bytes": 1024} for name in sorted(report.INPUTS)]
    implementations = ["cecil-rs", *report.COMPETITORS]
    counts = {"types": 1, "methods": 2, "instructions": 3}
    env = {
        "inputs": inputs,
        "modes": list(report.MODES),
        "implementations": implementations,
        "rounds": 3,
        "samples_per_round": 3,
        "source_snapshot": {"manifest": "source.json", "archive": "source.zip"},
        "build": {"fresh_rust_build": True},
        "source_consistent": True,
        "validation": [
            {"name": item["name"], "counts": counts, "semantic_validation": "passed",
             "outputs": {impl: {"readers": {"cecil-rs": "rust", "Mono.Cecil": "cecil"}}
                         for impl in implementations}}
            for item in inputs
        ],
    }
    raw = [
        {"input": item["name"], "input_bytes": item["bytes"], "counts": counts,
         "mode": mode, "implementation": impl, "round": round_number,
         "samples_us": [10.0 if impl == "cecil-rs" else 20.0] * 3}
        for item in inputs for mode in report.MODES for impl in implementations
        for round_number in range(1, 4)
    ]
    return env, raw


class AcceptanceTests(unittest.TestCase):
    def setUp(self):
        self.env, self.raw = measurements()

    def gate(self, env=None, raw=None):
        env = self.env if env is None else env
        raw = self.raw if raw is None else raw
        return report.acceptance(env, report.summarize(env, raw))

    def test_complete_repeated_matrix_passes(self):
        gate = self.gate()
        self.assertTrue(gate["passed"])
        self.assertEqual(gate["measured_comparisons"], 63)

    def test_one_losing_round_fails_even_when_pooled_median_wins(self):
        self.raw[0]["samples_us"] = [30.0] * 3
        gate = self.gate()
        self.assertEqual(gate["median_wins"], 63)
        self.assertFalse(gate["passed"])
        self.assertEqual(len(gate["failed_comparisons"]), 3)

    def test_one_slow_cell_and_ties_cannot_be_averaged_away(self):
        for latency in (10.0, 9.0):
            with self.subTest(competitor_us=latency):
                raw = copy.deepcopy(self.raw)
                target = raw[0]["input"]
                for row in raw:
                    if (row["input"], row["mode"], row["implementation"]) == (
                            target, "read", "dnlib"):
                        row["samples_us"] = [latency] * 3
                gate = self.gate(raw=raw)
                self.assertFalse(gate["passed"])
                self.assertEqual(gate["median_wins"], 62)

    def test_filtered_and_single_round_runs_cannot_pass(self):
        filtered = copy.deepcopy(self.env)
        filtered["inputs"] = filtered["inputs"][:1]
        filtered["validation"] = filtered["validation"][:1]
        raw = [r for r in self.raw if r["input"] == filtered["inputs"][0]["name"]]
        self.assertFalse(self.gate(filtered, raw)["passed"])
        single = copy.deepcopy(self.env)
        single["rounds"] = 1
        self.assertFalse(self.gate(single, [r for r in self.raw if r["round"] == 1])["passed"])

    def test_every_output_needs_both_semantic_readers(self):
        for implementation in self.env["implementations"]:
            for reader in ("cecil-rs", "Mono.Cecil"):
                with self.subTest(writer=implementation, reader=reader):
                    env = copy.deepcopy(self.env)
                    del env["validation"][0]["outputs"][implementation]["readers"][reader]
                    self.assertFalse(self.gate(env=env)["passed"])

    def test_semantic_failure_or_missing_build_provenance_refuses_acceptance(self):
        for field in ("semantic", "snapshot", "fresh", "consistent"):
            with self.subTest(field=field):
                env = copy.deepcopy(self.env)
                if field == "semantic":
                    env["validation"][0]["semantic_validation"] = "failed"
                elif field == "snapshot":
                    del env["source_snapshot"]
                elif field == "fresh":
                    env["build"]["fresh_rust_build"] = False
                else:
                    env["source_consistent"] = False
                self.assertFalse(self.gate(env=env)["passed"])

    def test_missing_or_duplicate_measurement_is_rejected(self):
        for raw in (self.raw[:-1], self.raw + [self.raw[0]]):
            with self.assertRaises(AssertionError):
                self.gate(raw=raw)

    def test_invalid_counts_sizes_samples_and_latencies_are_rejected(self):
        for field, value in (("counts", {}), ("input_bytes", 2048),
                             ("samples_us", [1.0]), ("samples_us", [float("nan")] * 3),
                             ("samples_us", [float("inf")] * 3), ("samples_us", [0.0] * 3)):
            with self.subTest(field=field, value=value):
                raw = copy.deepcopy(self.raw)
                raw[0][field] = value
                with self.assertRaises(AssertionError):
                    self.gate(raw=raw)


if __name__ == "__main__":
    unittest.main()
