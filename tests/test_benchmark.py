"""
Unit test for Phase 4 Benchmark Harness and §10 Differential Check.
"""

import os
import pytest
from benchmark.harness import BenchmarkHarness
from benchmark.differential_check import run_differential_check


def test_benchmark_harness_execution():
    gt_path = os.path.join(os.path.dirname(__file__), "..", "benchmark", "ground_truth.json")
    assert os.path.exists(gt_path), "ground_truth.json must exist"
    
    harness = BenchmarkHarness(gt_path)
    metrics = harness.evaluate()
    
    assert "metrics" in metrics
    assert "precision" in metrics["metrics"]
    assert "recall" in metrics["metrics"]
    assert "f1_score" in metrics["metrics"]
    assert metrics["ambiguous_excluded_count"] >= 1
    assert metrics["metrics"]["precision"] == 1.0
    assert metrics["metrics"]["recall"] == 1.0


def test_z3_performance_benchmark_functions():
    """
    Unit test targeting benchmark/z3_performance_benchmark.py functions.
    Validates reachability and NSG measurement routines return expected dictionary keys.
    """
    from benchmark.z3_performance_benchmark import (
        generate_synthetic_reachability_graph,
        generate_synthetic_nsg_rules,
        measure_reachability_solve,
        measure_nsg_solve,
    )

    # 1. Test synthetic reachability graph generation and measurement
    tg, targets = generate_synthetic_reachability_graph(num_nodes=5, hop_bound_k=3)
    reach_res = measure_reachability_solve(tg, targets, k=3, use_prefilter=True, runs=1)
    assert "median_ms" in reach_res
    assert "raw_runs_ms" in reach_res
    assert reach_res["nodes_encoded_to_z3"] <= 5

    # 2. Test synthetic NSG rules generation and measurement
    rules = generate_synthetic_nsg_rules(num_rules=5, make_vulnerable=True)
    nsg_res = measure_nsg_solve(rules, runs=1)
    assert nsg_res["input_rules_count"] == 5
    assert nsg_res["top_level_assertions"] == 2
    assert "median_solving_ms" in nsg_res
    assert "median_encoding_ms" in nsg_res

