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
