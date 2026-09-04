"""
tests/test_azure_benchmark_corpus.py

Unit test for evaluating the 27-case Azure Ground-Truth Benchmark Corpus using BenchmarkHarness.
Verifies 1.0 Precision, 1.0 Recall, and 1.0 F1-Score across all 27 cases.
"""

import os
import json
import pytest
from benchmark.harness import BenchmarkHarness


def test_azure_benchmark_corpus_precision_recall():
    gt_file = os.path.join("fixtures", "phase11", "azure_ground_truth.json")
    assert os.path.exists(gt_file), f"Azure ground truth file not found at {gt_file}"

    harness = BenchmarkHarness(gt_file)
    results = harness.evaluate()

    metrics = results["metrics"]
    print("\n=== Azure Benchmark Corpus Metrics ===")
    print(f"Total Cases: {results['total_cases']}")
    print(f"Evaluated Count: {results['evaluated_count']}")
    print(f"True Positives: {metrics['true_positives']}")
    print(f"True Negatives: {metrics['true_negatives']}")
    print(f"False Positives: {metrics['false_positives']}")
    print(f"False Negatives: {metrics['false_negatives']}")
    print(f"Precision: {metrics['precision']}")
    print(f"Recall: {metrics['recall']}")
    print(f"F1 Score: {metrics['f1_score']}")

    assert results["total_cases"] == 32
    assert results["evaluated_count"] == 32
    assert results["unresolvable_metrics"]["correct_unresolvable"] == 5
    assert metrics["false_positives"] == 0
    assert metrics["false_negatives"] == 0
    assert metrics["precision"] == 1.0
    assert metrics["recall"] == 1.0
    assert metrics["f1_score"] == 1.0


def test_azure_benchmark_corpus_categories_breakdown():
    gt_file = os.path.join("fixtures", "phase11", "azure_ground_truth.json")
    with open(gt_file, "r", encoding="utf-8") as f:
        cases = json.load(f)

    categories = {}
    formats = {"HCL": 0, "ARM": 0}
    for c in cases:
        cat = c["category"]
        fmt = c["format"]
        categories[cat] = categories.get(cat, 0) + 1
        formats[fmt] = formats.get(fmt, 0) + 1

    assert categories["NSG_OVER_EXPOSURE"] == 7
    assert categories["RBAC_PRIVILEGE_ESCALATION"] == 7
    assert categories["SCOPE_INHERITANCE"] == 6
    assert categories["AZURE_GOVERNANCE_POLICY_VIOLATION"] == 12
    assert formats["HCL"] == 15
    assert formats["ARM"] == 17
