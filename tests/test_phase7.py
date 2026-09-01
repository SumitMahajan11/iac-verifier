"""
Phase 7 Integration Tests (tests/test_phase7.py).

Verifies CLI exit codes (0/1/2), assumption-based core pre-filtering in AutoRepairEngine,
and end-to-end benchmark harness evaluation.
"""

import json
import os
import subprocess
import sys
import pytest

from cli.main import run_verify, run_repair
from parser.hcl_parser import parse_file, build_graph
from parser.references import resolve_resource_references
from parser.attachments import resolve_rule_attachments
from solver.repair import AutoRepairEngine
from benchmark.harness import BenchmarkHarness


FIXTURES_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "fixtures"))


def test_cli_verify_clean_exit_0():
    """Verify that cli verify returns exit code 0 for safe Terraform files."""
    safe_file = os.path.join(FIXTURES_DIR, "phase2", "sg_restricted_ssh.tf")
    assert os.path.exists(safe_file), f"Missing fixture {safe_file}"
    code = run_verify(safe_file, json_output=True)
    assert code == 0


def test_cli_verify_vulnerable_exit_1():
    """Verify that cli verify returns exit code 1 when vulnerabilities (SAT) are detected."""
    vuln_file = os.path.join(FIXTURES_DIR, "phase2", "sg_open_ssh.tf")
    assert os.path.exists(vuln_file), f"Missing fixture {vuln_file}"
    code = run_verify(vuln_file, json_output=True)
    assert code == 1


def test_cli_repair_success_exit_0():
    """Verify that cli repair successfully remediates a vulnerable fixture and returns exit code 0."""
    vuln_file = os.path.join(FIXTURES_DIR, "phase2", "sg_open_ssh.tf")
    assert os.path.exists(vuln_file), f"Missing fixture {vuln_file}"
    code = run_repair(
        target_path=vuln_file,
        resource_address="aws_security_group.open_ssh",
        pattern="SG_OVER_EXPOSURE",
        json_output=True,
    )
    assert code == 0


def test_unsat_core_prefiltering():
    """Verify that AutoRepairEngine's UNSAT core pre-filtering shrinks candidate search space while preserving REMEDIATED_MINIMAL."""
    file_path = os.path.join(FIXTURES_DIR, "phase6", "multi_rule_vulnerability.tf")
    assert os.path.exists(file_path), f"Missing fixture {file_path}"

    parsed = parse_file(file_path)
    graph = build_graph(parsed)
    graph = resolve_resource_references(graph)
    graph = resolve_rule_attachments(graph)

    repair_engine = AutoRepairEngine()
    result = repair_engine.repair_resource(
        graph, "aws_security_group.multi_rule_sg", "SG_OVER_EXPOSURE"
    )

    assert result.status == "REMEDIATED_MINIMAL"
    assert len(result.deleted_rules) == 2
    assert result.reverified_status == "UNSAT"


def test_benchmark_harness_phase7_execution():
    """Verify end-to-end evaluation using BenchmarkHarness over ground_truth.json."""
    gt_path = os.path.join(os.path.dirname(__file__), "..", "benchmark", "ground_truth.json")
    assert os.path.exists(gt_path), f"Missing ground truth file at {gt_path}"

    harness = BenchmarkHarness(gt_path)
    summary = harness.evaluate()

    assert summary["metrics"]["precision"] >= 0.95
    assert summary["metrics"]["recall"] >= 0.95
    assert summary["metrics"]["false_positives"] == 0
