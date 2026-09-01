from __future__ import annotations

import json
from pathlib import Path
import pytest

from parser.attachments import resolve_rule_attachments
from parser.hcl_parser import build_graph, parse_file
from parser.references import resolve_resource_references
from solver.engine import VerificationEngine
from solver.repair import AutoRepairEngine, copy_graph_without_rules


def test_adversarial_multi_rule_vulnerability():
    """
    Tests adversarial fixture requiring a MULTI-RULE fix.
    The security group has 2 open SSH ingress blocks.
    Deleting only 1 block leaves the resource SAT (vulnerable).
    Both blocks MUST be deleted simultaneously to restore UNSAT.
    """
    fixture_path = Path("fixtures/phase6/multi_rule_vulnerability.tf")
    parsed = parse_file(fixture_path)
    graph = build_graph(parsed)
    graph = resolve_resource_references(graph)
    graph = resolve_rule_attachments(graph)

    engine = VerificationEngine()
    repair_engine = AutoRepairEngine(engine)

    res_addr = "aws_security_group.multi_rule_sg"

    # Step 1: Confirm initial status is SAT
    initial_ver = engine.verify_security_group(graph.resources[res_addr])
    assert initial_ver is not None
    assert initial_ver.status == "SAT"

    # Step 2: Confirm deleting only rule 0 leaves graph SAT
    graph_minus_0 = copy_graph_without_rules(graph, [(res_addr, 0)])
    ver_minus_0 = engine.verify_security_group(graph_minus_0.resources[res_addr])
    assert ver_minus_0 is not None
    assert ver_minus_0.status == "SAT"

    # Step 3: Run auto-repair engine
    repair_res = repair_engine.repair_resource(graph, res_addr, "SG_OVER_EXPOSURE")

    assert repair_res.status == "REMEDIATED_MINIMAL"
    assert repair_res.reverified_status == "UNSAT"
    assert len(repair_res.deleted_rules) == 2
    assert repair_res.deleted_rules[0]["statement_index"] == 0
    assert repair_res.deleted_rules[1]["statement_index"] == 1

    # Verify certificate schema compliance
    assert repair_res.initial_certificate is not None
    assert repair_res.initial_certificate["certificate_type"] == "SAT_WITNESS_TRACE"
    assert repair_res.reverified_certificate is not None
    assert repair_res.reverified_certificate["certificate_type"] == "UNSAT_PROOF_CERTIFICATE"


def test_adversarial_multiple_minimal_fixes_deterministic():
    """
    Tests adversarial fixture where MULTIPLE independent minimal fixes exist across resources.
    Confirms the auto-repair algorithm isolates 1-statement minimal fixes deterministically.
    """
    fixture_path = Path("fixtures/phase6/multiple_minimal_fixes.tf")
    parsed = parse_file(fixture_path)
    graph = build_graph(parsed)
    graph = resolve_resource_references(graph)
    graph = resolve_rule_attachments(graph)

    engine = VerificationEngine()
    repair_engine = AutoRepairEngine(engine)

    pol_1 = "aws_iam_policy.policy_1"
    initial_ver_1 = engine.verify_iam_policy(graph.resources[pol_1])
    assert initial_ver_1 is not None
    assert initial_ver_1.status == "SAT"

    repair_1 = repair_engine.repair_resource(graph, pol_1, "IAM_WILDCARD_ALLOW")
    assert repair_1.status == "REMEDIATED_MINIMAL"
    assert repair_1.reverified_status == "UNSAT"
    assert len(repair_1.deleted_rules) == 1
    assert repair_1.deleted_rules[0]["statement_index"] == 0

    pol_2 = "aws_iam_policy.policy_2"
    initial_ver_2 = engine.verify_iam_policy(graph.resources[pol_2])
    assert initial_ver_2 is not None
    assert initial_ver_2.status == "SAT"

    repair_2 = repair_engine.repair_resource(graph, pol_2, "IAM_WILDCARD_ALLOW")
    assert repair_2.status == "REMEDIATED_MINIMAL"
    assert repair_2.reverified_status == "UNSAT"
    assert len(repair_2.deleted_rules) == 1
    assert repair_2.deleted_rules[0]["statement_index"] == 1


def test_corpus_remediation_1_sg_open_ssh():
    """Corpus Remediation 1: Security Group Open SSH."""
    fixture_path = Path("fixtures/phase2/sg_open_ssh.tf")
    parsed = parse_file(fixture_path)
    graph = build_graph(parsed)
    graph = resolve_resource_references(graph)
    graph = resolve_rule_attachments(graph)

    engine = VerificationEngine()
    repair_engine = AutoRepairEngine(engine)
    res_addr = "aws_security_group.open_ssh"

    # Initial solver output
    before_ver = engine.verify_security_group(graph.resources[res_addr])
    assert before_ver is not None
    assert before_ver.status == "SAT"

    repair_res = repair_engine.repair_resource(graph, res_addr, "SG_OVER_EXPOSURE")
    assert repair_res.status == "REMEDIATED_MINIMAL"
    assert repair_res.reverified_status == "UNSAT"

    # Confirm solver re-verification output is UNSAT
    reverified_graph = copy_graph_without_rules(graph, [(d["resource_address"], d["statement_index"]) for d in repair_res.deleted_rules])
    after_ver = engine.verify_security_group(reverified_graph.resources[res_addr])
    assert after_ver is not None
    assert after_ver.status == "UNSAT"


def test_corpus_remediation_2_iam_wildcard_allow():
    """Corpus Remediation 2: IAM Policy Wildcard Allow."""
    fixture_path = Path("fixtures/phase2/iam_wildcard_allow.tf")
    parsed = parse_file(fixture_path)
    graph = build_graph(parsed)
    graph = resolve_resource_references(graph)
    graph = resolve_rule_attachments(graph)

    engine = VerificationEngine()
    repair_engine = AutoRepairEngine(engine)
    res_addr = "aws_iam_policy.wildcard_allow"

    before_ver = engine.verify_iam_policy(graph.resources[res_addr])
    assert before_ver is not None
    assert before_ver.status == "SAT"

    repair_res = repair_engine.repair_resource(graph, res_addr, "IAM_WILDCARD_ALLOW")
    assert repair_res.status == "REMEDIATED_MINIMAL"
    assert repair_res.reverified_status == "UNSAT"

    reverified_graph = copy_graph_without_rules(graph, [(d["resource_address"], d["statement_index"]) for d in repair_res.deleted_rules])
    after_ver = engine.verify_iam_policy(reverified_graph.resources[res_addr])
    assert after_ver is not None
    assert after_ver.status == "UNSAT"


def test_corpus_remediation_3_chained_escalation():
    """Corpus Remediation 3: Chained Privilege Escalation."""
    fixture_path = Path("fixtures/phase3/chained_escalation.tf")
    parsed = parse_file(fixture_path)
    graph = build_graph(parsed)
    graph = resolve_resource_references(graph)
    graph = resolve_rule_attachments(graph)

    engine = VerificationEngine()
    repair_engine = AutoRepairEngine(engine)

    target_res = "aws_iam_role.target_role"

    before_ver = engine.verify_privilege_escalation(graph, target_resource=target_res)
    assert before_ver.status == "SAT"

    repair_res = repair_engine.repair_resource(graph, target_res, "PRIVILEGE_ESCALATION_REACHABILITY")
    assert repair_res.status == "REMEDIATED_MINIMAL"
    assert repair_res.reverified_status == "UNSAT"

    reverified_graph = copy_graph_without_rules(graph, [(d["resource_address"], d["statement_index"]) for d in repair_res.deleted_rules])
    after_ver = engine.verify_privilege_escalation(reverified_graph, target_resource=target_res)
    assert after_ver.status == "UNSAT"
