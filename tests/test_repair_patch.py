from pathlib import Path
from parser.hcl_parser import parse_file, build_graph
from parser.references import resolve_resource_references
from parser.attachments import resolve_rule_attachments
from solver.engine import VerificationEngine
from solver.repair import AutoRepairEngine, generate_unified_diff


def test_generate_unified_diff_hcl_file_deletion():
    fixture_path = "fixtures/phase6/multi_rule_vulnerability.tf"
    deleted_rules = [
        {"resource_address": "aws_security_group.multi_rule_sg", "statement_index": 0, "rule_type": "SecurityGroupRule"},
        {"resource_address": "aws_security_group.multi_rule_sg", "statement_index": 1, "rule_type": "SecurityGroupRule"},
    ]
    diff = generate_unified_diff(fixture_path, deleted_rules, "aws_security_group.multi_rule_sg")
    assert "--- a/multi_rule_vulnerability.tf" in diff
    assert "+++ b/multi_rule_vulnerability.tf" in diff
    assert "-  ingress {" in diff


def test_generate_unified_diff_canonical_fallback():
    deleted_rules = [
        {"resource_address": "aws_security_group.non_existent", "statement_index": 0, "rule_type": "SecurityGroupRule", "rule_details": "port=22"}
    ]
    diff = generate_unified_diff(None, deleted_rules, "aws_security_group.non_existent")
    assert "--- a/aws_security_group.non_existent.tf" in diff
    assert "+++ b/aws_security_group.non_existent.tf" in diff
    assert "-  # [0] SecurityGroupRule: port=22" in diff


def test_auto_repair_result_contains_patch():
    fixture_path = Path("fixtures/phase6/multi_rule_vulnerability.tf")
    parsed = parse_file(fixture_path)
    graph = build_graph(parsed, file_path=str(fixture_path))
    graph = resolve_resource_references(graph)
    graph = resolve_rule_attachments(graph)

    engine = VerificationEngine()
    repair_engine = AutoRepairEngine(engine)
    result = repair_engine.repair_resource(graph, "aws_security_group.multi_rule_sg", "SG_OVER_EXPOSURE")

    assert result.status == "REMEDIATED_MINIMAL"
    assert result.patch is not None
    assert "--- a/multi_rule_vulnerability.tf" in result.patch
    assert "+++ b/multi_rule_vulnerability.tf" in result.patch


def test_generate_unified_diff_non_contiguous_and_multi_resource():
    fixture_path = "fixtures/phase6/non_contiguous_and_multi_resource.tf"
    # Target resource is sg_target, statement indices 0 and 2 (skipping 1)
    deleted_rules = [
        {"resource_address": "aws_security_group.sg_target", "statement_index": 0, "rule_type": "SecurityGroupRule"},
        {"resource_address": "aws_security_group.sg_target", "statement_index": 2, "rule_type": "SecurityGroupRule"},
    ]
    diff = generate_unified_diff(fixture_path, deleted_rules, "aws_security_group.sg_target")

    # 1. Check sg_safe is not modified
    assert "sg_safe" not in diff
    # 2. Check port 80 (statement index 1) is NOT deleted
    assert "-    from_port   = 80" not in diff
    assert "from_port   = 80" in diff
    # 3. Check port 22 (statement index 0 and 2) ARE deleted
    assert "-    from_port   = 22" in diff


def test_repair_engine_non_contiguous_multi_resource():
    fixture_path = Path("fixtures/phase6/non_contiguous_and_multi_resource.tf")
    parsed = parse_file(fixture_path)
    graph = build_graph(parsed, file_path=str(fixture_path))
    graph = resolve_resource_references(graph)
    graph = resolve_rule_attachments(graph)

    engine = VerificationEngine()
    repair_engine = AutoRepairEngine(engine)
    result = repair_engine.repair_resource(graph, "aws_security_group.sg_target", "SG_OVER_EXPOSURE")

    assert result.status == "REMEDIATED_MINIMAL"
    assert len(result.deleted_rules) == 2
    deleted_indices = {r["statement_index"] for r in result.deleted_rules}
    assert deleted_indices == {0, 2}

    assert result.patch is not None
    assert "sg_safe" not in result.patch
    assert "-    from_port   = 80" not in result.patch
    assert "-    from_port   = 22" in result.patch

