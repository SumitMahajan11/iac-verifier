from __future__ import annotations

from pathlib import Path

from parser.attachments import resolve_rule_attachments
from parser.hcl_parser import build_graph, parse_file
from parser.references import resolve_resource_references
from solver.engine import VerificationEngine

FIXTURES_DIR = Path(__file__).parent.parent / "fixtures" / "phase5"

def load_and_verify_fixture(tf_filename: str, configured_cap: int = 10, target_resource=None):
    file_path = FIXTURES_DIR / tf_filename
    parsed = parse_file(file_path)
    graph = build_graph(parsed)
    graph = resolve_resource_references(graph)
    graph = resolve_rule_attachments(graph)

    engine = VerificationEngine()
    return engine.verify_privilege_escalation(graph, target_resource=target_resource, configured_cap=configured_cap)

def test_fixture_realistic_escalation_sat():
    res_c = load_and_verify_fixture("realistic_escalation.tf", target_resource="aws_iam_role.role_c")

    assert res_c.status == "SAT"
    assert res_c.witness is not None
    assert res_c.witness["path_length"] == 3
    assert res_c.witness["target_resource"] == "aws_iam_role.role_c"

def test_fixture_realistic_escalation_unsat_blocked_hop():
    res_blocked = load_and_verify_fixture("realistic_escalation.tf", target_resource="aws_iam_role.role_blocked")

    assert res_blocked.status in ("UNSAT", "UNSAT_BOUNDED")
