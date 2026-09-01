from __future__ import annotations

from pathlib import Path
import pytest

from parser.attachments import resolve_rule_attachments
from parser.hcl_parser import build_graph, parse_file
from parser.references import resolve_resource_references
from solver.engine import VerificationEngine
from graph.trust_graph import TrustEdge, TrustGraph, build_trust_graph
from parser.graph import IamPolicyStatement, Resource, ResourceGraph

FIXTURES_DIR = Path(__file__).parent.parent / "fixtures" / "phase3"


def load_and_verify_fixture(tf_filename: str, configured_cap: int = 10, target_resource=None):
    file_path = FIXTURES_DIR / tf_filename
    parsed = parse_file(file_path)
    graph = build_graph(parsed)
    graph = resolve_resource_references(graph)
    graph = resolve_rule_attachments(graph)

    engine = VerificationEngine()
    return engine.verify_privilege_escalation(graph, target_resource=target_resource, configured_cap=configured_cap)




def test_fixture_direct_escalation():
    res = load_and_verify_fixture("direct_escalation.tf")

    assert res.status == "SAT"
    assert res.witness is not None
    assert res.witness["entry_point"] == "account:111122223333"
    assert res.witness["target_resource"] == "aws_iam_role.admin_role"
    assert res.witness["path_length"] == 1
    assert len(res.witness["hops"]) == 1
    assert res.witness["hops"][0]["from"] == "account:111122223333"
    assert res.witness["hops"][0]["to"] == "aws_iam_role.admin_role"


def test_fixture_chained_escalation():
    res = load_and_verify_fixture("chained_escalation.tf")

    assert res.status == "SAT"
    assert res.witness is not None
    assert res.witness["entry_point"] == "account:111122223333"
    assert res.witness["target_resource"] == "aws_iam_role.target_role"
    assert res.witness["path_length"] == 2
    assert len(res.witness["hops"]) == 2

    hop1 = res.witness["hops"][0]
    assert hop1["from"] == "account:111122223333"
    assert hop1["to"] == "aws_iam_role.jump_role"

    hop2 = res.witness["hops"][1]
    assert hop2["from"] == "aws_iam_role.jump_role"
    assert hop2["to"] == "aws_iam_role.target_role"


def test_fixture_no_path_safe():
    res = load_and_verify_fixture("no_path_safe.tf")

    assert res.status == "UNSAT"
    assert res.witness is None
    assert "complete proof of unreachability" in res.message


def test_fixture_unresolved_trust():
    res = load_and_verify_fixture("unresolved_trust.tf")

    assert res.status == "UNRESOLVABLE"
    assert res.witness is None
    assert "unresolved" in res.message.lower()


def test_unsat_bounded_synthetic_graph():
    # Build a synthetic graph with 15 roles in a linear line (r0 -> r1 -> ... -> r14)
    # Target is r14. If configured_cap=5, solver cannot reach r14 within 5 hops.
    # Because 15 roles > cap 5, result must be UNSAT_BOUNDED.
    rg = ResourceGraph()

    stmt_ext = IamPolicyStatement(effect="Allow", actions=["sts:AssumeRole"], resources=["*"], principal="100000000000")
    role_0 = Resource(
        address="aws_iam_role.role_0",
        type="aws_iam_role",
        attributes={"name": "role_0"},
        rule_sources=[stmt_ext],
    )
    rg.add_resource(role_0)

    for i in range(1, 15):
        stmt_prev = IamPolicyStatement(
            effect="Allow",
            actions=["sts:AssumeRole"],
            resources=["*"],
            principal=f"aws_iam_role.role_{i-1}",
        )
        role_i = Resource(
            address=f"aws_iam_role.role_{i}",
            type="aws_iam_role",
            attributes={"name": f"role_{i}"},
            rule_sources=[stmt_prev],
        )
        # Add wildcard permission to target role_14
        if i == 14:
            stmt_wildcard = IamPolicyStatement(effect="Allow", actions=["*"], resources=["*"])
            role_i.rule_sources.append(stmt_wildcard)

        rg.add_resource(role_i)

    engine = VerificationEngine()
    res = engine.verify_privilege_escalation(rg, target_resource="aws_iam_role.role_14", configured_cap=5)

    assert res.status == "UNSAT_BOUNDED"
    assert "No privilege escalation path found within bounded limit of 5 hops" in res.message
