from __future__ import annotations

import pytest
from graph.trust_graph import build_trust_graph
from parser.graph import (
    IamPolicyStatement,
    Resource,
    ResourceGraph,
    ResourceReference,
    Unresolved,
)


def test_two_internal_roles_trust_edge():
    stmt_id = IamPolicyStatement(
        effect="Allow",
        actions=["sts:AssumeRole"],
        resources=["aws_iam_role.role_b"],
        principal=None,
    )
    res_a = Resource(
        address="aws_iam_role.role_a",
        type="aws_iam_role",
        attributes={"name": "role_a"},
        rule_sources=[stmt_id],
    )
    # role_b trusts role_a
    stmt_trust = IamPolicyStatement(
        effect="Allow",
        actions=["sts:AssumeRole"],
        resources=["*"],
        principal="aws_iam_role.role_a",
    )
    res_b = Resource(
        address="aws_iam_role.role_b",
        type="aws_iam_role",
        attributes={"name": "role_b"},
        rule_sources=[stmt_trust],
    )
    rg = ResourceGraph()
    rg.add_resource(res_a)
    rg.add_resource(res_b)

    tg = build_trust_graph(rg)

    assert "aws_iam_role.role_a" in tg.nodes
    assert "aws_iam_role.role_b" in tg.nodes
    assert len(tg.edges) == 1
    edge = tg.edges[0]
    assert edge.from_node == "aws_iam_role.role_a"
    assert edge.to_node == "aws_iam_role.role_b"
    assert edge.trust_statement == stmt_trust
    assert edge.identity_statement == stmt_id
    assert len(tg.unresolvable_roles) == 0


def test_external_account_trust_node():
    stmt_external = IamPolicyStatement(
        effect="Allow",
        actions=["sts:AssumeRole"],
        resources=["*"],
        principal="123456789012",
    )
    role_b = Resource(
        address="aws_iam_role.target_role",
        type="aws_iam_role",
        attributes={"name": "target_role"},
        rule_sources=[stmt_external],
    )
    rg = ResourceGraph()
    rg.add_resource(role_b)

    tg = build_trust_graph(rg)

    assert "account:123456789012" in tg.nodes
    assert "account:123456789012" in tg.external_entry_points
    assert len(tg.edges) == 1
    edge = tg.edges[0]
    assert edge.from_node == "account:123456789012"
    assert edge.to_node == "aws_iam_role.target_role"
    assert len(tg.unresolvable_roles) == 0


def test_unresolved_trust_reference_propagates():
    unresolved_ref = Unresolved(
        reason="References module.missing_mod.role_arn",
        expression="module.missing_mod.role_arn",
    )
    stmt_unresolved = IamPolicyStatement(
        effect="Allow",
        actions=["sts:AssumeRole"],
        resources=["*"],
        principal=unresolved_ref,
    )
    role_c = Resource(
        address="aws_iam_role.unresolved_role",
        type="aws_iam_role",
        attributes={"name": "unresolved_role"},
        rule_sources=[stmt_unresolved],
    )
    rg = ResourceGraph()
    rg.add_resource(role_c)

    tg = build_trust_graph(rg)

    assert "aws_iam_role.unresolved_role" in tg.nodes
    assert "aws_iam_role.unresolved_role" in tg.unresolvable_roles
    assert len(tg.unresolvable_reasons) == 1
    assert "unresolved principal reference" in tg.unresolvable_reasons[0]


def test_disconnected_external_trust_role():
    # Role A trusts external account but has no permission to anything
    stmt_ext = IamPolicyStatement(
        effect="Allow",
        actions=["sts:AssumeRole"],
        resources=["*"],
        principal="999999999999",
    )
    role_a = Resource(
        address="aws_iam_role.isolated_role",
        type="aws_iam_role",
        attributes={"name": "isolated_role"},
        rule_sources=[stmt_ext],
    )
    rg = ResourceGraph()
    rg.add_resource(role_a)

    tg = build_trust_graph(rg)

    assert "account:999999999999" in tg.nodes
    assert "aws_iam_role.isolated_role" in tg.nodes
    assert len(tg.edges) == 1
    assert tg.edges[0].from_node == "account:999999999999"
    assert tg.edges[0].to_node == "aws_iam_role.isolated_role"

    from solver.engine import VerificationEngine
    engine = VerificationEngine()
    res = engine.verify_privilege_escalation(rg)
    assert res.status == "UNSAT"
    assert "complete proof of unreachability" in res.message
