"""
tests/test_fail_closed_gating.py

Targeted test suite verifying fail-closed security gating branches across:
1. encoder/sg_encoder.py (unresolved rule sources, protocols/ports, CIDRs, non-string CIDRs)
2. graph/trust_graph.py (dangling ResourceReference principal -> unresolvable_roles)
3. graph/azure_trust_graph.py (azuread_group principal -> unresolvable_roles)
4. encoder/reachability_encoder.py (empty entry-point or target-role set short-circuiting to UNSAT)
5. solver/engine.py (Unresolved SG encoding -> UNRESOLVABLE status)
"""

import pytest
import z3

from encoder.reachability_encoder import encode_reachability_bmc
from encoder.sg_encoder import encode_sg_resource_symbolic
from graph.azure_trust_graph import build_azure_trust_graph
from graph.trust_graph import TrustGraph, build_trust_graph
from parser.graph import (
    IamPolicyStatement,
    Resource,
    ResourceGraph,
    ResourceReference,
    SecurityGroupRule,
    Unresolved,
)
from solver.engine import VerificationEngine


# 1. encoder/sg_encoder.py (lines 63, 70, 80, 87)
def test_sg_encoder_unresolved_rule_source():
    """Line 63: Unresolved object directly in rule_sources."""
    res = Resource(
        address="aws_security_group.test_sg",
        type="aws_security_group",
        rule_sources=[Unresolved(reason="Dynamic rule computation", expression="concat(...)")],
    )
    result = encode_sg_resource_symbolic(res)
    assert isinstance(result, Unresolved)
    assert "rule source is unresolved" in result.reason


def test_sg_encoder_unresolved_protocol_or_ports():
    """Line 70: SecurityGroupRule with Unresolved protocol/from_port/to_port."""
    rule = SecurityGroupRule(
        direction="ingress",
        protocol=Unresolved(reason="Dynamic protocol", expression="var.proto"),
        from_port=22,
        to_port=22,
        cidr_blocks=["0.0.0.0/0"],
    )
    res = Resource(
        address="aws_security_group.test_sg",
        type="aws_security_group",
        rule_sources=[rule],
    )
    result = encode_sg_resource_symbolic(res)
    assert isinstance(result, Unresolved)
    assert "unresolved fields" in result.reason


def test_sg_encoder_unresolved_cidr():
    """Line 80: SecurityGroupRule with Unresolved CIDR block."""
    rule = SecurityGroupRule(
        direction="ingress",
        protocol="tcp",
        from_port=22,
        to_port=22,
        cidr_blocks=[Unresolved(reason="Unresolved var.allowed_cidrs", expression="var.allowed_cidrs")],
    )
    res = Resource(
        address="aws_security_group.test_sg",
        type="aws_security_group",
        rule_sources=[rule],
    )
    result = encode_sg_resource_symbolic(res)
    assert isinstance(result, Unresolved)
    assert "unresolved CIDR block" in result.reason


def test_sg_encoder_non_string_cidr():
    """Line 87: SecurityGroupRule with non-string CIDR (e.g. ResourceReference)."""
    rule = SecurityGroupRule(
        direction="ingress",
        protocol="tcp",
        from_port=22,
        to_port=22,
        cidr_blocks=[ResourceReference(target_address="aws_vpc.main.cidr_block", attribute="cidr_block")],
    )
    res = Resource(
        address="aws_security_group.test_sg",
        type="aws_security_group",
        rule_sources=[rule],
    )
    result = encode_sg_resource_symbolic(res)
    assert isinstance(result, Unresolved)
    assert "non-string CIDR" in result.reason


# 2. graph/trust_graph.py (lines 137-142)
def test_trust_graph_unresolved_resource_reference_principal():
    """Lines 137-142: ResourceReference principal not present in trust_graph.nodes lands in unresolvable_roles."""
    rg = ResourceGraph()
    role_res = Resource(
        address="aws_iam_role.app_role",
        type="aws_iam_role",
        rule_sources=[
            IamPolicyStatement(
                effect="Allow",
                actions=["sts:AssumeRole"],
                resources=["*"],
                principal=ResourceReference(target_address="aws_iam_role.missing_role", attribute="arn"),
            )
        ],
    )
    rg.resources["aws_iam_role.app_role"] = role_res

    tg = build_trust_graph(rg)
    assert "aws_iam_role.app_role" in tg.unresolvable_roles


# 3. graph/azure_trust_graph.py (lines 176-180 / 388-403)
def test_azure_trust_graph_azuread_group_principal_fail_closed():
    """Azure AD group principal assignment lands in unresolvable_roles."""
    rg = ResourceGraph()
    group_res = Resource(
        address="azuread_group.sec_ops",
        type="azuread_group",
        attributes={"display_name": "SecOps Group"},
    )
    ra_res = Resource(
        address="azurerm_role_assignment.ra_secops",
        type="azurerm_role_assignment",
        attributes={
            "principal_id": ResourceReference(target_address="azuread_group.sec_ops", attribute="object_id"),
            "role_definition_name": "Owner",
            "scope": "/subscriptions/sub-123",
        },
    )
    rg.resources["azuread_group.sec_ops"] = group_res
    rg.resources["azurerm_role_assignment.ra_secops"] = ra_res

    tg = TrustGraph()
    build_azure_trust_graph(rg, tg)

    assert "azurerm_role_assignment.ra_secops" in tg.unresolvable_roles
    assert any("Active Directory group principal" in reason for reason in tg.unresolvable_reasons)


# 4. encoder/reachability_encoder.py (lines 78, 110)
def test_reachability_encoder_empty_entry_point_set():
    """Line 78: Empty entry-point set forces BoolVal(False) short-circuit."""
    tg = TrustGraph()
    tg.nodes = {"aws_iam_role.role_a", "aws_iam_role.role_b"}
    tg.target_roles = {"aws_iam_role.role_b"}
    # entry_points is set()
    hop_vars, formula = encode_reachability_bmc(tg, target_roles=tg.target_roles, k=2, entry_points=set())
    solver = z3.Solver()
    solver.add(formula)
    assert solver.check() == z3.unsat


def test_reachability_encoder_empty_target_set():
    """Line 110: Empty target-role set forces BoolVal(False) short-circuit."""
    tg = TrustGraph()
    tg.nodes = {"aws_iam_role.role_a", "aws_iam_role.role_b"}
    tg.external_entry_points = {"account:123456789012"}
    # target_roles is set()
    hop_vars, formula = encode_reachability_bmc(tg, target_roles=set(), k=2, entry_points=tg.external_entry_points)
    solver = z3.Solver()
    solver.add(formula)
    assert solver.check() == z3.unsat


# 5. solver/engine.py (line 246)
def test_solver_engine_verify_sg_unresolved_returns_unresolvable():
    """Line 246: VerificationEngine returns UNRESOLVABLE for unresolved SG resource."""
    engine = VerificationEngine()
    res = Resource(
        address="aws_security_group.unresolved_sg",
        type="aws_security_group",
        rule_sources=[Unresolved(reason="Dynamic rule computation", expression="var.rules")],
    )
    result = engine.verify_security_group(res)
    assert result is not None
    assert result.status == "UNRESOLVABLE"
    assert "Unable to verify security group due to unresolved data" in result.message
