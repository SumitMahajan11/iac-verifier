from __future__ import annotations

import pytest
import z3
from encoder.reachability_encoder import (
    encode_reachability_bmc,
    extract_witness_from_model,
)
from graph.trust_graph import TrustEdge, TrustGraph
from parser.graph import IamPolicyStatement


def test_reachability_encoder_sat_chain():
    tg = TrustGraph()
    tg.nodes = {"account:123456789012", "aws_iam_role.jump", "aws_iam_role.admin"}
    tg.external_entry_points = {"account:123456789012"}

    stmt1 = IamPolicyStatement(effect="Allow", actions=["sts:AssumeRole"], resources=["*"], principal="123456789012")
    stmt2 = IamPolicyStatement(effect="Allow", actions=["sts:AssumeRole"], resources=["*"], principal="aws_iam_role.jump")

    tg.edges = [
        TrustEdge(from_node="account:123456789012", to_node="aws_iam_role.jump", trust_statement=stmt1, identity_statement=None),
        TrustEdge(from_node="aws_iam_role.jump", to_node="aws_iam_role.admin", trust_statement=stmt2, identity_statement=None),
    ]

    target_roles = {"aws_iam_role.admin"}
    k = 2

    hop_vars, formula = encode_reachability_bmc(tg, target_roles, k)

    solver = z3.Solver()
    solver.add(formula)
    check_res = solver.check()

    assert check_res == z3.sat
    model = solver.model()

    witness = extract_witness_from_model(model, hop_vars, tg)

    assert witness["entry_point"] == "account:123456789012"
    assert witness["target_resource"] == "aws_iam_role.admin"
    assert witness["path_length"] == 2
    assert len(witness["hops"]) == 2
    assert witness["hops"][0]["from"] == "account:123456789012"
    assert witness["hops"][0]["to"] == "aws_iam_role.jump"
    assert witness["hops"][1]["from"] == "aws_iam_role.jump"
    assert witness["hops"][1]["to"] == "aws_iam_role.admin"


def test_reachability_encoder_unsat():
    tg = TrustGraph()
    tg.nodes = {"account:123456789012", "aws_iam_role.safe_role", "aws_iam_role.admin"}
    tg.external_entry_points = {"account:123456789012"}

    stmt1 = IamPolicyStatement(effect="Allow", actions=["sts:AssumeRole"], resources=["*"], principal="123456789012")
    tg.edges = [
        TrustEdge(from_node="account:123456789012", to_node="aws_iam_role.safe_role", trust_statement=stmt1, identity_statement=None)
    ]

    # Target is admin, but admin is disconnected
    target_roles = {"aws_iam_role.admin"}
    k = 2

    hop_vars, formula = encode_reachability_bmc(tg, target_roles, k)

    solver = z3.Solver()
    solver.add(formula)
    check_res = solver.check()

    assert check_res == z3.unsat
