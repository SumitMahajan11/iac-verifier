from encoder.iam_encoder import (
    encode_iam_scope_symbolic,
    make_action_match_expr,
    make_resource_match_expr,
    is_full_wildcard_action,
    is_full_wildcard_resource,
)
from parser.graph import IamPolicyStatement, Unresolved, ExternalManagedPolicy
import z3


def test_symbolic_string_action_match():
    act_var = z3.String("test_act")
    expr = make_action_match_expr(act_var, "s3:*")

    # s3:GetObject -> SAT
    s1 = z3.Solver()
    s1.add(expr, act_var == z3.StringVal("s3:GetObject"))
    assert s1.check() == z3.sat

    # sqs:SendMessage -> UNSAT
    s2 = z3.Solver()
    s2.add(expr, act_var == z3.StringVal("sqs:SendMessage"))
    assert s2.check() == z3.unsat


def test_single_allow_wildcard_action_flagged_unsafe():
    stmts = [
        IamPolicyStatement(
            effect="Allow",
            actions=["*"],
            resources=["arn:aws:s3:::my-bucket"],
        )
    ]
    res = encode_iam_scope_symbolic(stmts, scope_id="test1")
    assert not isinstance(res, Unresolved)
    act_var, res_var, unsafe_expr = res

    solver = z3.Solver()
    solver.add(unsafe_expr)
    assert solver.check() == z3.sat


def test_single_allow_wildcard_resource_flagged_unsafe():
    """
    Kickoff spec requirement: Action ["*"] OR Resource ["*"] triggers unsafe evaluation.
    This test verifies that a policy with specific action but wildcard Resource ["*"] is flagged unsafe via SMT String theory.
    """
    stmts = [
        IamPolicyStatement(
            effect="Allow",
            actions=["s3:GetObject"],
            resources=["*"],
        )
    ]
    res = encode_iam_scope_symbolic(stmts, scope_id="test2")
    assert not isinstance(res, Unresolved)
    act_var, res_var, unsafe_expr = res

    solver = z3.Solver()
    solver.add(unsafe_expr)
    assert solver.check() == z3.sat


def test_allow_service_wildcard_with_scoped_resource_flagged_unsafe():
    """
    Regression test for service wildcard actions (e.g. 's3:*') paired with a scoped resource.
    Under literal asterisk checking on action_var, this would have returned UNSAT (false negative).
    Under the fixed statement-level wildcard tracking formula, Z3 solves for a matching action (e.g. 's3:')
    and correctly returns SAT (unsafe).
    """
    stmts = [
        IamPolicyStatement(
            effect="Allow",
            actions=["s3:*"],
            resources=["arn:aws:s3:::my-bucket/*"],
        )
    ]
    res = encode_iam_scope_symbolic(stmts, scope_id="service_wildcard_test")
    assert not isinstance(res, Unresolved)
    act_var, res_var, unsafe_expr = res

    solver = z3.Solver()
    solver.add(unsafe_expr)
    assert solver.check() == z3.sat
    m = solver.model()
    # The solved action_var must be a valid s3 action matching the 's3:' prefix
    action_val = str(m[act_var]).strip('"')
    assert action_val.startswith("s3:")


def test_scoped_prefix_arn_not_unscoped_wildcard():
    """
    Verifies that a scoped prefix ARN (e.g. 'arn:aws:s3:::my-bucket/*') is recognized as
    a scoped resource prefix rather than a blanket un-scoped wildcard resource.
    """
    assert is_full_wildcard_resource("*") is True
    assert is_full_wildcard_resource("*/*") is True
    assert is_full_wildcard_resource("arn:aws:s3:::my-bucket/*") is False


def test_allow_wildcard_with_blanket_deny_precedence():
    """
    If a policy grants 'Allow *', but an explicit blanket 'Deny *' exists in scope,
    the explicit Deny takes precedence and suppresses the finding, resulting in UNSAT (safe).
    """
    stmts = [
        IamPolicyStatement(
            effect="Allow",
            actions=["*"],
            resources=["*"],
        ),
        IamPolicyStatement(
            effect="Deny",
            actions=["*"],
            resources=["*"],
        ),
    ]
    res = encode_iam_scope_symbolic(stmts, scope_id="test3")
    assert not isinstance(res, Unresolved)
    act_var, res_var, unsafe_expr = res

    solver = z3.Solver()
    solver.add(unsafe_expr)
    assert solver.check() == z3.unsat


def test_allow_wildcard_with_specific_action_deny():
    """
    Allow * + Deny s3:DeleteBucket.
    Asserting action_var == 's3:DeleteBucket' -> Deny wins -> UNSAT for s3:DeleteBucket.
    General SMT search -> SAT (solver finds counterexample action starting with 's3:' or other non-denied actions).
    """
    stmts = [
        IamPolicyStatement(
            effect="Allow",
            actions=["*"],
            resources=["*"],
        ),
        IamPolicyStatement(
            effect="Deny",
            actions=["s3:DeleteBucket"],
            resources=["*"],
        ),
    ]
    res = encode_iam_scope_symbolic(stmts, scope_id="test4")
    assert not isinstance(res, Unresolved)
    act_var, res_var, unsafe_expr = res

    # 1. Asserting specific action 's3:DeleteBucket' -> UNSAT (Deny overrides Allow)
    solver1 = z3.Solver()
    solver1.add(unsafe_expr)
    solver1.add(act_var == z3.StringVal("s3:DeleteBucket"))
    assert solver1.check() == z3.unsat

    # 2. General SMT search -> SAT (solver finds counterexample for non-denied actions)
    solver2 = z3.Solver()
    solver2.add(unsafe_expr)
    assert solver2.check() == z3.sat


def test_unresolved_statement_propagates_fail_closed():
    stmts = [
        IamPolicyStatement(
            effect="Allow",
            actions=["s3:GetObject"],
            resources=["arn:aws:s3:::my-bucket/*"],
        ),
        Unresolved(reason="Dynamic interpolation in policy", expression="jsonencode(...)"),
    ]
    res = encode_iam_scope_symbolic(stmts, scope_id="test5")
    assert isinstance(res, Unresolved)
    assert "unresolved policy statement" in res.reason.lower()
