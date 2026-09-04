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


def test_not_action_encoding():
    """
    Verifies that a policy using NotAction (e.g. Allow on NotAction ['ec2:*'] on Resource '*')
    is correctly encoded as SAT (vulnerable wildcard grant).
    """
    stmts = [
        IamPolicyStatement(
            effect="Allow",
            not_actions=["ec2:*"],
            resources=["*"],
        )
    ]
    res = encode_iam_scope_symbolic(stmts, scope_id="not_action_test")
    assert not isinstance(res, Unresolved)
    act_var, res_var, unsafe_expr = res

    solver = z3.Solver()
    solver.add(unsafe_expr)
    assert solver.check() == z3.sat
    m = solver.model()
    action_val = str(m[act_var]).strip('"')
    assert not action_val.startswith("ec2:")


def test_not_action_prefix_wildcard_matching():
    """
    Verifies that trailing prefix wildcards in NotAction (e.g. 'ec2:Describe*') are encoded
    as PrefixOf constraints rather than plain string equality.
    """
    act_var = z3.String("act")
    expr = make_action_match_expr(act_var, "ec2:Describe*")
    assert not isinstance(expr, Unresolved)

    # ec2:DescribeInstances matches ec2:Describe* -> SAT
    s1 = z3.Solver()
    s1.add(expr, act_var == z3.StringVal("ec2:DescribeInstances"))
    assert s1.check() == z3.sat

    # ec2:RunInstances does NOT match ec2:Describe* -> UNSAT
    s2 = z3.Solver()
    s2.add(expr, act_var == z3.StringVal("ec2:RunInstances"))
    assert s2.check() == z3.unsat


def test_not_action_deny_service_exclusion_safe():
    """
    Test fixture where safety depends on resolving NotAction correctly:
    Statement 1: Allow Action "*" on Resource "*"
    Statement 2: Deny NotAction ["s3:*"] on Resource "*" (Denies everything except s3:*)

    Asserting non-S3 action (e.g. iam:CreateUser) -> UNSAT (Deny is active for non-S3 actions).
    Asserting S3 action (e.g. s3:GetObject) -> SAT (Deny is excluded for S3 actions).
    """
    stmts = [
        IamPolicyStatement(
            effect="Allow",
            actions=["*"],
            resources=["*"],
        ),
        IamPolicyStatement(
            effect="Deny",
            not_actions=["s3:*"],
            resources=["*"],
        ),
    ]
    res = encode_iam_scope_symbolic(stmts, scope_id="not_action_deny_test")
    assert not isinstance(res, Unresolved)
    act_var, res_var, unsafe_expr = res

    # 1. Non-S3 action (e.g. iam:CreateUser) -> Deny is active -> UNSAT (Safe/Blocked)
    solver1 = z3.Solver()
    solver1.add(unsafe_expr)
    solver1.add(act_var == z3.StringVal("iam:CreateUser"))
    assert solver1.check() == z3.unsat

    # 2. S3 action (e.g. s3:GetObject) -> Deny excluded -> SAT (Allowed)
    solver2 = z3.Solver()
    solver2.add(unsafe_expr)
    solver2.add(act_var == z3.StringVal("s3:GetObject"))
    assert solver2.check() == z3.sat


def test_not_action_deny_verb_prefix_exclusion():
    """
    Test fixture where NotAction uses a VERB-LEVEL prefix wildcard ('ec2:Describe*'):
    Statement 1: Allow Action "*" on Resource "*"
    Statement 2: Deny NotAction ["ec2:Describe*"] on Resource "*"

    - ec2:DescribeInstances: matches NotAction 'ec2:Describe*' -> EXCLUDED from Deny -> SAT (Allowed).
    - ec2:RunInstances: does NOT match NotAction 'ec2:Describe*' -> NOT excluded from Deny -> Deny Active -> UNSAT (Blocked).
    - iam:CreateUser: does NOT match NotAction 'ec2:Describe*' -> NOT excluded from Deny -> Deny Active -> UNSAT (Blocked).
    """
    stmts = [
        IamPolicyStatement(
            effect="Allow",
            actions=["*"],
            resources=["*"],
        ),
        IamPolicyStatement(
            effect="Deny",
            not_actions=["ec2:Describe*"],
            resources=["*"],
        ),
    ]
    res = encode_iam_scope_symbolic(stmts, scope_id="not_action_verb_deny_test")
    assert not isinstance(res, Unresolved)
    act_var, res_var, unsafe_expr = res

    # 1. ec2:DescribeInstances matches ec2:Describe* -> Excluded from Deny -> SAT (Allowed)
    solver1 = z3.Solver()
    solver1.add(unsafe_expr)
    solver1.add(act_var == z3.StringVal("ec2:DescribeInstances"))
    assert solver1.check() == z3.sat

    # 2. ec2:RunInstances does NOT match ec2:Describe* -> Denied -> UNSAT (Blocked)
    solver2 = z3.Solver()
    solver2.add(unsafe_expr)
    solver2.add(act_var == z3.StringVal("ec2:RunInstances"))
    assert solver2.check() == z3.unsat

    # 3. iam:CreateUser does NOT match ec2:Describe* -> Denied -> UNSAT (Blocked)
    solver3 = z3.Solver()
    solver3.add(unsafe_expr)
    solver3.add(act_var == z3.StringVal("iam:CreateUser"))
    assert solver3.check() == z3.unsat


def test_mid_string_glob_fail_closed_unresolved():
    """
    Verifies that unsupported mid-string glob patterns (e.g. 's3:Get*Object' or '?')
    fail closed and return Unresolved rather than silently executing plain string equality.
    """
    stmts = [
        IamPolicyStatement(
            effect="Allow",
            actions=["s3:Get*Object"],
            resources=["*"],
        )
    ]
    res = encode_iam_scope_symbolic(stmts, scope_id="mid_string_glob_test")
    assert isinstance(res, Unresolved)
    assert "unsupported mid-string glob pattern" in res.reason.lower()


