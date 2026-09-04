from __future__ import annotations

from typing import List, Tuple, Union
import z3

from parser.graph import ExternalManagedPolicy, IamPolicyStatement, Unresolved


def is_full_wildcard_action(action: str) -> bool:
    """
    Checks if an action string is a full wildcard ('*') or service wildcard ('s3:*').
    """
    act = action.strip().lower()
    return act == "*" or act.endswith(":*")


def is_full_wildcard_resource(resource: str) -> bool:
    """
    Checks if a resource string is an un-scoped full wildcard ('*').
    Scoped prefix ARNs (e.g. 'arn:aws:s3:::my-bucket/*') are scoped prefix patterns,
    not un-scoped full wildcards.
    """
    res = resource.strip().lower()
    return res == "*" or res == "*/*"


def make_action_match_expr(action_var: z3.SeqRef, action_pattern: str) -> z3.BoolRef:
    """
    Generates a symbolic Z3 String constraint asserting that free String variable action_var
    matches action_pattern using Z3 String theory (PrefixOf or equality).
    """
    pattern = action_pattern.strip()
    if pattern == "*":
        return z3.BoolVal(True)
    if pattern.endswith(":*"):
        prefix = pattern[:-1]  # e.g. "s3:"
        return z3.PrefixOf(z3.StringVal(prefix), action_var)
    return action_var == z3.StringVal(pattern)


def make_resource_match_expr(resource_var: z3.SeqRef, resource_pattern: str) -> z3.BoolRef:
    """
    Generates a symbolic Z3 String constraint asserting that free String variable resource_var
    matches resource_pattern using Z3 String theory (PrefixOf or equality).
    """
    pattern = resource_pattern.strip()
    if pattern == "*" or pattern == "*/*":
        return z3.BoolVal(True)
    if pattern.endswith("*"):
        prefix = pattern[:-1]
        return z3.PrefixOf(z3.StringVal(prefix), resource_var)
    return resource_var == z3.StringVal(pattern)


def make_statement_match_expr(
    action_var: z3.SeqRef,
    resource_var: z3.SeqRef,
    stmt: IamPolicyStatement,
) -> z3.BoolRef:
    """
    Encodes an IamPolicyStatement into a symbolic Z3 String expression asserting
    that (action_var, resource_var) is matched by the statement's actions/not_actions and resources/not_resources.
    """
    if stmt.actions:
        action_exprs = [make_action_match_expr(action_var, act) for act in stmt.actions]
        action_match = z3.Or(action_exprs)
    elif stmt.not_actions:
        not_action_exprs = [make_action_match_expr(action_var, act) for act in stmt.not_actions]
        action_match = z3.Not(z3.Or(not_action_exprs))
    else:
        action_match = z3.BoolVal(True)

    if stmt.resources:
        resource_exprs = [make_resource_match_expr(resource_var, res) for res in stmt.resources]
        resource_match = z3.Or(resource_exprs)
    elif stmt.not_resources:
        not_resource_exprs = [make_resource_match_expr(resource_var, res) for res in stmt.not_resources]
        resource_match = z3.Not(z3.Or(not_resource_exprs))
    else:
        resource_match = z3.BoolVal(True)

    return z3.And(action_match, resource_match)


def encode_iam_scope_symbolic(
    statements: List[Union[IamPolicyStatement, ExternalManagedPolicy, Unresolved]],
    scope_id: str = "scope",
) -> Union[Tuple[z3.SeqRef, z3.SeqRef, z3.BoolRef], Unresolved]:
    """
    Encodes an IAM policy statement scope into genuine symbolic Z3 SMT String constraints
    over free String variables 'action_var' and 'resource_var'.

    Unsafe Predicate:
    An (action_var, resource_var) pair is unsafe if:
    1. It is matched by an Allow statement that grants wildcard permissions (Action '*' or 's3:*', or Resource '*').
    2. It is NOT denied by any matching Deny statement (Deny-overrides-Allow precedence).

    Returns:
    - (action_var, resource_var, unsafe_smt_formula)
    - Unresolved: if any statement in scope is unparseable (fail-closed).
    """
    # 1. Fail-closed check
    for stmt in statements:
        if isinstance(stmt, Unresolved):
            return Unresolved(
                reason=f"Evaluation scope contains unresolved policy statement: {stmt.reason}",
                expression=stmt.expression,
            )

    action_var = z3.String(f"action_{scope_id}")
    resource_var = z3.String(f"resource_{scope_id}")

    wildcard_allow_exprs: List[z3.BoolRef] = []
    deny_exprs: List[z3.BoolRef] = []

    for stmt in statements:
        if isinstance(stmt, ExternalManagedPolicy):
            # Managed policy (e.g. AdministratorAccess) allows all actions on all resources via wildcard
            wildcard_allow_exprs.append(z3.BoolVal(True))
            continue

        if not isinstance(stmt, IamPolicyStatement):
            continue

        stmt_match = make_statement_match_expr(action_var, resource_var, stmt)

        if stmt.effect.lower() == "deny":
            deny_exprs.append(stmt_match)
        elif stmt.effect.lower() == "allow":
            # Check if this Allow statement is granted via a wildcard pattern (Action '*' or 's3:*', or Resource '*')
            if stmt.actions:
                has_act_wildcard = any(is_full_wildcard_action(act) for act in stmt.actions)
            elif stmt.not_actions:
                has_act_wildcard = not any(is_full_wildcard_action(act) for act in stmt.not_actions)
            else:
                has_act_wildcard = True

            if stmt.resources:
                has_res_wildcard = any(is_full_wildcard_resource(res) for res in stmt.resources)
            elif stmt.not_resources:
                has_res_wildcard = not any(is_full_wildcard_resource(res) for res in stmt.not_resources)
            else:
                has_res_wildcard = True

            if has_act_wildcard or has_res_wildcard:
                wildcard_allow_exprs.append(stmt_match)

    if not wildcard_allow_exprs:
        # No wildcard-granting Allow statements in scope -> safe
        return action_var, resource_var, z3.BoolVal(False)

    policy_wildcard_allows = z3.Or(wildcard_allow_exprs)
    policy_denies = z3.Or(deny_exprs) if deny_exprs else z3.BoolVal(False)

    # Unsafe SMT formula: Wildcard-granted permission is active AND not denied
    unsafe_formula = z3.And(policy_wildcard_allows, z3.Not(policy_denies))

    return action_var, resource_var, unsafe_formula
