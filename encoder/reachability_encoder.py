from __future__ import annotations

from typing import Any, Dict, List, Optional, Set, Tuple
import z3

from graph.trust_graph import TrustEdge, TrustGraph
from parser.graph import IamPolicyStatement, ResourceReference, Unresolved


# ANSWER TO SPEC QUESTION:
# Free variables Z3 is searching over:
# `hop_vars = [hop_0, hop_1, ..., hop_k]` where each `hop_i` is a Z3 String variable representing
# which role address or external entry point node is occupied at step `i`.
# Z3 searches the decision space of possible node assignments to `hop_0...hop_k` subject to
# transition constraints derived directly from `trust_graph.edges` and entry/target constraints.


def statement_to_dict(stmt: IamPolicyStatement | Any) -> Dict[str, Any]:
    """Converts an IamPolicyStatement into a clean dictionary for witness reporting."""
    if not isinstance(stmt, IamPolicyStatement):
        return {"raw": str(stmt)}

    def _clean_val(v: Any) -> Any:
        if isinstance(v, Unresolved):
            return {"unresolved": v.reason}
        if isinstance(v, ResourceReference):
            return f"{v.target_address}.{v.attribute}"
        if isinstance(v, list):
            return [_clean_val(x) for x in v]
        if isinstance(v, dict):
            return {k: _clean_val(val) for k, val in v.items()}
        return v

    return {
        "effect": stmt.effect,
        "actions": [_clean_val(a) for a in stmt.actions],
        "resources": [_clean_val(r) for r in stmt.resources],
        "principal": _clean_val(stmt.principal),
    }


def encode_reachability_bmc(
    trust_graph: TrustGraph,
    target_roles: Set[str] | List[str],
    k: int,
    entry_points: Optional[Set[str] | List[str]] = None,
) -> Tuple[List[z3.ExprRef], z3.BoolRef]:
    """Encodes trust graph reachability over bound `k` into a genuine Z3 SMT BMC formula.

    Args:
        trust_graph: Built `TrustGraph` containing nodes, entry points, and edges.
        target_roles: Set or list of role addresses that grant sensitive/wildcard permissions.
        k: The maximum hop bound.
        entry_points: Optional explicit set of entry point nodes to check reachability from.

    Returns:
        tuple[list[z3.ExprRef], z3.BoolRef]:
            - hop_vars: List of z3.String variables `[hop_0, ..., hop_k]`.
            - formula: The conjunction of entry point, transition, and target constraints.
    """
    target_set = set(target_roles)
    if entry_points is not None:
        external_set = set(entry_points)
    else:
        external_set = set(trust_graph.external_entry_points)


    hop_vars = [z3.String(f"hop_{i}") for i in range(k + 1)]

    constraints: List[z3.BoolRef] = []

    # 1. Entry point constraint for hop_0
    if external_set:
        entry_disjuncts = [hop_vars[0] == z3.StringVal(ext) for ext in external_set]
        constraints.append(z3.Or(entry_disjuncts))
    else:
        # No external entry points -> unsatisfiable
        constraints.append(z3.BoolVal(False))

    # 2. Transition constraints for step i -> step i+1
    for i in range(k):
        step_disjuncts: List[z3.BoolRef] = []

        # Real edges in trust graph
        for edge in trust_graph.edges:
            step_disjuncts.append(
                z3.And(
                    hop_vars[i] == z3.StringVal(edge.from_node),
                    hop_vars[i + 1] == z3.StringVal(edge.to_node),
                )
            )

        # Self-loops (stuttering steps) for all graph nodes
        for node in trust_graph.nodes:
            step_disjuncts.append(
                z3.And(
                    hop_vars[i] == z3.StringVal(node),
                    hop_vars[i + 1] == z3.StringVal(node),
                )
            )

        constraints.append(z3.Or(step_disjuncts))

    # 3. Target constraint for hop_k
    if target_set:
        target_disjuncts = [hop_vars[k] == z3.StringVal(tgt) for tgt in target_set]
        constraints.append(z3.Or(target_disjuncts))
    else:
        # No target roles -> unsatisfiable
        constraints.append(z3.BoolVal(False))

    formula = z3.And(constraints)
    return hop_vars, formula


def extract_witness_from_model(
    model: z3.ModelRef,
    hop_vars: List[z3.ExprRef],
    trust_graph: TrustGraph,
) -> Dict[str, Any]:
    """Reconstructs the SAT witness hop sequence from a Z3 SMT model."""
    raw_path: List[str] = []
    for var in hop_vars:
        val = model[var]
        if val is not None:
            # Strip quotes from Z3 string representation if present
            node_str = str(val).strip('"')
            raw_path.append(node_str)
        else:
            raw_path.append("")

    # Deduplicate consecutive self-loop / stuttering steps
    dedup_path: List[str] = []
    for node in raw_path:
        if not dedup_path or dedup_path[-1] != node:
            dedup_path.append(node)

    if not dedup_path:
        return {
            "entry_point": "",
            "target_resource": "",
            "path_length": 0,
            "hops": [],
        }

    entry_point = dedup_path[0]
    target_resource = dedup_path[-1]

    # Map consecutive steps to edge statements in trust_graph
    edge_map: Dict[Tuple[str, str], TrustEdge] = {}
    for edge in trust_graph.edges:
        edge_map[(edge.from_node, edge.to_node)] = edge

    hops_witness: List[Dict[str, Any]] = []
    for i in range(len(dedup_path) - 1):
        u = dedup_path[i]
        v = dedup_path[i + 1]
        edge = edge_map.get((u, v))
        if edge:
            hops_witness.append(
                {
                    "from": u,
                    "to": v,
                    "trust_statement": statement_to_dict(edge.trust_statement),
                    "identity_statement": statement_to_dict(edge.identity_statement) if edge.identity_statement else None,
                }
            )
        else:
            hops_witness.append({"from": u, "to": v, "statement": {}})

    return {
        "entry_point": entry_point,
        "target_resource": target_resource,
        "path_length": len(hops_witness),
        "hops": hops_witness,
    }
