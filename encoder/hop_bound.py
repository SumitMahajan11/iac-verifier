from __future__ import annotations


def compute_hop_bound(role_count: int, configured_cap: int = 10) -> tuple[int, bool]:
    """Calculates the symbolic hop bound `k` and completeness flag for reachability SMT solving.

    In a graph with N role nodes and external account entry points, the maximum simple path
    length from an external entry point through N role nodes is N hops (1 entry-point assumption + N-1 role-to-role hops).

    Formula:
        k = min(configured_cap, role_count)
        is_complete = role_count <= configured_cap

    Args:
        role_count: Number of IAM role nodes in the resource graph.
        configured_cap: Maximum hop capacity limit (default 10).

    Returns:
        tuple[int, bool]: (k, is_complete)
            - k: Symbolic BMC hop bound constraint.
            - is_complete: True if role_count <= configured_cap (complete unreachability proof),
                           False if role_count > configured_cap (bounded search space).
    """
    if role_count <= 0:
        return 0, True

    k = min(configured_cap, role_count)
    is_complete = role_count <= configured_cap
    return k, is_complete
