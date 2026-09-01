from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, List, Set, Union

from parser.graph import (
    IamPolicyStatement,
    Resource,
    ResourceGraph,
    ResourceReference,
    Unresolved,
)


@dataclass(frozen=True)
class TrustEdge:
    """Represents a directed sts:AssumeRole trust edge from `from_node` to `to_node`."""

    from_node: str  # Role address or external account string e.g. "arn:aws:iam::123456789012:root"
    to_node: str    # Target role address, e.g. "aws_iam_role.target_role"
    trust_statement: IamPolicyStatement  # The target's assume_role_policy statement
    identity_statement: Optional[IamPolicyStatement] = None  # The source's attached identity statement (for internal hops)


@dataclass
class TrustGraph:
    """Holds nodes and directed edges of role assumption permissions across the graph."""

    nodes: Set[str] = field(default_factory=set)
    external_entry_points: Set[str] = field(default_factory=set)
    edges: List[TrustEdge] = field(default_factory=list)
    unresolvable_roles: Set[str] = field(default_factory=set)
    unresolvable_reasons: List[str] = field(default_factory=list)


RE_ACCOUNT_ID = re.compile(r"^\d{12}$")
RE_ACCOUNT_ARN = re.compile(r"^arn:aws:iam::(\d{12}):root$")


def _extract_principal_strings(principal_val: Any) -> list[str | Unresolved | ResourceReference]:
    """Extracts principal identifiers from an IAM statement principal dict or value."""
    if principal_val is None:
        return []
    if isinstance(principal_val, (Unresolved, ResourceReference)):
        return [principal_val]
    if isinstance(principal_val, str):
        return [principal_val]

    results: list[str | Unresolved | ResourceReference] = []
    if isinstance(principal_val, dict):
        # e.g., {"AWS": "arn:aws:iam::123456789012:root"} or {"AWS": ["...", ...]} or {"Service": "ec2.amazonaws.com"}
        for k, v in principal_val.items():
            if isinstance(v, list):
                for item in v:
                    if isinstance(item, (Unresolved, ResourceReference, str)):
                        results.append(item)
            elif isinstance(v, (Unresolved, ResourceReference, str)):
                results.append(v)
    return results


def build_trust_graph(resource_graph: ResourceGraph) -> TrustGraph:
    """Builds the role-assumption trust graph from a parsed `ResourceGraph`.

    Nodes are internal roles and external principal entry points.
    Edges are `sts:AssumeRole` permissions extracted from `assume_role_policy` statements.
    """
    trust_graph = TrustGraph()

    # Collect all aws_iam_role addresses as internal role nodes
    role_resources: dict[str, Resource] = {}
    for address, res in resource_graph.resources.items():
        if res.type == "aws_iam_role":
            trust_graph.nodes.add(address)
            role_resources[address] = res

    # Build reverse lookup maps for Tier B role identification by name or ARN attribute
    name_to_role: dict[str, str] = {}
    for address, res in role_resources.items():
        name_attr = res.attributes.get("name")
        if isinstance(name_attr, str):
            clean_n = name_attr.strip().strip('"\'')
            name_to_role[clean_n] = address
        # Role name fallback to resource name from address (e.g., aws_iam_role.my_role -> my_role)
        role_short_name = address.rsplit(".", 1)[-1]
        name_to_role[role_short_name] = address

    # Pass 1 & 2: collect candidate trust policies and candidate identity policies
    candidate_trust: List[tuple[str, str, IamPolicyStatement]] = []
    candidate_identity: List[tuple[str, str, IamPolicyStatement]] = []

    def match_target(p_str: str) -> Optional[str]:
        if p_str in trust_graph.nodes:
            return p_str
        if p_str in name_to_role:
            return name_to_role[p_str]
        if "role/" in p_str:
            role_name_part = p_str.rsplit("role/", 1)[-1]
            if role_name_part in name_to_role:
                return name_to_role[role_name_part]
        return None

    for role_address, res in role_resources.items():
        for rs in res.rule_sources:
            if isinstance(rs, Unresolved):
                trust_graph.unresolvable_roles.add(role_address)
                trust_graph.unresolvable_reasons.append(
                    f"Role '{role_address}' has unresolved rule source: {rs.reason}"
                )
                continue

            if not isinstance(rs, IamPolicyStatement):
                continue

            actions_lower = [str(a).lower() for a in rs.actions if isinstance(a, str)]
            is_assume_role = any(
                a in ("sts:assumerole", "sts:*", "*") for a in actions_lower
            )
            if not is_assume_role:
                continue

            if rs.effect.lower() != "allow":
                continue

            if rs.principal:
                # Target Role's assume_role_policy
                principals = _extract_principal_strings(rs.principal)
                for p in principals:
                    if isinstance(p, Unresolved):
                        trust_graph.unresolvable_roles.add(role_address)
                        trust_graph.unresolvable_reasons.append(f"Role '{role_address}' has unresolved principal reference: {p.reason}")
                        continue

                    if isinstance(p, ResourceReference):
                        target_addr = p.target_address
                        if target_addr in trust_graph.nodes:
                            candidate_trust.append((target_addr, role_address, rs))
                        else:
                            trust_graph.unresolvable_roles.add(role_address)
                        continue

                    if isinstance(p, str):
                        p_str = p.strip().strip('"\'')
                        matched = match_target(p_str)
                        if matched:
                            candidate_trust.append((matched, role_address, rs))
                        else:
                            is_external_acct = False
                            if RE_ACCOUNT_ID.match(p_str):
                                is_external_acct = True
                                ext_node = f"account:{p_str}"
                            elif RE_ACCOUNT_ARN.match(p_str):
                                is_external_acct = True
                                acct_id = RE_ACCOUNT_ARN.match(p_str).group(1)
                                ext_node = f"account:{acct_id}"

                            if is_external_acct:
                                trust_graph.nodes.add(ext_node)
                                trust_graph.external_entry_points.add(ext_node)
                                candidate_trust.append((ext_node, role_address, rs))
                            elif "${" in p_str or "var." in p_str or "local." in p_str or "module." in p_str:
                                trust_graph.unresolvable_roles.add(role_address)
            
            if rs.resources and not rs.principal:
                # Source Role's attached identity policy
                for r in rs.resources:
                    if isinstance(r, Unresolved):
                        trust_graph.unresolvable_roles.add(role_address)
                        continue
                    if isinstance(r, ResourceReference):
                        target_addr = r.target_address
                        if target_addr in trust_graph.nodes:
                            candidate_identity.append((role_address, target_addr, rs))
                        continue
                    if isinstance(r, str):
                        r_str = r.strip().strip('"\'')
                        matched = match_target(r_str)
                        if matched:
                            candidate_identity.append((role_address, matched, rs))
                        elif r_str == "*":
                            for target_node in trust_graph.nodes:
                                if target_node != role_address and not target_node.startswith("account:"):
                                    candidate_identity.append((role_address, target_node, rs))

    # Intersection: cross-account role assumption requires both
    for from_n, to_n, t_stmt in candidate_trust:
        if from_n in trust_graph.external_entry_points:
            trust_graph.edges.append(TrustEdge(from_node=from_n, to_node=to_n, trust_statement=t_stmt))
        else:
            matched_i_stmt = None
            for i_from, i_to, i_stmt in candidate_identity:
                if i_from == from_n and i_to == to_n:
                    matched_i_stmt = i_stmt
                    break
            
            if matched_i_stmt:
                trust_graph.edges.append(
                    TrustEdge(from_node=from_n, to_node=to_n, trust_statement=t_stmt, identity_statement=matched_i_stmt)
                )

    return trust_graph
