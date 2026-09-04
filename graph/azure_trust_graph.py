"""
graph/azure_trust_graph.py

Azure RBAC privilege escalation trust graph builder.
Models Azure RBAC scope inheritance (Management Group -> Subscription -> Resource Group -> Resource),
built-in and custom role definition permissions, user-assigned and system-assigned managed identities,
and compute workload identity assumption edges.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Set, Tuple

from graph.trust_graph import TrustEdge, TrustGraph
from parser.graph import (
    IamPolicyStatement,
    Resource,
    ResourceGraph,
    ResourceReference,
    Unresolved,
)

# Built-in roles that grant control over compute workloads / identities
AZURE_CONTROL_BUILTIN_ROLES = {
    "owner",
    "contributor",
    "user access administrator",
    "role based access control administrator",
    "virtual machine contributor",
}

# Built-in roles that grant high-privilege administrative access over scope targets
AZURE_HIGH_PRIV_BUILTIN_ROLES = {
    "owner",
    "contributor",
    "user access administrator",
    "role based access control administrator",
}

AZURE_ADMIN_ACTION_PATTERNS = [
    "*",
    "microsoft.authorization/*",
    "microsoft.authorization/roleassignments/*",
    "microsoft.authorization/roleassignments/write",
    "microsoft.authorization/roledefinitions/*",
    "microsoft.authorization/roledefinitions/write",
]


def _clean_str(val: Any) -> str:
    if isinstance(val, str):
        return val.strip().strip('"\'')
    return str(val)


def is_azure_control_role(
    role_def_val: Any,
    role_definitions: Dict[str, Resource],
) -> bool:
    """Determines whether a role definition grants control over workload resources or identities."""
    if isinstance(role_def_val, str):
        clean_name = role_def_val.strip().strip('"\'').lower()
        if clean_name in AZURE_CONTROL_BUILTIN_ROLES:
            return True
        if role_def_val in role_definitions:
            return _is_custom_role_admin(role_definitions[role_def_val])

    if isinstance(role_def_val, ResourceReference):
        target_addr = role_def_val.target_address
        if target_addr in role_definitions:
            return _is_custom_role_admin(role_definitions[target_addr])

    return False


def is_azure_high_priv_role(
    role_def_val: Any,
    role_definitions: Dict[str, Resource],
) -> bool:
    """Determines whether a role definition grants high-privilege administrative access."""
    if isinstance(role_def_val, str):
        clean_name = role_def_val.strip().strip('"\'').lower()
        if clean_name in AZURE_HIGH_PRIV_BUILTIN_ROLES:
            return True
        if role_def_val in role_definitions:
            return _is_custom_role_admin(role_definitions[role_def_val])

    if isinstance(role_def_val, ResourceReference):
        target_addr = role_def_val.target_address
        if target_addr in role_definitions:
            return _is_custom_role_admin(role_definitions[target_addr])

    return False


def _is_custom_role_admin(res: Resource) -> bool:
    """Checks custom azurerm_role_definition for administrative actions."""
    perms = res.attributes.get("permissions")
    if not perms:
        return False
    if isinstance(perms, dict):
        perms = [perms]
    if isinstance(perms, list):
        for perm in perms:
            if isinstance(perm, dict):
                actions = perm.get("actions", [])
                if isinstance(actions, list):
                    for act in actions:
                        if isinstance(act, str):
                            act_lower = act.strip().strip('"\'').lower()
                            for pat in AZURE_ADMIN_ACTION_PATTERNS:
                                if pat == act_lower or (pat.endswith("*") and act_lower.startswith(pat[:-1])):
                                    return True
    return False


def is_scope_subsumed(
    parent_scope: str | ResourceReference,
    child_scope: str | ResourceReference,
    resource_graph: ResourceGraph,
) -> bool:
    """
    Determines if parent_scope covers or inherits to child_scope according to Azure's 4-level scope hierarchy:
    Management Group -> Subscription -> Resource Group -> Resource.
    """
    if parent_scope == child_scope:
        return True

    p_str = _clean_str(parent_scope)
    c_str = _clean_str(child_scope)

    if p_str == c_str:
        return True

    p_lower = p_str.lower().rstrip("/")
    c_lower = c_str.lower().rstrip("/")

    if p_lower.startswith("/"):
        if c_lower.startswith("/") and c_lower.startswith(p_lower):
            return True

        if isinstance(child_scope, ResourceReference):
            child_addr = child_scope.target_address
        else:
            child_addr = c_str

        child_res = resource_graph.resources.get(child_addr)
        if child_res:
            res_scope = child_res.attributes.get("scope")
            if isinstance(res_scope, str) and res_scope.lower().startswith(p_lower):
                return True
            # Management Group or Subscription scope subsumes all sub-resources unless explicitly restricted
            if p_lower.startswith("/providers/microsoft.management/managementgroups") or p_lower.startswith("/subscriptions"):
                return True

    if isinstance(parent_scope, ResourceReference):
        parent_addr = parent_scope.target_address
    else:
        parent_addr = p_str

    if isinstance(child_scope, ResourceReference):
        child_addr = child_scope.target_address
    else:
        child_addr = c_str

    if parent_addr == child_addr:
        return True

    child_res = resource_graph.resources.get(child_addr)
    if child_res:
        rg_attr = child_res.attributes.get("resource_group_name")
        if rg_attr:
            if isinstance(rg_attr, ResourceReference) and rg_attr.target_address == parent_addr:
                return True
            if isinstance(rg_attr, str) and (rg_attr == parent_addr or parent_addr.endswith(f".{rg_attr}")):
                return True

    return False


def build_azure_trust_graph(
    resource_graph: ResourceGraph,
    trust_graph: TrustGraph,
) -> Set[str]:
    """
    Populates TrustGraph with Azure RBAC nodes and directed privilege escalation edges.

    Identifies:
      1. User-assigned & system-assigned identities as nodes.
      2. Role assignments connecting principals to target scopes.
      3. Compute workload resources holding identities.
      4. Administrative target roles.

    Returns:
        azure_target_roles: Set of principal node addresses holding administrative roles over a scope.
    """
    role_assignments: List[Tuple[str, Resource]] = []
    role_definitions: Dict[str, Resource] = {}
    identities: Dict[str, Resource] = {}
    workload_resources: Dict[str, Resource] = {}

    azure_target_roles: Set[str] = set()

    for address, res in resource_graph.resources.items():
        if res.type == "azurerm_role_assignment":
            role_assignments.append((address, res))
        elif res.type == "azurerm_role_definition":
            role_definitions[address] = res
            name_attr = res.attributes.get("name")
            if isinstance(name_attr, str):
                role_definitions[name_attr] = res
        elif res.type == "azurerm_user_assigned_identity":
            trust_graph.nodes.add(address)
            identities[address] = res
            name_attr = res.attributes.get("name")
            if isinstance(name_attr, str):
                identities[name_attr] = res
        elif "identity" in res.attributes or res.type in (
            "azurerm_linux_virtual_machine",
            "azurerm_windows_virtual_machine",
            "azurerm_linux_web_app",
            "azurerm_windows_web_app",
            "azurerm_kubernetes_cluster",
            "azurerm_function_app",
        ):
            workload_resources[address] = res

    # Resolve workload identity bindings
    compute_attached_identities: Dict[str, Set[str]] = {}
    for address, res in workload_resources.items():
        attached_ids: Set[str] = set()
        ident_attr = res.attributes.get("identity")
        if isinstance(ident_attr, dict):
            id_list = ident_attr.get("identity_ids", [])
            if isinstance(id_list, list):
                for item in id_list:
                    if isinstance(item, ResourceReference):
                        attached_ids.add(item.target_address)
                    elif isinstance(item, str):
                        clean_item = _clean_str(item)
                        if clean_item in identities:
                            attached_ids.add(clean_item)
            elif isinstance(id_list, ResourceReference):
                attached_ids.add(id_list.target_address)
        elif isinstance(ident_attr, list):
            for block in ident_attr:
                if isinstance(block, dict):
                    id_list = block.get("identity_ids", [])
                    if isinstance(id_list, list):
                        for item in id_list:
                            if isinstance(item, ResourceReference):
                                attached_ids.add(item.target_address)
                            elif isinstance(item, str):
                                clean_item = _clean_str(item)
                                if clean_item in identities:
                                    attached_ids.add(clean_item)
        if attached_ids:
            compute_attached_identities[address] = attached_ids

    # Process Role Assignments
    for ra_addr, res in role_assignments:
        principal_id = res.attributes.get("principal_id")
        scope = res.attributes.get("scope")
        role_def = res.attributes.get("role_definition_name") or res.attributes.get("role_definition_id")

        # Unresolved fail-closed check
        if isinstance(principal_id, Unresolved):
            trust_graph.unresolvable_roles.add(ra_addr)
            trust_graph.unresolvable_reasons.append(
                f"Role assignment '{ra_addr}' has unresolved principal_id: {principal_id.reason}"
            )
            continue
        if isinstance(scope, Unresolved):
            trust_graph.unresolvable_roles.add(ra_addr)
            trust_graph.unresolvable_reasons.append(
                f"Role assignment '{ra_addr}' has unresolved scope: {scope.reason}"
            )
            continue
        if isinstance(role_def, Unresolved):
            trust_graph.unresolvable_roles.add(ra_addr)
            trust_graph.unresolvable_reasons.append(
                f"Role assignment '{ra_addr}' has unresolved role definition: {role_def.reason}"
            )
            continue

        # Extract principal node name
        principal_node: Optional[str] = None
        if isinstance(principal_id, ResourceReference):
            principal_node = principal_id.target_address
        elif isinstance(principal_id, str):
            clean_p = _clean_str(principal_id)
            if clean_p in identities:
                principal_node = clean_p
            elif clean_p in trust_graph.nodes:
                principal_node = clean_p
            else:
                principal_node = f"account:{clean_p}"
                trust_graph.nodes.add(principal_node)
                trust_graph.external_entry_points.add(principal_node)
        else:
            trust_graph.unresolvable_roles.add(ra_addr)
            trust_graph.unresolvable_reasons.append(
                f"Role assignment '{ra_addr}' has invalid principal_id"
            )
            continue

        trust_graph.nodes.add(principal_node)

        is_control = is_azure_control_role(role_def, role_definitions)
        is_high_priv = is_azure_high_priv_role(role_def, role_definitions)

        if is_high_priv and not principal_node.startswith("account:"):
            azure_target_roles.add(principal_node)

        # Create Directed Edges for identity assumption
        if scope:
            for workload_addr, attached_ids in compute_attached_identities.items():
                if is_scope_subsumed(scope, workload_addr, resource_graph) and is_control:
                    for target_id in attached_ids:
                        if principal_node != target_id:
                            fake_stmt = IamPolicyStatement(
                                effect="Allow",
                                actions=[_clean_str(role_def)],
                                resources=[_clean_str(scope)],
                                principal=principal_node,
                            )
                            trust_graph.edges.append(
                                TrustEdge(
                                    from_node=principal_node,
                                    to_node=target_id,
                                    trust_statement=fake_stmt,
                                )
                            )

            for ident_addr in identities:
                if is_scope_subsumed(scope, ident_addr, resource_graph) and is_control:
                    if principal_node != ident_addr:
                        fake_stmt = IamPolicyStatement(
                            effect="Allow",
                            actions=[_clean_str(role_def)],
                            resources=[_clean_str(scope)],
                            principal=principal_node,
                        )
                        trust_graph.edges.append(
                            TrustEdge(
                                from_node=principal_node,
                                to_node=ident_addr,
                                trust_statement=fake_stmt,
                            )
                        )

    return azure_target_roles
