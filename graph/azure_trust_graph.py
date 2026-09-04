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


AZURE_BUILTIN_ROLE_GUIDS = {
    "8e3af657-a8ff-443c-a75c-2fe8c4bcb635": "owner",
    "b24988ac-6180-42a0-ab88-20f7382dd24c": "contributor",
    "18d50028-4b7d-4f3d-b86b-2d056041761f": "user access administrator",
    "f58310d9-a9f6-439a-9e8d-f62e7b41a168": "role based access control administrator",
    "acdd72a7-3385-48ef-bd42-f606fba81ae7": "virtual machine contributor",
}


def _normalize_role_name(role_def_val: Any) -> str:
    if not isinstance(role_def_val, str):
        return ""
    clean = role_def_val.strip().strip('"\'').lower()
    last_seg = clean.split("/")[-1]
    if last_seg in AZURE_BUILTIN_ROLE_GUIDS:
        return AZURE_BUILTIN_ROLE_GUIDS[last_seg]
    return clean


def is_azure_control_role(
    role_def_val: Any,
    role_definitions: Dict[str, Resource],
) -> bool:
    """Determines whether a role definition grants control over workload resources or identities."""
    if isinstance(role_def_val, str):
        norm_name = _normalize_role_name(role_def_val)
        if norm_name in AZURE_CONTROL_BUILTIN_ROLES:
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
        norm_name = _normalize_role_name(role_def_val)
        if norm_name in AZURE_HIGH_PRIV_BUILTIN_ROLES:
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


def _resolve_role_def_name(
    role_def_val: Any,
    role_definitions: Dict[str, Resource],
    resource_graph: ResourceGraph,
) -> str:
    """Resolves role_definition attribute to string role name or resource address."""
    if isinstance(role_def_val, str):
        return _clean_str(role_def_val)
    if isinstance(role_def_val, ResourceReference):
        target_addr = role_def_val.target_address
        target_res = role_definitions.get(target_addr) or resource_graph.resources.get(target_addr)
        if target_res:
            name_attr = target_res.attributes.get("name")
            if isinstance(name_attr, str):
                return _clean_str(name_attr)
        return target_addr
    return str(role_def_val)


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

    # Resolve child resource if child_scope references a resource
    if isinstance(child_scope, ResourceReference):
        child_addr = child_scope.target_address
    else:
        child_addr = c_str

    child_res = resource_graph.resources.get(child_addr)

    # 1. Handle parent_scope as formatted string path (e.g. /subscriptions/..., /providers/...)
    if p_lower.startswith("/"):
        if c_lower.startswith("/") and c_lower.startswith(p_lower):
            return True

        if child_res:
            res_scope = child_res.attributes.get("scope")
            if isinstance(res_scope, str) and res_scope.lower().rstrip("/").startswith(p_lower):
                return True
            if isinstance(res_scope, ResourceReference):
                target_scope_res = resource_graph.resources.get(res_scope.target_address)
                if target_scope_res:
                    res_scope_val = target_scope_res.attributes.get("scope") or target_scope_res.address
                    if isinstance(res_scope_val, str) and res_scope_val.lower().rstrip("/").startswith(p_lower):
                        return True

            # Resource Group scope check: /subscriptions/<sub_id>/resourcegroups/<rg_name>
            rg_match = re.search(r"/resourcegroups/([^/]+)", p_lower)
            if rg_match:
                parent_rg_name = rg_match.group(1).lower()
                child_rg = child_res.attributes.get("resource_group_name")
                if child_rg:
                    child_rg_str = _clean_str(child_rg).lower()
                    if child_rg_str == parent_rg_name or child_rg_str.endswith(f".{parent_rg_name}"):
                        # Ensure subscription matches if child specifies one
                        sub_match = re.match(r"^/subscriptions/([^/]+)", p_lower)
                        if sub_match:
                            parent_sub_id = sub_match.group(1)
                            child_sub_id = child_res.attributes.get("subscription_id")
                            if isinstance(child_sub_id, str) and child_sub_id.strip('"\'').lower() != parent_sub_id:
                                return False
                        return True
                    else:
                        return False  # Explicit resource group mismatch: role scoped to rg-finance cannot subsume workload in rg-prod

            # Subscription scope check: /subscriptions/<sub_id>
            sub_match = re.match(r"^/subscriptions/([^/]+)", p_lower)
            if sub_match:
                parent_sub_id = sub_match.group(1)
                child_sub_id = child_res.attributes.get("subscription_id")
                if isinstance(child_sub_id, str):
                    if child_sub_id.strip('"\'').lower() == parent_sub_id:
                        return True
                    else:
                        return False  # Explicitly isolated to a different subscription
                # If child resource does not specify a different subscription_id, it belongs to default sub
                return True


            # Management Group scope check: /providers/microsoft.management/managementgroups/<mg_id>
            mg_match = re.match(r"^/providers/microsoft\.management/managementgroups/([^/]+)", p_lower)
            if mg_match:
                parent_mg_id = mg_match.group(1)
                child_mg_id = child_res.attributes.get("management_group_id")
                if isinstance(child_mg_id, str):
                    if child_mg_id.strip('"\'').lower() == parent_mg_id:
                        return True
                    else:
                        return False
                return True

        return False

    # 2. Handle parent_scope as a ResourceReference or resource address (e.g. azurerm_resource_group.rg1)
    if isinstance(parent_scope, ResourceReference):
        parent_addr = parent_scope.target_address
    else:
        parent_addr = p_str

    if parent_addr == child_addr:
        return True

    if child_res:
        rg_attr = child_res.attributes.get("resource_group_name")
        if rg_attr:
            if isinstance(rg_attr, ResourceReference) and rg_attr.target_address == parent_addr:
                return True
            if isinstance(rg_attr, str):
                rg_str = _clean_str(rg_attr)
                if rg_str == parent_addr or parent_addr.endswith(f".{rg_str}"):
                    return True
                # Check if parent_addr is a resource group resource whose 'name' attribute matches rg_attr
                parent_res = resource_graph.resources.get(parent_addr)
                if parent_res and parent_res.type == "azurerm_resource_group":
                    p_name = parent_res.attributes.get("name")
                    if isinstance(p_name, str) and _clean_str(p_name).lower() == rg_str.lower():
                        return True

    return False



def build_azure_trust_graph(
    resource_graph: ResourceGraph,
    trust_graph: Optional[TrustGraph] = None,
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
    if trust_graph is None:
        trust_graph = TrustGraph()
    resource_graph.trust_graph = trust_graph
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
            id_list = list(ident_attr.get("identity_ids", []))
            u_assigned = ident_attr.get("userAssignedIdentities") or ident_attr.get("user_assigned_identities")
            if isinstance(u_assigned, dict):
                id_list.extend(list(u_assigned.keys()))
            elif isinstance(u_assigned, list):
                id_list.extend(u_assigned)

            for item in id_list:
                if isinstance(item, ResourceReference):
                    attached_ids.add(item.target_address)
                elif isinstance(item, str):
                    clean_item = _clean_str(item)
                    if clean_item.endswith(".id"):
                        clean_item = clean_item[:-3]
                    short_name = clean_item.split("/")[-1]
                    if clean_item in identities:
                        attached_ids.add(identities[clean_item].address)
                    elif short_name in identities:
                        attached_ids.add(identities[short_name].address)
                    elif f"azurerm_user_assigned_identity.{short_name}" in identities:
                        attached_ids.add(f"azurerm_user_assigned_identity.{short_name}")
        elif isinstance(ident_attr, list):
            for block in ident_attr:
                if isinstance(block, dict):
                    id_list = list(block.get("identity_ids", []))
                    u_assigned = block.get("userAssignedIdentities") or block.get("user_assigned_identities")
                    if isinstance(u_assigned, dict):
                        id_list.extend(list(u_assigned.keys()))
                    elif isinstance(u_assigned, list):
                        id_list.extend(u_assigned)

                    for item in id_list:
                        if isinstance(item, ResourceReference):
                            attached_ids.add(item.target_address)
                        elif isinstance(item, str):
                            clean_item = _clean_str(item)
                            if clean_item.endswith(".id"):
                                clean_item = clean_item[:-3]
                            short_name = clean_item.split("/")[-1]
                            if clean_item in identities:
                                attached_ids.add(identities[clean_item].address)
                            elif short_name in identities:
                                attached_ids.add(identities[short_name].address)
                            elif f"azurerm_user_assigned_identity.{short_name}" in identities:
                                attached_ids.add(f"azurerm_user_assigned_identity.{short_name}")
        if attached_ids:
            compute_attached_identities[address] = attached_ids
            for att_id in attached_ids:
                trust_graph.nodes.add(att_id)

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

        # Fail-closed check for Active Directory Group principal references
        if isinstance(principal_id, ResourceReference):
            p_target = resource_graph.resources.get(principal_id.target_address)
            if p_target and p_target.type in ("azuread_group", "azuread_group_member"):
                trust_graph.unresolvable_roles.add(ra_addr)
                trust_graph.unresolvable_reasons.append(
                    f"Role assignment '{ra_addr}' uses Active Directory group principal '{principal_id.target_address}': static group membership expansion requires runtime directory access (fail-closed)"
                )
                continue
        elif isinstance(principal_id, str):
            clean_p = _clean_str(principal_id)
            if clean_p in resource_graph.resources and resource_graph.resources[clean_p].type in ("azuread_group", "azuread_group_member"):
                trust_graph.unresolvable_roles.add(ra_addr)
                trust_graph.unresolvable_reasons.append(
                    f"Role assignment '{ra_addr}' uses Active Directory group principal '{clean_p}': static group membership expansion requires runtime directory access (fail-closed)"
                )
                continue

        # Extract principal node name
        principal_node: Optional[str] = None
        if isinstance(principal_id, ResourceReference):
            principal_node = principal_id.target_address
        elif isinstance(principal_id, str):
            clean_p = _clean_str(principal_id)
            if clean_p in identities:
                principal_node = identities[clean_p].address
            elif clean_p in trust_graph.nodes:
                principal_node = clean_p
            else:
                # Try matching clean_p against identity resource names or principal_id attributes
                matched_id_addr = None
                for id_addr, id_res in identities.items():
                    id_name = id_res.attributes.get("name")
                    id_pid = id_res.attributes.get("principal_id")
                    if (id_name and id_name == clean_p) or (id_pid and id_pid == clean_p):
                        matched_id_addr = id_res.address
                        break
                if matched_id_addr:
                    principal_node = matched_id_addr
                else:
                    principal_node = clean_p if clean_p.startswith("account:") else f"account:{clean_p}"
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

        resolved_role_name = _resolve_role_def_name(role_def, role_definitions, resource_graph)
        resolved_scope_str = scope.target_address if isinstance(scope, ResourceReference) else _clean_str(scope)

        if is_high_priv:
            if principal_node.startswith("account:"):
                # Only add ra_addr as a target role if no compute workloads with attached managed identities exist in the graph
                if not compute_attached_identities:
                    trust_graph.nodes.add(ra_addr)
                    azure_target_roles.add(ra_addr)
                    fake_stmt = IamPolicyStatement(
                        effect="Allow",
                        actions=[resolved_role_name],
                        resources=[resolved_scope_str],
                        principal=principal_node,
                    )
                    trust_graph.edges.append(
                        TrustEdge(
                            from_node=principal_node,
                            to_node=ra_addr,
                            trust_statement=fake_stmt,
                        )
                    )
            else:
                azure_target_roles.add(principal_node)

        # Create Directed Edges for identity assumption
        if scope:
            for workload_addr, attached_ids in compute_attached_identities.items():
                if is_scope_subsumed(scope, workload_addr, resource_graph) and is_control:
                    for target_id in attached_ids:
                        if principal_node != target_id:
                            fake_stmt = IamPolicyStatement(
                                effect="Allow",
                                actions=[resolved_role_name],
                                resources=[resolved_scope_str],
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
                            actions=[resolved_role_name],
                            resources=[resolved_scope_str],
                            principal=principal_node,
                        )
                        trust_graph.edges.append(
                            TrustEdge(
                                from_node=principal_node,
                                to_node=ident_addr,
                                trust_statement=fake_stmt,
                            )
                        )

    trust_graph.target_roles.update(azure_target_roles)
    return azure_target_roles

