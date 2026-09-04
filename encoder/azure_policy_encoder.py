"""
encoder/azure_policy_encoder.py

Z3 SMT Encoder for Azure Policy definitions and assignments.
Translates Azure Policy definitions (if/then rules) and scope assignments into Z3 boolean formulas
representing POLICY_VIOLATION.

Supports:
- azurerm_policy_definition, azurerm_policy_assignment, azurerm_management_group_policy_assignment
- ARM Microsoft.Authorization/policyDefinitions and Microsoft.Authorization/policyAssignments
- If/then logical operators: field, equals, notEquals, in, notIn, contains, not, allOf, anyOf
- Scope subsumption matching via graph.azure_trust_graph.is_scope_subsumed
"""

from __future__ import annotations

import json
import re
from typing import Any, Dict, List, Optional, Tuple, Union
import z3

from graph.azure_trust_graph import is_scope_subsumed
from parser.graph import Resource, ResourceGraph, ResourceReference, Unresolved


def _resolve_attribute_val(resource: Resource, field_name: str) -> Any:
    """
    Resolves a policy field name (e.g. 'location', 'type', 'name', 'properties.publicNetworkAccess')
    against a target Resource's attributes dictionary.
    Handles snake_case / camelCase conversion and property nesting.
    """
    field_clean = field_name.strip().strip('"\'')

    # Direct match in attributes
    if field_clean in resource.attributes:
        return resource.attributes[field_clean]

    # Clean field path (e.g. 'properties.publicNetworkAccess' -> 'public_network_access')
    field_parts = field_clean.split(".")
    leaf_name = field_parts[-1]

    # Convert camelCase to snake_case
    leaf_snake = re.sub(r"(?<!^)(?=[A-Z])", "_", leaf_name).lower()
    if leaf_snake in resource.attributes:
        return resource.attributes[leaf_snake]

    if leaf_name.lower() in resource.attributes:
        return resource.attributes[leaf_name.lower()]

    aliases = {
        "supports_https_traffic_only": ["enable_https_traffic_only"],
        "enable_https_traffic_only": ["supports_https_traffic_only"],
        "public_ip_address_id": ["public_ip_address", "public_ip", "public_ip_id"],
    }
    if leaf_snake in aliases:
        for alias in aliases[leaf_snake]:
            if alias in resource.attributes:
                return resource.attributes[alias]

    # Special fields
    if field_clean.lower() in ("type", "resource_type"):
        return resource.type
    if field_clean.lower() in ("name", "resource_name"):
        return resource.attributes.get("name") or resource.address.split(".")[-1]
    if field_clean.lower() == "location":
        return resource.attributes.get("location")

    return None


class AzurePolicyEncoder:
    """
    SMT Encoder for Azure Policy definitions and assignments.
    """

    def encode_policy_condition(
        self,
        cond_dict: Dict[str, Any],
        target_resource: Resource,
    ) -> Tuple[z3.BoolRef, List[str]]:
        """
        Recursively translates an Azure Policy 'if' condition dictionary into a Z3 BoolRef expression and unresolvable reasons.
        Supports: allOf, anyOf, not, field (equals, notEquals, in, notIn, contains, exists).
        """
        if not isinstance(cond_dict, dict):
            return z3.BoolVal(False), []

        # 1. allOf
        if "allOf" in cond_dict:
            all_of_list = cond_dict["allOf"]
            if isinstance(all_of_list, list) and all_of_list:
                sub_exprs = []
                reasons = []
                for c in all_of_list:
                    expr, errs = self.encode_policy_condition(c, target_resource)
                    sub_exprs.append(expr)
                    reasons.extend(errs)
                return z3.And(sub_exprs), reasons
            return z3.BoolVal(True), []

        # 2. anyOf
        if "anyOf" in cond_dict:
            any_of_list = cond_dict["anyOf"]
            if isinstance(any_of_list, list) and any_of_list:
                sub_exprs = []
                reasons = []
                for c in any_of_list:
                    expr, errs = self.encode_policy_condition(c, target_resource)
                    sub_exprs.append(expr)
                    reasons.extend(errs)
                return z3.Or(sub_exprs), reasons
            return z3.BoolVal(False), []

        # 3. not
        if "not" in cond_dict:
            not_cond = cond_dict["not"]
            sub_expr, errs = self.encode_policy_condition(not_cond, target_resource)
            return z3.Not(sub_expr), errs

        # 4. field condition
        if "field" in cond_dict:
            field_name = str(cond_dict["field"])
            val = _resolve_attribute_val(target_resource, field_name)

            if isinstance(val, Unresolved):
                return z3.BoolVal(False), [f"Unresolved dynamic attribute '{field_name}': {val.reason}"]

            # Check operators
            if "equals" in cond_dict:
                target_val = cond_dict["equals"]
                if isinstance(target_val, Unresolved):
                    return z3.BoolVal(False), [f"Unresolved target value in policy 'equals' condition: {target_val.reason}"]
                if val is None:
                    return z3.BoolVal(False), []
                eq = str(val).strip().lower() == str(target_val).strip().lower()
                return z3.BoolVal(eq), []

            if "notEquals" in cond_dict or "not_equals" in cond_dict:
                target_val = cond_dict.get("notEquals") or cond_dict.get("not_equals")
                if isinstance(target_val, Unresolved):
                    return z3.BoolVal(False), [f"Unresolved target value in policy 'notEquals' condition: {target_val.reason}"]
                if val is None:
                    return z3.BoolVal(True), []
                neq = str(val).strip().lower() != str(target_val).strip().lower()
                return z3.BoolVal(neq), []

            if "in" in cond_dict:
                target_list = cond_dict["in"]
                if isinstance(target_list, Unresolved):
                    return z3.BoolVal(False), [f"Unresolved target value in policy 'in' condition: {target_list.reason}"]
                if not isinstance(target_list, list):
                    target_list = [target_list]
                if any(isinstance(x, Unresolved) for x in target_list):
                    return z3.BoolVal(False), ["Unresolved item in target list for policy 'in' condition"]
                if val is None:
                    return z3.BoolVal(False), []
                val_str = str(val).strip().lower()
                in_list = any(val_str == str(x).strip().lower() for x in target_list)
                return z3.BoolVal(in_list), []

            if "notIn" in cond_dict or "not_in" in cond_dict:
                target_list = cond_dict.get("notIn") or cond_dict.get("not_in")
                if isinstance(target_list, Unresolved):
                    return z3.BoolVal(False), [f"Unresolved target value in policy 'notIn' condition: {target_list.reason}"]
                if not isinstance(target_list, list):
                    target_list = [target_list]
                if any(isinstance(x, Unresolved) for x in target_list):
                    return z3.BoolVal(False), ["Unresolved item in target list for policy 'notIn' condition"]
                if val is None:
                    return z3.BoolVal(True), []
                val_str = str(val).strip().lower()
                in_list = any(val_str == str(x).strip().lower() for x in target_list)
                return z3.BoolVal(not in_list), []

            if "contains" in cond_dict:
                target_val = cond_dict["contains"]
                if isinstance(target_val, Unresolved):
                    return z3.BoolVal(False), [f"Unresolved target value in policy 'contains' condition: {target_val.reason}"]
                target_substr = str(target_val).strip().lower()
                if val is None:
                    return z3.BoolVal(False), []
                if isinstance(val, list):
                    val_contains = any(target_substr in str(item).strip().lower() for item in val)
                else:
                    val_contains = target_substr in str(val).strip().lower()
                return z3.BoolVal(val_contains), []

            if "exists" in cond_dict:
                target_val = cond_dict["exists"]
                if isinstance(target_val, Unresolved):
                    return z3.BoolVal(False), [f"Unresolved target value in policy 'exists' condition: {target_val.reason}"]
                should_exist = bool(target_val)
                exists = val is not None
                return z3.BoolVal(exists == should_exist), []

        return z3.BoolVal(False), []

    def encode_policy_violation(
        self,
        policy_def: Resource,
        policy_assign: Resource,
        target_resource: Resource,
        graph: ResourceGraph,
    ) -> Tuple[z3.BoolRef, Optional[str]]:
        """
        Encodes whether deploying target_resource within policy_assign scope violates policy_def.

        Returns (violation_formula, failure_reason_if_unresolvable).
        violation_formula evaluates to True (SAT) if a policy violation occurs.
        """
        # 1. Scope Applicability Check using graph.azure_trust_graph.is_scope_subsumed
        scope_attr = (
            policy_assign.attributes.get("scope")
            or policy_assign.attributes.get("management_group_id")
            or policy_assign.attributes.get("management_group_name")
            or policy_assign.attributes.get("subscription_id")
        )

        if scope_attr is None:
            scope_attr = "/subscriptions/00000000-0000-0000-0000-000000000000"

        if isinstance(scope_attr, Unresolved):
            return z3.BoolVal(False), f"Unresolved policy assignment scope: {scope_attr.reason}"

        if isinstance(scope_attr, ResourceReference):
            target_scope_res = graph.resources.get(scope_attr.target_address)
            if target_scope_res:
                scope_attr = target_scope_res.attributes.get("name") or target_scope_res.address
            else:
                scope_attr = scope_attr.target_address

        target_scope = target_resource.attributes.get("scope") or target_resource.address
        applicable = is_scope_subsumed(scope_attr, target_scope, graph)

        if not applicable:
            return z3.BoolVal(False), None

        # 2. Extract policy_rule from policy definition
        rule_attr = (
            policy_def.attributes.get("policy_rule")
            or policy_def.attributes.get("policy_rule_json")
            or policy_def.attributes.get("policy_rule_dict")
        )

        if rule_attr is None:
            return z3.BoolVal(False), "Policy definition has no policy_rule attribute"

        if isinstance(rule_attr, Unresolved):
            return z3.BoolVal(False), f"Unresolved policy rule: {rule_attr.reason}"

        policy_rule = None
        if isinstance(rule_attr, str):
            try:
                policy_rule = json.loads(rule_attr)
            except Exception as e:
                return z3.BoolVal(False), f"Invalid JSON in policy_rule: {e}"
        elif isinstance(rule_attr, dict):
            policy_rule = rule_attr

        if not isinstance(policy_rule, dict):
            return z3.BoolVal(False), "policy_rule is not a JSON object"

        # 3. Check Policy Effect
        then_block = policy_rule.get("then", {})
        effect = str(then_block.get("effect", "Deny")).strip().lower()

        if effect != "deny":
            return z3.BoolVal(False), None

        # 4. Encode IF Condition
        if_cond = policy_rule.get("if", {})
        cond_expr, cond_errs = self.encode_policy_condition(if_cond, target_resource)

        if cond_errs:
            return z3.BoolVal(False), f"Unresolved dynamic policy expression: {'; '.join(cond_errs)}"

        violation_expr = z3.And(z3.BoolVal(applicable), cond_expr)
        return violation_expr, None
