"""
parser/arm_parser.py

Native ARM JSON Template Parser.
Parses Azure Resource Manager (ARM) JSON deployment templates into the canonical
Resource and ResourceGraph data structures, enabling direct multi-cloud SMT verification
and trust reachability analysis without Terraform conversion.
"""

from __future__ import annotations

import json
from pathlib import Path
import re
from typing import Any, Dict, List, Optional, Tuple, Union

from parser.graph import (
    AttributeValue,
    AzureNsgRule,
    Resource,
    ResourceGraph,
    ResourceReference,
    Unresolved,
)

# Standard mapping from ARM Resource Types to canonical azurerm_* types
ARM_TO_AZURE_TYPE_MAP: Dict[str, str] = {
    "microsoft.network/networksecuritygroups": "azurerm_network_security_group",
    "microsoft.network/networksecuritygroups/securityrules": "azurerm_network_security_rule",
    "securityrules": "azurerm_network_security_rule",
    "microsoft.authorization/roleassignments": "azurerm_role_assignment",
    "microsoft.authorization/roledefinitions": "azurerm_role_definition",
    "microsoft.authorization/policydefinitions": "azurerm_policy_definition",
    "microsoft.authorization/policyassignments": "azurerm_policy_assignment",
    "microsoft.management/managementgroups/policyassignments": "azurerm_management_group_policy_assignment",
    "microsoft.authorization/managementgrouppolicyassignments": "azurerm_management_group_policy_assignment",
    "microsoft.managedidentity/userassignedidentities": "azurerm_user_assigned_identity",
    "microsoft.compute/virtualmachines": "azurerm_linux_virtual_machine",
    "microsoft.compute/virtualmachines/scalesets": "azurerm_linux_virtual_machine_scale_set",
    "microsoft.web/sites": "azurerm_linux_web_app",
    "microsoft.containerservice/managedclusters": "azurerm_kubernetes_cluster",
    "microsoft.storage/storageaccounts": "azurerm_storage_account",
    "microsoft.keyvault/vaults": "azurerm_key_vault",
}


def _clean_str(val: Any) -> str:
    """Strips outer quotes and whitespace from string representation."""
    if isinstance(val, str):
        return val.strip().strip('"\'')
    return str(val)


def _sanitize_identifier(name_str: str) -> str:
    """Converts resource name string into valid Python/HCL identifier for graph keying."""
    clean = _clean_str(name_str).lower()
    # Replace invalid chars with underscore
    clean = re.sub(r"[^a-z0-9_]", "_", clean)
    clean = re.sub(r"_+", "_", clean).strip("_")
    return clean or "unnamed_res"


def _map_arm_type_to_azurerm(arm_type: str) -> str:
    """Maps an ARM resource type string to corresponding azurerm_* resource type."""
    type_lower = arm_type.lower().strip()
    if type_lower in ARM_TO_AZURE_TYPE_MAP:
        return ARM_TO_AZURE_TYPE_MAP[type_lower]

    # Generic fallback: Microsoft.Foo/bar -> azurerm_foo_bar
    if type_lower.startswith("microsoft."):
        suffix = type_lower[len("microsoft."):]
        parts = suffix.split("/")
        parts_snake = [_sanitize_identifier(p) for p in parts]
        return "azurerm_" + "_".join(parts_snake)

    return "azurerm_" + _sanitize_identifier(type_lower)


def _eval_arm_expr(
    val: Any,
    parameters: Dict[str, Any],
    variables: Dict[str, Any],
) -> AttributeValue:
    """Evaluates an ARM JSON expression string or structure statically.

    Resolves parameters(), variables(), concat(), and basic string interpolations.
    Returns Unresolved for dynamic dynamic ARM functions (resourceId, reference, etc.).
    """
    if isinstance(val, (int, float, bool)) or val is None:
        return val

    if isinstance(val, list):
        return [_eval_arm_expr(item, parameters, variables) for item in val]

    if isinstance(val, dict):
        return {
            k: _eval_arm_expr(v, parameters, variables) for k, v in val.items()
        }

    if not isinstance(val, str):
        return str(val)

    s = val.strip()
    # Check if expression is wrapped in [ ... ]
    if s.startswith("[") and s.endswith("]") and not s.startswith("[["):
        expr = s[1:-1].strip()
        return _eval_arm_expression_string(expr, val, parameters, variables)

    # String without wrapping brackets
    return s


def _eval_arm_expression_string(
    expr: str,
    original_raw: str,
    parameters: Dict[str, Any],
    variables: Dict[str, Any],
) -> AttributeValue:
    """Parses and evaluates the body of an ARM expression string."""
    expr_clean = expr.strip()
    if (expr_clean.startswith("'") and expr_clean.endswith("'")) or (expr_clean.startswith('"') and expr_clean.endswith('"')):
        return expr_clean[1:-1]
    if expr_clean.isdigit():
        return int(expr_clean)
    if expr_clean.lower() == "true":
        return True
    if expr_clean.lower() == "false":
        return False

    # 1. parameters('paramName')
    param_match = re.match(r"^parameters\(['\"]([^'\"]+)['\"]\)$", expr, re.IGNORECASE)
    if param_match:
        p_name = param_match.group(1)
        if p_name in parameters:
            p_def = parameters[p_name]
            if isinstance(p_def, dict):
                if "defaultValue" in p_def:
                    default_v = p_def["defaultValue"]
                    if isinstance(default_v, dict) and "value" in default_v:
                        return default_v["value"]
                    return _eval_arm_expr(default_v, parameters, variables)
                elif "value" in p_def:
                    return _eval_arm_expr(p_def["value"], parameters, variables)
                else:
                    return Unresolved(
                        reason=f"ARM parameter '{p_name}' has no defaultValue",
                        expression=original_raw,
                    )
            else:
                return _eval_arm_expr(p_def, parameters, variables)
        else:
            return Unresolved(
                reason=f"ARM parameter '{p_name}' is not defined in template",
                expression=original_raw,
            )

    # 2. variables('varName')
    var_match = re.match(r"^variables\(['\"]([^'\"]+)['\"]\)$", expr, re.IGNORECASE)
    if var_match:
        v_name = var_match.group(1)
        if v_name in variables:
            v_val = variables[v_name]
            return _eval_arm_expr(v_val, parameters, variables)
        else:
            return Unresolved(
                reason=f"ARM variable '{v_name}' is not defined in template",
                expression=original_raw,
            )

    # 3. concat(arg1, arg2, ...)
    concat_match = re.match(r"^concat\((.*)\)$", expr, re.IGNORECASE)
    if concat_match:
        inner_args_str = concat_match.group(1)
        # Parse comma-separated arguments
        raw_args = _split_arm_func_args(inner_args_str)
        evaluated_args = []
        for arg in raw_args:
            eval_arg = _eval_arm_expression_string(arg.strip(), arg.strip(), parameters, variables)
            if isinstance(eval_arg, Unresolved):
                return eval_arg
            evaluated_args.append(str(eval_arg))
        return "".join(evaluated_args)

    # 4. toLower(arg) / toUpper(arg)
    lower_match = re.match(r"^toLower\((.*)\)$", expr, re.IGNORECASE)
    if lower_match:
        inner = lower_match.group(1).strip()
        eval_inner = _eval_arm_expression_string(inner, inner, parameters, variables)
        if isinstance(eval_inner, str):
            return eval_inner.lower()
        return eval_inner

    upper_match = re.match(r"^toUpper\((.*)\)$", expr, re.IGNORECASE)
    if upper_match:
        inner = upper_match.group(1).strip()
        eval_inner = _eval_arm_expression_string(inner, inner, parameters, variables)
        if isinstance(eval_inner, str):
            return eval_inner.upper()
        return eval_inner

    # Unsupported dynamic function calls (resourceId, reference, subscription, etc.)
    return Unresolved(
        reason=f"Dynamic or unsupported ARM function call: '{expr}'",
        expression=original_raw,
    )


def _split_arm_func_args(args_str: str) -> List[str]:
    """Splits function argument list respecting nested parens and quotes."""
    args = []
    current = []
    in_quotes = False
    quote_char = ""
    paren_depth = 0

    for char in args_str:
        if char in ("'", '"'):
            if not in_quotes:
                in_quotes = True
                quote_char = char
            elif char == quote_char:
                in_quotes = False
            current.append(char)
        elif char == "(" and not in_quotes:
            paren_depth += 1
            current.append(char)
        elif char == ")" and not in_quotes:
            paren_depth -= 1
            current.append(char)
        elif char == "," and not in_quotes and paren_depth == 0:
            args.append("".join(current).strip())
            current = []
        else:
            current.append(char)

    if current:
        args.append("".join(current).strip())
    return args


def _extract_arm_nsg_rule(rule_dict: Dict[str, Any], parameters: Dict[str, Any], variables: Dict[str, Any]) -> AzureNsgRule:
    """Converts ARM security rule JSON object into an AzureNsgRule instance."""
    raw_props = rule_dict.get("properties", {})
    if not isinstance(raw_props, dict):
        raw_props = rule_dict

    name_eval = _eval_arm_expr(rule_dict.get("name"), parameters, variables)
    name_str = name_eval if isinstance(name_eval, str) else None

    prio_raw = _eval_arm_expr(raw_props.get("priority"), parameters, variables)
    priority = None
    if isinstance(prio_raw, int):
        priority = prio_raw
    elif isinstance(prio_raw, str) and prio_raw.isdigit():
        priority = int(prio_raw)

    direction = _eval_arm_expr(raw_props.get("direction"), parameters, variables)
    direction_str = direction if isinstance(direction, str) else None

    access = _eval_arm_expr(raw_props.get("access"), parameters, variables)
    access_str = access if isinstance(access, str) else None

    protocol = _eval_arm_expr(raw_props.get("protocol"), parameters, variables)
    protocol_str = protocol if isinstance(protocol, str) else None

    src_port = _eval_arm_expr(raw_props.get("sourcePortRange") or raw_props.get("sourcePortRanges"), parameters, variables)
    dst_port = _eval_arm_expr(raw_props.get("destinationPortRange") or raw_props.get("destinationPortRanges"), parameters, variables)
    src_addr = _eval_arm_expr(raw_props.get("sourceAddressPrefix") or raw_props.get("sourceAddressPrefixes"), parameters, variables)
    dst_addr = _eval_arm_expr(raw_props.get("destinationAddressPrefix") or raw_props.get("destinationAddressPrefixes"), parameters, variables)

    return AzureNsgRule(
        name=name_str,
        priority=priority,
        direction=direction_str,
        access=access_str,
        protocol=protocol_str,
        source_port_range=src_port if not isinstance(src_port, Unresolved) else None,
        destination_port_range=dst_port if not isinstance(dst_port, Unresolved) else None,
        source_address_prefix=src_addr,
        destination_address_prefix=dst_addr,
    )


def parse_arm_dict(arm_data: Dict[str, Any], file_path: Optional[str] = None) -> ResourceGraph:
    """Parses raw ARM template dictionary into a compliant ResourceGraph."""
    graph = ResourceGraph()

    if not isinstance(arm_data, dict):
        return graph

    parameters: Dict[str, Any] = arm_data.get("parameters", {})
    if not isinstance(parameters, dict):
        parameters = {}

    variables: Dict[str, Any] = arm_data.get("variables", {})
    if not isinstance(variables, dict):
        variables = {}

    resources_list = arm_data.get("resources", [])
    schema_str = str(arm_data.get("$schema", "")).lower()
    has_valid_schema = "schema.management.azure.com" in schema_str

    if not isinstance(resources_list, list) or ("resources" not in arm_data and not has_valid_schema):
        unresolved_json = Unresolved(
            reason="JSON file is not a valid ARM deployment template (missing '$schema' or 'resources' array)",
            expression=file_path or "raw_json_dict",
        )
        graph.add_resource(
            Resource(
                address="unresolved_json.invalid_arm_template",
                type="unresolved_json",
                attributes={},
                rule_sources=[unresolved_json],
                file_path=file_path,
            )
        )
        return graph

    # Validate that at least one resource in a non-empty resources list is a recognized ARM type if $schema is omitted
    parsed_resources = 0
    for idx, res_entry in enumerate(resources_list):
        if isinstance(res_entry, dict) and (res_entry.get("type", "").lower().startswith("microsoft.") or res_entry.get("type", "").lower() in ARM_TO_AZURE_TYPE_MAP):
            parsed_resources += 1

    if len(resources_list) > 0 and parsed_resources == 0 and not has_valid_schema:
        unresolved_json = Unresolved(
            reason="JSON file contains a 'resources' array but no valid ARM 'Microsoft.*' resource definitions or Azure template schema",
            expression=file_path or "raw_json_dict",
        )
        graph.add_resource(
            Resource(
                address="unresolved_json.structurally_invalid_arm_template",
                type="unresolved_json",
                attributes={},
                rule_sources=[unresolved_json],
                file_path=file_path,
            )
        )
        return graph

    for idx, res_entry in enumerate(resources_list):
        if not isinstance(res_entry, dict):
            continue

        # Check for copy loop iteration on resource
        if "copy" in res_entry:
            unresolved_copy = Unresolved(reason="ARM 'copy' iteration loops are out of static analysis scope per §11")
            raw_type = res_entry.get("type", "unknown")
            res_type = _map_arm_type_to_azurerm(raw_type)
            res_name = f"res_copy_{idx}"
            graph.add_resource(
                Resource(
                    address=f"{res_type}.{res_name}",
                    type=res_type,
                    attributes={"status": unresolved_copy},
                    rule_sources=[unresolved_copy],
                    file_path=file_path,
                )
            )
            continue

        arm_type = res_entry.get("type", "")
        if not arm_type:
            continue

        raw_name = res_entry.get("name", f"res_{idx}")
        name_eval = _eval_arm_expr(raw_name, parameters, variables)
        if isinstance(name_eval, str):
            clean_name = _sanitize_identifier(name_eval)
        else:
            clean_name = f"res_{idx}"

        res_type = _map_arm_type_to_azurerm(arm_type)
        address = f"{res_type}.{clean_name}"

        properties = res_entry.get("properties", {})
        if not isinstance(properties, dict):
            properties = {}

        processed_attrs: Dict[str, AttributeValue] = {}

        # Copy top-level metadata fields (name, location, scope, kind, etc.)
        for top_k in ("name", "location", "scope", "kind"):
            if top_k in res_entry:
                processed_attrs[top_k] = _eval_arm_expr(res_entry[top_k], parameters, variables)

        # Handle top-level identity block if present
        if "identity" in res_entry:
            processed_attrs["identity"] = _eval_arm_expr(res_entry["identity"], parameters, variables)
        elif "identity" in properties:
            processed_attrs["identity"] = _eval_arm_expr(properties["identity"], parameters, variables)

        # Evaluate all properties into snake_case attributes
        for prop_k, prop_v in properties.items():
            snake_k = _sanitize_identifier(prop_k)
            processed_attrs[snake_k] = _eval_arm_expr(prop_v, parameters, variables)

        # Handle specific resource types rule extraction & attribute normalization
        rule_sources = []

        if res_type == "azurerm_network_security_group":
            # 1. Extract securityRules defined inside properties.securityRules
            sec_rules = properties.get("securityRules", [])
            if isinstance(sec_rules, list):
                for rule_dict in sec_rules:
                    if isinstance(rule_dict, dict):
                        rule_sources.append(_extract_arm_nsg_rule(rule_dict, parameters, variables))

            # 2. Extract child resources of type securityRules inside resources array
            child_res = res_entry.get("resources", [])
            if isinstance(child_res, list):
                for c_res in child_res:
                    if isinstance(c_res, dict):
                        c_type = c_res.get("type", "").lower()
                        if c_type in ("securityrules", "microsoft.network/networksecuritygroups/securityrules"):
                            rule_sources.append(_extract_arm_nsg_rule(c_res, parameters, variables))

        elif res_type == "azurerm_network_security_rule":
            rule_sources.append(_extract_arm_nsg_rule(res_entry, parameters, variables))

        elif res_type == "azurerm_role_assignment":
            principal_id = _eval_arm_expr(properties.get("principalId"), parameters, variables)
            role_def_id = _eval_arm_expr(properties.get("roleDefinitionId") or properties.get("roleDefinitionName"), parameters, variables)
            scope_val = _eval_arm_expr(properties.get("scope") or res_entry.get("scope"), parameters, variables)

            processed_attrs["principal_id"] = principal_id
            processed_attrs["role_definition_name"] = role_def_id
            processed_attrs["role_definition_id"] = role_def_id
            processed_attrs["scope"] = scope_val

        elif res_type == "azurerm_role_definition":
            role_name = _eval_arm_expr(properties.get("roleName") or res_entry.get("name"), parameters, variables)
            permissions = _eval_arm_expr(properties.get("permissions"), parameters, variables)
            scopes = _eval_arm_expr(properties.get("assignableScopes"), parameters, variables)

            processed_attrs["name"] = role_name
            processed_attrs["role_name"] = role_name
            processed_attrs["permissions"] = permissions
            processed_attrs["assignable_scopes"] = scopes

        elif res_type == "azurerm_policy_definition":
            policy_rule = _eval_arm_expr(properties.get("policyRule") or properties.get("policy_rule"), parameters, variables)
            processed_attrs["policy_rule"] = policy_rule
            processed_attrs["policy_rule_dict"] = policy_rule if isinstance(policy_rule, dict) else None

        elif res_type in ("azurerm_policy_assignment", "azurerm_management_group_policy_assignment"):
            pol_def_id = _eval_arm_expr(properties.get("policyDefinitionId") or properties.get("policy_definition_id"), parameters, variables)
            scope_val = _eval_arm_expr(properties.get("scope") or res_entry.get("scope"), parameters, variables)
            processed_attrs["policy_definition_id"] = pol_def_id
            processed_attrs["scope"] = scope_val

        resource = Resource(
            address=address,
            type=res_type,
            attributes=processed_attrs,
            rule_sources=rule_sources,
            file_path=file_path,
        )
        graph.add_resource(resource)

    return graph


def parse_arm_file(file_path: Union[str, Path]) -> ResourceGraph:
    """Loads an ARM JSON template file from disk and returns a ResourceGraph."""
    p = Path(file_path)
    if not p.exists():
        raise FileNotFoundError(f"ARM template file not found at: {file_path}")

    with open(p, "r", encoding="utf-8-sig") as f:
        data = json.load(f)

    return parse_arm_dict(data, file_path=str(p))
