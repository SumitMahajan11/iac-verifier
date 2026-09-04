from __future__ import annotations

import ast
import json
import re
from io import StringIO
from pathlib import Path
from typing import Any

import hcl2

from parser.graph import (
    AttributeValue,
    IamPolicyStatement,
    Resource,
    ResourceGraph,
    RuleSource,
    SecurityGroupRule,
    Unresolved,
    ResourceReference,
)


class HclParseError(Exception):
    """Raised when an HCL file cannot be read or parsed."""

    pass


RE_BARE_REF = re.compile(
    r"^(var|local|module|data|count|each|aws_[a-zA-Z0-9_]+)\.[a-zA-Z0-9_\-\.\[\]]+$"
)

RE_UNRESOLVED_REF = re.compile(
    r"\b(var|local|module|data|count|each|aws_[a-zA-Z0-9_]+)\.[a-zA-Z0-9_\-\.\[\]]+"
)


def _clean_key(key: str) -> str:
    """Strips outer quotes from HCL2 keys."""
    if isinstance(key, str):
        key = key.strip()
        if (key.startswith('"') and key.endswith('"')) or (key.startswith("'") and key.endswith("'")):
            key = key[1:-1]
    return key


def _is_jsonencode_expression(s: str) -> bool:
    """Returns True if string is a jsonencode(...) HCL function call."""
    cleaned = s.strip()
    return cleaned.startswith("${jsonencode(") or cleaned.startswith("jsonencode(")


def _clean_string(val: Any) -> Any:
    """Strips all outer quotes (single or double) from string literals."""
    if isinstance(val, str):
        cleaned = val.strip()
        while len(cleaned) >= 2 and (
            (cleaned.startswith('"') and cleaned.endswith('"'))
            or (cleaned.startswith("'") and cleaned.endswith("'"))
        ):
            cleaned = cleaned[1:-1].strip()
        return cleaned
    if isinstance(val, list):
        return [_clean_string(item) for item in val]
    return val


def _process_attribute_value(val: Any) -> AttributeValue:
    """Processes raw HCL attribute value into clean literals or Unresolved."""
    if isinstance(val, str):
        cleaned = _clean_string(val)

        # Handle jsonencode(...) function calls
        if _is_jsonencode_expression(cleaned):
            if cleaned.startswith("${") and cleaned.endswith("}"):
                cleaned = cleaned[2:-1].strip()
            # Check if jsonencode contains unresolved variable references
            if RE_UNRESOLVED_REF.search(cleaned):
                return Unresolved(
                    reason=f"Contains unresolved reference inside jsonencode: '{cleaned}'",
                    expression=cleaned,
                )
            # Literal jsonencode call without variable references
            return cleaned

        # Check for unresolved interpolation syntax
        if "${" in cleaned:
            return Unresolved(
                reason=f"Contains interpolation expression: '{cleaned}'",
                expression=cleaned,
            )

        # Check for bare variable/reference syntax
        if RE_BARE_REF.match(cleaned):
            return Unresolved(
                reason=f"References unresolved symbol: '{cleaned}'",
                expression=cleaned,
            )

        # Clean heredoc markers if present
        if cleaned.startswith("<<"):
            cleaned = re.sub(r"^<<[A-Za-z0-9_]+\s*", "", cleaned)
            cleaned = re.sub(r"\s*[A-Za-z0-9_]+$", "", cleaned).strip()

        return cleaned

    if isinstance(val, list):
        if len(val) == 1 and not isinstance(val[0], list):
            return _process_attribute_value(val[0])
        return [_process_attribute_value(item) for item in val]

    if isinstance(val, dict):
        return {
            _clean_key(k): _process_attribute_value(v)
            for k, v in val.items()
            if k != "__is_block__"
        }

    return val


def parse_file(path: str | Path) -> dict[str, Any]:
    """Reads a single .tf file and returns its raw parsed HCL2 structure.

    Raises HclParseError on file not found or malformed HCL syntax.
    """
    file_path = Path(path)
    if not file_path.exists():
        raise HclParseError(f"HCL file not found: {file_path}")

    try:
        with file_path.open("r", encoding="utf-8") as f:
            return hcl2.load(f)
    except Exception as e:
        raise HclParseError(f"Failed to parse HCL file '{file_path}': {e}") from e


def _clean_principal(val: Any) -> Any:
    """Recursively cleans principal values while preserving dict key structure."""
    if isinstance(val, dict):
        return {_clean_key(k): _clean_principal(v) for k, v in val.items()}
    if isinstance(val, list):
        return [_clean_principal(v) for v in val]
    if isinstance(val, str):
        return _clean_string(val)
    return val


def _has_unresolved_element(val: Any) -> bool:
    """Recursively checks if a structure contains Unresolved objects or unresolved interpolation strings."""
    if isinstance(val, Unresolved):
        return True
    if isinstance(val, str):
        return bool(RE_UNRESOLVED_REF.search(val) or "${" in val)
    if isinstance(val, dict):
        return any(_has_unresolved_element(k) or _has_unresolved_element(v) for k, v in val.items())
    if isinstance(val, list):
        return any(_has_unresolved_element(v) for v in val)
    return False


def _walk_iam_policy_dict(policy_dict: dict[str, Any], raw_expr: Any) -> list[IamPolicyStatement] | Unresolved:
    """Walks a native Python dict representing an IAM policy, returning list of IamPolicyStatements or Unresolved."""
    raw_stmts = policy_dict.get("Statement") or policy_dict.get("statement")
    if raw_stmts is None:
        return Unresolved(
            reason=f"IAM policy structure missing 'Statement' field: '{raw_expr}'",
            expression=str(raw_expr),
        )

    if isinstance(raw_stmts, dict):
        raw_stmts = [raw_stmts]
    elif not isinstance(raw_stmts, list):
        return Unresolved(
            reason=f"IAM policy 'Statement' field is neither dict nor list: '{raw_stmts}'",
            expression=str(raw_expr),
        )

    statements: list[IamPolicyStatement] = []

    for stmt in raw_stmts:
        if not isinstance(stmt, dict):
            return Unresolved(
                reason=f"IAM policy statement entry is not a dictionary: '{stmt}'",
                expression=str(raw_expr),
            )

        if _has_unresolved_element(stmt):
            return Unresolved(
                reason=f"Statement entry contains unresolved expression or reference: '{stmt}'",
                expression=str(raw_expr),
            )

        effect_raw = stmt.get("Effect") or stmt.get("effect") or "Allow"
        effect = _clean_string(str(effect_raw))

        actions_raw = stmt.get("Action") or stmt.get("action")
        if actions_raw is None:
            return Unresolved(
                reason=f"Statement entry missing 'Action' field: '{stmt}'",
                expression=str(raw_expr),
            )
        if isinstance(actions_raw, (str, bytes)):
            actions = [_clean_string(actions_raw)]
        elif isinstance(actions_raw, list):
            actions = [_clean_string(a) for a in actions_raw]
        else:
            return Unresolved(
                reason=f"Statement 'Action' field has invalid type: '{type(actions_raw).__name__}'",
                expression=str(raw_expr),
            )

        resources_raw = stmt.get("Resource") or stmt.get("resource")
        if resources_raw is None:
            resources = []
        elif isinstance(resources_raw, (str, bytes)):
            resources = [_clean_string(resources_raw)]
        elif isinstance(resources_raw, list):
            resources = [_clean_string(r) for r in resources_raw]
        else:
            return Unresolved(
                reason=f"Statement 'Resource' field has invalid type: '{type(resources_raw).__name__}'",
                expression=str(raw_expr),
            )

        principal_raw = stmt.get("Principal") or stmt.get("principal")
        principal = _clean_principal(principal_raw)

        statements.append(
            IamPolicyStatement(
                effect=effect,
                actions=actions,
                resources=resources,
                principal=principal,
            )
        )

    return statements


def _parse_iam_policy_statements(policy_val: Any) -> list[IamPolicyStatement] | Unresolved:
    """Parses JSON or HCL policy structures into IamPolicyStatement objects or returns Unresolved on failure."""
    if isinstance(policy_val, list):
        if not policy_val:
            return []
        if len(policy_val) == 1:
            policy_val = policy_val[0]

    if isinstance(policy_val, Unresolved):
        return policy_val

    if not policy_val:
        return []

    policy_dict: dict | None = None

    if isinstance(policy_val, dict):
        policy_dict = policy_val
    elif isinstance(policy_val, str):
        clean_val = policy_val.strip()
        if clean_val.startswith("${") and clean_val.endswith("}"):
            clean_val = clean_val[2:-1].strip()

        if clean_val.startswith("jsonencode(") and clean_val.endswith(")"):
            arg_str = clean_val[11:-1].strip()

            if RE_UNRESOLVED_REF.search(arg_str):
                return Unresolved(
                    reason=f"Contains unresolved reference inside jsonencode: '{arg_str}'",
                    expression=arg_str,
                )

            # Try parsing arg_str using ast.literal_eval (for Python dict repr) or python-hcl2 AST parser
            try:
                if isinstance(arg_str, str) and arg_str.startswith("{") and arg_str.endswith("}"):
                    try:
                        eval_res = ast.literal_eval(arg_str)
                        if isinstance(eval_res, dict):
                            policy_dict = eval_res
                    except Exception:
                        pass

                if policy_dict is None:
                    hcl_wrapper = f"temp_attr = {arg_str}\n"
                    parsed_hcl = hcl2.load(StringIO(hcl_wrapper))
                    if isinstance(parsed_hcl, dict) and "temp_attr" in parsed_hcl:
                        res_attr = parsed_hcl["temp_attr"]
                        if isinstance(res_attr, list) and len(res_attr) == 1 and isinstance(res_attr[0], dict):
                            policy_dict = res_attr[0]
                        elif isinstance(res_attr, dict):
                            policy_dict = res_attr
            except Exception:
                pass

        if policy_dict is None:
            clean_str = clean_val
            if clean_str.startswith("<<"):
                clean_str = re.sub(r"^<<[A-Za-z0-9_]+\s*", "", clean_str)
                clean_str = re.sub(r"\s*[A-Za-z0-9_]+$", "", clean_str).strip()
            try:
                policy_dict = json.loads(clean_str)
            except Exception:
                pass

    if policy_dict is None or not isinstance(policy_dict, dict):
        return Unresolved(
            reason=f"Unable to parse IAM policy as valid JSON or HCL structure: '{policy_val}'",
            expression=str(policy_val),
        )

    return _walk_iam_policy_dict(policy_dict, policy_val)


def _extract_security_group_rules(
    direction: str, blocks: Any
) -> list[SecurityGroupRule]:
    """Extracts SecurityGroupRule objects from ingress/egress blocks."""
    rules: list[SecurityGroupRule] = []
    if isinstance(blocks, dict):
        blocks = [blocks]
    if isinstance(blocks, list):
        for block in blocks:
            if not isinstance(block, dict):
                continue
            cleaned_block = {
                _clean_key(k): _process_attribute_value(v)
                for k, v in block.items()
                if k != "__is_block__"
            }
            from_port = cleaned_block.get("from_port")
            to_port = cleaned_block.get("to_port")
            raw_cidr = cleaned_block.get("cidr_blocks", [])
            if isinstance(raw_cidr, list):
                cidr_list = raw_cidr
            elif raw_cidr is not None:
                cidr_list = [raw_cidr]
            else:
                cidr_list = []
            rules.append(
                SecurityGroupRule(
                    direction=_clean_string(direction),
                    protocol=_clean_string(str(cleaned_block.get("protocol", "-1"))),
                    from_port=int(from_port) if isinstance(from_port, (int, str)) and str(from_port).isdigit() else (from_port if isinstance(from_port, int) else None),
                    to_port=int(to_port) if isinstance(to_port, (int, str)) and str(to_port).isdigit() else (to_port if isinstance(to_port, int) else None),
                    cidr_blocks=[_clean_string(c) if isinstance(c, str) else c for c in cidr_list],
                    referenced_security_group_id=cleaned_block.get("security_groups") or cleaned_block.get("referenced_security_group_id"),
                )
            )
    return rules

from parser.graph import AzureNsgRule

def _extract_azure_nsg_rules(blocks: Any) -> list[AzureNsgRule]:
    """Extracts AzureNsgRule objects from security_rule blocks."""
    rules: list[AzureNsgRule] = []
    if isinstance(blocks, dict):
        blocks = [blocks]
    if isinstance(blocks, list):
        for block in blocks:
            if not isinstance(block, dict):
                continue
            cleaned_block = {
                _clean_key(k): _process_attribute_value(v)
                for k, v in block.items()
                if k != "__is_block__"
            }
            
            prio = cleaned_block.get("priority")
            if isinstance(prio, str) and prio.isdigit():
                prio = int(prio)
            
            rules.append(
                AzureNsgRule(
                    name=_clean_string(cleaned_block.get("name")),
                    priority=prio if isinstance(prio, int) else None,
                    direction=_clean_string(cleaned_block.get("direction")),
                    access=_clean_string(cleaned_block.get("access")),
                    protocol=_clean_string(cleaned_block.get("protocol")),
                    source_port_range=cleaned_block.get("source_port_range") or cleaned_block.get("source_port_ranges"),
                    destination_port_range=cleaned_block.get("destination_port_range") or cleaned_block.get("destination_port_ranges"),
                    source_address_prefix=cleaned_block.get("source_address_prefix") or cleaned_block.get("source_address_prefixes"),
                    destination_address_prefix=cleaned_block.get("destination_address_prefix") or cleaned_block.get("destination_address_prefixes"),
                )
            )
    return rules



def extract_rule_sources(res_type: str, processed_attrs: dict[str, Any]) -> list[RuleSource]:
    """Extracts RuleSource objects from processed resource attributes based on resource type."""
    rule_sources: list[RuleSource] = []

    if res_type == "aws_security_group":
        ingress_blocks = processed_attrs.get("ingress")
        if ingress_blocks:
            rule_sources.extend(_extract_security_group_rules("ingress", ingress_blocks))
        egress_blocks = processed_attrs.get("egress")
        if egress_blocks:
            rule_sources.extend(_extract_security_group_rules("egress", egress_blocks))
    elif res_type == "aws_security_group_rule":
        direction = _clean_string(processed_attrs.get("type", "ingress"))
        protocol = _clean_string(processed_attrs.get("protocol", "-1"))
        from_port = processed_attrs.get("from_port")
        to_port = processed_attrs.get("to_port")
        raw_cidr = processed_attrs.get("cidr_blocks")
        if isinstance(raw_cidr, list):
            cidr_blocks = [_clean_string(c) if isinstance(c, str) else c for c in raw_cidr]
        elif raw_cidr is not None:
            cidr_blocks = [_clean_string(raw_cidr) if isinstance(raw_cidr, str) else raw_cidr]
        else:
            cidr_blocks = []
        ref_sg = processed_attrs.get("source_security_group_id") or processed_attrs.get("security_group_id")
        rule_sources.append(
            SecurityGroupRule(
                direction=direction,
                protocol=protocol,
                from_port=int(from_port) if isinstance(from_port, (int, str)) and str(from_port).isdigit() else (from_port if isinstance(from_port, int) else None),
                to_port=int(to_port) if isinstance(to_port, (int, str)) and str(to_port).isdigit() else (to_port if isinstance(to_port, int) else None),
                cidr_blocks=cidr_blocks,
                referenced_security_group_id=ref_sg if not isinstance(ref_sg, str) else _clean_string(ref_sg),
            )
        )
    elif res_type in ("aws_iam_policy", "aws_iam_role_policy", "aws_s3_bucket_policy"):
        policy_val = processed_attrs.get("policy")
        if policy_val:
            parsed = _parse_iam_policy_statements(policy_val)
            if isinstance(parsed, list):
                rule_sources.extend(parsed)
            elif isinstance(parsed, Unresolved):
                rule_sources.append(parsed)
    elif res_type == "aws_iam_role":
        assume_role = processed_attrs.get("assume_role_policy")
        if assume_role:
            parsed = _parse_iam_policy_statements(assume_role)
            if isinstance(parsed, list):
                rule_sources.extend(parsed)
            elif isinstance(parsed, Unresolved):
                rule_sources.append(parsed)
        inline = processed_attrs.get("inline_policy")
        if inline:
            if isinstance(inline, list):
                for item in inline:
                    if isinstance(item, dict) and "policy" in item:
                        parsed = _parse_iam_policy_statements(item["policy"])
                        if isinstance(parsed, list):
                            rule_sources.extend(parsed)
                        elif isinstance(parsed, Unresolved):
                            rule_sources.append(parsed)
            elif isinstance(inline, dict) and "policy" in inline:
                parsed = _parse_iam_policy_statements(inline["policy"])
                if isinstance(parsed, list):
                    rule_sources.extend(parsed)
                elif isinstance(parsed, Unresolved):
                    rule_sources.append(parsed)
    elif res_type == "azurerm_network_security_group":
        security_rule_blocks = processed_attrs.get("security_rule")
        if security_rule_blocks:
            rule_sources.extend(_extract_azure_nsg_rules(security_rule_blocks))
    elif res_type == "azurerm_network_security_rule":
        prio = processed_attrs.get("priority")
        if isinstance(prio, str) and prio.isdigit():
            prio = int(prio)
        rule_sources.append(
            AzureNsgRule(
                name=_clean_string(processed_attrs.get("name")),
                priority=prio if isinstance(prio, int) else None,
                direction=_clean_string(processed_attrs.get("direction")),
                access=_clean_string(processed_attrs.get("access")),
                protocol=_clean_string(processed_attrs.get("protocol")),
                source_port_range=processed_attrs.get("source_port_range") or processed_attrs.get("source_port_ranges"),
                destination_port_range=processed_attrs.get("destination_port_range") or processed_attrs.get("destination_port_ranges"),
                source_address_prefix=processed_attrs.get("source_address_prefix") or processed_attrs.get("source_address_prefixes"),
                destination_address_prefix=processed_attrs.get("destination_address_prefix") or processed_attrs.get("destination_address_prefixes"),
            )
        )

    return rule_sources

    return rule_sources


def build_graph(parsed: dict[str, Any], file_path: str | None = None) -> ResourceGraph:
    """Walks parsed HCL structure and constructs a ResourceGraph populated with resources and rule sources."""
    graph = ResourceGraph()
    resource_blocks = parsed.get("resource", [])

    for res_block in resource_blocks:
        if not isinstance(res_block, dict):
            continue

        for raw_type, res_dict in res_block.items():
            res_type = _clean_key(raw_type)
            if not isinstance(res_dict, dict):
                continue

            for raw_name, raw_attrs in res_dict.items():
                res_name = _clean_key(raw_name)
                address = f"{res_type}.{res_name}"

                if not isinstance(raw_attrs, dict):
                    continue

                processed_attrs: dict[str, AttributeValue] = {}
                rule_sources: list[RuleSource] = []

                for k, v in raw_attrs.items():
                    clean_k = _clean_key(k)
                    if clean_k == "__is_block__":
                        continue
                    processed_attrs[clean_k] = _process_attribute_value(v)

                # Post-processing rule sources from extracted attributes
                rule_sources = extract_rule_sources(res_type, processed_attrs)

                resource = Resource(
                    address=address,
                    type=res_type,
                    attributes=processed_attrs,
                    rule_sources=rule_sources,
                    file_path=file_path,
                )
                graph.add_resource(resource)
                
    return graph

