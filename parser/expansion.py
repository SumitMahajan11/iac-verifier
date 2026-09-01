from __future__ import annotations

import copy
from pathlib import Path
import re
from typing import Any

from parser.graph import (
    AttributeValue,
    IamPolicyStatement,
    Resource,
    ResourceGraph,
    RuleSource,
    SecurityGroupRule,
    Unresolved,
)
from parser.hcl_parser import (
    _clean_key,
    _process_attribute_value,
    extract_rule_sources,
)
from parser.variables import (
    _resolve_rule_source,
    load_local_values,
    load_variable_values,
    resolve_attribute,
)


def _substitute_in_value(val: Any, replacements: dict[str, Any]) -> Any:
    """Recursively substitutes key-value replacements in a structure."""
    if isinstance(val, list):
        return [_substitute_in_value(item, replacements) for item in val]

    if isinstance(val, dict):
        return {
            k: _substitute_in_value(v, replacements)
            for k, v in val.items()
        }

    if isinstance(val, Unresolved):
        reason = val.reason
        for target, replacement in replacements.items():
            pattern = re.escape(target)
            reason = re.sub(pattern, str(replacement), reason)
        return Unresolved(reason=reason)

    if isinstance(val, str):
        result_str = val
        for target, replacement in replacements.items():
            if val == target:
                return replacement
            if f"${{{target}}}" in result_str or target in result_str:
                result_str = result_str.replace(f"${{{target}}}", str(replacement))
                result_str = result_str.replace(target, str(replacement))
        return result_str

    return val


def expand_count(resource_block: dict[str, Any], count_value: int) -> list[dict[str, Any]]:
    """Expands a resource block dict with count = N into N instance dictionary descriptors.

    resource_block structure expected:
      {"type": "aws_instance", "name": "web", "attributes": {...}}
    """
    type_name = resource_block.get("type", "")
    res_name = resource_block.get("name", "")
    raw_attrs = resource_block.get("attributes", {})

    attrs = {k: v for k, v in raw_attrs.items() if _clean_key(k) != "count"}

    expanded_blocks: list[dict[str, Any]] = []

    for i in range(count_value):
        replacements = {
            "count.index": i,
            "${count.index}": i,
        }
        instance_attrs = _substitute_in_value(attrs, replacements)
        instance_name = f"{res_name}[{i}]"
        expanded_blocks.append(
            {
                "type": type_name,
                "name": instance_name,
                "index": i,
                "attributes": instance_attrs,
            }
        )

    return expanded_blocks


def expand_for_each(
    resource_block: dict[str, Any], for_each_value: dict[str, Any] | list[Any] | set[Any]
) -> list[dict[str, Any]]:
    """Expands a resource block dict with for_each into instance dictionary descriptors.

    resource_block structure expected:
      {"type": "aws_security_group_rule", "name": "ingress_rules", "attributes": {...}}
    """
    type_name = resource_block.get("type", "")
    res_name = resource_block.get("name", "")
    raw_attrs = resource_block.get("attributes", {})

    attrs = {k: v for k, v in raw_attrs.items() if _clean_key(k) != "for_each"}

    expanded_blocks: list[dict[str, Any]] = []

    if isinstance(for_each_value, dict):
        for raw_k, val in for_each_value.items():
            clean_k = _clean_key(raw_k)
            replacements = {
                "each.key": clean_k,
                "${each.key}": clean_k,
                "each.value": val,
                "${each.value}": val,
            }
            instance_attrs = _substitute_in_value(attrs, replacements)
            instance_name = f'{res_name}["{clean_k}"]'
            expanded_blocks.append(
                {
                    "type": type_name,
                    "name": instance_name,
                    "key": clean_k,
                    "attributes": instance_attrs,
                }
            )
    elif isinstance(for_each_value, (list, set)):
        for item in for_each_value:
            clean_item = (
                _clean_key(item) if isinstance(item, str) else str(item)
            )
            replacements = {
                "each.key": clean_item,
                "${each.key}": clean_item,
                "each.value": item,
                "${each.value}": item,
            }
            instance_attrs = _substitute_in_value(attrs, replacements)
            instance_name = f'{res_name}["{clean_item}"]'
            expanded_blocks.append(
                {
                    "type": type_name,
                    "name": instance_name,
                    "key": clean_item,
                    "attributes": instance_attrs,
                }
            )

    return expanded_blocks


def build_graph_with_expansion(
    parsed: dict[str, Any],
    repo_dir: str | Path | None = None,
    override_variable_values: dict[str, Any] | None = None,
) -> ResourceGraph:
    """Builds a ResourceGraph from parsed HCL, performing variable resolution and count/for_each expansion."""
    variable_values: dict[str, Any] = {}
    if override_variable_values is not None:
        variable_values = override_variable_values
    elif repo_dir is not None:
        variable_values = load_variable_values(repo_dir)


    local_values = load_local_values(parsed, variable_values)

    resource_blocks = parsed.get("resource", [])
    graph = ResourceGraph()

    for res_dict in resource_blocks:
        if not isinstance(res_dict, dict):
            continue

        for res_type_raw, name_dict in res_dict.items():
            res_type = _clean_key(res_type_raw)
            if not isinstance(name_dict, dict):
                continue

            for res_name_raw, block_contents in name_dict.items():
                res_name = _clean_key(res_name_raw)
                if not isinstance(block_contents, dict):
                    continue

                raw_attrs: dict[str, Any] = {}
                count_expr: Any = None
                for_each_expr: Any = None

                for k, v in block_contents.items():
                    clean_k = _clean_key(k)
                    if clean_k == "__is_block__":
                        continue
                    if clean_k == "count":
                        count_expr = v
                    elif clean_k == "for_each":
                        for_each_expr = v
                    else:
                        raw_attrs[clean_k] = v

                res_block_desc = {
                    "type": res_type,
                    "name": res_name,
                    "attributes": raw_attrs,
                }

                instances_to_create: list[dict[str, Any]] = []

                if count_expr is not None:
                    count_processed = _process_attribute_value(count_expr)
                    resolved_count = resolve_attribute(
                        count_processed, variable_values, local_values
                    )

                    if isinstance(resolved_count, int):
                        instances_to_create = expand_count(res_block_desc, resolved_count)
                    elif isinstance(resolved_count, Unresolved):
                        placeholder_reason = (
                            f"Resource expansion count is unresolved: {resolved_count.reason}"
                        )
                        unresolved_attrs = {
                            k: Unresolved(reason=placeholder_reason)
                            for k in raw_attrs.keys()
                        }
                        instances_to_create = [
                            {
                                "type": res_type,
                                "name": res_name,
                                "attributes": unresolved_attrs,
                                "is_unresolved_expansion": True,
                                "unresolved_reason": placeholder_reason,
                            }
                        ]
                    else:
                        try:
                            c_int = int(str(resolved_count))
                            instances_to_create = expand_count(res_block_desc, c_int)
                        except (ValueError, TypeError):
                            placeholder_reason = f"Resource expansion count is not an integer: {resolved_count!r}"
                            unresolved_attrs = {
                                k: Unresolved(reason=placeholder_reason)
                                for k in raw_attrs.keys()
                            }
                            instances_to_create = [
                                {
                                    "type": res_type,
                                    "name": res_name,
                                    "attributes": unresolved_attrs,
                                    "is_unresolved_expansion": True,
                                    "unresolved_reason": placeholder_reason,
                                }
                            ]

                elif for_each_expr is not None:
                    for_each_processed = _process_attribute_value(for_each_expr)
                    resolved_for_each = resolve_attribute(
                        for_each_processed, variable_values, local_values
                    )

                    if isinstance(resolved_for_each, (dict, list, set)):
                        instances_to_create = expand_for_each(
                            res_block_desc, resolved_for_each
                        )
                    elif isinstance(resolved_for_each, Unresolved):
                        placeholder_reason = f"Resource expansion for_each is unresolved: {resolved_for_each.reason}"
                        unresolved_attrs = {
                            k: Unresolved(reason=placeholder_reason)
                            for k in raw_attrs.keys()
                        }
                        instances_to_create = [
                            {
                                "type": res_type,
                                "name": res_name,
                                "attributes": unresolved_attrs,
                                "is_unresolved_expansion": True,
                                "unresolved_reason": placeholder_reason,
                            }
                        ]
                    else:
                        placeholder_reason = f"Resource expansion for_each is not a collection: {resolved_for_each!r}"
                        unresolved_attrs = {
                            k: Unresolved(reason=placeholder_reason)
                            for k in raw_attrs.keys()
                        }
                        instances_to_create = [
                            {
                                "type": res_type,
                                "name": res_name,
                                "attributes": unresolved_attrs,
                                "is_unresolved_expansion": True,
                                "unresolved_reason": placeholder_reason,
                            }
                        ]
                else:
                    instances_to_create = [
                        {
                            "type": res_type,
                            "name": res_name,
                            "attributes": raw_attrs,
                        }
                    ]

                for inst in instances_to_create:
                    inst_type = inst["type"]
                    inst_name = inst["name"]
                    address = f"{inst_type}.{inst_name}"
                    inst_raw_attrs = inst["attributes"]

                    if inst.get("is_unresolved_expansion"):
                        res_attrs = inst_raw_attrs
                        unresolved_reason = inst["unresolved_reason"]
                        proc_attrs = {k: _process_attribute_value(v) for k, v in inst_raw_attrs.items()}
                        rule_sources = extract_rule_sources(inst_type, proc_attrs)
                        unresolved_rule_sources = []
                        for rs in rule_sources:
                            if isinstance(rs, SecurityGroupRule):
                                unresolved_rule_sources.append(
                                    SecurityGroupRule(
                                        direction=rs.direction,
                                        protocol=rs.protocol,
                                        from_port=Unresolved(reason=unresolved_reason),
                                        to_port=Unresolved(reason=unresolved_reason),
                                        cidr_blocks=[Unresolved(reason=unresolved_reason)],
                                    )
                                )
                            elif isinstance(rs, IamPolicyStatement):
                                unresolved_rule_sources.append(
                                    IamPolicyStatement(
                                        effect=rs.effect,
                                        actions=[Unresolved(reason=unresolved_reason)],
                                        resources=[Unresolved(reason=unresolved_reason)],
                                    )
                                )
                            else:
                                unresolved_rule_sources.append(rs)

                        resource = Resource(
                            address=address,
                            type=inst_type,
                            attributes=res_attrs,
                            rule_sources=unresolved_rule_sources,
                        )
                        graph.add_resource(resource)
                    else:
                        resolved_attributes: dict[str, AttributeValue] = {}
                        for k, v in inst_raw_attrs.items():
                            proc_v = _process_attribute_value(v)
                            resolved_attributes[k] = resolve_attribute(
                                proc_v, variable_values, local_values
                            )

                        rule_sources = extract_rule_sources(inst_type, resolved_attributes)
                        resolved_rule_sources = [
                            _resolve_rule_source(rs, variable_values, local_values)
                            for rs in rule_sources
                        ]

                        resource = Resource(
                            address=address,
                            type=inst_type,
                            attributes=resolved_attributes,
                            rule_sources=resolved_rule_sources,
                        )
                        graph.add_resource(resource)

    return graph
