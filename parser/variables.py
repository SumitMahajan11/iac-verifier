from __future__ import annotations

import json
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
from parser.hcl_parser import build_graph, parse_file


class _UnresolvedError(Exception):
    """Internal helper exception carrying an Unresolved instance during attribute resolution."""

    def __init__(self, unresolved: Unresolved):
        self.unresolved = unresolved
        super().__init__(unresolved.reason)


def load_variable_values(repo_dir: str | Path) -> dict[str, Any]:
    """Reads declared variable defaults and tfvars overrides from repo_dir.

    Returns a merged dictionary of variable name -> resolved value.
    Variables with no default and no tfvars entry are omitted.
    """
    dir_path = Path(repo_dir)
    if not dir_path.exists() or not dir_path.is_dir():
        return {}

    variable_defaults: dict[str, Any] = {}

    for tf_file in dir_path.glob("*.tf"):
        try:
            parsed = parse_file(tf_file)
            var_blocks = parsed.get("variable", [])
            for var_block in var_blocks:
                if not isinstance(var_block, dict):
                    continue
                for raw_name, var_decl in var_block.items():
                    var_name = raw_name.strip().strip('"\'')
                    if isinstance(var_decl, dict) and "default" in var_decl:
                        raw_default = var_decl["default"]
                        if isinstance(raw_default, list) and len(raw_default) == 1:
                            raw_default = raw_default[0]
                        if isinstance(raw_default, str):
                            raw_default = raw_default.strip().strip('"\'')
                        variable_defaults[var_name] = raw_default
        except Exception:
            pass

    tfvars_overrides: dict[str, Any] = {}
    tfvars_file = dir_path / "terraform.tfvars"
    tfvars_json_file = dir_path / "terraform.tfvars.json"

    if tfvars_file.exists():
        try:
            parsed_tfvars = parse_file(tfvars_file)
            if isinstance(parsed_tfvars, dict):
                for k, v in parsed_tfvars.items():
                    clean_k = k.strip().strip('"\'')
                    if isinstance(v, list) and len(v) == 1:
                        v = v[0]
                    if isinstance(v, str):
                        v = v.strip().strip('"\'')
                    tfvars_overrides[clean_k] = v
        except Exception:
            pass

    if tfvars_json_file.exists():
        try:
            with tfvars_json_file.open("r", encoding="utf-8") as f:
                data = json.load(f)
                if isinstance(data, dict):
                    for k, v in data.items():
                        clean_k = str(k).strip().strip('"\'')
                        if isinstance(v, str):
                            v = v.strip().strip('"\'')
                        tfvars_overrides[clean_k] = v
        except Exception:
            pass

    return {**variable_defaults, **tfvars_overrides}


def load_local_values(
    parsed: dict[str, Any], variable_values: dict[str, Any]
) -> dict[str, Any]:
    """Resolves locals { ... } blocks, supporting chained local references."""
    raw_locals: dict[str, Any] = {}

    locals_blocks = parsed.get("locals", [])
    for loc_block in locals_blocks:
        if not isinstance(loc_block, dict):
            continue
        for k, v in loc_block.items():
            clean_k = k.strip().strip('"\'')
            if clean_k == "__is_block__":
                continue
            if isinstance(v, list) and len(v) == 1:
                v = v[0]
            if isinstance(v, str):
                v = v.strip().strip('"\'')
            raw_locals[clean_k] = v

    resolved_locals: dict[str, Any] = {}
    remaining_locals = dict(raw_locals)

    max_passes = len(remaining_locals) + 5
    for _ in range(max_passes):
        if not remaining_locals:
            break
        made_progress = False

        for local_name in list(remaining_locals.keys()):
            val = remaining_locals[local_name]
            resolved_val = resolve_attribute(val, variable_values, resolved_locals)

            if not isinstance(resolved_val, Unresolved):
                if isinstance(resolved_val, str):
                    resolved_val = resolved_val.strip().strip('"\'')
                resolved_locals[local_name] = resolved_val
                del remaining_locals[local_name]
                made_progress = True

        if not made_progress:
            for local_name, val in remaining_locals.items():
                unres = resolve_attribute(val, variable_values, resolved_locals)
                if not isinstance(unres, Unresolved):
                    unres = Unresolved(
                        reason=f"Locals dependency chain unresolvable or circular for local.{local_name}"
                    )
                resolved_locals[local_name] = unres
            break

    return resolved_locals


def resolve_attribute(
    value: Any, variable_values: dict[str, Any], local_values: dict[str, Any]
) -> AttributeValue:
    """Attempts to resolve an Unresolved value or container using variable and local values."""
    if isinstance(value, list):
        return [resolve_attribute(item, variable_values, local_values) for item in value]

    if isinstance(value, dict):
        return {
            k: resolve_attribute(v, variable_values, local_values)
            for k, v in value.items()
        }

    expr: str | None = None
    if isinstance(value, Unresolved):
        m = re.search(r"'(.*)'", value.reason)
        if m:
            expr = m.group(1)
        else:
            expr = value.reason
    elif isinstance(value, str):
        expr = value
    else:
        return value

    if not expr:
        return value

    clean_expr = expr.strip().strip('"\'')

    # Check for apply-time / out-of-static-scope references
    m_data = re.search(r"\b(data\.[a-zA-Z0-9_\-\.]+)", clean_expr)
    if m_data:
        return Unresolved(
            reason=f"References {m_data.group(1)}, an apply-time data source — out of static resolution scope per §11",
            expression=clean_expr,
        )

    m_res = re.search(r"\b((?:aws_[a-zA-Z0-9_]+|[a-zA-Z0-9_]+_[a-zA-Z0-9_]+)\.[a-zA-Z0-9_\-\.\[\]\"]+)", clean_expr)
    if m_res:
        return Unresolved(
            reason=f"References {m_res.group(1)}, an apply-time resource attribute — out of static resolution scope per §11",
            expression=clean_expr,
        )


    m_dyn = re.search(r"\b((?:module|count|each)\.[a-zA-Z0-9_\-\.]+)", clean_expr)
    if m_dyn:
        return Unresolved(
            reason=f"References {m_dyn.group(1)}, dynamic/apply-time expression — out of static resolution scope per §11",
            expression=clean_expr,
        )


    # Check single var reference: e.g. var.foo or ${var.foo}
    m_var = re.fullmatch(r"\$\{?\s*var\.([a-zA-Z0-9_\-]+)\s*\}?", clean_expr)
    if m_var:
        var_name = m_var.group(1)
        if var_name in variable_values:
            val = variable_values[var_name]
            if isinstance(val, Unresolved):
                return val
            if isinstance(val, str):
                val = val.strip().strip('"\'')
            return val
        return Unresolved(
            reason=f"References undeclared variable var.{var_name} with no default or tfvars value"
        )

    # Check single local reference: e.g. local.foo or ${local.foo}
    m_local = re.fullmatch(r"\$\{?\s*local\.([a-zA-Z0-9_\-]+)\s*\}?", clean_expr)
    if m_local:
        local_name = m_local.group(1)
        if local_name in local_values:
            val = local_values[local_name]
            if isinstance(val, Unresolved):
                return val
            if isinstance(val, str):
                val = val.strip().strip('"\'')
            return val
        return Unresolved(
            reason=f"References undefined local variable local.{local_name}"
        )

    # Process inline string interpolations `${...}` or embedded references
    if "${" in clean_expr:

        def replace_interp(match: re.Match[str]) -> str:
            inner = match.group(1).strip()
            if inner.startswith("var."):
                vname = inner[4:]
                if vname in variable_values:
                    res_v = variable_values[vname]
                    if isinstance(res_v, Unresolved):
                        raise _UnresolvedError(res_v)
                    if isinstance(res_v, str):
                        res_v = res_v.strip().strip('"\'')
                    return str(res_v)
                raise _UnresolvedError(
                    Unresolved(
                        reason=f"References undeclared variable var.{vname} with no default or tfvars value"
                    )
                )
            if inner.startswith("local."):
                lname = inner[6:]
                if lname in local_values:
                    res_l = local_values[lname]
                    if isinstance(res_l, Unresolved):
                        raise _UnresolvedError(res_l)
                    if isinstance(res_l, str):
                        res_l = res_l.strip().strip('"\'')
                    return str(res_l)
                raise _UnresolvedError(
                    Unresolved(
                        reason=f"References undefined local variable local.{lname}"
                    )
                )
            if inner.startswith("data."):
                raise _UnresolvedError(
                    Unresolved(
                        reason=f"References {inner}, an apply-time data source — out of static resolution scope per §11"
                    )
                )
            if re.match(r"^aws_[a-zA-Z0-9_]+\.", inner):
                raise _UnresolvedError(
                    Unresolved(
                        reason=f"References {inner}, an apply-time resource attribute — out of static resolution scope per §11"
                    )
                )
            raise _UnresolvedError(
                Unresolved(reason=f"Unresolvable expression inside interpolation: '{inner}'")
            )

        try:
            resolved_str = re.sub(r"\$\{([^}]+)\}", replace_interp, clean_expr)
            return resolved_str
        except _UnresolvedError as err:
            return err.unresolved

    return value


def _resolve_rule_source(
    rule_source: RuleSource, variable_values: dict[str, Any], local_values: dict[str, Any]
) -> RuleSource:
    """Resolves any Unresolved attributes inside a RuleSource."""
    if isinstance(rule_source, SecurityGroupRule):
        return SecurityGroupRule(
            direction=rule_source.direction,
            protocol=rule_source.protocol,
            from_port=rule_source.from_port,
            to_port=rule_source.to_port,
            cidr_blocks=resolve_attribute(rule_source.cidr_blocks, variable_values, local_values),  # type: ignore
            referenced_security_group_id=resolve_attribute(rule_source.referenced_security_group_id, variable_values, local_values),  # type: ignore
        )
    if isinstance(rule_source, IamPolicyStatement):
        return IamPolicyStatement(
            effect=rule_source.effect,
            actions=resolve_attribute(rule_source.actions, variable_values, local_values),  # type: ignore
            resources=resolve_attribute(rule_source.resources, variable_values, local_values),  # type: ignore
            principal=resolve_attribute(rule_source.principal, variable_values, local_values),  # type: ignore
        )
    return rule_source


def build_graph_with_variables(
    parsed: dict[str, Any], repo_dir: str | Path | None = None
) -> ResourceGraph:
    """Builds a ResourceGraph from parsed HCL and performs a second pass resolving variables and locals."""
    graph = build_graph(parsed)

    variable_values: dict[str, Any] = {}
    if repo_dir is not None:
        variable_values = load_variable_values(repo_dir)

    local_values = load_local_values(parsed, variable_values)

    resolved_graph = ResourceGraph()
    for address, res in graph.resources.items():
        resolved_attributes: dict[str, AttributeValue] = {}
        for k, v in res.attributes.items():
            resolved_attributes[k] = resolve_attribute(v, variable_values, local_values)

        resolved_rule_sources: list[RuleSource] = []
        for rs in res.rule_sources:
            resolved_rule_sources.append(_resolve_rule_source(rs, variable_values, local_values))

        resolved_res = Resource(
            address=res.address,
            type=res.type,
            attributes=resolved_attributes,
            rule_sources=resolved_rule_sources,
        )
        resolved_graph.add_resource(resolved_res)

    return resolved_graph
