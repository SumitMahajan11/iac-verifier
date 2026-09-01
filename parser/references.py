from __future__ import annotations

from dataclasses import is_dataclass, replace
import re
from typing import Any

from parser.graph import (
    AttributeValue,
    Resource,
    ResourceGraph,
    ResourceReference,
    RuleSource,
    Unresolved,
)


def _extract_reference_candidates(expr_or_reason: str) -> list[tuple[str, str]]:
    """Extracts candidate (target_address, attribute) tuples from an Unresolved expression or reason string."""
    clean = expr_or_reason.strip()
    # Strip wrapping ${ ... }
    m_interp = re.search(r"\$\{?\s*([a-zA-Z0-9_\-\.\[\]\"]+)\s*\}?", clean)
    if m_interp:
        raw_expr = m_interp.group(1)
    else:
        # Fallback regex for "References <expr>, an apply-time..."
        m_reason = re.search(r"References\s+([a-zA-Z0-9_\-\.\[\]\"]+)", clean)
        if m_reason:
            raw_expr = m_reason.group(1)
        else:
            raw_expr = clean

    if "." not in raw_expr:
        return []

    parts = raw_expr.rsplit(".", 1)
    target_cand = parts[0].strip()
    attr = parts[1].strip()

    # Do not match data sources, vars, locals, or dynamic expressions
    if target_cand.startswith(("data.", "var.", "local.", "count.", "each.")):
        return []

    return [(target_cand, attr)]


def _try_resolve_unresolved(
    unres: Unresolved, current_res_address: str, graph: ResourceGraph
) -> AttributeValue:
    """Attempts to match an Unresolved instance to a ResourceReference target address in graph."""
    expr_text = unres.expression or unres.reason
    candidates = _extract_reference_candidates(expr_text)

    if not candidates:
        return unres

    # Determine current resource module prefix if any (e.g., 'module.foo.')
    mod_prefix = ""
    if current_res_address.startswith("module."):
        # Extract module prefix up to the resource type e.g., 'module.app_service["frontend"].'
        parts = current_res_address.split(".")
        # Find where resource type (e.g. aws_) starts
        for i, part in enumerate(parts):
            if part.startswith("aws_") or i >= len(parts) - 2:
                mod_prefix = ".".join(parts[:i]) + "."
                break

    for target_cand, attr in candidates:
        # 1. Exact match
        if target_cand in graph.resources:
            return ResourceReference(target_address=target_cand, attribute=attr)

        # 2. Module-scoped match
        if mod_prefix:
            scoped_target = f"{mod_prefix}{target_cand}"
            if scoped_target in graph.resources:
                return ResourceReference(target_address=scoped_target, attribute=attr)

    return unres


def _resolve_value_references(
    val: Any, current_res_address: str, graph: ResourceGraph
) -> Any:
    """Recursively replaces matching Unresolved instances with ResourceReference objects."""
    if isinstance(val, Unresolved):
        return _try_resolve_unresolved(val, current_res_address, graph)

    if isinstance(val, list):
        return [
            _resolve_value_references(item, current_res_address, graph)
            for item in val
        ]

    if isinstance(val, dict):
        return {
            k: _resolve_value_references(v, current_res_address, graph)
            for k, v in val.items()
        }

    if is_dataclass(val) and not isinstance(
        val, (Unresolved, ResourceReference)
    ):
        changes = {}
        for field_name in val.__dataclass_fields__:
            field_val = getattr(val, field_name)
            new_val = _resolve_value_references(
                field_val, current_res_address, graph
            )
            if new_val is not field_val:
                changes[field_name] = new_val
        if changes:
            return replace(val, **changes)

    return val


def resolve_resource_references(graph: ResourceGraph) -> ResourceGraph:
    """Scans every resource's attributes and rule sources for Unresolved values.

    Replaces Unresolved values pointing to existing graph resources with ResourceReference(target_address, attribute).
    """
    for address, res in graph.resources.items():
        new_attributes = _resolve_value_references(res.attributes, address, graph)
        new_rule_sources = _resolve_value_references(res.rule_sources, address, graph)

        res.attributes = new_attributes
        res.rule_sources = new_rule_sources

    return graph
