from __future__ import annotations

import copy
from pathlib import Path
from typing import Any

from parser.expansion import _substitute_in_value, build_graph_with_expansion
from parser.graph import Resource, ResourceGraph, Unresolved
from parser.hcl_parser import _clean_key, _process_attribute_value, parse_file
from parser.variables import (
    load_local_values,
    load_variable_values,
    resolve_attribute,
)


def parse_directory(dir_path: str | Path) -> dict[str, Any]:
    """Reads all .tf files in dir_path and merges their raw parsed HCL structures."""
    directory = Path(dir_path)
    merged: dict[str, Any] = {
        "variable": [],
        "resource": [],
        "locals": [],
        "module": [],
        "data": [],
    }

    if not directory.exists() or not directory.is_dir():
        return merged

    for file_path in sorted(directory.glob("*.tf")):
        try:
            parsed = parse_file(file_path)
            for k in ("variable", "resource", "locals", "module", "data"):
                if k in parsed and isinstance(parsed[k], list):
                    merged[k].extend(parsed[k])
        except Exception:
            continue

    return merged


def _expand_single_module_block(
    mod_name: str,
    block_contents: dict[str, Any],
    parent_var_values: dict[str, Any] | None = None,
    parent_local_values: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    """Helper to evaluate count/for_each on a module block and return one or more module block descriptors."""
    parent_vars = parent_var_values or {}
    parent_locals = parent_local_values or {}

    source_val = block_contents.get("source")
    if isinstance(source_val, list) and len(source_val) == 1:
        source_val = source_val[0]
    if source_val is not None:
        source_val = _clean_key(source_val)

    is_local = False
    out_of_scope_reason: str | None = None

    if isinstance(source_val, str) and (
        source_val.startswith("./") or source_val.startswith("../")
    ):
        is_local = True
    elif source_val is None:
        out_of_scope_reason = f"Module '{mod_name}' is missing source attribute"
    else:
        out_of_scope_reason = (
            f"Non-local module source '{source_val}' is out of static analysis scope per §11"
        )

    # 1. Handle count expansion if present
    if "count" in block_contents:
        raw_count = _process_attribute_value(block_contents["count"])
        count_val = resolve_attribute(raw_count, parent_vars, parent_locals)

        if isinstance(count_val, int) and count_val >= 0:
            expanded = []
            for i in range(count_val):
                sub_inputs = {}
                for k, v in block_contents.items():
                    clean_k = _clean_key(k)
                    if clean_k in ("source", "count", "for_each", "__is_block__"):
                        continue
                    sub_inputs[clean_k] = _substitute_in_value(v, {"count.index": i})
                expanded.append(
                    {
                        "name": f"{mod_name}[{i}]",
                        "source": source_val,
                        "is_local": is_local,
                        "inputs": sub_inputs,
                        "out_of_scope_reason": out_of_scope_reason,
                    }
                )
            return expanded
        elif isinstance(count_val, Unresolved):
            return [
                {
                    "name": mod_name,
                    "source": source_val,
                    "is_local": False,
                    "inputs": {},
                    "out_of_scope_reason": f"Module '{mod_name}' has unresolvable count: {count_val.reason}",
                }
            ]

    # 2. Handle for_each expansion if present
    if "for_each" in block_contents:
        raw_for_each = _process_attribute_value(block_contents["for_each"])
        for_each_val = resolve_attribute(raw_for_each, parent_vars, parent_locals)

        if isinstance(for_each_val, dict):
            expanded = []
            for k_key, v_val in for_each_val.items():
                clean_k = str(k_key).strip('"\'')
                sub_inputs = {}
                for k, v in block_contents.items():
                    clean_input_k = _clean_key(k)
                    if clean_input_k in ("source", "count", "for_each", "__is_block__"):
                        continue
                    sub_inputs[clean_input_k] = _substitute_in_value(
                        v, {"each.key": clean_k, "each.value": v_val}
                    )
                expanded.append(
                    {
                        "name": f'{mod_name}["{clean_k}"]',
                        "source": source_val,
                        "is_local": is_local,
                        "inputs": sub_inputs,
                        "out_of_scope_reason": out_of_scope_reason,
                    }
                )
            return expanded
        elif isinstance(for_each_val, list):
            expanded = []
            for item in for_each_val:
                clean_item = str(item).strip('"\'')
                sub_inputs = {}
                for k, v in block_contents.items():
                    clean_input_k = _clean_key(k)
                    if clean_input_k in ("source", "count", "for_each", "__is_block__"):
                        continue
                    sub_inputs[clean_input_k] = _substitute_in_value(
                        v, {"each.key": clean_item, "each.value": clean_item}
                    )
                expanded.append(
                    {
                        "name": f'{mod_name}["{clean_item}"]',
                        "source": source_val,
                        "is_local": is_local,
                        "inputs": sub_inputs,
                        "out_of_scope_reason": out_of_scope_reason,
                    }
                )
            return expanded

        elif isinstance(for_each_val, Unresolved):
            return [
                {
                    "name": mod_name,
                    "source": source_val,
                    "is_local": False,
                    "inputs": {},
                    "out_of_scope_reason": f"Module '{mod_name}' has unresolvable for_each: {for_each_val.reason}",
                }
            ]

    # 3. Standard un-expanded module block
    inputs: dict[str, Any] = {}
    for k, v in block_contents.items():
        clean_k = _clean_key(k)
        if clean_k in ("source", "count", "for_each", "__is_block__"):
            continue
        inputs[clean_k] = v

    return [
        {
            "name": mod_name,
            "source": source_val,
            "is_local": is_local,
            "inputs": inputs,
            "out_of_scope_reason": out_of_scope_reason,
        }
    ]


def find_module_blocks(
    parsed: dict[str, Any],
    parent_var_values: dict[str, Any] | None = None,
    parent_local_values: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    """Locates module blocks in parsed HCL structure, expanding count/for_each if present.

    Returns a list of module block descriptors:
      {
        "name": module_name,
        "source": source_str,
        "is_local": bool,
        "inputs": dict,
        "out_of_scope_reason": str | None,
      }
    """
    module_blocks: list[dict[str, Any]] = []
    modules = parsed.get("module", [])

    if not isinstance(modules, list):
        return module_blocks

    for mod_entry in modules:
        if not isinstance(mod_entry, dict):
            continue

        for mod_name_raw, block_contents in mod_entry.items():
            mod_name = _clean_key(mod_name_raw)
            if not isinstance(block_contents, dict):
                continue

            expanded_descriptors = _expand_single_module_block(
                mod_name, block_contents, parent_var_values, parent_local_values
            )
            module_blocks.extend(expanded_descriptors)

    return module_blocks


def merge_into_parent(
    parent: ResourceGraph, module_graph: ResourceGraph, module_name: str
) -> ResourceGraph:
    """Merges module_graph resources into parent graph, prefixing addresses with module.{module_name}."""
    for old_addr, res in module_graph.resources.items():
        if old_addr == f"module.{module_name}" or old_addr.startswith(f"module.{module_name}."):
            new_addr = old_addr
        else:
            new_addr = f"module.{module_name}.{old_addr}"

        new_res = Resource(
            address=new_addr,
            type=res.type,
            attributes=copy.deepcopy(res.attributes),
            rule_sources=copy.deepcopy(res.rule_sources),
        )
        parent.add_resource(new_res)
    return parent


def inline_module(
    module_block: dict[str, Any],
    repo_dir: str | Path,
    is_nested: bool = False,
    parent_var_values: dict[str, Any] | None = None,
    parent_local_values: dict[str, Any] | None = None,
) -> ResourceGraph:
    """Parses local module files and returns module resources as a standalone ResourceGraph."""
    mod_name = module_block.get("name", "unnamed")
    graph = ResourceGraph()

    if parent_var_values is None:
        parent_var_values = {}
    if parent_local_values is None:
        parent_local_values = {}

    # Requirement 4: Nested module limitation
    if is_nested:
        reason = f"Nested module 'module.{mod_name}' is out of scope for single-level expansion per §11"
        out_of_scope_res = Resource(
            address=f"module.{mod_name}",
            type="module",
            attributes={"status": Unresolved(reason=reason)},
            rule_sources=[],
        )
        graph.add_resource(out_of_scope_res)
        return graph

    # Non-local module source
    if not module_block.get("is_local"):
        reason = (
            module_block.get("out_of_scope_reason")
            or f"Module '{mod_name}' is out of scope"
        )
        out_of_scope_res = Resource(
            address=f"module.{mod_name}",
            type="module",
            attributes={"status": Unresolved(reason=reason)},
            rule_sources=[],
        )
        graph.add_resource(out_of_scope_res)
        return graph

    # Local module processing
    source_rel = module_block.get("source", "")
    module_dir = (Path(repo_dir) / source_rel).resolve()

    if not module_dir.exists() or not module_dir.is_dir():
        reason = f"Local module path '{source_rel}' does not exist at {module_dir}"
        out_of_scope_res = Resource(
            address=f"module.{mod_name}",
            type="module",
            attributes={"status": Unresolved(reason=reason)},
            rule_sources=[],
        )
        graph.add_resource(out_of_scope_res)
        return graph

    # Parse module directory .tf files
    module_parsed = parse_directory(module_dir)

    # 1. Module declared variables and defaults
    module_declared_vars = load_variable_values(module_dir)

    # 2. Resolve input arguments passed from parent module block
    raw_inputs = module_block.get("inputs", {})
    resolved_inputs: dict[str, Any] = {}
    for k, v in raw_inputs.items():
        proc_v = _process_attribute_value(v)
        resolved_inputs[k] = resolve_attribute(
            proc_v, parent_var_values, parent_local_values
        )

    # Merge declared defaults with input arguments passed from parent (inputs override defaults)
    module_var_values = {**module_declared_vars, **resolved_inputs}

    # Build graph of module resources using expansion pipeline
    module_graph = build_graph_with_expansion(
        module_parsed, module_dir, override_variable_values=module_var_values
    )

    # Check for nested module calls within the local module
    nested_module_blocks = find_module_blocks(
        module_parsed,
        parent_var_values=module_var_values,
        parent_local_values=load_local_values(module_parsed, module_var_values),
    )
    for nested_block in nested_module_blocks:
        nested_graph = inline_module(
            nested_block,
            module_dir,
            is_nested=True,
            parent_var_values=module_var_values,
            parent_local_values=load_local_values(module_parsed, module_var_values),
        )
        merge_into_parent(module_graph, nested_graph, nested_block["name"])

    return module_graph


from parser.attachments import resolve_rule_attachments
from parser.references import resolve_resource_references


def build_graph_with_modules(
    parsed: dict[str, Any], repo_dir: str | Path
) -> ResourceGraph:
    """Builds full ResourceGraph including variable resolution, expansion, module inlining, reference resolution, and attachment resolution."""
    root_var_values = load_variable_values(repo_dir)
    root_local_values = load_local_values(parsed, root_var_values)

    root_graph = build_graph_with_expansion(
        parsed, repo_dir, override_variable_values=root_var_values
    )

    module_blocks = find_module_blocks(
        parsed, parent_var_values=root_var_values, parent_local_values=root_local_values
    )
    for mod_block in module_blocks:
        mod_graph = inline_module(
            mod_block,
            repo_dir,
            is_nested=False,
            parent_var_values=root_var_values,
            parent_local_values=root_local_values,
        )
        merge_into_parent(root_graph, mod_graph, mod_block["name"])

    # Final pipeline passes (Prompt 1.7 Parts B & C)
    resolve_resource_references(root_graph)
    resolve_rule_attachments(root_graph)

    return root_graph

