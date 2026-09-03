from pathlib import Path
import pytest

from parser.graph import Resource, ResourceGraph, Unresolved
from parser.modules import (
    build_graph_with_modules,
    find_module_blocks,
    inline_module,
    merge_into_parent,
    parse_directory,
)

FIXTURES_DIR = Path("fixtures/phase1/modules")


def format_graph_summary(graph: ResourceGraph) -> str:
    """Helper to produce a clean printed summary of a ResourceGraph."""
    lines = [f"ResourceGraph ({len(graph.resources)} resources):"]
    for address, res in graph.resources.items():
        lines.append(f"  - Resource: {address} (Type: {res.type})")
        lines.append(f"    Attributes ({len(res.attributes)}):")
        for k, v in res.attributes.items():
            lines.append(f"      {k}: {v!r}")
        lines.append(f"    RuleSources ({len(res.rule_sources)}):")
        for rs in res.rule_sources:
            lines.append(f"      {rs}")
    return "\n".join(lines)


def test_find_module_blocks():
    parsed = {
        "module": [
            {
                "local_mod": {
                    "source": "./modules/local",
                    "vpc_cidr": "10.0.0.0/16",
                }
            },
            {
                "remote_mod": {
                    "source": "terraform-aws-modules/vpc/aws",
                    "version": "3.14.0",
                }
            },
        ]
    }
    blocks = find_module_blocks(parsed)
    assert len(blocks) == 2

    assert blocks[0]["name"] == "local_mod"
    assert blocks[0]["is_local"] is True
    assert blocks[0]["inputs"]["vpc_cidr"] == "10.0.0.0/16"
    assert blocks[0]["out_of_scope_reason"] is None

    assert blocks[1]["name"] == "remote_mod"
    assert blocks[1]["is_local"] is False
    assert "Non-local module source" in blocks[1]["out_of_scope_reason"]


def test_merge_into_parent():
    parent = ResourceGraph()
    parent.add_resource(
        Resource(
            address="aws_instance.root_app",
            type="aws_instance",
            attributes={"name": "root"},
        )
    )

    child = ResourceGraph()
    child.add_resource(
        Resource(
            address="aws_security_group.web_sg",
            type="aws_security_group",
            attributes={"name": "web"},
        )
    )

    merged = merge_into_parent(parent, child, "networking")
    assert len(merged.resources) == 2
    assert "aws_instance.root_app" in merged.resources
    assert "module.networking.aws_security_group.web_sg" in merged.resources


def test_fixture_local_module():
    repo_dir = FIXTURES_DIR / "local_module"
    parsed = parse_directory(repo_dir)
    graph = build_graph_with_modules(parsed, repo_dir)

    summary = format_graph_summary(graph)
    print("\n--- Summary: local_module ---\n" + summary)

    assert len(graph.resources) == 3
    assert "aws_instance.app" in graph.resources
    assert "module.networking.aws_security_group.web_sg" in graph.resources
    assert "module.networking.aws_security_group_rule.web_ingress" in graph.resources

    # Verify input variable pass-through from root
    rule_res = graph.resources["module.networking.aws_security_group_rule.web_ingress"]
    assert rule_res.attributes["cidr_blocks"] == ["10.0.0.0/16"] or rule_res.attributes["cidr_blocks"] == "10.0.0.0/16"


def test_fixture_nested_module():
    repo_dir = FIXTURES_DIR / "nested_module"
    parsed = parse_directory(repo_dir)
    graph = build_graph_with_modules(parsed, repo_dir)

    summary = format_graph_summary(graph)
    print("\n--- Summary: nested_module ---\n" + summary)

    assert len(graph.resources) == 3
    assert "aws_instance.root_app" in graph.resources
    assert "module.parent_mod.aws_security_group.parent_sg" in graph.resources
    assert "module.parent_mod.module.child_mod" in graph.resources

    nested_res = graph.resources["module.parent_mod.module.child_mod"]
    assert nested_res.type == "module"
    assert isinstance(nested_res.attributes["status"], Unresolved)
    assert "Nested module 'module.child_mod' is out of scope" in nested_res.attributes["status"].reason


def test_remote_module_out_of_scope():
    mod_block = {
        "name": "remote_vpc",
        "source": "terraform-aws-modules/vpc/aws",
        "is_local": False,
        "inputs": {},
        "out_of_scope_reason": "Non-local module source 'terraform-aws-modules/vpc/aws' is out of static analysis scope per §11",
    }

    graph = inline_module(mod_block, FIXTURES_DIR)
    assert len(graph.resources) == 1
    assert "module.remote_vpc" in graph.resources

    res = graph.resources["module.remote_vpc"]
    assert isinstance(res.attributes["status"], Unresolved)
    assert "Non-local module source" in res.attributes["status"].reason
