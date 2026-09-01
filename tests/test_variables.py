from pathlib import Path
import pytest

from parser.graph import ResourceGraph, SecurityGroupRule, Unresolved
from parser.hcl_parser import parse_file
from parser.variables import (
    build_graph_with_variables,
    load_local_values,
    load_variable_values,
    resolve_attribute,
)

FIXTURES_DIR = Path("fixtures/phase1/variables")


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


def test_load_variable_values():
    repo_dir = FIXTURES_DIR / "straightforward_vars"
    vars_dict = load_variable_values(repo_dir)

    assert vars_dict["vpc_id"] == "vpc-default123"
    # tfvars override
    assert vars_dict["vpc_cidr"] == "192.168.1.0/24"


def test_load_variable_values_omits_unconfigured_var(tmp_path):
    # Write a variable with no default
    tf_file = tmp_path / "variables.tf"
    tf_file.write_text('variable "missing_var" { type = string }', encoding="utf-8")

    vars_dict = load_variable_values(tmp_path)
    assert "missing_var" not in vars_dict


def test_load_local_values_chained():
    parsed = {
        "locals": [
            {
                "env": "${var.environment}",
                "prefix": '"${local.env}-app"',
                "cidr": "${var.cidr}",
            }
        ]
    }
    variable_values = {"environment": "prod", "cidr": "172.16.0.0/16"}
    local_values = load_local_values(parsed, variable_values)

    assert local_values["env"] == "prod"
    assert local_values["prefix"] == "prod-app"
    assert local_values["cidr"] == "172.16.0.0/16"


def test_load_local_values_circular():
    parsed = {
        "locals": [
            {
                "a": "${local.b}",
                "b": "${local.a}",
            }
        ]
    }
    local_values = load_local_values(parsed, {})
    assert isinstance(local_values["a"], Unresolved)
    assert isinstance(local_values["b"], Unresolved)


def test_fixture_straightforward_vars():
    repo_dir = FIXTURES_DIR / "straightforward_vars"
    parsed = parse_file(repo_dir / "main.tf")
    graph = build_graph_with_variables(parsed, repo_dir)

    summary = format_graph_summary(graph)
    print("\n--- Summary: straightforward_vars ---\n" + summary)

    assert len(graph.resources) == 1
    res = graph.resources["aws_security_group.web_sg"]

    # Verify literal values after resolution
    assert res.attributes["vpc_id"] == "vpc-default123"
    assert res.attributes["name"] == "web-sg"

    rule = res.rule_sources[0]
    assert isinstance(rule, SecurityGroupRule)
    assert rule.cidr_blocks == ["192.168.1.0/24"]


def test_fixture_chained_locals():
    repo_dir = FIXTURES_DIR / "chained_locals"
    parsed = parse_file(repo_dir / "main.tf")
    graph = build_graph_with_variables(parsed, repo_dir)

    summary = format_graph_summary(graph)
    print("\n--- Summary: chained_locals ---\n" + summary)

    assert len(graph.resources) == 1
    res = graph.resources["aws_security_group.app_sg"]

    # Verify literal values after resolution
    assert res.attributes["name"] == "prod-app-sg"
    assert res.attributes["description"] == "App SG in prod"

    rule = res.rule_sources[0]
    assert isinstance(rule, SecurityGroupRule)
    assert rule.cidr_blocks == ["172.16.0.0/16"]


def test_fixture_unresolvable_data():
    repo_dir = FIXTURES_DIR / "unresolvable_data"
    parsed = parse_file(repo_dir / "main.tf")
    graph = build_graph_with_variables(parsed, repo_dir)

    summary = format_graph_summary(graph)
    print("\n--- Summary: unresolvable_data ---\n" + summary)

    assert len(graph.resources) == 1
    res = graph.resources["aws_security_group.data_sg"]

    # Must STAY Unresolved with accurate reason
    vpc_id_val = res.attributes["vpc_id"]
    assert isinstance(vpc_id_val, Unresolved)
    assert "data.aws_vpc.selected.id" in vpc_id_val.reason
    assert "apply-time data source" in vpc_id_val.reason

    rule = res.rule_sources[0]
    assert isinstance(rule, SecurityGroupRule)
    cidr_val = rule.cidr_blocks[0]
    assert isinstance(cidr_val, Unresolved)
    assert "data.aws_vpc.selected.cidr_block" in cidr_val.reason
    assert "apply-time data source" in cidr_val.reason
