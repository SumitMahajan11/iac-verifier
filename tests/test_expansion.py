from pathlib import Path
import pytest

from parser.expansion import (
    build_graph_with_expansion,
    expand_count,
    expand_for_each,
)
from parser.graph import ResourceGraph, SecurityGroupRule, Unresolved
from parser.hcl_parser import parse_file

FIXTURES_DIR = Path("fixtures/phase1/expansion")


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


def test_expand_count_unit():
    resource_block = {
        "type": "aws_instance",
        "name": "vm",
        "attributes": {
            "count": 2,
            "ami": "ami-123",
            "name": "node-${count.index}",
        },
    }
    expanded = expand_count(resource_block, 2)
    assert len(expanded) == 2
    assert expanded[0]["name"] == "vm[0]"
    assert expanded[0]["attributes"]["name"] == "node-0"
    assert "count" not in expanded[0]["attributes"]

    assert expanded[1]["name"] == "vm[1]"
    assert expanded[1]["attributes"]["name"] == "node-1"


def test_expand_for_each_unit():
    resource_block = {
        "type": "aws_subnet",
        "name": "sub",
        "attributes": {
            "for_each": {"us-east-1a": "10.0.1.0/24", "us-east-1b": "10.0.2.0/24"},
            "cidr_block": "${each.value}",
            "availability_zone": "${each.key}",
        },
    }
    for_each_val = {"us-east-1a": "10.0.1.0/24", "us-east-1b": "10.0.2.0/24"}
    expanded = expand_for_each(resource_block, for_each_val)

    assert len(expanded) == 2
    assert expanded[0]["name"] == 'sub["us-east-1a"]'
    assert expanded[0]["attributes"]["cidr_block"] == "10.0.1.0/24"
    assert expanded[0]["attributes"]["availability_zone"] == "us-east-1a"
    assert "for_each" not in expanded[0]["attributes"]


def test_fixture_count_literal():
    repo_dir = FIXTURES_DIR / "count_literal"
    parsed = parse_file(repo_dir / "main.tf")
    graph = build_graph_with_expansion(parsed, repo_dir)

    summary = format_graph_summary(graph)
    print("\n--- Summary: count_literal ---\n" + summary)

    assert len(graph.resources) == 2
    assert "aws_instance.web[0]" in graph.resources
    assert "aws_instance.web[1]" in graph.resources

    res0 = graph.resources["aws_instance.web[0]"]
    assert res0.attributes["tags"] == {"Name": "web-server-0"}

    res1 = graph.resources["aws_instance.web[1]"]
    assert res1.attributes["tags"] == {"Name": "web-server-1"}


def test_fixture_count_variable():
    repo_dir = FIXTURES_DIR / "count_variable"
    parsed = parse_file(repo_dir / "main.tf")
    graph = build_graph_with_expansion(parsed, repo_dir)

    summary = format_graph_summary(graph)
    print("\n--- Summary: count_variable ---\n" + summary)

    assert len(graph.resources) == 3
    assert "aws_instance.server[0]" in graph.resources
    assert "aws_instance.server[1]" in graph.resources
    assert "aws_instance.server[2]" in graph.resources

    assert graph.resources["aws_instance.server[0]"].attributes["tags"] == {"Name": "server-0"}
    assert graph.resources["aws_instance.server[1]"].attributes["tags"] == {"Name": "server-1"}
    assert graph.resources["aws_instance.server[2]"].attributes["tags"] == {"Name": "server-2"}


def test_fixture_for_each_map():
    repo_dir = FIXTURES_DIR / "for_each_map"
    parsed = parse_file(repo_dir / "main.tf")
    graph = build_graph_with_expansion(parsed, repo_dir)

    summary = format_graph_summary(graph)
    print("\n--- Summary: for_each_map ---\n" + summary)

    assert len(graph.resources) == 4
    assert "aws_security_group.web_sg" in graph.resources
    assert 'aws_security_group_rule.ingress_rules["http"]' in graph.resources
    assert 'aws_security_group_rule.ingress_rules["https"]' in graph.resources
    assert 'aws_security_group_rule.ingress_rules["ssh"]' in graph.resources

    http_rule = graph.resources['aws_security_group_rule.ingress_rules["http"]']
    assert http_rule.attributes["from_port"] == 80
    assert http_rule.attributes["to_port"] == 80
    assert http_rule.attributes["description"] == "Allow http"

    ssh_rule = graph.resources['aws_security_group_rule.ingress_rules["ssh"]']
    assert ssh_rule.attributes["from_port"] == 22
    assert ssh_rule.attributes["to_port"] == 22
    assert ssh_rule.attributes["description"] == "Allow ssh"


def test_fixture_unresolvable_for_each():
    repo_dir = FIXTURES_DIR / "unresolvable_for_each"
    parsed = parse_file(repo_dir / "main.tf")
    graph = build_graph_with_expansion(parsed, repo_dir)

    summary = format_graph_summary(graph)
    print("\n--- Summary: unresolvable_for_each ---\n" + summary)

    # Base address without [N] or ["key"] suffix
    assert len(graph.resources) == 1
    assert "aws_security_group_rule.data_rule" in graph.resources

    res = graph.resources["aws_security_group_rule.data_rule"]

    # All attributes must be Unresolved
    for k, v in res.attributes.items():
        assert isinstance(v, Unresolved)
        assert "for_each is unresolved" in v.reason
        assert "data.aws_vpc.selected.cidr_blocks" in v.reason

    # Rule sources must also be Unresolved
    rule = res.rule_sources[0]
    assert isinstance(rule, SecurityGroupRule)
    assert isinstance(rule.from_port, Unresolved)
    assert isinstance(rule.cidr_blocks[0], Unresolved)
