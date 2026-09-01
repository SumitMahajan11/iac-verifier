from pathlib import Path
import pytest

from parser.graph import IamPolicyStatement, ResourceGraph, SecurityGroupRule, Unresolved
from parser.hcl_parser import HclParseError, build_graph, parse_file

FIXTURE_DIR = Path("fixtures/phase1/literal")


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


def test_parse_sg_single_ingress():
    fixture_path = FIXTURE_DIR / "sg_single_ingress.tf"
    parsed = parse_file(fixture_path)
    graph = build_graph(parsed)

    summary = format_graph_summary(graph)
    print("\n--- Summary: sg_single_ingress.tf ---\n" + summary)

    assert len(graph.resources) == 1
    assert "aws_security_group.web_sg" in graph.resources

    res = graph.resources["aws_security_group.web_sg"]
    assert res.attributes["name"] == "web-server-sg"
    assert res.attributes["description"] == "Security group for web server"

    assert len(res.rule_sources) == 1
    rule = res.rule_sources[0]
    assert isinstance(rule, SecurityGroupRule)
    assert rule.direction == "ingress"
    assert rule.protocol == "tcp"
    assert rule.from_port == 80
    assert rule.to_port == 80
    assert rule.cidr_blocks == ["0.0.0.0/0"]


def test_parse_sg_multiple_rules():
    fixture_path = FIXTURE_DIR / "sg_multiple_rules.tf"
    parsed = parse_file(fixture_path)
    graph = build_graph(parsed)

    summary = format_graph_summary(graph)
    print("\n--- Summary: sg_multiple_rules.tf ---\n" + summary)

    assert len(graph.resources) == 1
    assert "aws_security_group.app_sg" in graph.resources

    res = graph.resources["aws_security_group.app_sg"]
    assert res.attributes["name"] == "app-server-sg"

    assert len(res.rule_sources) == 3
    ingress1 = res.rule_sources[0]
    ingress2 = res.rule_sources[1]
    egress1 = res.rule_sources[2]

    assert isinstance(ingress1, SecurityGroupRule)
    assert ingress1.direction == "ingress"
    assert ingress1.from_port == 80

    assert isinstance(ingress2, SecurityGroupRule)
    assert ingress2.direction == "ingress"
    assert ingress2.from_port == 443

    assert isinstance(egress1, SecurityGroupRule)
    assert egress1.direction == "egress"
    assert egress1.protocol == "-1"
    assert egress1.cidr_blocks == ["0.0.0.0/0"]


def test_parse_iam_role_policy():
    fixture_path = FIXTURE_DIR / "iam_role_policy.tf"
    parsed = parse_file(fixture_path)
    graph = build_graph(parsed)

    summary = format_graph_summary(graph)
    print("\n--- Summary: iam_role_policy.tf ---\n" + summary)

    assert len(graph.resources) == 3
    assert "aws_iam_role.app_role" in graph.resources
    assert "aws_iam_role_policy_attachment.app_attach" in graph.resources
    assert "aws_iam_role_policy.inline_app_policy" in graph.resources

    role_res = graph.resources["aws_iam_role.app_role"]
    assert role_res.attributes["name"] == "application-execution-role"
    assert len(role_res.rule_sources) == 1
    assume_stmt = role_res.rule_sources[0]
    assert isinstance(assume_stmt, IamPolicyStatement)
    assert assume_stmt.effect == "Allow"
    assert assume_stmt.actions == ["sts:AssumeRole"]

    attach_res = graph.resources["aws_iam_role_policy_attachment.app_attach"]
    assert attach_res.attributes["role"] == "application-execution-role"
    assert attach_res.attributes["policy_arn"] == "arn:aws:iam::aws:policy/ReadOnlyAccess"

    inline_res = graph.resources["aws_iam_role_policy.inline_app_policy"]
    assert inline_res.attributes["name"] == "inline-app-policy"
    assert len(inline_res.rule_sources) == 1
    inline_stmt = inline_res.rule_sources[0]
    assert isinstance(inline_stmt, IamPolicyStatement)
    assert inline_stmt.effect == "Allow"
    assert "s3:GetObject" in inline_stmt.actions


def test_parse_s3_bucket_policy():
    fixture_path = FIXTURE_DIR / "s3_bucket_policy.tf"
    parsed = parse_file(fixture_path)
    graph = build_graph(parsed)

    summary = format_graph_summary(graph)
    print("\n--- Summary: s3_bucket_policy.tf ---\n" + summary)

    assert len(graph.resources) == 2
    assert "aws_s3_bucket.logs_bucket" in graph.resources
    assert "aws_s3_bucket_policy.logs_policy" in graph.resources

    bucket_res = graph.resources["aws_s3_bucket.logs_bucket"]
    assert bucket_res.attributes["bucket"] == "my-corporate-logs-bucket"

    policy_res = graph.resources["aws_s3_bucket_policy.logs_policy"]
    assert policy_res.attributes["bucket"] == "my-corporate-logs-bucket"
    assert len(policy_res.rule_sources) == 1
    stmt = policy_res.rule_sources[0]
    assert isinstance(stmt, IamPolicyStatement)
    assert stmt.effect == "Allow"
    assert stmt.principal == "*"
    assert stmt.actions == ["s3:GetObject"]


def test_parse_unresolved_references():
    fixture_path = FIXTURE_DIR / "unresolved_refs.tf"
    parsed = parse_file(fixture_path)
    graph = build_graph(parsed)

    summary = format_graph_summary(graph)
    print("\n--- Summary: unresolved_refs.tf ---\n" + summary)

    assert len(graph.resources) == 1
    res = graph.resources["aws_security_group.unresolved_sg"]

    assert isinstance(res.attributes["vpc_id"], Unresolved)
    assert "var.vpc_id" in res.attributes["vpc_id"].reason

    assert isinstance(res.attributes["description"], Unresolved)
    assert "interpolation expression" in res.attributes["description"].reason

    unresolved_res_list = graph.unresolved_resources()
    assert len(unresolved_res_list) == 1
    assert unresolved_res_list[0].address == "aws_security_group.unresolved_sg"


def test_parse_sg_standalone_rule_clean_strings():
    fixture_path = FIXTURE_DIR / "sg_standalone_rule.tf"
    parsed = parse_file(fixture_path)
    graph = build_graph(parsed)

    summary = format_graph_summary(graph)
    print("\n--- Summary: sg_standalone_rule.tf ---\n" + summary)

    assert len(graph.resources) == 2
    assert "aws_security_group.inline_sg" in graph.resources
    assert "aws_security_group_rule.standalone_ingress" in graph.resources

    inline_sg = graph.resources["aws_security_group.inline_sg"]
    standalone_rule = graph.resources["aws_security_group_rule.standalone_ingress"]

    # Assert exact clean string equality (no embedded quotes) on inline rule
    assert len(inline_sg.rule_sources) == 1
    inline_rs = inline_sg.rule_sources[0]
    assert isinstance(inline_rs, SecurityGroupRule)
    assert inline_rs.direction == "ingress"
    assert inline_rs.protocol == "tcp"
    assert inline_rs.from_port == 443
    assert inline_rs.to_port == 443
    assert inline_rs.cidr_blocks == ["0.0.0.0/0"]

    # Assert exact clean string equality (no embedded quotes) on standalone rule
    assert len(standalone_rule.rule_sources) == 1
    standalone_rs = standalone_rule.rule_sources[0]
    assert isinstance(standalone_rs, SecurityGroupRule)
    assert standalone_rs.direction == "ingress"
    assert standalone_rs.protocol == "tcp"
    assert standalone_rs.from_port == 80
    assert standalone_rs.to_port == 80
    assert standalone_rs.cidr_blocks == ["10.0.0.0/16"]
    assert standalone_rs.referenced_security_group_id == "inline-web-sg"


def test_parse_file_errors(tmp_path):
    # Test missing file error
    with pytest.raises(HclParseError, match="HCL file not found"):
        parse_file(tmp_path / "non_existent.tf")

    # Test malformed syntax error
    bad_tf = tmp_path / "bad_syntax.tf"
    bad_tf.write_text("resource aws_security_group {{{", encoding="utf-8")

    with pytest.raises(HclParseError, match="Failed to parse HCL file"):
        parse_file(bad_tf)

