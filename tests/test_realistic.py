from pathlib import Path
import pytest

from parser.graph import ExternalManagedPolicy, IamPolicyStatement, SecurityGroupRule, Unresolved
from parser.modules import build_graph_with_modules, parse_directory

REALISTIC_DIR = Path("fixtures/phase1/realistic")


def test_realistic_repo_a():
    repo_path = REALISTIC_DIR / "repo_a"
    parsed = parse_directory(repo_path)
    graph = build_graph_with_modules(parsed, repo_path)

    # 1. Total resources
    assert len(graph.resources) == 8

    # Check key resources
    assert "aws_security_group.web_sg" in graph.resources
    assert "aws_security_group_rule.http_ingress" in graph.resources
    assert "aws_security_group_rule.ssh_ingress" in graph.resources
    assert "aws_security_group_rule.custom_ingress" in graph.resources
    assert "aws_iam_role.app_role" in graph.resources
    assert "aws_iam_role_policy.custom_policy" in graph.resources
    assert "aws_iam_role_policy_attachment.managed_attach" in graph.resources
    assert "aws_instance.app_server" in graph.resources

    # 2. Verify N:1 rule source attached model with merged standalone rules
    web_sg = graph.resources["aws_security_group.web_sg"]
    assert len(web_sg.rule_sources) == 4
    assert isinstance(web_sg.rule_sources[0], SecurityGroupRule)
    assert web_sg.rule_sources[0].from_port == 443

    http_rule = graph.resources["aws_security_group_rule.http_ingress"]
    assert len(http_rule.rule_sources) == 1
    assert isinstance(http_rule.rule_sources[0], SecurityGroupRule)
    assert http_rule.rule_sources[0].from_port == 80
    assert http_rule.merged_into == "aws_security_group.web_sg"

    custom_rule = graph.resources["aws_security_group_rule.custom_ingress"]
    assert len(custom_rule.rule_sources) == 1
    assert isinstance(custom_rule.rule_sources[0], SecurityGroupRule)
    assert custom_rule.rule_sources[0].from_port == 8080
    assert custom_rule.merged_into == "aws_security_group.web_sg"
    assert custom_rule.attributes["security_group_id"] == "production-web-sg"

    app_role = graph.resources["aws_iam_role.app_role"]
    # 1 assume_role + 1 inline_policy + 1 custom_policy + 1 external managed_policy = 4 rule sources
    assert len(app_role.rule_sources) == 4
    assert isinstance(app_role.rule_sources[0], IamPolicyStatement)
    assert isinstance(app_role.rule_sources[1], IamPolicyStatement)
    assert isinstance(app_role.rule_sources[2], IamPolicyStatement)
    assert isinstance(app_role.rule_sources[3], ExternalManagedPolicy)

    custom_policy = graph.resources["aws_iam_role_policy.custom_policy"]
    assert len(custom_policy.rule_sources) == 1
    assert isinstance(custom_policy.rule_sources[0], IamPolicyStatement)
    assert custom_policy.merged_into == "aws_iam_role.app_role"

    managed_attach = graph.resources["aws_iam_role_policy_attachment.managed_attach"]
    assert managed_attach.merged_into == "aws_iam_role.app_role"


def test_realistic_repo_b():
    repo_path = REALISTIC_DIR / "repo_b"
    parsed = parse_directory(repo_path)
    graph = build_graph_with_modules(parsed, repo_path)

    # 2 module instances ("frontend", "backend") x 3 resources (1 SG + 2 instances) = 6 resources
    assert len(graph.resources) == 6
    assert len(graph.unresolved_resources()) == 0

    assert 'module.app_service["frontend"].aws_security_group.svc_sg' in graph.resources
    assert 'module.app_service["frontend"].aws_instance.server[0]' in graph.resources
    assert 'module.app_service["frontend"].aws_instance.server[1]' in graph.resources

    assert 'module.app_service["backend"].aws_security_group.svc_sg' in graph.resources
    assert 'module.app_service["backend"].aws_instance.server[0]' in graph.resources
    assert 'module.app_service["backend"].aws_instance.server[1]' in graph.resources

    frontend_node_0 = graph.resources['module.app_service["frontend"].aws_instance.server[0]']
    assert frontend_node_0.attributes["instance_type"] == "t3.micro"
    assert frontend_node_0.attributes["tags"] == {"Name": "frontend-node-0"}

    backend_node_1 = graph.resources['module.app_service["backend"].aws_instance.server[1]']
    assert backend_node_1.attributes["instance_type"] == "t3.small"
    assert backend_node_1.attributes["tags"] == {"Name": "backend-node-1"}


def test_realistic_repo_c():
    repo_path = REALISTIC_DIR / "repo_c"
    parsed = parse_directory(repo_path)
    graph = build_graph_with_modules(parsed, repo_path)

    # Total resources: 3
    assert len(graph.resources) == 3
    assert "aws_security_group.db_sg" in graph.resources
    assert "aws_security_group_rule.db_ingress" in graph.resources
    assert "aws_db_instance.db" in graph.resources

    # Unresolved resources count is 2 (db_sg via merged rule source, and db_ingress via attribute/rule_source)
    unresolved = graph.unresolved_resources()
    unresolved_addrs = {r.address for r in unresolved}
    assert unresolved_addrs == {"aws_security_group.db_sg", "aws_security_group_rule.db_ingress"}

    # Resolved static resources in repo_c
    db_sg = graph.resources["aws_security_group.db_sg"]
    assert db_sg.attributes["name"] == "analytics-staging-sg"
    assert db_sg.attributes["vpc_id"] == "vpc-tfvars123"

    db_inst = graph.resources["aws_db_instance.db"]
    assert db_inst.attributes["identifier"] == "analytics-staging"
    assert db_inst.attributes["engine"] == "postgres"
