from pathlib import Path
from parser.hcl_parser import parse_file, build_graph
from parser.graph import IamPolicyStatement, Unresolved

FIXTURES_DIR = Path(__file__).parent.parent / "fixtures" / "phase1" / "literal" / "jsonencode"


def test_multi_statement_fixture():
    path = str(FIXTURES_DIR / "multi_statement.tf")
    parsed = parse_file(path)
    graph = build_graph(parsed)

    policy_res = graph.resources["aws_iam_policy.multi_stmt"]
    assert len(policy_res.rule_sources) == 3

    stmt1, stmt2, stmt3 = policy_res.rule_sources
    assert isinstance(stmt1, IamPolicyStatement)
    assert stmt1.effect == "Allow"
    assert stmt1.actions == ["s3:GetObject"]
    assert stmt1.resources == ["arn:aws:s3:::my-bucket/*"]

    assert isinstance(stmt2, IamPolicyStatement)
    assert stmt2.effect == "Deny"
    assert stmt2.actions == ["s3:DeleteBucket"]
    assert stmt2.resources == ["arn:aws:s3:::my-bucket"]

    assert isinstance(stmt3, IamPolicyStatement)
    assert stmt3.effect == "Allow"
    assert stmt3.actions == ["sqs:SendMessage", "sqs:ReceiveMessage"]
    assert stmt3.resources == ["arn:aws:sqs:us-east-1:123456789012:my-queue"]


def test_single_statement_bare_object_fixture():
    path = str(FIXTURES_DIR / "single_statement_bare_object.tf")
    parsed = parse_file(path)
    graph = build_graph(parsed)

    policy_res = graph.resources["aws_iam_policy.bare_object"]
    assert len(policy_res.rule_sources) == 1

    stmt = policy_res.rule_sources[0]
    assert isinstance(stmt, IamPolicyStatement)
    assert stmt.effect == "Allow"
    assert stmt.actions == ["s3:ListBucket"]
    assert stmt.resources == ["arn:aws:s3:::my-bucket"]


def test_action_resource_normalization_fixture():
    path = str(FIXTURES_DIR / "action_resource_normalization.tf")
    parsed = parse_file(path)
    graph = build_graph(parsed)

    policy_res = graph.resources["aws_iam_policy.normalization"]
    assert len(policy_res.rule_sources) == 2

    stmt1, stmt2 = policy_res.rule_sources
    assert isinstance(stmt1, IamPolicyStatement)
    assert stmt1.actions == ["s3:GetObject"]
    assert stmt1.resources == ["arn:aws:s3:::my-bucket/*"]

    assert isinstance(stmt2, IamPolicyStatement)
    assert stmt2.actions == ["s3:GetObject", "s3:PutObject"]
    assert stmt2.resources == ["arn:aws:s3:::my-bucket/*", "arn:aws:s3:::my-bucket2/*"]


def test_unparseable_statement_fixture():
    path = str(FIXTURES_DIR / "unparseable_statement.tf")
    parsed = parse_file(path)
    graph = build_graph(parsed)

    policy_res = graph.resources["aws_iam_policy.unparseable"]
    assert len(policy_res.rule_sources) == 1

    rule_source = policy_res.rule_sources[0]
    assert isinstance(rule_source, Unresolved)
    assert "Contains unresolved reference inside jsonencode" in rule_source.reason
