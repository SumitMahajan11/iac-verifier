from parser.attachments import resolve_rule_attachments
from parser.graph import (
    ExternalManagedPolicy,
    IamPolicyStatement,
    Resource,
    ResourceGraph,
    ResourceReference,
    SecurityGroupRule,
)


def test_tier_a_security_group_rule_merge():
    graph = ResourceGraph()
    sg = Resource(address="aws_security_group.web_sg", type="aws_security_group")
    rule = Resource(
        address="aws_security_group_rule.http",
        type="aws_security_group_rule",
        attributes={
            "security_group_id": ResourceReference(
                target_address="aws_security_group.web_sg", attribute="id"
            )
        },
        rule_sources=[
            SecurityGroupRule(
                direction="ingress",
                protocol="tcp",
                from_port=80,
                to_port=80,
                cidr_blocks=["0.0.0.0/0"],
            )
        ],
    )
    graph.add_resource(sg)
    graph.add_resource(rule)

    resolve_rule_attachments(graph)

    target = graph.resources["aws_security_group.web_sg"]
    rule_res = graph.resources["aws_security_group_rule.http"]
    assert len(target.rule_sources) == 1
    assert rule_res.merged_into == "aws_security_group.web_sg"


def test_tier_a_iam_role_policy_merge():
    graph = ResourceGraph()
    role = Resource(
        address="aws_iam_role.app_role",
        type="aws_iam_role",
        attributes={"name": "my-role"},
    )
    policy = Resource(
        address="aws_iam_role_policy.custom",
        type="aws_iam_role_policy",
        attributes={
            "role": ResourceReference(
                target_address="aws_iam_role.app_role", attribute="id"
            )
        },
        rule_sources=[
            IamPolicyStatement(
                effect="Allow",
                actions=["s3:GetObject"],
                resources=["arn:aws:s3:::bucket/*"],
            )
        ],
    )
    graph.add_resource(role)
    graph.add_resource(policy)

    resolve_rule_attachments(graph)

    target_role = graph.resources["aws_iam_role.app_role"]
    assert len(target_role.rule_sources) == 1
    assert policy.merged_into == "aws_iam_role.app_role"


def test_external_managed_policy_attachment():
    graph = ResourceGraph()
    role = Resource(
        address="aws_iam_role.app_role",
        type="aws_iam_role",
        attributes={"name": "my-role"},
    )
    attach = Resource(
        address="aws_iam_role_policy_attachment.managed",
        type="aws_iam_role_policy_attachment",
        attributes={
            "role": ResourceReference(
                target_address="aws_iam_role.app_role", attribute="name"
            ),
            "policy_arn": "arn:aws:iam::aws:policy/ReadOnlyAccess",
        },
    )
    graph.add_resource(role)
    graph.add_resource(attach)

    resolve_rule_attachments(graph)

    target_role = graph.resources["aws_iam_role.app_role"]
    assert len(target_role.rule_sources) == 1
    assert isinstance(target_role.rule_sources[0], ExternalManagedPolicy)
    assert (
        target_role.rule_sources[0].policy_arn == "arn:aws:iam::aws:policy/ReadOnlyAccess"
    )
    assert attach.merged_into == "aws_iam_role.app_role"


def test_tier_b_literal_match_merge():
    graph = ResourceGraph()
    role = Resource(
        address="aws_iam_role.unique_role",
        type="aws_iam_role",
        attributes={"name": "production-app-role"},
    )
    policy = Resource(
        address="aws_iam_role_policy.sqs",
        type="aws_iam_role_policy",
        attributes={"role": "production-app-role"},
        rule_sources=[
            IamPolicyStatement(
                effect="Allow",
                actions=["sqs:SendMessage"],
                resources=["arn:aws:sqs:queue"],
            )
        ],
    )
    graph.add_resource(role)
    graph.add_resource(policy)

    resolve_rule_attachments(graph)

    target_role = graph.resources["aws_iam_role.unique_role"]
    assert len(target_role.rule_sources) == 1
    assert policy.merged_into == "aws_iam_role.unique_role"


def test_tier_b_ambiguity_refuses_to_merge(capsys):
    graph = ResourceGraph()
    sg1 = Resource(
        address="aws_security_group.sg1",
        type="aws_security_group",
        attributes={"name": "shared-web-sg"},
    )
    sg2 = Resource(
        address="aws_security_group.sg2",
        type="aws_security_group",
        attributes={"name": "shared-web-sg"},
    )
    rule = Resource(
        address="aws_security_group_rule.rule1",
        type="aws_security_group_rule",
        attributes={"security_group_id": "shared-web-sg"},
        rule_sources=[
            SecurityGroupRule(
                direction="ingress",
                protocol="tcp",
                from_port=80,
                to_port=80,
                cidr_blocks=["0.0.0.0/0"],
            )
        ],
    )
    graph.add_resource(sg1)
    graph.add_resource(sg2)
    graph.add_resource(rule)

    resolve_rule_attachments(graph)

    # Confirm rule was NOT merged into either candidate
    assert len(sg1.rule_sources) == 0
    assert len(sg2.rule_sources) == 0
    assert rule.merged_into is None

    # Confirm ambiguity logging
    captured = capsys.readouterr().out
    assert "Tier B Ambiguous" in captured
    assert "2 candidates found" in captured
