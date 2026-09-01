from parser.graph import (
    IamPolicyStatement,
    Resource,
    ResourceGraph,
    RuleSource,
    SecurityGroupRule,
    Unresolved,
)


def test_resource_multiple_rule_sources():
    """Validates that a Resource can hold multiple rule sources (N:1 cardinality)."""
    sg_rule1 = SecurityGroupRule(
        direction="ingress",
        protocol="tcp",
        from_port=80,
        to_port=80,
        cidr_blocks=["0.0.0.0/0"],
    )
    sg_rule2 = SecurityGroupRule(
        direction="ingress",
        protocol="tcp",
        from_port=443,
        to_port=443,
        cidr_blocks=["0.0.0.0/0"],
    )
    sg_rule3 = SecurityGroupRule(
        direction="egress",
        protocol="-1",
        from_port=0,
        to_port=0,
        cidr_blocks=["0.0.0.0/0"],
    )

    resource = Resource(
        address="aws_security_group.web",
        type="aws_security_group",
        attributes={"name": "web-sg"},
        rule_sources=[sg_rule1, sg_rule2, sg_rule3],
    )

    assert len(resource.rule_sources) == 3
    assert resource.rule_sources[0] == sg_rule1
    assert resource.rule_sources[1] == sg_rule2
    assert resource.rule_sources[2] == sg_rule3
    assert isinstance(resource.rule_sources[0], RuleSource)


def test_resource_iam_and_sg_rule_sources():
    """Validates attaching mixed RuleSource types to a single resource."""
    policy1 = IamPolicyStatement(
        effect="Allow",
        actions=["s3:GetObject"],
        resources=["arn:aws:s3:::my-bucket/*"],
    )
    policy2 = IamPolicyStatement(
        effect="Deny",
        actions=["s3:PutObject"],
        resources=["arn:aws:s3:::my-bucket/*"],
    )

    resource = Resource(
        address="aws_iam_role.app_role",
        type="aws_iam_role",
        attributes={"name": "app-role"},
        rule_sources=[policy1, policy2],
    )

    assert len(resource.rule_sources) == 2
    assert resource.rule_sources[0].effect == "Allow"
    assert resource.rule_sources[1].effect == "Deny"


def test_unresolved_attribute_representation():
    """Validates explicit Unresolved attribute representation and distinction from empty values."""
    unresolved_val = Unresolved(reason="references var.vpc_cidr, not yet resolved")

    resource = Resource(
        address="aws_security_group_rule.ingress",
        type="aws_security_group_rule",
        attributes={
            "type": "ingress",
            "cidr_blocks": unresolved_val,
            "description": "",  # genuinely empty string
            "optional_tag": None,  # genuinely None
        },
    )

    assert isinstance(resource.attributes["cidr_blocks"], Unresolved)
    assert resource.attributes["cidr_blocks"].reason == "references var.vpc_cidr, not yet resolved"
    assert resource.attributes["description"] == ""
    assert resource.attributes["optional_tag"] is None
    assert not isinstance(resource.attributes["description"], Unresolved)
    assert not isinstance(resource.attributes["optional_tag"], Unresolved)


def test_resource_graph_unresolved_resources():
    """Validates ResourceGraph add_resource and unresolved_resources identification."""
    graph = ResourceGraph()

    resolved_res = Resource(
        address="aws_vpc.main",
        type="aws_vpc",
        attributes={"cidr_block": "10.0.0.0/16"},
    )

    unresolved_res = Resource(
        address="aws_instance.web",
        type="aws_instance",
        attributes={
            "ami": "ami-12345678",
            "subnet_id": Unresolved(reason="depends on aws_subnet.public.id apply-time value"),
        },
    )

    graph.add_resource(resolved_res)
    graph.add_resource(unresolved_res)

    assert len(graph.resources) == 2
    assert graph.resources["aws_vpc.main"] == resolved_res
    assert graph.resources["aws_instance.web"] == unresolved_res

    unresolved_list = graph.unresolved_resources()
    assert len(unresolved_list) == 1
    assert unresolved_list[0].address == "aws_instance.web"


def test_resource_graph_unresolved_in_rule_source():
    """Validates that unresolved_resources() identifies resources with Unresolved inside rule_sources."""
    graph = ResourceGraph()

    unres_sg_rule = SecurityGroupRule(
        direction="ingress",
        protocol="tcp",
        from_port=80,
        to_port=80,
        cidr_blocks=[Unresolved(reason="references apply-time data source")],
    )

    res = Resource(
        address="aws_security_group.web",
        type="aws_security_group",
        attributes={"name": "web-sg"},
        rule_sources=[unres_sg_rule],
    )

    graph.add_resource(res)

    unresolved_list = graph.unresolved_resources()
    assert len(unresolved_list) == 1
    assert unresolved_list[0].address == "aws_security_group.web"

