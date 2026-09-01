from parser.graph import (
    Resource,
    ResourceGraph,
    ResourceReference,
    Unresolved,
)
from parser.references import resolve_resource_references


def test_same_file_reference_resolution():
    graph = ResourceGraph()
    sg = Resource(address="aws_security_group.web_sg", type="aws_security_group")
    rule = Resource(
        address="aws_security_group_rule.http_ingress",
        type="aws_security_group_rule",
        attributes={
            "security_group_id": Unresolved(
                reason="References aws_security_group.web_sg.id, an apply-time attribute",
                expression="aws_security_group.web_sg.id",
            )
        },
    )
    graph.add_resource(sg)
    graph.add_resource(rule)

    resolve_resource_references(graph)

    res_ref = graph.resources["aws_security_group_rule.http_ingress"].attributes[
        "security_group_id"
    ]
    assert isinstance(res_ref, ResourceReference)
    assert res_ref.target_address == "aws_security_group.web_sg"
    assert res_ref.attribute == "id"


def test_cross_module_reference_resolution():
    graph = ResourceGraph()
    mod_sg = Resource(
        address='module.app_service["frontend"].aws_security_group.svc_sg',
        type="aws_security_group",
    )
    mod_rule = Resource(
        address='module.app_service["frontend"].aws_security_group_rule.r1',
        type="aws_security_group_rule",
        attributes={
            "security_group_id": Unresolved(
                reason="References aws_security_group.svc_sg.id",
                expression="aws_security_group.svc_sg.id",
            )
        },
    )
    graph.add_resource(mod_sg)
    graph.add_resource(mod_rule)

    resolve_resource_references(graph)

    res_ref = graph.resources[
        'module.app_service["frontend"].aws_security_group_rule.r1'
    ].attributes["security_group_id"]
    assert isinstance(res_ref, ResourceReference)
    assert (
        res_ref.target_address
        == 'module.app_service["frontend"].aws_security_group.svc_sg'
    )
    assert res_ref.attribute == "id"


def test_data_source_reference_remains_unresolved():
    graph = ResourceGraph()
    rule = Resource(
        address="aws_security_group_rule.r1",
        type="aws_security_group_rule",
        attributes={
            "cidr_blocks": [
                Unresolved(
                    reason="References data.aws_vpc.selected.cidr_block, an apply-time data source",
                    expression="${data.aws_vpc.selected.cidr_block}",
                )
            ]
        },
    )
    graph.add_resource(rule)

    resolve_resource_references(graph)

    unres = graph.resources["aws_security_group_rule.r1"].attributes["cidr_blocks"][0]
    assert isinstance(unres, Unresolved)
    assert "data.aws_vpc.selected.cidr_block" in unres.reason


def test_nonexistent_resource_remains_unresolved():
    graph = ResourceGraph()
    rule = Resource(
        address="aws_security_group_rule.r1",
        type="aws_security_group_rule",
        attributes={
            "security_group_id": Unresolved(
                reason="References aws_security_group.nonexistent.id",
                expression="aws_security_group.nonexistent.id",
            )
        },
    )
    graph.add_resource(rule)

    resolve_resource_references(graph)

    unres = graph.resources["aws_security_group_rule.r1"].attributes[
        "security_group_id"
    ]
    assert isinstance(unres, Unresolved)
