"""
tests/test_coverage_expansion.py

Targeted coverage expansion tests for fail-closed security gating, unresolved value handling,
and scope/permission logic.
"""

from pathlib import Path
from parser.graph import (
    AzureNsgRule,
    IamPolicyStatement,
    Resource,
    ResourceGraph,
    ResourceReference,
    Unresolved,
)
from parser.attachments import resolve_rule_attachments
from parser.modules import find_module_blocks, inline_module
from parser.arm_parser import parse_arm_dict
from graph.azure_trust_graph import build_azure_trust_graph
from graph.trust_graph import TrustGraph
from solver.engine import VerificationEngine


def test_azure_trust_graph_unresolved_role_def():
    """Targets graph/azure_trust_graph.py lines 381-385:

    Unresolved role definition in role assignment adds to unresolvable_roles
    and causes privilege escalation verification to return UNRESOLVABLE.
    """
    graph = ResourceGraph()
    ra = Resource(
        address="azurerm_role_assignment.ra1",
        type="azurerm_role_assignment",
        attributes={
            "principal_id": "account:user1",
            "scope": "/subscriptions/sub-123",
            "role_definition_name": Unresolved(reason="dynamic role def"),
        },
    )
    graph.add_resource(ra)

    trust_graph = TrustGraph()
    build_azure_trust_graph(graph, trust_graph)

    assert "azurerm_role_assignment.ra1" in trust_graph.unresolvable_roles
    assert any("unresolved role definition" in r for r in trust_graph.unresolvable_reasons)

    engine = VerificationEngine(use_cache=False)
    res = engine.verify_privilege_escalation(graph)
    assert res.status == "UNRESOLVABLE"


def test_azure_trust_graph_azuread_group_str_principal():
    """Targets graph/azure_trust_graph.py lines 397-403:

    Role assignment using string principal ID matching an Azure AD group resource
    fails closed by flagging as unresolvable.
    """
    graph = ResourceGraph()
    grp = Resource(
        address="azuread_group.devs",
        type="azuread_group",
        attributes={"display_name": "Devs"},
    )
    ra = Resource(
        address="azurerm_role_assignment.ra1",
        type="azurerm_role_assignment",
        attributes={
            "principal_id": "azuread_group.devs",
            "scope": "/subscriptions/sub-123",
            "role_definition_name": "Owner",
        },
    )
    graph.add_resource(grp)
    graph.add_resource(ra)

    trust_graph = TrustGraph()
    build_azure_trust_graph(graph, trust_graph)

    assert "azurerm_role_assignment.ra1" in trust_graph.unresolvable_roles
    assert any("Active Directory group principal" in r for r in trust_graph.unresolvable_reasons)

    engine = VerificationEngine(use_cache=False)
    res = engine.verify_privilege_escalation(graph)
    assert res.status == "UNRESOLVABLE"


def test_verification_engine_unresolvable_target_not_in_nodes():
    """Targets solver/engine.py line 570:

    Explicit target_resource not present in trust graph nodes returns UNRESOLVABLE status.
    """
    graph = ResourceGraph()
    ra = Resource(
        address="azurerm_role_assignment.ra1",
        type="azurerm_role_assignment",
        attributes={
            "principal_id": "account:user1",
            "scope": "/subscriptions/sub-123",
            "role_definition_name": "Owner",
        },
    )
    graph.add_resource(ra)

    engine = VerificationEngine(use_cache=False)
    res = engine.verify_privilege_escalation(graph, target_resource="azurerm_user_assigned_identity.nonexistent")

    assert res.status == "UNRESOLVABLE"
    assert "not found in trust graph nodes" in res.message


def test_verification_engine_priv_esc_zero_role_nodes():
    """Targets solver/engine.py lines 615-623:

    Privilege escalation check with zero non-account role nodes returns UNSAT/UNSAT_BOUNDED.
    """
    graph = ResourceGraph()
    ra = Resource(
        address="azurerm_role_assignment.ra1",
        type="azurerm_role_assignment",
        attributes={
            "principal_id": "account:user1",
            "scope": "/subscriptions/sub-123",
            "role_definition_name": "Owner",
        },
    )
    graph.add_resource(ra)

    engine = VerificationEngine(use_cache=False)
    res = engine.verify_privilege_escalation(graph, target_resource="account:account:user1")
    assert res.status in ("UNSAT", "UNSAT_BOUNDED")
    assert "0 role nodes in graph" in res.message


def test_verification_engine_incremental_nsg(tmp_path):
    """Targets solver/engine.py lines 768-788:

    verify_incremental for NSG resources properly checks dependency invalidation.
    """
    file_a = tmp_path / "nsg.tf"
    file_a.write_text("resource azurerm_network_security_group nsg1 {}", encoding="utf-8")

    graph = ResourceGraph()
    nsg = Resource(
        address="azurerm_network_security_group.nsg1",
        type="azurerm_network_security_group",
        attributes={},
        rule_sources=[
            AzureNsgRule(
                name="AllowSSH",
                priority=100,
                direction="Inbound",
                access="Allow",
                protocol="Tcp",
                destination_port_range="22",
                source_address_prefix="*",
            )
        ],
        file_path=str(file_a),
    )
    graph.add_resource(nsg)

    engine = VerificationEngine(use_cache=True)
    results = engine.verify_incremental(graph, [str(file_a)])
    assert len(results) >= 1
    assert any(r.resource_address == "azurerm_network_security_group.nsg1" for r in results)


def test_attachments_azure_nsg_rule_tier_b_match():
    """Targets parser/attachments.py lines 100-113:

    azurerm_network_security_rule Tier B string match into azurerm_network_security_group.
    """
    graph = ResourceGraph()
    nsg = Resource(
        address="azurerm_network_security_group.sec_grp",
        type="azurerm_network_security_group",
        attributes={"name": "my-nsg"},
        rule_sources=[],
    )
    rule = Resource(
        address="azurerm_network_security_rule.rule1",
        type="azurerm_network_security_rule",
        attributes={"network_security_group_name": "my-nsg"},
        rule_sources=[
            AzureNsgRule(
                name="AllowHTTP",
                priority=100,
                direction="Inbound",
                access="Allow",
                protocol="Tcp",
                destination_port_range="80",
                source_address_prefix="*",
            )
        ],
    )
    graph.add_resource(nsg)
    graph.add_resource(rule)

    resolve_rule_attachments(graph)

    assert rule.merged_into == "azurerm_network_security_group.sec_grp"
    assert len(nsg.rule_sources) == 1


def test_attachments_aws_iam_role_policy_attachment_resource_reference():
    """Targets parser/attachments.py lines 177-184:

    aws_iam_role_policy_attachment with ResourceReference policy_arn merges rule_sources into target role.
    """
    graph = ResourceGraph()
    role = Resource(
        address="aws_iam_role.my_role",
        type="aws_iam_role",
        attributes={"name": "my_role"},
        rule_sources=[],
    )
    policy = Resource(
        address="aws_iam_policy.my_policy",
        type="aws_iam_policy",
        attributes={"name": "my_policy"},
        rule_sources=[
            IamPolicyStatement(
                effect="Allow",
                actions=["s3:*"],
                resources=["*"],
            )
        ],
    )
    att = Resource(
        address="aws_iam_role_policy_attachment.att1",
        type="aws_iam_role_policy_attachment",
        attributes={
            "role": ResourceReference("aws_iam_role.my_role", "name"),
            "policy_arn": ResourceReference("aws_iam_policy.my_policy", "arn"),
        },
    )
    graph.add_resource(role)
    graph.add_resource(policy)
    graph.add_resource(att)

    resolve_rule_attachments(graph)

    assert att.merged_into == "aws_iam_role.my_role"
    assert len(role.rule_sources) == 1


def test_modules_unresolved_count_and_list_for_each():
    """Targets parser/modules.py lines 97-106 and 135-156:

    Unresolved count and list for_each in module block expansion.
    """
    parsed_unresolved = {
        "module": [
            {
                "mod1": {
                    "source": "./modules/sub",
                    "count": Unresolved(reason="dynamic count"),
                }
            }
        ]
    }
    blocks = find_module_blocks(parsed_unresolved)
    assert len(blocks) == 1
    assert "unresolvable count" in blocks[0]["out_of_scope_reason"]

    parsed_list_for_each = {
        "module": [
            {
                "mod2": {
                    "source": "./modules/sub",
                    "for_each": ["us-east-1", "us-west-2"],
                }
            }
        ]
    }
    blocks_list = find_module_blocks(parsed_list_for_each)
    assert len(blocks_list) == 2
    assert blocks_list[0]["name"] == 'mod2["us-east-1"]'
    assert blocks_list[1]["name"] == 'mod2["us-west-2"]'


def test_modules_nonexistent_local_dir(tmp_path):
    """Targets parser/modules.py lines 295-303:

    inline_module with non-existent local module directory path.
    """
    mod_block = {
        "name": "missing_mod",
        "source": "./nonexistent_module_dir_12345",
        "is_local": True,
        "inputs": {},
    }
    graph = inline_module(mod_block, tmp_path)
    assert "module.missing_mod" in graph.resources
    status_attr = graph.resources["module.missing_mod"].attributes.get("status")
    assert isinstance(status_attr, Unresolved)
    assert "does not exist" in status_attr.reason


def test_arm_parser_undefined_param_and_copy_loop():
    """Targets parser/arm_parser.py lines 148-151 and 343-356:

    ARM parser handling of parameter without default value and resource with copy loop.
    """
    arm_data = {
        "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
        "parameters": {
            "noDefaultParam": {
                "type": "string"
            }
        },
        "resources": [
            {
                "type": "Microsoft.Network/networkSecurityGroups",
                "name": "[parameters('noDefaultParam')]",
                "location": "eastus",
                "copy": {
                    "name": "nsgloop",
                    "count": 3
                }
            }
        ]
    }
    graph = parse_arm_dict(arm_data)
    assert len(graph.resources) == 1
    res = list(graph.resources.values())[0]
    status_attr = res.attributes.get("status")
    assert isinstance(status_attr, Unresolved)
    assert "copy" in status_attr.reason
