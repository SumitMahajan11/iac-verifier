"""
tests/test_arm_parser.py

Comprehensive unit and integration test suite for ARM JSON template parsing,
file-type dispatching, cross-format (HCL vs ARM) equivalence, and downstream SMT engine verification.
"""

import json
from pathlib import Path
import pytest

from parser.arm_parser import parse_arm_dict, parse_arm_file
from parser import parse_iac_file
from parser.graph import ResourceGraph, Unresolved, AzureNsgRule
from graph.trust_graph import TrustGraph
from graph.azure_trust_graph import build_azure_trust_graph
from solver.engine import VerificationEngine
from cli.main import run_verify, run_repair


@pytest.fixture
def arm_nsg_vulnerable_json(tmp_path: Path) -> Path:
    data = {
        "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
        "contentVersion": "1.0.0.0",
        "parameters": {
            "adminPort": {
                "type": "string",
                "defaultValue": "22"
            }
        },
        "variables": {
            "nsgName": "nsg-open-ssh"
        },
        "resources": [
            {
                "type": "Microsoft.Network/networkSecurityGroups",
                "apiVersion": "2020-11-01",
                "name": "[variables('nsgName')]",
                "location": "eastus",
                "properties": {
                    "securityRules": [
                        {
                            "name": "Allow-SSH-Anywhere",
                            "properties": {
                                "priority": 100,
                                "direction": "Inbound",
                                "access": "Allow",
                                "protocol": "Tcp",
                                "sourcePortRange": "*",
                                "destinationPortRange": "[parameters('adminPort')]",
                                "sourceAddressPrefix": "*",
                                "destinationAddressPrefix": "*"
                            }
                        }
                    ]
                }
            }
        ]
    }
    p = tmp_path / "vulnerable_nsg.json"
    p.write_text(json.dumps(data, indent=2), encoding="utf-8")
    return p


@pytest.fixture
def arm_nsg_safe_json(tmp_path: Path) -> Path:
    data = {
        "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
        "contentVersion": "1.0.0.0",
        "resources": [
            {
                "type": "Microsoft.Network/networkSecurityGroups",
                "apiVersion": "2020-11-01",
                "name": "nsg-restricted-ssh",
                "location": "eastus",
                "properties": {
                    "securityRules": [
                        {
                            "name": "Allow-SSH-Restricted",
                            "properties": {
                                "priority": 100,
                                "direction": "Inbound",
                                "access": "Allow",
                                "protocol": "Tcp",
                                "sourcePortRange": "*",
                                "destinationPortRange": "22",
                                "sourceAddressPrefix": "10.0.0.0/24",
                                "destinationAddressPrefix": "*"
                            }
                        }
                    ]
                }
            }
        ]
    }
    p = tmp_path / "safe_nsg.json"
    p.write_text(json.dumps(data, indent=2), encoding="utf-8")
    return p


@pytest.fixture
def hcl_nsg_vulnerable_tf(tmp_path: Path) -> Path:
    content = """
resource "azurerm_network_security_group" "nsg_open_ssh" {
  name                = "nsg-open-ssh"
  location            = "eastus"
  resource_group_name = "rg1"

  security_rule {
    name                       = "Allow-SSH-Anywhere"
    priority                   = 100
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "22"
    source_address_prefix      = "*"
    destination_address_prefix = "*"
  }
}
"""
    p = tmp_path / "vulnerable_nsg.tf"
    p.write_text(content, encoding="utf-8")
    return p


def test_arm_nsg_vulnerable_verification(arm_nsg_vulnerable_json: Path):
    graph = parse_arm_file(arm_nsg_vulnerable_json)
    assert "azurerm_network_security_group.nsg_open_ssh" in graph.resources

    res = graph.resources["azurerm_network_security_group.nsg_open_ssh"]
    assert len(res.rule_sources) == 1
    rule = res.rule_sources[0]
    assert isinstance(rule, AzureNsgRule)
    assert rule.name == "Allow-SSH-Anywhere"
    assert rule.destination_port_range == "22"

    engine = VerificationEngine()
    results = engine.verify_graph(graph)
    assert len(results) == 1
    eval_res = results[0]
    assert eval_res.status == "SAT"
    assert eval_res.witness is not None
    assert "sensitive_ports" in eval_res.witness


def test_arm_nsg_safe_verification(arm_nsg_safe_json: Path):
    graph = parse_arm_file(arm_nsg_safe_json)
    engine = VerificationEngine()
    results = engine.verify_graph(graph)
    assert len(results) == 1
    assert results[0].status == "UNSAT"


def test_cross_format_nsg_equivalence(arm_nsg_vulnerable_json: Path, hcl_nsg_vulnerable_tf: Path):
    arm_graph = parse_arm_file(arm_nsg_vulnerable_json)
    hcl_graph = parse_iac_file(hcl_nsg_vulnerable_tf)

    engine = VerificationEngine()
    arm_results = engine.verify_graph(arm_graph)
    hcl_results = engine.verify_graph(hcl_graph)

    assert len(arm_results) == 1
    assert len(hcl_results) == 1
    assert arm_results[0].status == hcl_results[0].status == "SAT"
    assert arm_results[0].witness["sensitive_ports"] == hcl_results[0].witness["sensitive_ports"]


def test_cross_format_azure_rbac_equivalence(tmp_path: Path):
    arm_rbac_data = {
        "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
        "contentVersion": "1.0.0.0",
        "resources": [
            {
                "type": "Microsoft.ManagedIdentity/userAssignedIdentities",
                "name": "id1",
                "location": "eastus"
            },
            {
                "type": "Microsoft.Compute/virtualMachines",
                "name": "workload_vm",
                "location": "eastus",
                "identity": {
                    "type": "UserAssigned",
                    "userAssignedIdentities": {
                        "/subscriptions/sub1/resourceGroups/rg1/providers/Microsoft.ManagedIdentity/userAssignedIdentities/id1": {}
                    }
                },
                "properties": {
                    "resourceGroupName": "rg1"
                }
            },
            {
                "type": "Microsoft.Authorization/roleAssignments",
                "name": "assign_vm_control",
                "properties": {
                    "principalId": "ext-user-1234",
                    "roleDefinitionName": "Virtual Machine Contributor",
                    "scope": "/subscriptions/sub1/resourceGroups/rg1"
                }
            },
            {
                "type": "Microsoft.Authorization/roleAssignments",
                "name": "assign_owner",
                "properties": {
                    "principalId": "id1",
                    "roleDefinitionName": "Owner",
                    "scope": "/subscriptions/sub1"
                }
            }
        ]
    }

    hcl_rbac_content = """
resource "azurerm_user_assigned_identity" "id1" {
  name                = "id1"
  location            = "eastus"
  resource_group_name = "rg1"
}

resource "azurerm_linux_virtual_machine" "workload_vm" {
  name                = "workload_vm"
  location            = "eastus"
  resource_group_name = "rg1"

  identity {
    type         = "UserAssigned"
    identity_ids = ["azurerm_user_assigned_identity.id1.id"]
  }
}

resource "azurerm_role_assignment" "assign_vm_control" {
  scope                = "/subscriptions/sub1/resourceGroups/rg1"
  role_definition_name = "Virtual Machine Contributor"
  principal_id         = "ext-user-1234"
}

resource "azurerm_role_assignment" "assign_owner" {
  scope                = "/subscriptions/sub1"
  role_definition_name = "Owner"
  principal_id         = "id1"
}
"""

    arm_file = tmp_path / "rbac.json"
    arm_file.write_text(json.dumps(arm_rbac_data, indent=2), encoding="utf-8")

    hcl_file = tmp_path / "rbac.tf"
    hcl_file.write_text(hcl_rbac_content, encoding="utf-8")

    arm_graph = parse_arm_file(arm_file)
    hcl_graph = parse_iac_file(hcl_file)

    engine = VerificationEngine()
    arm_esc = engine.verify_privilege_escalation(arm_graph)
    hcl_esc = engine.verify_privilege_escalation(hcl_graph)

    assert arm_esc is not None and hcl_esc is not None
    print("ARM WITNESS:", arm_esc.witness)
    print("HCL WITNESS:", hcl_esc.witness)
    assert arm_esc.status == hcl_esc.status == "SAT"
    assert arm_esc.witness["entry_point"] == hcl_esc.witness["entry_point"] == "account:ext-user-1234"
    assert arm_esc.witness["target_resource"] == hcl_esc.witness["target_resource"] == "azurerm_user_assigned_identity.id1"


def test_arm_parser_param_var_resolution():
    arm_data = {
        "parameters": {
            "env": {
                "type": "string",
                "defaultValue": "prod"
            }
        },
        "variables": {
            "nsgName": "[concat(parameters('env'), '-nsg')]"
        },
        "resources": [
            {
                "type": "Microsoft.Network/networkSecurityGroups",
                "name": "[variables('nsgName')]",
                "location": "eastus"
            }
        ]
    }
    graph = parse_arm_dict(arm_data)
    assert "azurerm_network_security_group.prod_nsg" in graph.resources


def test_arm_parser_unresolved_fail_closed():
    arm_data = {
        "resources": [
            {
                "type": "Microsoft.Network/networkSecurityGroups",
                "name": "nsg-dynamic",
                "properties": {
                    "securityRules": [
                        {
                            "name": "rule-dynamic",
                            "properties": {
                                "priority": 100,
                                "direction": "Inbound",
                                "access": "Allow",
                                "protocol": "Tcp",
                                "sourceAddressPrefix": "[reference(resourceId('Microsoft.Network/publicIPAddresses', 'pip1')).ipAddress]",
                                "destinationAddressPrefix": "*"
                            }
                        }
                    ]
                }
            }
        ]
    }
    graph = parse_arm_dict(arm_data)
    unresolved_list = graph.unresolved_resources()
    assert len(unresolved_list) == 1

    engine = VerificationEngine()
    results = engine.verify_graph(graph)
    assert len(results) == 1
    assert results[0].status == "UNRESOLVABLE"


def test_arm_rbac_safe_verification(tmp_path: Path):
    arm_rbac_safe_data = {
        "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
        "contentVersion": "1.0.0.0",
        "resources": [
            {
                "type": "Microsoft.ManagedIdentity/userAssignedIdentities",
                "name": "id_safe",
                "location": "eastus"
            },
            {
                "type": "Microsoft.Authorization/roleAssignments",
                "name": "assign_reader_only",
                "properties": {
                    "principalId": "ext-user-read-only",
                    "roleDefinitionName": "Reader",
                    "scope": "/subscriptions/sub1/resourceGroups/rg1"
                }
            }
        ]
    }
    arm_file = tmp_path / "rbac_safe.json"
    arm_file.write_text(json.dumps(arm_rbac_safe_data, indent=2), encoding="utf-8")

    graph = parse_arm_file(arm_file)
    engine = VerificationEngine()
    esc_eval = engine.verify_privilege_escalation(graph)

    assert esc_eval is not None
    assert esc_eval.status == "UNSAT"


def test_arm_rbac_unresolved_param_verification(tmp_path: Path):
    arm_rbac_unresolved_data = {
        "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
        "contentVersion": "1.0.0.0",
        "parameters": {
            "dynamicPrincipal": {
                "type": "string"
                # No defaultValue provided
            }
        },
        "resources": [
            {
                "type": "Microsoft.ManagedIdentity/userAssignedIdentities",
                "name": "id_dynamic",
                "location": "eastus"
            },
            {
                "type": "Microsoft.Authorization/roleAssignments",
                "name": "assign_dynamic",
                "properties": {
                    "principalId": "[parameters('dynamicPrincipal')]",
                    "roleDefinitionName": "Owner",
                    "scope": "/subscriptions/sub1"
                }
            }
        ]
    }
    arm_file = tmp_path / "rbac_unresolved.json"
    arm_file.write_text(json.dumps(arm_rbac_unresolved_data, indent=2), encoding="utf-8")

    graph = parse_arm_file(arm_file)
    engine = VerificationEngine()
    esc_eval = engine.verify_privilege_escalation(graph)

    assert esc_eval is not None
    assert esc_eval.status == "UNRESOLVABLE"


def test_non_arm_json_fail_closed(tmp_path: Path):
    non_arm = tmp_path / "arbitrary_config.json"
    non_arm.write_text(json.dumps({"appSetting": "value", "debug": True}), encoding="utf-8")

    graph = parse_arm_file(non_arm)
    unresolved_list = graph.unresolved_resources()
    assert len(unresolved_list) == 1
    rule_src = unresolved_list[0].rule_sources[0]
    assert isinstance(rule_src, Unresolved)
    assert "JSON file is not a valid ARM deployment template" in rule_src.reason

    code = run_verify(str(non_arm), json_output=True)
    assert code == 2


def test_cli_verify_arm_json(arm_nsg_vulnerable_json: Path, arm_nsg_safe_json: Path):
    code_sat = run_verify(str(arm_nsg_vulnerable_json), json_output=True)
    assert code_sat == 1

    code_unsat = run_verify(str(arm_nsg_safe_json), json_output=True)
    assert code_unsat == 0


def test_cli_repair_arm_json_unsupported_guard(arm_nsg_vulnerable_json: Path):
    code_repair = run_repair(str(arm_nsg_vulnerable_json), "azurerm_network_security_group.nsg_open_ssh", "SG_OVER_EXPOSURE")
    assert code_repair == 2


def test_non_arm_json_structurally_invalid_resources_array(tmp_path: Path):
    k8s_manifest_list = tmp_path / "k8s_list.json"
    k8s_manifest_list.write_text(json.dumps({
        "apiVersion": "v1",
        "kind": "List",
        "resources": [
            {
                "apiVersion": "apps/v1",
                "kind": "Deployment",
                "metadata": {"name": "web"}
            }
        ]
    }), encoding="utf-8")

    graph = parse_arm_file(k8s_manifest_list)
    unresolved_list = graph.unresolved_resources()
    assert len(unresolved_list) == 1
    rule_src = unresolved_list[0].rule_sources[0]
    assert isinstance(rule_src, Unresolved)
    assert "JSON file contains a 'resources' array but no valid ARM 'Microsoft.*' resource definitions" in rule_src.reason

    code = run_verify(str(k8s_manifest_list), json_output=True)
    assert code == 2


def test_arm_rbac_unresolved_reference_function_verification(tmp_path: Path):
    arm_dynamic_ref_data = {
        "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
        "contentVersion": "1.0.0.0",
        "resources": [
            {
                "type": "Microsoft.Authorization/roleAssignments",
                "name": "assign_dynamic_ref",
                "properties": {
                    "principalId": "[reference(resourceId('Microsoft.ManagedIdentity/userAssignedIdentities', 'myId')).principalId]",
                    "roleDefinitionName": "Owner",
                    "scope": "/subscriptions/sub1"
                }
            }
        ]
    }
    arm_file = tmp_path / "rbac_dynamic_ref.json"
    arm_file.write_text(json.dumps(arm_dynamic_ref_data, indent=2), encoding="utf-8")

    graph = parse_arm_file(arm_file)
    engine = VerificationEngine()
    esc_eval = engine.verify_privilege_escalation(graph)

    assert esc_eval is not None
    assert esc_eval.status == "UNRESOLVABLE"
