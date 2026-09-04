"""
tests/test_azure_policy_encoder.py

Unit tests for AzurePolicyEncoder SMT logic and condition translation.
"""

import json
import pytest
import z3

from encoder.azure_policy_encoder import AzurePolicyEncoder, _resolve_attribute_val
from parser.graph import Resource, ResourceGraph, ResourceReference, Unresolved


def test_resolve_attribute_val():
    res = Resource(
        address="azurerm_storage_account.sa",
        type="azurerm_storage_account",
        attributes={
            "location": "eastus",
            "name": "sttest01",
            "public_network_access_enabled": False,
        },
    )

    assert _resolve_attribute_val(res, "location") == "eastus"
    assert _resolve_attribute_val(res, "type") == "azurerm_storage_account"
    assert _resolve_attribute_val(res, "name") == "sttest01"
    assert _resolve_attribute_val(res, "properties.publicNetworkAccessEnabled") is False
    assert _resolve_attribute_val(res, "nonexistent") is None


def test_encode_policy_condition_equals():
    encoder = AzurePolicyEncoder()
    res = Resource(
        address="azurerm_storage_account.sa",
        type="azurerm_storage_account",
        attributes={"location": "eastus"},
    )

    # location == eastus
    cond = {"field": "location", "equals": "eastus"}
    expr, _ = encoder.encode_policy_condition(cond, res)
    solver = z3.Solver()
    solver.add(expr)
    assert solver.check() == z3.sat

    # location == westeurope
    cond_diff = {"field": "location", "equals": "westeurope"}
    expr_diff, _ = encoder.encode_policy_condition(cond_diff, res)
    solver_diff = z3.Solver()
    solver_diff.add(expr_diff)
    assert solver_diff.check() == z3.unsat


def test_encode_policy_condition_in_notin():
    encoder = AzurePolicyEncoder()
    res = Resource(
        address="azurerm_storage_account.sa",
        type="azurerm_storage_account",
        attributes={"location": "eastus"},
    )

    # location notIn ["westeurope", "northeurope"]
    cond = {"field": "location", "notIn": ["westeurope", "northeurope"]}
    expr, _ = encoder.encode_policy_condition(cond, res)
    solver = z3.Solver()
    solver.add(expr)
    assert solver.check() == z3.sat

    # location in ["westeurope", "northeurope"]
    cond_in = {"field": "location", "in": ["westeurope", "northeurope"]}
    expr_in, _ = encoder.encode_policy_condition(cond_in, res)
    solver_in = z3.Solver()
    solver_in.add(expr_in)
    assert solver_in.check() == z3.unsat


def test_encode_policy_condition_allof_anyof_not():
    encoder = AzurePolicyEncoder()
    res = Resource(
        address="azurerm_network_security_rule.nsg_rule",
        type="azurerm_network_security_rule",
        attributes={
            "access": "Allow",
            "destination_port_range": "22",
            "source_address_prefix": "*",
        },
    )

    # allOf: access == Allow AND destination_port_range == 22 AND source_address_prefix == *
    cond = {
        "allOf": [
            {"field": "access", "equals": "Allow"},
            {"field": "destination_port_range", "equals": "22"},
            {"field": "source_address_prefix", "equals": "*"},
        ]
    }
    expr, _ = encoder.encode_policy_condition(cond, res)
    solver = z3.Solver()
    solver.add(expr)
    assert solver.check() == z3.sat


def test_encode_policy_violation_matching_scope():
    encoder = AzurePolicyEncoder()
    graph = ResourceGraph()

    policy_def = Resource(
        address="azurerm_policy_definition.deny_public_ip",
        type="azurerm_policy_definition",
        attributes={
            "policy_rule": json.dumps(
                {
                    "if": {"field": "location", "notIn": ["westeurope"]},
                    "then": {"effect": "Deny"},
                }
            )
        },
    )

    policy_assign = Resource(
        address="azurerm_policy_assignment.sub_assign",
        type="azurerm_policy_assignment",
        attributes={
            "scope": "/subscriptions/sub-12345",
            "policy_definition_id": "azurerm_policy_definition.deny_public_ip",
        },
    )

    target_res = Resource(
        address="azurerm_storage_account.sa",
        type="azurerm_storage_account",
        attributes={
            "scope": "/subscriptions/sub-12345/resourceGroups/rg1",
            "location": "eastus",
        },
    )

    graph.add_resource(policy_def)
    graph.add_resource(policy_assign)
    graph.add_resource(target_res)

    expr, err = encoder.encode_policy_violation(policy_def, policy_assign, target_res, graph)
    assert err is None
    solver = z3.Solver()
    solver.add(expr)
    # Target location is eastus, not in ["westeurope"] -> Deny condition triggers -> Violation SAT!
    assert solver.check() == z3.sat


def test_encode_policy_violation_mismatched_scope():
    encoder = AzurePolicyEncoder()
    graph = ResourceGraph()

    policy_def = Resource(
        address="azurerm_policy_definition.deny_public_ip",
        type="azurerm_policy_definition",
        attributes={
            "policy_rule": json.dumps(
                {
                    "if": {"field": "location", "notIn": ["westeurope"]},
                    "then": {"effect": "Deny"},
                }
            )
        },
    )

    # Assigned to subscription sub-A
    policy_assign = Resource(
        address="azurerm_policy_assignment.sub_assign",
        type="azurerm_policy_assignment",
        attributes={
            "scope": "/subscriptions/sub-A",
            "policy_definition_id": "azurerm_policy_definition.deny_public_ip",
        },
    )

    # Target resource in subscription sub-B
    target_res = Resource(
        address="azurerm_storage_account.sa",
        type="azurerm_storage_account",
        attributes={
            "scope": "/subscriptions/sub-B/resourceGroups/rg1",
            "location": "eastus",
        },
    )

    graph.add_resource(policy_def)
    graph.add_resource(policy_assign)
    graph.add_resource(target_res)

    expr, err = encoder.encode_policy_violation(policy_def, policy_assign, target_res, graph)
    assert err is None
    solver = z3.Solver()
    solver.add(expr)
    # Scope does not subsume -> Policy does not apply -> Violation UNSAT!
    assert solver.check() == z3.unsat
