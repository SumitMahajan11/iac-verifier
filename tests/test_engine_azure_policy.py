"""
tests/test_engine_azure_policy.py

Integration tests for VerificationEngine Azure Policy dispatch and cache key invalidation.
"""

import json
import pytest
from parser.graph import Resource, ResourceGraph
from solver.engine import VerificationEngine, compute_cache_key


def test_verification_engine_azure_policy_sat():
    graph = ResourceGraph()

    policy_def = Resource(
        address="azurerm_policy_definition.deny_non_eu",
        type="azurerm_policy_definition",
        attributes={
            "policy_rule": json.dumps(
                {
                    "if": {"field": "location", "notIn": ["westeurope", "northeurope"]},
                    "then": {"effect": "Deny"},
                }
            )
        },
    )

    policy_assign = Resource(
        address="azurerm_policy_assignment.sub_policy",
        type="azurerm_policy_assignment",
        attributes={
            "scope": "/subscriptions/sub-100",
            "policy_definition_id": "azurerm_policy_definition.deny_non_eu",
        },
    )

    target_res = Resource(
        address="azurerm_storage_account.bad_sa",
        type="azurerm_storage_account",
        attributes={
            "scope": "/subscriptions/sub-100/resourceGroups/rg1",
            "location": "eastus",
        },
    )

    graph.add_resource(policy_def)
    graph.add_resource(policy_assign)
    graph.add_resource(target_res)

    engine = VerificationEngine(use_cache=False)
    results = engine.verify_graph(graph)

    assert len(results) == 1
    res = results[0]
    assert res.status == "SAT"
    assert res.pattern == "AZURE_GOVERNANCE_POLICY_VIOLATION"
    assert res.witness is not None
    assert res.witness["policy_definition"] == "azurerm_policy_definition.deny_non_eu"
    assert res.witness["effect"] == "Deny"


def test_verification_engine_azure_policy_unsat_compliant():
    graph = ResourceGraph()

    policy_def = Resource(
        address="azurerm_policy_definition.deny_non_eu",
        type="azurerm_policy_definition",
        attributes={
            "policy_rule": json.dumps(
                {
                    "if": {"field": "location", "notIn": ["westeurope", "northeurope"]},
                    "then": {"effect": "Deny"},
                }
            )
        },
    )

    policy_assign = Resource(
        address="azurerm_policy_assignment.sub_policy",
        type="azurerm_policy_assignment",
        attributes={
            "scope": "/subscriptions/sub-100",
            "policy_definition_id": "azurerm_policy_definition.deny_non_eu",
        },
    )

    # Compliant location: westeurope
    target_res = Resource(
        address="azurerm_storage_account.good_sa",
        type="azurerm_storage_account",
        attributes={
            "scope": "/subscriptions/sub-100/resourceGroups/rg1",
            "location": "westeurope",
        },
    )

    graph.add_resource(policy_def)
    graph.add_resource(policy_assign)
    graph.add_resource(target_res)

    engine = VerificationEngine(use_cache=False)
    results = engine.verify_graph(graph)

    assert len(results) == 1
    res = results[0]
    assert res.status == "UNSAT"
    assert res.pattern == "AZURE_GOVERNANCE_POLICY_VIOLATION"


def test_azure_policy_cache_key_invalidation():
    graph1 = ResourceGraph()
    policy_def1 = Resource(
        address="azurerm_policy_definition.p1",
        type="azurerm_policy_definition",
        attributes={"policy_rule": json.dumps({"if": {"field": "location", "equals": "eastus"}, "then": {"effect": "Deny"}})},
    )
    policy_assign = Resource(
        address="azurerm_policy_assignment.a1",
        type="azurerm_policy_assignment",
        attributes={"scope": "/subscriptions/sub1", "policy_definition_id": "azurerm_policy_definition.p1"},
    )
    target_res = Resource(
        address="azurerm_storage_account.sa1",
        type="azurerm_storage_account",
        attributes={"scope": "/subscriptions/sub1/resourceGroups/rg1", "location": "eastus"},
    )

    graph1.add_resource(policy_def1)
    graph1.add_resource(policy_assign)
    graph1.add_resource(target_res)

    key1 = compute_cache_key(graph1, "azurerm_storage_account.sa1", "AZURE_GOVERNANCE_POLICY_VIOLATION")

    # Modify policy definition rule in graph2
    graph2 = ResourceGraph()
    policy_def2 = Resource(
        address="azurerm_policy_definition.p1",
        type="azurerm_policy_definition",
        attributes={"policy_rule": json.dumps({"if": {"field": "location", "equals": "westeurope"}, "then": {"effect": "Deny"}})},
    )
    graph2.add_resource(policy_def2)
    graph2.add_resource(policy_assign)
    graph2.add_resource(target_res)

    key2 = compute_cache_key(graph2, "azurerm_storage_account.sa1", "AZURE_GOVERNANCE_POLICY_VIOLATION")

    # Hashes must differ because policy definition content changed!
    assert key1 != key2
