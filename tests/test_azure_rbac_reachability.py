"""
tests/test_azure_rbac_reachability.py

Integration test suite for Azure RBAC cross-account privilege escalation reachability.
Validates:
1. Scope hierarchy inheritance (Management Group -> Subscription -> Resource Group -> Resource).
2. Multi-hop transitive privilege escalation paths (SAT + witness extraction).
3. Custom role definition evaluation (wildcards, Microsoft.Authorization/*).
4. Non-administrative roles (Reader) yielding UNSAT unreachability proofs.
5. Fail-closed security for unresolved scope / principal / role_definition references (UNRESOLVABLE).
"""

import unittest
from parser.graph import (
    Resource,
    ResourceGraph,
    ResourceReference,
    Unresolved,
)
from solver.engine import VerificationEngine
from graph.trust_graph import build_trust_graph


class TestAzureRBACReachability(unittest.TestCase):
    def setUp(self):
        self.engine = VerificationEngine()

    def test_azure_rbac_direct_escalation_sat(self):
        """External user assigned Contributor on VM with Managed Identity that holds Owner on Subscription."""
        graph = ResourceGraph(
            resources={
                "azurerm_user_assigned_identity.admin_id": Resource(
                    address="azurerm_user_assigned_identity.admin_id",
                    type="azurerm_user_assigned_identity",
                    attributes={"name": "admin-identity"},
                ),
                "azurerm_linux_virtual_machine.app_vm": Resource(
                    address="azurerm_linux_virtual_machine.app_vm",
                    type="azurerm_linux_virtual_machine",
                    attributes={
                        "name": "app-vm",
                        "resource_group_name": "rg-prod",
                        "identity": {
                            "type": "UserAssigned",
                            "identity_ids": [
                                ResourceReference("azurerm_user_assigned_identity.admin_id", "id")
                            ],
                        },
                    },
                ),
                "azurerm_role_assignment.user_to_vm": Resource(
                    address="azurerm_role_assignment.user_to_vm",
                    type="azurerm_role_assignment",
                    attributes={
                        "principal_id": "ext-user-1234",
                        "role_definition_name": "Contributor",
                        "scope": ResourceReference("azurerm_linux_virtual_machine.app_vm", "id"),
                    },
                ),
                "azurerm_role_assignment.identity_to_sub": Resource(
                    address="azurerm_role_assignment.identity_to_sub",
                    type="azurerm_role_assignment",
                    attributes={
                        "principal_id": ResourceReference("azurerm_user_assigned_identity.admin_id", "id"),
                        "role_definition_name": "Owner",
                        "scope": "/subscriptions/00000000-0000-0000-0000-000000000000",
                    },
                ),
            }
        )

        res = self.engine.verify_privilege_escalation(graph)
        self.assertEqual(res.status, "SAT")
        self.assertIsNotNone(res.witness)
        self.assertEqual(res.witness["entry_point"], "account:ext-user-1234")
        self.assertEqual(res.witness["target_resource"], "azurerm_user_assigned_identity.admin_id")
        self.assertEqual(len(res.witness["hops"]), 1)

    def test_azure_rbac_multi_hop_transitive_escalation_sat(self):
        """Transitive 2-hop escalation: ext-user -> VM1 (ID1) -> VM2 (ID2/Owner)."""
        graph = ResourceGraph(
            resources={
                "azurerm_user_assigned_identity.id1": Resource(
                    address="azurerm_user_assigned_identity.id1",
                    type="azurerm_user_assigned_identity",
                    attributes={"name": "identity-1"},
                ),
                "azurerm_user_assigned_identity.id2": Resource(
                    address="azurerm_user_assigned_identity.id2",
                    type="azurerm_user_assigned_identity",
                    attributes={"name": "identity-2"},
                ),
                "azurerm_linux_virtual_machine.vm1": Resource(
                    address="azurerm_linux_virtual_machine.vm1",
                    type="azurerm_linux_virtual_machine",
                    attributes={
                        "identity": {
                            "identity_ids": [ResourceReference("azurerm_user_assigned_identity.id1", "id")]
                        }
                    },
                ),
                "azurerm_linux_virtual_machine.vm2": Resource(
                    address="azurerm_linux_virtual_machine.vm2",
                    type="azurerm_linux_virtual_machine",
                    attributes={
                        "identity": {
                            "identity_ids": [ResourceReference("azurerm_user_assigned_identity.id2", "id")]
                        }
                    },
                ),
                # ext-user -> vm1 (holds id1)
                "azurerm_role_assignment.ext_to_vm1": Resource(
                    address="azurerm_role_assignment.ext_to_vm1",
                    type="azurerm_role_assignment",
                    attributes={
                        "principal_id": "ext-user-9999",
                        "role_definition_name": "Contributor",
                        "scope": ResourceReference("azurerm_linux_virtual_machine.vm1", "id"),
                    },
                ),
                # id1 -> vm2 (holds id2)
                "azurerm_role_assignment.id1_to_vm2": Resource(
                    address="azurerm_role_assignment.id1_to_vm2",
                    type="azurerm_role_assignment",
                    attributes={
                        "principal_id": ResourceReference("azurerm_user_assigned_identity.id1", "id"),
                        "role_definition_name": "Virtual Machine Contributor",
                        "scope": ResourceReference("azurerm_linux_virtual_machine.vm2", "id"),
                    },
                ),
                # id2 -> Subscription Owner
                "azurerm_role_assignment.id2_to_sub": Resource(
                    address="azurerm_role_assignment.id2_to_sub",
                    type="azurerm_role_assignment",
                    attributes={
                        "principal_id": ResourceReference("azurerm_user_assigned_identity.id2", "id"),
                        "role_definition_name": "Owner",
                        "scope": "/subscriptions/sub-1234",
                    },
                ),
            }
        )

        res = self.engine.verify_privilege_escalation(graph)
        self.assertEqual(res.status, "SAT")
        self.assertEqual(res.witness["entry_point"], "account:ext-user-9999")
        self.assertEqual(res.witness["target_resource"], "azurerm_user_assigned_identity.id2")
        self.assertEqual(len(res.witness["hops"]), 2)

    def test_azure_rbac_scope_inheritance_management_group_sat(self):
        """Role assignment at Management Group scope inherits to VM resource inside Subscription under MG."""
        graph = ResourceGraph(
            resources={
                "azurerm_user_assigned_identity.sec_admin": Resource(
                    address="azurerm_user_assigned_identity.sec_admin",
                    type="azurerm_user_assigned_identity",
                    attributes={"name": "sec-admin"},
                ),
                "azurerm_linux_virtual_machine.mg_vm": Resource(
                    address="azurerm_linux_virtual_machine.mg_vm",
                    type="azurerm_linux_virtual_machine",
                    attributes={
                        "scope": "/providers/Microsoft.Management/managementGroups/mg-corp/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Compute/virtualMachines/mg-vm",
                        "identity": {
                            "identity_ids": [
                                ResourceReference("azurerm_user_assigned_identity.sec_admin", "id")
                            ]
                        },
                    },
                ),
                "azurerm_role_assignment.mg_admin": Resource(
                    address="azurerm_role_assignment.mg_admin",
                    type="azurerm_role_assignment",
                    attributes={
                        "principal_id": "ext-auditor",
                        "role_definition_name": "User Access Administrator",
                        "scope": "/providers/Microsoft.Management/managementGroups/mg-corp",
                    },
                ),
                "azurerm_role_assignment.sec_admin_sub": Resource(
                    address="azurerm_role_assignment.sec_admin_sub",
                    type="azurerm_role_assignment",
                    attributes={
                        "principal_id": ResourceReference("azurerm_user_assigned_identity.sec_admin", "id"),
                        "role_definition_name": "Owner",
                        "scope": "/providers/Microsoft.Management/managementGroups/mg-corp",
                    },
                ),
            }
        )

        res = self.engine.verify_privilege_escalation(graph)
        self.assertEqual(res.status, "SAT")
        self.assertEqual(res.witness["entry_point"], "account:ext-auditor")
        self.assertEqual(res.witness["target_resource"], "azurerm_user_assigned_identity.sec_admin")

    def test_azure_rbac_custom_role_definition_admin(self):
        """Custom azurerm_role_definition with Microsoft.Authorization/* permissions."""
        graph = ResourceGraph(
            resources={
                "azurerm_role_definition.custom_admin": Resource(
                    address="azurerm_role_definition.custom_admin",
                    type="azurerm_role_definition",
                    attributes={
                        "name": "CustomAuthAdmin",
                        "permissions": [{"actions": ["Microsoft.Authorization/*"]}],
                    },
                ),
                "azurerm_user_assigned_identity.identity_a": Resource(
                    address="azurerm_user_assigned_identity.identity_a",
                    type="azurerm_user_assigned_identity",
                    attributes={"name": "identity-a"},
                ),
                "azurerm_role_assignment.custom_assign": Resource(
                    address="azurerm_role_assignment.custom_assign",
                    type="azurerm_role_assignment",
                    attributes={
                        "principal_id": ResourceReference("azurerm_user_assigned_identity.identity_a", "id"),
                        "role_definition_name": ResourceReference("azurerm_role_definition.custom_admin", "name"),
                        "scope": "/subscriptions/sub-custom",
                    },
                ),
            }
        )

        tg = build_trust_graph(graph)
        self.assertIn("azurerm_user_assigned_identity.identity_a", tg.target_roles)

    def test_azure_rbac_reader_only_unsat(self):
        """Reader role assignment cannot escalate -> UNSAT."""
        graph = ResourceGraph(
            resources={
                "azurerm_user_assigned_identity.target_id": Resource(
                    address="azurerm_user_assigned_identity.target_id",
                    type="azurerm_user_assigned_identity",
                    attributes={"name": "target-id"},
                ),
                "azurerm_role_assignment.reader_assignment": Resource(
                    address="azurerm_role_assignment.reader_assignment",
                    type="azurerm_role_assignment",
                    attributes={
                        "principal_id": "ext-reader-user",
                        "role_definition_name": "Reader",
                        "scope": "/subscriptions/sub-safe",
                    },
                ),
            }
        )

        res = self.engine.verify_privilege_escalation(graph)
        self.assertEqual(res.status, "UNSAT")

    def test_azure_rbac_unresolved_scope_unresolvable(self):
        """Unresolved scope attribute in role assignment -> UNRESOLVABLE (fail-closed)."""
        graph = ResourceGraph(
            resources={
                "azurerm_role_assignment.bad_assignment": Resource(
                    address="azurerm_role_assignment.bad_assignment",
                    type="azurerm_role_assignment",
                    attributes={
                        "principal_id": "user-111",
                        "role_definition_name": "Owner",
                        "scope": Unresolved("Missing scope module variable"),
                    },
                ),
            }
        )

        res = self.engine.verify_privilege_escalation(graph)
        self.assertEqual(res.status, "UNRESOLVABLE")

    def test_azure_rbac_bounded_unreachability_unsat_bounded(self):
        """When max_hops cap is less than required path length, returns UNSAT_BOUNDED."""
        graph = ResourceGraph(
            resources={
                "azurerm_user_assigned_identity.id1": Resource(
                    address="azurerm_user_assigned_identity.id1",
                    type="azurerm_user_assigned_identity",
                    attributes={"name": "identity-1"},
                ),
                "azurerm_user_assigned_identity.id2": Resource(
                    address="azurerm_user_assigned_identity.id2",
                    type="azurerm_user_assigned_identity",
                    attributes={"name": "identity-2"},
                ),
                "azurerm_linux_virtual_machine.vm1": Resource(
                    address="azurerm_linux_virtual_machine.vm1",
                    type="azurerm_linux_virtual_machine",
                    attributes={
                        "identity": {
                            "identity_ids": [ResourceReference("azurerm_user_assigned_identity.id1", "id")]
                        }
                    },
                ),
                "azurerm_linux_virtual_machine.vm2": Resource(
                    address="azurerm_linux_virtual_machine.vm2",
                    type="azurerm_linux_virtual_machine",
                    attributes={
                        "identity": {
                            "identity_ids": [ResourceReference("azurerm_user_assigned_identity.id2", "id")]
                        }
                    },
                ),
                # ext-user -> vm1 (holds id1)
                "azurerm_role_assignment.ext_to_vm1": Resource(
                    address="azurerm_role_assignment.ext_to_vm1",
                    type="azurerm_role_assignment",
                    attributes={
                        "principal_id": "ext-user-9999",
                        "role_definition_name": "Contributor",
                        "scope": ResourceReference("azurerm_linux_virtual_machine.vm1", "id"),
                    },
                ),
                # id1 -> vm2 (holds id2)
                "azurerm_role_assignment.id1_to_vm2": Resource(
                    address="azurerm_role_assignment.id1_to_vm2",
                    type="azurerm_role_assignment",
                    attributes={
                        "principal_id": ResourceReference("azurerm_user_assigned_identity.id1", "id"),
                        "role_definition_name": "Virtual Machine Contributor",
                        "scope": ResourceReference("azurerm_linux_virtual_machine.vm2", "id"),
                    },
                ),
                # id2 -> Subscription Owner
                "azurerm_role_assignment.id2_to_sub": Resource(
                    address="azurerm_role_assignment.id2_to_sub",
                    type="azurerm_role_assignment",
                    attributes={
                        "principal_id": ResourceReference("azurerm_user_assigned_identity.id2", "id"),
                        "role_definition_name": "Owner",
                        "scope": "/subscriptions/sub-1234",
                    },
                ),
            }
        )

        engine_no_cache = VerificationEngine(use_cache=False)
        res = engine_no_cache.verify_privilege_escalation(graph, configured_cap=1)
        self.assertEqual(res.status, "UNSAT_BOUNDED")


if __name__ == "__main__":
    unittest.main()


