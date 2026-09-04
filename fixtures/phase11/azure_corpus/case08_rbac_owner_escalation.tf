# CATEGORY: RBAC_PRIVILEGE_ESCALATION
# FORMAT: HCL
# EXPECTED: SAT
# DESCRIPTION: User assignment of Owner role at subscription scope allowing full privilege escalation

resource "azurerm_role_assignment" "owner_assign" {
  name                 = "00000000-0000-0000-0000-000000000001"
  scope                = "/subscriptions/00000000-0000-0000-0000-000000000001"
  role_definition_name = "Owner"
  principal_id         = "user-principal-id-001"
}
