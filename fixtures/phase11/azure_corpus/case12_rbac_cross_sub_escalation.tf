# CATEGORY: RBAC_PRIVILEGE_ESCALATION
# FORMAT: HCL
# EXPECTED: SAT
# DESCRIPTION: Cross-subscription role assignment granting Contributor role across subscription scope boundary

resource "azurerm_role_assignment" "cross_sub_assign" {
  name                 = "00000000-0000-0000-0000-000000000012"
  scope                = "/subscriptions/sub-production-999"
  role_definition_name = "Contributor"
  principal_id         = "dev-user-principal-id"
}
