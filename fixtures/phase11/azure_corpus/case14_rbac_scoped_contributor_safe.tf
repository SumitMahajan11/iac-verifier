# CATEGORY: RBAC_PRIVILEGE_ESCALATION
# FORMAT: HCL
# EXPECTED: UNSAT
# DESCRIPTION: Role assignment restricted to specific RG scope without authorization management permissions

resource "azurerm_role_assignment" "rg_scoped_contributor" {
  name                 = "00000000-0000-0000-0000-000000000014"
  scope                = "/subscriptions/00000000-0000-0000-0000-000000000001/resourceGroups/rg-app-only"
  role_definition_name = "Reader"
  principal_id         = "user-principal-id-014"
}
