# CATEGORY: RBAC_PRIVILEGE_ESCALATION
# FORMAT: HCL
# EXPECTED: SAT
# DESCRIPTION: Custom role definition granting Microsoft.Authorization/*/Write permissions allowing role assignment modification

resource "azurerm_role_definition" "custom_admin" {
  name        = "CustomRoleWriteAdmin"
  scope       = "/subscriptions/00000000-0000-0000-0000-000000000001"
  description = "Custom role with auth write permissions"

  permissions {
    actions = [
      "Microsoft.Authorization/*/Write",
      "Microsoft.Resources/subscriptions/resourceGroups/read"
    ]
    not_actions = []
  }

  assignable_scopes = [
    "/subscriptions/00000000-0000-0000-0000-000000000001"
  ]
}

resource "azurerm_role_assignment" "custom_assign" {
  name               = "00000000-0000-0000-0000-000000000003"
  scope              = "/subscriptions/00000000-0000-0000-0000-000000000001"
  role_definition_id = azurerm_role_definition.custom_admin.role_definition_id
  principal_id       = "user-principal-id-003"
}
