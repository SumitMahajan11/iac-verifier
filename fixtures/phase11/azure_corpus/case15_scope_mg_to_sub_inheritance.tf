# CATEGORY: SCOPE_INHERITANCE
# FORMAT: HCL
# EXPECTED: SAT
# DESCRIPTION: Governance policy assigned at Management Group scope inherited down to subscription resource

resource "azurerm_policy_definition" "deny_unencrypted_storage_mg" {
  name         = "deny-unencrypted-storage-mg"
  policy_type  = "Custom"
  mode         = "All"
  display_name = "Deny Unencrypted Storage"

  policy_rule = <<POLICY_RULE
{
  "if": {
    "field": "supports_https_traffic_only",
    "equals": "false"
  },
  "then": {
    "effect": "Deny"
  }
}
POLICY_RULE
}

resource "azurerm_management_group_policy_assignment" "mg_policy_assign" {
  name                 = "mg-storage-policy"
  management_group_id  = "/providers/Microsoft.Management/managementGroups/mg-enterprise"
  policy_definition_id = azurerm_policy_definition.deny_unencrypted_storage_mg.id
}

resource "azurerm_storage_account" "sub_unencrypted_storage" {
  name                     = "stgmgviolator"
  resource_group_name      = "rg-prod"
  location                 = "westeurope"
  account_tier             = "Standard"
  account_replication_type = "LRS"
  scope                    = "/providers/Microsoft.Management/managementGroups/mg-enterprise/subscriptions/sub-100/resourceGroups/rg-prod"
  enable_https_traffic_only = false
}
