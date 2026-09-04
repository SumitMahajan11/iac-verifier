# CATEGORY: SCOPE_INHERITANCE
# FORMAT: HCL
# EXPECTED: SAT
# DESCRIPTION: Root Management Group policy assignment enforces SKU restrictions top-down across child subscriptions

resource "azurerm_policy_definition" "deny_large_sku" {
  name         = "deny-large-sku"
  policy_type  = "Custom"
  mode         = "All"
  display_name = "Deny Premium Storage SKU"

  policy_rule = <<POLICY_RULE
{
  "if": {
    "field": "account_tier",
    "equals": "Premium"
  },
  "then": {
    "effect": "Deny"
  }
}
POLICY_RULE
}

resource "azurerm_management_group_policy_assignment" "root_mg_assign" {
  name                 = "root-sku-policy"
  management_group_id  = "/providers/Microsoft.Management/managementGroups/root-mg"
  policy_definition_id = azurerm_policy_definition.deny_large_sku.id
}

resource "azurerm_storage_account" "child_sub_premium_storage" {
  name                     = "stgpremiumviolator"
  resource_group_name      = "rg-data"
  location                 = "westeurope"
  account_tier             = "Premium"
  account_replication_type = "LRS"
  scope                    = "/providers/Microsoft.Management/managementGroups/root-mg/subscriptions/sub-child-500/resourceGroups/rg-data"
}
