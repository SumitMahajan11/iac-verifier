# CATEGORY: SCOPE_INHERITANCE
# FORMAT: HCL
# EXPECTED: UNSAT
# DESCRIPTION: Policy assigned to Sub-A does not subsume or apply to resources in Sub-B

resource "azurerm_policy_definition" "deny_location_sub_a" {
  name         = "deny-location-sub-a"
  policy_type  = "Custom"
  mode         = "All"
  display_name = "Deny Non-US"

  policy_rule = <<POLICY_RULE
{
  "if": {
    "field": "location",
    "equals": "westeurope"
  },
  "then": {
    "effect": "Deny"
  }
}
POLICY_RULE
}

resource "azurerm_subscription_policy_assignment" "sub_a_assign" {
  name                 = "sub-a-policy"
  subscription_id      = "/subscriptions/sub-aaa-111"
  policy_definition_id = azurerm_policy_definition.deny_location_sub_a.id
}

resource "azurerm_storage_account" "sub_b_storage" {
  name                     = "stgsubb"
  resource_group_name      = "rg-isolated"
  location                 = "westeurope"
  account_tier             = "Standard"
  account_replication_type = "LRS"
  scope                    = "/subscriptions/sub-bbb-222/resourceGroups/rg-isolated"
}
