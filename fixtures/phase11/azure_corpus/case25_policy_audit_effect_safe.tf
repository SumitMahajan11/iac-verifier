# CATEGORY: AZURE_GOVERNANCE_POLICY_VIOLATION
# FORMAT: HCL
# EXPECTED: UNSAT
# DESCRIPTION: Policy with Audit effect instead of Deny does not enforce block condition in security engine

resource "azurerm_policy_definition" "audit_location" {
  name         = "audit-location-policy"
  policy_type  = "Custom"
  mode         = "All"
  display_name = "Audit Non-EU Locations"

  policy_rule = <<POLICY_RULE
{
  "if": {
    "field": "location",
    "equals": "eastus"
  },
  "then": {
    "effect": "Audit"
  }
}
POLICY_RULE
}

resource "azurerm_subscription_policy_assignment" "audit_assign" {
  name                 = "audit-assign"
  subscription_id      = "/subscriptions/sub-policy-5"
  policy_definition_id = azurerm_policy_definition.audit_location.id
}

resource "azurerm_storage_account" "audit_storage" {
  name                     = "stgauditonly"
  resource_group_name      = "rg-test"
  location                 = "eastus"
  account_tier             = "Standard"
  account_replication_type = "LRS"
  scope                    = "/subscriptions/sub-policy-5/resourceGroups/rg-test"
}
