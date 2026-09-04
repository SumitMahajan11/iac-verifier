# CATEGORY: AZURE_GOVERNANCE_POLICY_VIOLATION
# FORMAT: HCL
# EXPECTED: SAT
# DESCRIPTION: Policy requiring HTTPS-only traffic violated by storage account with supports_https_traffic_only set to false

resource "azurerm_policy_definition" "enforce_https" {
  name         = "enforce-https-storage"
  policy_type  = "Custom"
  mode         = "All"
  display_name = "Enforce HTTPS Storage"

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

resource "azurerm_subscription_policy_assignment" "https_assignment" {
  name                 = "enforce-https-assign"
  subscription_id      = "/subscriptions/sub-policy-3"
  policy_definition_id = azurerm_policy_definition.enforce_https.id
}

resource "azurerm_storage_account" "insecure_storage" {
  name                     = "stginsecurehttp"
  resource_group_name      = "rg-data"
  location                 = "westeurope"
  account_tier             = "Standard"
  account_replication_type = "LRS"
  scope                    = "/subscriptions/sub-policy-3/resourceGroups/rg-data"
  enable_https_traffic_only = false
}
