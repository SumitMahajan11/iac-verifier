# CATEGORY: AZURE_GOVERNANCE_POLICY_VIOLATION
# FORMAT: HCL
# EXPECTED: UNSAT
# DESCRIPTION: Storage account configured with enable_https_traffic_only = true fully compliant with HTTPS policy

resource "azurerm_policy_definition" "enforce_https_safe" {
  name         = "enforce-https-policy"
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

resource "azurerm_subscription_policy_assignment" "https_assign_safe" {
  name                 = "https-assign-safe"
  subscription_id      = "/subscriptions/sub-policy-7"
  policy_definition_id = azurerm_policy_definition.enforce_https_safe.id
}

resource "azurerm_storage_account" "secure_storage" {
  name                     = "stgsecurehttpsonly"
  resource_group_name      = "rg-prod"
  location                 = "westeurope"
  account_tier             = "Standard"
  account_replication_type = "LRS"
  scope                    = "/subscriptions/sub-policy-7/resourceGroups/rg-prod"
  enable_https_traffic_only = true
}
