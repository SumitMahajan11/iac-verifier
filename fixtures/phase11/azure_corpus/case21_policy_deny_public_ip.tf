# CATEGORY: AZURE_GOVERNANCE_POLICY_VIOLATION
# FORMAT: HCL
# EXPECTED: SAT
# DESCRIPTION: Policy denying public IP assignment violated by NIC with public IP allocation

resource "azurerm_policy_definition" "deny_public_ip" {
  name         = "deny-public-ip"
  policy_type  = "Custom"
  mode         = "All"
  display_name = "Deny Public IP"

  policy_rule = <<POLICY_RULE
{
  "if": {
    "field": "public_ip_address_id",
    "equals": "enabled"
  },
  "then": {
    "effect": "Deny"
  }
}
POLICY_RULE
}

resource "azurerm_subscription_policy_assignment" "public_ip_assign" {
  name                 = "deny-public-ip-assign"
  subscription_id      = "/subscriptions/sub-policy-1"
  policy_definition_id = azurerm_policy_definition.deny_public_ip.id
}

resource "azurerm_network_interface" "bad_nic" {
  name                = "nic-public-violator"
  location            = "eastus"
  resource_group_name = "rg-net"
  scope               = "/subscriptions/sub-policy-1/resourceGroups/rg-net"
  public_ip_address_id = "enabled"
}
