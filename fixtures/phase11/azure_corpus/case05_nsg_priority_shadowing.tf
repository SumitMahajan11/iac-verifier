# CATEGORY: NSG_OVER_EXPOSURE
# FORMAT: HCL
# EXPECTED: UNSAT
# DESCRIPTION: Azure NSG where higher-priority Deny rule (100) shadows lower-priority Allow rule (200)

resource "azurerm_network_security_group" "nsg_shadowed" {
  name                = "nsg-shadowed"
  location            = "eastus"
  resource_group_name = "rg-security"
}

resource "azurerm_network_security_rule" "deny_ssh_priority100" {
  name                        = "DenySSH"
  priority                    = 100
  direction                   = "Inbound"
  access                      = "Deny"
  protocol                    = "Tcp"
  source_port_range           = "*"
  destination_port_range      = "22"
  source_address_prefix       = "*"
  destination_address_prefix  = "*"
  resource_group_name         = "rg-security"
  network_security_group_name = azurerm_network_security_group.nsg_shadowed.name
}

resource "azurerm_network_security_rule" "allow_ssh_priority200" {
  name                        = "AllowSSH"
  priority                    = 200
  direction                   = "Inbound"
  access                      = "Allow"
  protocol                    = "Tcp"
  source_port_range           = "*"
  destination_port_range      = "22"
  source_address_prefix       = "*"
  destination_address_prefix  = "*"
  resource_group_name         = "rg-security"
  network_security_group_name = azurerm_network_security_group.nsg_shadowed.name
}
