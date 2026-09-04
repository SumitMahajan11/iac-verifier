# CATEGORY: NSG_OVER_EXPOSURE
# FORMAT: HCL
# EXPECTED: SAT
# DESCRIPTION: Azure NSG rule allowing inbound SSH (port 22) from any source IP (*)

resource "azurerm_network_security_group" "nsg_bad" {
  name                = "nsg-open-ssh"
  location            = "eastus"
  resource_group_name = "rg-security"
}

resource "azurerm_network_security_rule" "allow_ssh" {
  name                        = "AllowSSHAny"
  priority                    = 100
  direction                   = "Inbound"
  access                      = "Allow"
  protocol                    = "Tcp"
  source_port_range           = "*"
  destination_port_range      = "22"
  source_address_prefix       = "*"
  destination_address_prefix  = "*"
  resource_group_name         = "rg-security"
  network_security_group_name = azurerm_network_security_group.nsg_bad.name
}
