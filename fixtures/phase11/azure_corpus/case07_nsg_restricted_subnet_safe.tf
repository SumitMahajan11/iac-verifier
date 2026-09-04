# CATEGORY: NSG_OVER_EXPOSURE
# FORMAT: HCL
# EXPECTED: UNSAT
# DESCRIPTION: Azure NSG restricting RDP (3389) strictly to internal private CIDR 10.0.1.0/24

resource "azurerm_network_security_group" "nsg_subnet_safe" {
  name                = "nsg-subnet-safe"
  location            = "eastus"
  resource_group_name = "rg-security"
}

resource "azurerm_network_security_rule" "allow_rdp_private" {
  name                        = "AllowRDPPrivateSubnet"
  priority                    = 100
  direction                   = "Inbound"
  access                      = "Allow"
  protocol                    = "Tcp"
  source_port_range           = "*"
  destination_port_range      = "3389"
  source_address_prefix       = "10.0.1.0/24"
  destination_address_prefix  = "10.0.1.0/24"
  resource_group_name         = "rg-security"
  network_security_group_name = azurerm_network_security_group.nsg_subnet_safe.name
}
