# CATEGORY: NSG_OVER_EXPOSURE
# FORMAT: HCL
# EXPECTED: SAT
# DESCRIPTION: Azure NSG rule allowing inbound PostgreSQL (5432) from public IP range 0.0.0.0/0

resource "azurerm_network_security_group" "nsg_db" {
  name                = "nsg-open-db"
  location            = "eastus"
  resource_group_name = "rg-db"
}

resource "azurerm_network_security_rule" "allow_postgres" {
  name                        = "AllowPostgresPublic"
  priority                    = 120
  direction                   = "Inbound"
  access                      = "Allow"
  protocol                    = "Tcp"
  source_port_range           = "*"
  destination_port_range      = "5432"
  source_address_prefix       = "0.0.0.0/0"
  destination_address_prefix  = "*"
  resource_group_name         = "rg-db"
  network_security_group_name = azurerm_network_security_group.nsg_db.name
}
