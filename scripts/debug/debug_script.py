import pytest
from parser.hcl_parser import parse_file, build_graph
from solver.engine import VerificationEngine
from solver.repair import AutoRepairEngine

tf = """
resource "azurerm_network_security_group" "vuln_nsg" {
  name                = "vuln_nsg"
  location            = "East US"
  resource_group_name = "rg-test"

  security_rule {
    name                       = "allow_ssh_any"
    priority                   = 100
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "22"
    source_address_prefix      = "*"
    destination_address_prefix = "*"
  }
}
"""
with open('nsg.tf', 'w') as f:
    f.write(tf)

parsed = parse_file('nsg.tf')
graph = build_graph(parsed, file_path='nsg.tf')
repair_engine = AutoRepairEngine()
result = repair_engine.repair_resource(graph, 'azurerm_network_security_group.vuln_nsg', 'NSG_OVER_EXPOSURE')
print('STATUS:', result.status)
print('MESSAGE:', result.message)
