from parser.hcl_parser import parse_file, build_graph
tf = """
resource "azurerm_network_security_group" "my_nsg" {
  name                = "my_nsg"
  location            = "East US"
  resource_group_name = "rg-test"
}
resource "azurerm_network_security_rule" "allow_ssh" {
  name                        = "allow_ssh"
  priority                    = 100
  direction                   = "Inbound"
  access                      = "Allow"
  protocol                    = "Tcp"
  source_port_range           = "*"
  destination_port_range      = "22"
  source_address_prefix       = "*"
  destination_address_prefix  = "*"
  resource_group_name         = "rg-test"
  network_security_group_name = azurerm_network_security_group.my_nsg.name
}
"""
with open('debug_5.tf', 'w') as f:
    f.write(tf)

parsed = parse_file('debug_5.tf')
graph = build_graph(parsed, file_path='debug_5.tf')
rule = graph.resources['azurerm_network_security_rule.allow_ssh']
print("Merged into:", rule.merged_into)
ref = rule.attributes.get('network_security_group_name')
print("Attr type:", type(ref))
if hasattr(ref, 'target_address'):
    print("Target address:", ref.target_address)
