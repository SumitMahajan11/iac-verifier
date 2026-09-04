from parser.hcl_parser import parse_file, build_graph
from solver.engine import VerificationEngine
tf = """
resource "azurerm_network_security_group" "vuln_nsg" {
  name                = "vuln_nsg"
  location            = "East US"
  resource_group_name = "rg-test"
}
"""
with open('nsg_empty.tf', 'w') as f:
    f.write(tf)

parsed = parse_file('nsg_empty.tf')
graph = build_graph(parsed, file_path='nsg_empty.tf')
engine = VerificationEngine()
res = engine.verify_azure_nsg(graph.resources['azurerm_network_security_group.vuln_nsg'])
print(res.status)
print(res.witness)
