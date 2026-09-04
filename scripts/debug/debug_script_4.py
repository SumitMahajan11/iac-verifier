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
from encoder.azure_nsg_encoder import AzureNSGEncoder
from encoder.cidr import make_ip_in_private_ranges_expr
import z3

encoder = AzureNSGEncoder()
chain_expr, ip_sym, port_sym, dest_ip_sym, src_port_sym, sorted_rules = encoder.encode_nsg_rules([], target_port=22, target_protocol="Tcp")
print("CHAIN EXPR:", chain_expr)

unsafe_formula = z3.And(
    chain_expr,
    port_sym == 22,
    z3.Not(make_ip_in_private_ranges_expr(ip_sym, ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8"]))
)

solver = z3.Solver()
solver.add(unsafe_formula)
print("SOLVER CHECK:", solver.check())
if solver.check() == z3.sat:
    model = solver.model()
    print("MODEL IP:", model[ip_sym])
