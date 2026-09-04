"""
tests/test_azure_nsg.py

Unit test suite for Azure Network Security Group (NSG) Z3 SMT Encoder (encoder/azure_nsg_encoder.py).
Validates priority shadowing, explicit allow/deny precedence, service tag isolation, and public exposure detection.
"""

import z3
import pytest
import ipaddress
from encoder.azure_nsg_encoder import (
    AzureNSGEncoder,
    parse_port_range,
    is_public_source_prefix,
    encode_source_prefix_expr,
    PRIVATE_RANGES,
)
from encoder.cidr import (
    make_ip_in_private_ranges_expr,
    make_ip_in_cidr_expr,
)



def test_parse_port_range():
    assert parse_port_range("*") == [(0, 65535)]
    assert parse_port_range("22") == [(22, 22)]
    assert parse_port_range("22-80") == [(22, 80)]
    assert parse_port_range(["22", "80-90"]) == [(22, 22), (80, 90)]


def test_is_public_source_prefix():
    assert is_public_source_prefix("*") is True
    assert is_public_source_prefix("0.0.0.0/0") is True
    assert is_public_source_prefix("Internet") is True
    assert is_public_source_prefix("VirtualNetwork") is False
    assert is_public_source_prefix("10.0.0.0/16") is False


def test_azure_nsg_priority_shadowing_deny_wins():
    """Validates that a higher priority (lower integer e.g. 100) Deny rule overrides a lower priority Allow rule (e.g. 200)."""
    rules = [
        {
            "name": "DenySSH",
            "priority": 100,
            "direction": "Inbound",
            "access": "Deny",
            "protocol": "Tcp",
            "source_address_prefix": "*",
            "destination_port_range": "22",
        },
        {
            "name": "AllowAll",
            "priority": 200,
            "direction": "Inbound",
            "access": "Allow",
            "protocol": "*",
            "source_address_prefix": "*",
            "destination_port_range": "*",
        },
    ]

    encoder = AzureNSGEncoder()
    chain_expr, ip_sym, port_sym, dest_ip_sym, src_port_sym, sorted_rules = encoder.encode_nsg_rules(rules, target_port=22)

    # Verify priority sorting order
    assert [r["name"] for r in sorted_rules[:2]] == ["DenySSH", "AllowAll"]

    solver = z3.Solver()
    solver.add(chain_expr)
    solver.add(port_sym == 22)

    result = solver.check()
    assert result == z3.unsat  # Deny rule at priority 100 blocked port 22 first


def test_azure_nsg_open_ssh_sat():
    """Validates that an unshadowed Allow rule on port 22 exposed to Internet returns SAT."""
    rules = [
        {
            "name": "AllowSSH",
            "priority": 100,
            "direction": "Inbound",
            "access": "Allow",
            "protocol": "Tcp",
            "source_address_prefix": "Internet",
            "destination_port_range": "22",
        }
    ]

    encoder = AzureNSGEncoder()
    chain_expr, ip_sym, port_sym, *rest = encoder.encode_nsg_rules(rules, target_port=22)

    solver = z3.Solver()
    solver.add(chain_expr)
    solver.add(port_sym == 22)

    result = solver.check()
    assert result == z3.sat  # Port 22 is exposed to Internet


def test_azure_nsg_default_deny_all_unsat():
    """
    Validates that empty custom rules fall through to Azure default rule DenyAllInBound (Priority 65500).
    For arbitrary public internet traffic (excluding private VNet and AzureLoadBalancer probe IP 168.63.129.16),
    the solver correctly proves UNSAT (public access denied).
    """
    rules = []

    encoder = AzureNSGEncoder()
    chain_expr, ip_sym, port_sym, *rest = encoder.encode_nsg_rules(rules, target_port=22)

    solver = z3.Solver()
    solver.add(chain_expr)
    solver.add(port_sym == 22)
    # Exclude internal VNet IPs and Azure LoadBalancer probe IP
    solver.add(z3.Not(make_ip_in_private_ranges_expr(ip_sym, PRIVATE_RANGES)))
    solver.add(z3.Not(make_ip_in_cidr_expr(ip_sym, "168.63.129.16/32")))

    result = solver.check()
    assert result == z3.unsat  # Default DenyAllInBound prevents public internet access


def test_azure_nsg_service_tag_fail_closed():
    """Validates that unrecognized service tags or ASG resource IDs fail closed (do not match internet traffic)."""
    ip_sym = z3.BitVec("src_ip", 32)
    expr = encode_source_prefix_expr("CustomAppSecurityGroup_ID_123", ip_sym)
    assert z3.is_false(expr)


def test_azure_nsg_concrete_cidr_bitvector():
    """Validates concrete public CIDRs are correctly encoded into 32-bit BitVector constraints."""
    rules = [
        {
            "name": "AllowSpecificPublicIP",
            "priority": 150,
            "direction": "Inbound",
            "access": "Allow",
            "protocol": "Tcp",
            "source_address_prefix": "203.0.113.0/24",
            "destination_port_range": "22",
        }
    ]

    encoder = AzureNSGEncoder()
    chain_expr, ip_sym, port_sym, *rest = encoder.encode_nsg_rules(rules, target_port=22)

    solver = z3.Solver()
    solver.add(chain_expr)
    solver.add(port_sym == 22)
    result = solver.check()
    assert result == z3.sat


def test_azure_nsg_protocol_isolation():
    """
    Validates protocol isolation: A high priority UDP Deny rule (priority 100) does NOT
    block a lower priority TCP Allow rule (priority 200) for TCP target evaluation.
    """
    rules = [
        {
            "name": "DenyUdpSSHPort",
            "priority": 100,
            "direction": "Inbound",
            "access": "Deny",
            "protocol": "Udp",
            "source_address_prefix": "*",
            "destination_port_range": "22",
        },
        {
            "name": "AllowTcpSSHPort",
            "priority": 200,
            "direction": "Inbound",
            "access": "Allow",
            "protocol": "Tcp",
            "source_address_prefix": "*",
            "destination_port_range": "22",
        },
    ]

    encoder = AzureNSGEncoder()
    # Evaluate for TCP traffic on port 22
    chain_expr, ip_sym, port_sym, *rest = encoder.encode_nsg_rules(
        rules, target_port=22, target_protocol="Tcp"
    )

    solver = z3.Solver()
    solver.add(chain_expr)
    solver.add(port_sym == 22)

    result = solver.check()
    assert result == z3.sat  # UDP Deny at priority 100 does NOT match TCP, so TCP Allow at 200 succeeds!


def test_azure_nsg_protocol_wildcard_deny_shadows_tcp_allow():
    """
    Validates that a wildcard protocol Deny rule (protocol = "*", priority = 100)
    correctly matches and shadows a specific TCP Allow rule (protocol = "Tcp", priority = 200)
    when evaluating TCP queries, producing UNSAT (Deny wins).
    """
    rules = [
        {
            "name": "DenyAllProtocolsPort22",
            "priority": 100,
            "direction": "Inbound",
            "access": "Deny",
            "protocol": "*",
            "source_address_prefix": "*",
            "destination_port_range": "22",
        },
        {
            "name": "AllowTcpSSHPort",
            "priority": 200,
            "direction": "Inbound",
            "access": "Allow",
            "protocol": "Tcp",
            "source_address_prefix": "*",
            "destination_port_range": "22",
        },
    ]

    encoder = AzureNSGEncoder()
    # Evaluate for TCP traffic on port 22
    chain_expr, ip_sym, port_sym, *rest = encoder.encode_nsg_rules(
        rules, target_port=22, target_protocol="Tcp"
    )

    solver = z3.Solver()
    solver.add(chain_expr)
    solver.add(port_sym == 22)

    result = solver.check()
    assert result == z3.unsat  # Wildcard protocol Deny at priority 100 matches TCP, so Deny wins!


def test_azure_nsg_destination_prefix_isolation():
    """
    Validates that destination_address_prefix is functionally load-bearing:
    An Allow rule scoped to 10.0.1.0/24 produces SAT when target_dest_ip is in 10.0.1.0/24 (e.g. 10.0.1.50),
    but produces UNSAT for public internet client traffic when target_dest_ip is outside (e.g. 10.0.2.5).
    """
    rules = [
        {
            "name": "AllowSubnet1Only",
            "priority": 100,
            "direction": "Inbound",
            "access": "Allow",
            "protocol": "Tcp",
            "source_address_prefix": "*",
            "destination_address_prefix": "10.0.1.0/24",
            "destination_port_range": "22",
        }
    ]

    encoder = AzureNSGEncoder()
    client_ip = int(ipaddress.IPv4Address("203.0.113.5"))

    # Query A: Target destination IP inside 10.0.1.0/24 -> SAT
    chain_expr_a, ip_sym_a, port_sym_a, dest_ip_sym_a, src_port_sym_a, _ = encoder.encode_nsg_rules(
        rules, target_port=22, target_dest_ip="10.0.1.50"
    )
    solver_a = z3.Solver()
    solver_a.add(chain_expr_a)
    solver_a.add(port_sym_a == 22)
    solver_a.add(ip_sym_a == client_ip)
    assert solver_a.check() == z3.sat

    # Query B: Target destination IP outside 10.0.1.0/24 (e.g. 10.0.2.5) for public internet client -> UNSAT
    chain_expr_b, ip_sym_b, port_sym_b, dest_ip_sym_b, src_port_sym_b, _ = encoder.encode_nsg_rules(
        rules, target_port=22, target_dest_ip="10.0.2.5"
    )
    solver_b = z3.Solver()
    solver_b.add(chain_expr_b)
    solver_b.add(port_sym_b == 22)
    solver_b.add(ip_sym_b == client_ip)
    assert solver_b.check() == z3.unsat


def test_azure_nsg_source_port_isolation():
    """
    Validates that source_port_range is functionally load-bearing:
    An Allow rule scoped to client source ports 1024-2000 produces SAT for source port 1500,
    but produces UNSAT for public internet client traffic on client source port 5000.
    """
    rules = [
        {
            "name": "AllowSpecificSourcePorts",
            "priority": 100,
            "direction": "Inbound",
            "access": "Allow",
            "protocol": "Tcp",
            "source_address_prefix": "*",
            "source_port_range": "1024-2000",
            "destination_port_range": "22",
        }
    ]

    encoder = AzureNSGEncoder()
    client_ip = int(ipaddress.IPv4Address("203.0.113.5"))

    # Query A: Client source port 1500 (in range) -> SAT
    chain_expr_a, ip_sym_a, port_sym_a, dest_ip_sym_a, src_port_sym_a, _ = encoder.encode_nsg_rules(
        rules, target_port=22, target_src_port=1500
    )
    solver_a = z3.Solver()
    solver_a.add(chain_expr_a)
    solver_a.add(port_sym_a == 22)
    solver_a.add(ip_sym_a == client_ip)
    assert solver_a.check() == z3.sat

    # Query B: Client source port 5000 (out of range) for public internet client -> UNSAT
    chain_expr_b, ip_sym_b, port_sym_b, dest_ip_sym_b, src_port_sym_b, _ = encoder.encode_nsg_rules(
        rules, target_port=22, target_src_port=5000
    )
    solver_b = z3.Solver()
    solver_b.add(chain_expr_b)
    solver_b.add(port_sym_b == 22)
    solver_b.add(ip_sym_b == client_ip)
    assert solver_b.check() == z3.unsat


def test_azure_nsg_destination_prefix_actually_narrows_sat():
    """A rule scoped to a specific destination IP must not match queries against a different destination."""
    rules = [{
        "name": "AllowRDPToSpecificHost",
        "priority": 100,
        "direction": "Inbound",
        "access": "Allow",
        "protocol": "Tcp",
        "source_address_prefix": "*",
        "destination_address_prefix": "203.0.113.5/32",
        "destination_port_range": "3389",
    }]
    encoder = AzureNSGEncoder()
    client_ip = int(ipaddress.IPv4Address("203.0.113.50"))

    # UNSAT Case: Bind destination to a host OUTSIDE the allowed /32 -> UNSAT
    chain_expr_b, ip_sym_b, port_sym_b, dest_ip_sym_b, src_port_sym_b, _ = encoder.encode_nsg_rules(
        rules, target_port=3389, target_protocol="Tcp"
    )
    solver_b = z3.Solver()
    solver_b.add(chain_expr_b)
    solver_b.add(port_sym_b == 3389)
    solver_b.add(ip_sym_b == client_ip)
    solver_b.add(dest_ip_sym_b == int(ipaddress.IPv4Address("198.51.100.9")))
    assert solver_b.check() == z3.unsat

    # SAT Case: Bind destination to host matching 203.0.113.5 -> SAT
    chain_expr_a, ip_sym_a, port_sym_a, dest_ip_sym_a, src_port_sym_a, _ = encoder.encode_nsg_rules(
        rules, target_port=3389, target_protocol="Tcp"
    )
    solver_a = z3.Solver()
    solver_a.add(chain_expr_a)
    solver_a.add(port_sym_a == 3389)
    solver_a.add(ip_sym_a == client_ip)
    solver_a.add(dest_ip_sym_a == int(ipaddress.IPv4Address("203.0.113.5")))
    assert solver_a.check() == z3.sat


def test_azure_nsg_target_dest_ip_and_src_port_parameters():
    """
    Validates that target_dest_ip and target_src_port optional parameters in encode_nsg_rules
    properly bind constraints into chain_expr.
    """
    rules = [
        {
            "name": "AllowSubnet1SpecificPort",
            "priority": 100,
            "direction": "Inbound",
            "access": "Allow",
            "protocol": "Tcp",
            "source_address_prefix": "*",
            "destination_address_prefix": "10.0.1.0/24",
            "source_port_range": "1000-2000",
            "destination_port_range": "22",
        }
    ]
    encoder = AzureNSGEncoder()
    client_ip = int(ipaddress.IPv4Address("203.0.113.5"))

    # Matching query parameters: target_dest_ip in 10.0.1.0/24, target_src_port 1500 -> SAT
    chain_expr_a, ip_sym_a, port_sym_a, _, _, _ = encoder.encode_nsg_rules(
        rules, target_port=22, target_dest_ip="10.0.1.50", target_src_port=1500
    )
    solver_a = z3.Solver()
    solver_a.add(chain_expr_a)
    solver_a.add(port_sym_a == 22)
    solver_a.add(ip_sym_a == client_ip)
    assert solver_a.check() == z3.sat

    # Non-matching destination parameter: target_dest_ip outside 10.0.1.0/24 -> UNSAT
    chain_expr_b, ip_sym_b, port_sym_b, _, _, _ = encoder.encode_nsg_rules(
        rules, target_port=22, target_dest_ip="10.0.2.5", target_src_port=1500
    )
    solver_b = z3.Solver()
    solver_b.add(chain_expr_b)
    solver_b.add(port_sym_b == 22)
    solver_b.add(ip_sym_b == client_ip)
    assert solver_b.check() == z3.unsat


def test_azure_nsg_virtual_network_destination_scoping():
    """
    Validates that destination_address_prefix: 'VirtualNetwork' accurately scopes
    to RFC1918 private IP ranges rather than acting as a blanket wildcard.
    """
    rules = [
        {
            "name": "AllowVnetToVnetOnly",
            "priority": 100,
            "direction": "Inbound",
            "access": "Allow",
            "protocol": "Tcp",
            "source_address_prefix": "*",
            "destination_address_prefix": "VirtualNetwork",
            "destination_port_range": "80",
        }
    ]
    encoder = AzureNSGEncoder()
    client_ip = int(ipaddress.IPv4Address("203.0.113.5"))

    # Destination inside VirtualNetwork (e.g. 10.0.1.50) -> SAT
    chain_expr_a, ip_sym_a, port_sym_a, dest_ip_sym_a, _, _ = encoder.encode_nsg_rules(
        rules, target_port=80
    )
    solver_a = z3.Solver()
    solver_a.add(chain_expr_a)
    solver_a.add(port_sym_a == 80)
    solver_a.add(ip_sym_a == client_ip)
    solver_a.add(dest_ip_sym_a == int(ipaddress.IPv4Address("10.0.1.50")))
    assert solver_a.check() == z3.sat

    # Destination outside VirtualNetwork (public IP 198.51.100.10) -> UNSAT
    chain_expr_b, ip_sym_b, port_sym_b, dest_ip_sym_b, _, _ = encoder.encode_nsg_rules(
        rules, target_port=80
    )
    solver_b = z3.Solver()
    solver_b.add(chain_expr_b)
    solver_b.add(port_sym_b == 80)
    solver_b.add(ip_sym_b == client_ip)
    solver_b.add(dest_ip_sym_b == int(ipaddress.IPv4Address("198.51.100.10")))
    assert solver_b.check() == z3.unsat








