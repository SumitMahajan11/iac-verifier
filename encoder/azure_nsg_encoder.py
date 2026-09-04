"""
encoder/azure_nsg_encoder.py

Z3 SMT Encoder for Azure Network Security Groups (NSGs).
Encodes priority-ordered, explicit Allow/Deny security rules into Z3 first-order logic formulas.
Supports inbound security evaluation, priority shadowing, service-tag isolation, and BitVector CIDR arithmetic.
"""

import ipaddress
import z3
from typing import List, Dict, Any, Tuple, Optional, Union

from encoder.cidr import (
    make_ip_in_cidr_expr,
    make_ip_in_private_ranges_expr,
)

PRIVATE_RANGES: List[str] = [
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "127.0.0.0/8",
]


def parse_port_range(port_val: Any) -> List[Tuple[int, int]]:
    """
    Parses port values into a list of (start_port, end_port) tuples.
    Supports '*', integer, string '22', or range '22-80', or list of ranges.
    """
    if port_val is None or port_val == "*":
        return [(0, 65535)]
    if isinstance(port_val, int):
        return [(port_val, port_val)]

    ranges = []
    ports = [port_val] if isinstance(port_val, str) else list(port_val)
    for p in ports:
        p_str = str(p).strip()
        if p_str == "*":
            ranges.append((0, 65535))
        elif "-" in p_str:
            parts = p_str.split("-")
            try:
                ranges.append((int(parts[0]), int(parts[1])))
            except ValueError:
                ranges.append((0, 65535))
        else:
            try:
                val = int(p_str)
                ranges.append((val, val))
            except ValueError:
                ranges.append((0, 65535))
    return ranges


def is_public_source_prefix(prefix: Any) -> bool:
    """
    Checks if a source prefix represents public internet traffic (0.0.0.0/0, *, Internet).
    """
    if prefix is None:
        return False
    if isinstance(prefix, (list, tuple)):
        return any(is_public_source_prefix(p) for p in prefix)

    p_str = str(prefix).strip()
    if p_str in ("*", "0.0.0.0/0", "Internet"):
        return True

    try:
        net = ipaddress.ip_network(p_str, strict=False)
        return net.prefixlen < 32 and not net.is_private
    except ValueError:
        return False


def encode_source_prefix_expr(
    prefix: Any, ip_sym: z3.BitVecRef
) -> z3.BoolRef:
    """
    Encodes an Azure NSG source address prefix or service tag into a Z3 BitVector IP expression.

    Service Tag / Prefix Behavior:
    - '*', '0.0.0.0/0', 'Internet': Matches any 32-bit IP (0.0.0.0/0).
    - 'VirtualNetwork': Matches RFC1918 private IP ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16).
    - 'AzureLoadBalancer': Matches Azure probe infrastructure IP (168.63.129.16/32).
    - Concrete CIDR (e.g. '192.168.1.0/24', '203.0.113.5/32'): BitVector range comparison.
    - Unrecognized service tags or Application Security Group (ASG) IDs:
      Evaluates to BoolVal(False) for internet reachability checks.
      This fails closed: an unknown service tag is isolated and not assumed to match arbitrary public internet traffic.
    """
    if prefix is None:
        return z3.BoolVal(False)

    if isinstance(prefix, (list, tuple)):
        exprs = [encode_source_prefix_expr(p, ip_sym) for p in prefix]
        return z3.Or(exprs) if exprs else z3.BoolVal(False)

    p_str = str(prefix).strip()

    if p_str in ("*", "0.0.0.0/0", "Internet"):
        return make_ip_in_cidr_expr(ip_sym, "0.0.0.0/0")

    if p_str == "VirtualNetwork":
        return make_ip_in_private_ranges_expr(ip_sym, PRIVATE_RANGES)

    if p_str == "AzureLoadBalancer":
        return make_ip_in_cidr_expr(ip_sym, "168.63.129.16/32")

    # Try parsing as concrete IPv4 CIDR or IP
    try:
        return make_ip_in_cidr_expr(ip_sym, p_str)
    except ValueError:
        # Fail closed for unrecognized service tags / ASG resource IDs
        return z3.BoolVal(False)


class AzureNSGEncoder:
    """
    SMT Encoder for Azure Network Security Group (NSG) rules.
    """

    def __init__(self, sensitive_ports: Optional[List[int]] = None):
        self.sensitive_ports = sensitive_ports or [21, 22, 23, 445, 3389]

    def encode_nsg_rules(
        self,
        rules: List[Dict[str, Any]],
        target_port: int = 22,
        target_protocol: str = "Tcp",
        target_dest_ip: Optional[str] = None,
        target_src_port: Optional[int] = None,
    ) -> Tuple[z3.BoolRef, z3.BitVecRef, z3.ArithRef, z3.BitVecRef, z3.ArithRef, List[Dict[str, Any]]]:
        """
        Encodes a list of Azure NSG rules into a Z3 priority chain formula.

        Priority Nesting Architecture:
        Rules are sorted by priority ascending (100, 200, ..., 65500).
        The nested z3.If chain is constructed by iterating through sorted_rules in REVERSE order:
            chain_expr = z3.If(rule_100, access_100, z3.If(rule_200, access_200, z3.If(rule_65500, access_65500, False)))

        This ensures priority 100 sits at the OUTERMOST z3.If node:
        If rule_100 matches, Z3 evaluates the then-branch immediately and never evaluates lower priority rules (shadowing).

        Returns (chain_expr, src_ip_sym, dest_port_sym, dest_ip_sym, src_port_sym, sorted_rules).
        """
        # Filter for Inbound rules
        inbound_rules = [
            r for r in rules
            if str(r.get("direction", "Inbound")).lower() == "inbound"
        ]

        # Sort rules by priority ascending
        sorted_rules = sorted(
            inbound_rules, key=lambda r: int(r.get("priority", 65535))
        )

        # Default Azure Inbound Rules
        default_rules = [
            {
                "name": "AllowVnetInBound",
                "priority": 65000,
                "direction": "Inbound",
                "access": "Allow",
                "protocol": "*",
                "source_address_prefix": "VirtualNetwork",
                "destination_address_prefix": "VirtualNetwork",
                "source_port_range": "*",
                "destination_port_range": "*",
            },
            {
                "name": "AllowAzureLoadBalancerInBound",
                "priority": 65001,
                "direction": "Inbound",
                "access": "Allow",
                "protocol": "*",
                "source_address_prefix": "AzureLoadBalancer",
                "destination_address_prefix": "*",
                "source_port_range": "*",
                "destination_port_range": "*",
            },
            {
                "name": "DenyAllInBound",
                "priority": 65500,
                "direction": "Inbound",
                "access": "Deny",
                "protocol": "*",
                "source_address_prefix": "*",
                "destination_address_prefix": "*",
                "source_port_range": "*",
                "destination_port_range": "*",
            },
        ]

        # Append defaults if not overridden by explicit priority
        existing_priorities = {int(r.get("priority", 0)) for r in sorted_rules}
        for d_rule in default_rules:
            if d_rule["priority"] not in existing_priorities:
                sorted_rules.append(d_rule)

        sorted_rules.sort(key=lambda r: int(r.get("priority", 65535)))

        ip_sym = z3.BitVec("src_ip", 32)
        port_sym = z3.Int("dest_port")
        dest_ip_sym = z3.BitVec("dest_ip", 32)
        src_port_sym = z3.Int("src_port")

        # Construct nested Z3 priority chain (first matching rule determines access)
        # Default base condition (if chain falls through completely) is False (Deny)
        chain_expr = z3.BoolVal(False)

        for rule in reversed(sorted_rules):
            access = str(rule.get("access", "Deny")).strip().capitalize()
            is_allow = access == "Allow"

            # Protocol match
            proto_val = str(rule.get("protocol", "*")).strip().capitalize()
            if proto_val in ("*", "Any"):
                proto_match = z3.BoolVal(True)
            else:
                target_proto_cap = target_protocol.strip().capitalize()
                proto_match = z3.BoolVal(proto_val == target_proto_cap)

            # Destination port match
            dest_port_val = rule.get("destination_port_range") or rule.get("destination_port_ranges")
            port_ranges = parse_port_range(dest_port_val)
            port_conds = [
                z3.And(port_sym >= low, port_sym <= high) for low, high in port_ranges
            ]
            port_match = z3.Or(port_conds) if port_conds else z3.BoolVal(True)

            # Source port match (ephemeral client ports typically wildcarded)
            src_port_val = rule.get("source_port_range") or rule.get("source_port_ranges")
            src_port_ranges = parse_port_range(src_port_val)
            if src_port_ranges == [(0, 65535)]:
                src_port_match = z3.BoolVal(True)
            else:
                src_port_match = z3.Or([
                    z3.And(src_port_sym >= low, src_port_sym <= high) for low, high in src_port_ranges
                ])

            # Source address prefix match
            src_prefix = rule.get("source_address_prefix") or rule.get("source_address_prefixes")
            src_match = encode_source_prefix_expr(src_prefix, ip_sym)

            # Destination address prefix match
            dest_prefix = rule.get("destination_address_prefix") or rule.get("destination_address_prefixes")
            if dest_prefix is None or str(dest_prefix).strip() in ("*", "0.0.0.0/0", "Internet"):
                dest_match = z3.BoolVal(True)
            else:
                dest_match = encode_source_prefix_expr(dest_prefix, dest_ip_sym)

            rule_match = z3.And(proto_match, port_match, src_port_match, src_match, dest_match)
            chain_expr = z3.If(rule_match, z3.BoolVal(is_allow), chain_expr)

        if target_dest_ip is not None:
            dest_ip_cond = make_ip_in_cidr_expr(dest_ip_sym, target_dest_ip)
            chain_expr = z3.And(dest_ip_cond, chain_expr)

        if target_src_port is not None:
            src_port_cond = (src_port_sym == target_src_port)
            chain_expr = z3.And(src_port_cond, chain_expr)

        return chain_expr, ip_sym, port_sym, dest_ip_sym, src_port_sym, sorted_rules

