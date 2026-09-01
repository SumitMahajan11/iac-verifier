from __future__ import annotations

from typing import List, Set, Tuple, Union
import z3

from encoder.cidr import (
    make_ip_in_cidr_expr,
    make_ip_in_private_ranges_expr,
    is_cidr_contained,
)
from parser.graph import Resource, SecurityGroupRule, Unresolved

SENSITIVE_PORTS: Set[int] = {21, 22, 23, 445, 3389}

# RFC 1918 Private Ranges + Loopback
PRIVATE_RANGES: List[str] = [
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "127.0.0.0/8",
]


def is_port_sensitive(from_port: int | None, to_port: int | None) -> bool:
    """
    Checks if a port range [from_port, to_port] covers any sensitive port (e.g. 22, 3389).
    Handles -1, 0, or None (all ports).
    """
    if from_port is None or to_port is None:
        return True
    if from_port <= 0 and to_port <= 0:
        return True
    for port in SENSITIVE_PORTS:
        if from_port <= port <= to_port:
            return True
    return False


def is_cidr_private(cidr_str: str) -> bool:
    """
    Returns True if cidr_str is fully contained within a private internal range.
    """
    return any(is_cidr_contained(cidr_str, priv) for priv in PRIVATE_RANGES)


def encode_sg_resource_symbolic(
    resource: Resource,
) -> Union[Tuple[z3.BitVecRef, z3.BoolRef], Unresolved]:
    """
    Encodes security group ingress rules into a genuine symbolic Z3 SMT BitVector formula.

    Creates a 32-bit BitVector variable 'src_ip' representing an arbitrary source IP.
    Returns:
    - (src_ip_var, unsafe_smt_formula): where unsafe_smt_formula asserts that 'src_ip' is
      allowed by an ingress rule on a sensitive port AND 'src_ip' is NOT in any private CIDR range.
    - Unresolved: if any rule source is unparseable (fail-closed).
    """
    src_ip = z3.BitVec(f"src_ip_{resource.address}", 32)
    rule_ip_matches: List[z3.BoolRef] = []

    for rule_src in resource.rule_sources:
        if isinstance(rule_src, Unresolved):
            return Unresolved(
                reason=f"Security group rule source is unresolved: {rule_src.reason}",
                expression=rule_src.expression,
            )

        if isinstance(rule_src, SecurityGroupRule):
            if any(isinstance(f, Unresolved) for f in (rule_src.protocol, rule_src.from_port, rule_src.to_port)):
                return Unresolved(
                    reason="Security group rule contains unresolved fields (protocol or ports)",
                    expression=None,
                )

            if rule_src.direction.lower() in ("ingress", "egress") and is_port_sensitive(
                rule_src.from_port, rule_src.to_port
            ):
                for cidr in rule_src.cidr_blocks:
                    if isinstance(cidr, Unresolved):
                        return Unresolved(
                            reason="Security group rule contains unresolved CIDR block",
                            expression=cidr.expression,
                        )
                    # Also skip ResourceReferences for CIDRs, or fail-closed?
                    # For safety, fail closed if we can't parse it as string.
                    if not isinstance(cidr, str):
                        return Unresolved(
                            reason=f"Security group rule contains non-string CIDR: {type(cidr)}",
                            expression=None,
                        )
                    rule_ip_matches.append(make_ip_in_cidr_expr(src_ip, cidr))

    if not rule_ip_matches:
        # No ingress rules on sensitive ports -> trivially safe
        return src_ip, z3.BoolVal(False)

    ip_is_allowed = z3.Or(rule_ip_matches)
    ip_is_private = make_ip_in_private_ranges_expr(src_ip, PRIVATE_RANGES)

    # Symbolic SMT Unsafe Predicate: IP is allowed on sensitive port AND IP is NOT private
    unsafe_formula = z3.And(ip_is_allowed, z3.Not(ip_is_private))

    return src_ip, unsafe_formula
