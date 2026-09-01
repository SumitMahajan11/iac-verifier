import ipaddress
import z3
from typing import List, Tuple


def cidr_to_int_range(cidr_str: str) -> Tuple[int, int]:
    """
    Parses an IPv4 CIDR string (e.g., '10.0.0.5/24' or '0.0.0.0/0')
    and returns the inclusive (low_int, high_int) 32-bit unsigned integer range.
    Automatically normalizes host bits (strict=False).
    """
    clean_str = cidr_str.strip().strip('"').strip("'")
    if "/" not in clean_str:
        clean_str = f"{clean_str}/32"

    network = ipaddress.IPv4Network(clean_str, strict=False)
    low_int = int(network.network_address)
    high_int = int(network.broadcast_address)
    return low_int, high_int


def cidr_to_bitvec_range(cidr_str: str) -> Tuple[z3.BitVecNumRef, z3.BitVecNumRef]:
    """
    Converts an IPv4 CIDR string to a tuple of Z3 32-bit BitVector values (low, high).
    """
    low_int, high_int = cidr_to_int_range(cidr_str)
    return z3.BitVecVal(low_int, 32), z3.BitVecVal(high_int, 32)


def make_ip_in_cidr_expr(ip_var: z3.BitVecRef, cidr_str: str) -> z3.BoolRef:
    """
    Generates a symbolic Z3 BitVector constraint asserting that 32-bit IP variable ip_var
    falls inclusively within the range of cidr_str using unsigned BitVector comparisons (UGE, ULE).
    """
    low_val, high_val = cidr_to_bitvec_range(cidr_str)
    return z3.And(z3.UGE(ip_var, low_val), z3.ULE(ip_var, high_val))


def make_ip_in_private_ranges_expr(
    ip_var: z3.BitVecRef, private_cidrs: List[str]
) -> z3.BoolRef:
    """
    Generates a symbolic Z3 BitVector constraint asserting that ip_var is contained
    within at least one of the private RFC1918/loopback CIDR ranges.
    """
    return z3.Or([make_ip_in_cidr_expr(ip_var, cidr) for cidr in private_cidrs])


def is_cidr_overlapping(cidr1: str, cidr2: str) -> bool:
    """
    Returns True if two CIDRs overlap, evaluated via integer range intersection.
    """
    low1, high1 = cidr_to_int_range(cidr1)
    low2, high2 = cidr_to_int_range(cidr2)
    return max(low1, low2) <= min(high1, high2)


def is_cidr_contained(inner_cidr: str, outer_cidr: str) -> bool:
    """
    Returns True if inner_cidr is completely contained within outer_cidr.
    """
    low_in, high_in = cidr_to_int_range(inner_cidr)
    low_out, high_out = cidr_to_int_range(outer_cidr)
    return low_out <= low_in and high_in <= high_out
