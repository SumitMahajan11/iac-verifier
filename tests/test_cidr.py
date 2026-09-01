import z3
from encoder.cidr import (
    cidr_to_bitvec_range,
    cidr_to_int_range,
    is_cidr_contained,
    is_cidr_overlapping,
    make_ip_in_cidr_expr,
    make_ip_in_private_ranges_expr,
)

PRIVATE_RANGES = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8"]


def test_cidr_0_0_0_0_slash_0():
    low, high = cidr_to_int_range("0.0.0.0/0")
    assert low == 0x00000000
    assert high == 0xFFFFFFFF

    bv_low, bv_high = cidr_to_bitvec_range("0.0.0.0/0")
    assert bv_low.as_long() == 0x00000000
    assert bv_high.as_long() == 0xFFFFFFFF


def test_symbolic_ip_in_cidr_expr():
    ip = z3.BitVec("test_ip", 32)
    expr = make_ip_in_cidr_expr(ip, "10.0.0.0/24")

    solver = z3.Solver()
    # Assert IP is 10.0.0.50 -> Should be SAT
    solver.add(expr)
    solver.add(ip == z3.BitVecVal(0x0A000032, 32))
    assert solver.check() == z3.sat

    solver2 = z3.Solver()
    # Assert IP is 10.0.1.50 -> Should be UNSAT
    solver2.add(expr)
    solver2.add(ip == z3.BitVecVal(0x0A000132, 32))
    assert solver2.check() == z3.unsat


def test_symbolic_private_ranges_expr():
    ip = z3.BitVec("test_ip", 32)
    priv_expr = make_ip_in_private_ranges_expr(ip, PRIVATE_RANGES)

    # 10.0.0.1 -> SAT
    s1 = z3.Solver()
    s1.add(priv_expr, ip == z3.BitVecVal(0x0A000001, 32))
    assert s1.check() == z3.sat

    # 8.8.8.8 (Public Google DNS) -> UNSAT for private ranges
    s2 = z3.Solver()
    s2.add(priv_expr, ip == z3.BitVecVal(0x08080808, 32))
    assert s2.check() == z3.unsat


def test_cidr_containment_not_equality():
    assert is_cidr_contained("10.0.0.0/24", "10.0.0.0/8") is True
    assert is_cidr_contained("10.0.0.0/8", "10.0.0.0/24") is False


def test_adjacent_non_overlapping_ranges():
    assert is_cidr_overlapping("10.0.0.0/24", "10.0.1.0/24") is False

    low1, high1 = cidr_to_int_range("10.0.0.0/24")
    low2, high2 = cidr_to_int_range("10.0.1.0/24")
    assert high1 + 1 == low2


def test_unaligned_host_ip_normalization():
    low, high = cidr_to_int_range("10.0.0.5/24")
    low_norm, high_norm = cidr_to_int_range("10.0.0.0/24")
    assert low == low_norm
    assert high == high_norm
