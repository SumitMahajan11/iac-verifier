from __future__ import annotations

import pytest
from encoder.hop_bound import compute_hop_bound


def test_hop_bound_small_graph():
    k, is_complete = compute_hop_bound(role_count=4, configured_cap=10)
    assert k == 4
    assert is_complete is True


def test_hop_bound_large_graph():
    k, is_complete = compute_hop_bound(role_count=50, configured_cap=10)
    assert k == 10
    assert is_complete is False


def test_hop_bound_single_role():
    k, is_complete = compute_hop_bound(role_count=1, configured_cap=10)
    assert k == 1
    assert is_complete is True


def test_hop_bound_zero_roles():
    k, is_complete = compute_hop_bound(role_count=0, configured_cap=10)
    assert k == 0
    assert is_complete is True


def test_hop_bound_exact_cap():
    k, is_complete = compute_hop_bound(role_count=10, configured_cap=10)
    assert k == 10
    assert is_complete is True
