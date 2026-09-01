from solver.smoke_test import run_smoke_test


def test_z3_smoke_test():
    """Verify that Z3 SMT solver end-to-end smoke test passes."""
    assert run_smoke_test() is True
