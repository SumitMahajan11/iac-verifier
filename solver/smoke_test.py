import sys
import z3


def run_smoke_test() -> bool:
    """
    Smoke test to verify Z3 Python bindings end-to-end using z3.Solver().

    Validates both:
    1. SAT case: concrete satisfying model extraction and verification.
    2. UNSAT case: proof of unsatisfiability.
    """
    # -------------------------------------------------------------
    # 1. SAT Case
    # -------------------------------------------------------------
    solver_sat = z3.Solver()
    x = z3.Int("x")
    y = z3.Int("y")

    c1 = x > 0
    c2 = y > 0
    c3 = x + y == 10

    solver_sat.add(c1, c2, c3)
    res_sat = solver_sat.check()

    sat_passed = False
    if res_sat == z3.sat:
        model = solver_sat.model()
        x_val = model.eval(x).as_long()
        y_val = model.eval(y).as_long()
        print(f"[SAT Case] Result: SAT | Witness Model: x = {x_val}, y = {y_val}")

        # Verify model correctness programmatically
        if x_val > 0 and y_val > 0 and (x_val + y_val == 10):
            print("[SAT Case] PASS: Model satisfies all constraints (x > 0, y > 0, x + y == 10)")
            sat_passed = True
        else:
            print("[SAT Case] FAIL: Model does not satisfy constraints")
    else:
        print(f"[SAT Case] FAIL: Expected sat, got {res_sat}")

    # -------------------------------------------------------------
    # 2. UNSAT Case
    # -------------------------------------------------------------
    solver_unsat = z3.Solver()
    z = z3.Int("z")
    solver_unsat.add(z > 10, z < 5)
    res_unsat = solver_unsat.check()

    unsat_passed = False
    if res_unsat == z3.unsat:
        print("[UNSAT Case] Result: UNSAT | Solver proved no satisfying value exists for (z > 10 AND z < 5)")
        print("[UNSAT Case] PASS: Correctly proved unsatisfiability")
        unsat_passed = True
    else:
        print(f"[UNSAT Case] FAIL: Expected unsat, got {res_unsat}")

    # -------------------------------------------------------------
    # Overall Result
    # -------------------------------------------------------------
    overall_pass = sat_passed and unsat_passed
    print(f"\n[Overall Result] {'PASS' if overall_pass else 'FAIL'}: Z3 Solver API integration")
    return overall_pass


if __name__ == "__main__":
    success = run_smoke_test()
    sys.exit(0 if success else 1)
