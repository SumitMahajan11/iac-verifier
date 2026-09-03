## Summary of Changes
Provide a brief summary of the changes introduced in this PR and the problem being solved.

## Related Issues
Fixes # (issue)

## PR Checklist
Please review and check all items that apply:

- [ ] **Ground-Truth Fixtures**: Added corresponding safe and unsafe `.tf` ground-truth fixtures under `fixtures/` or `tests/` for any new rules, resource types, or parser changes.
- [ ] **Verification Result Contract**: Verified that new checks return a valid `VerificationResult` (`SAT`, `UNSAT`, `UNSAT_BOUNDED`, `UNKNOWN`, or `UNRESOLVABLE`) with attached witnesses/proofs.
- [ ] **Fail-Closed Semantics**: Preserved zero-trust fail-closed behavior for solver timeouts, unresolved references, or unknown solver outcomes.
- [ ] **Test Suite Passing**: Ran `pytest -v` locally and confirmed all tests pass cleanly.
- [ ] **Submodules Verified**: Ensured submodules (`sadcloud`, `terragoat`) are updated (`git submodule update --init --recursive`).
