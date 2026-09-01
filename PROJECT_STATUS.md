# IaC Verifier — Project Status

## Current Phase
**Current Status:** Phase 4 Comparative Evaluation Report Completed (tfsec/checkov Baseline Comparison)
**Next Planned Phase:** Project Handoff

## Exit Criteria Status
- [x] Phase 0: Project Scaffolding & Repository Governance Structure
- [x] Phase 1: AST Parsing & Structural Resource Graph Engine
- [x] Phase 2: Symbolic SMT Encoders & Hardened Solver Engine (Security Groups & IAM Wildcards)
- [x] Phase 3: Cross-Account Privilege Escalation Reachability Engine (BMC SMT Solver)
- [x] Phase 4: Hardened Benchmark Harness & Ground-Truth Labeled Public Corpora Evaluation (Terragoat & Sadcloud)

## Test Suite Status
- **Pass Count:** 84 passed in 1.16s
- **Verification Command:** `.\.venv\Scripts\python -m pytest -v`

## Active Scope & Design Decisions
- **Fail-Closed Unresolved Trust Gating:** Any unresolved role or principal reference anywhere in the infrastructure graph yields `UNRESOLVABLE` status globally for privilege escalation reachability.
- **Bounded Unreachability Proofs:** Complete proofs (`UNSAT`) guaranteed when `role_count <= configured_cap`. Graph sizes exceeding `configured_cap` output `UNSAT_BOUNDED`.
- **Pre-flight Differential Verification:** All benchmark evaluations gate on §10 differential verification check passing to ensure encoder correctness against raw SMT satisfiability.
- **Strict Fail-Loud Policy:** Missing target resources or parser errors in pre-flight differential verification trigger explicit errors rather than silent pass states.
