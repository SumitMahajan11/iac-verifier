# IaC Verifier — Project Status

## Current Phase
**Current Status:** Tier 3 Part B Live-Cluster Verification Completed (Kubernetes Validating Admission Webhook & Compositional Incremental Verification)
**Next Planned Phase:** Project Handoff / Complete

## Exit Criteria Status
- [x] Phase 0: Project Scaffolding & Repository Governance Structure
- [x] Phase 1: AST Parsing & Structural Resource Graph Engine
- [x] Phase 2: Symbolic SMT Encoders & Hardened Solver Engine (Security Groups & IAM Wildcards)
- [x] Phase 3: Cross-Account Privilege Escalation Reachability Engine (BMC SMT Solver)
- [x] Phase 4: Hardened Benchmark Harness & Ground-Truth Labeled Public Corpora Evaluation (Terragoat & Sadcloud)
- [x] Phase 6: Auto-Repair Engine & Proof Certification
- [x] Phase 7: CLI Interface & Integration
- [x] Phase 8: GitHub Action CI/CD Integration
- [x] Tier 3 Part A: Compositional Incremental Verification (`verify_incremental` & subgraph cache invalidation)
- [x] Tier 3 Part B: Kubernetes Validating Admission Webhook (Live `kind` cluster `kubectl apply` verification)

## Test Suite Status
- **Pass Count:** 113 passed in ~4.5s
- **Verification Command:** `.\.venv\Scripts\python -m pytest -v`

## Active Scope & Design Decisions
- **Fail-Closed Unresolved Trust Gating:** Any unresolved role or principal reference anywhere in the infrastructure graph yields `UNRESOLVABLE` status globally for privilege escalation reachability.
- **Bounded Unreachability Proofs:** Complete proofs (`UNSAT`) guaranteed when `role_count <= configured_cap`. Graph sizes exceeding `configured_cap` output `UNSAT_BOUNDED`.
- **Pre-flight Differential Verification:** All benchmark evaluations gate on §10 differential verification check passing to ensure encoder correctness against raw SMT satisfiability.
- **Strict Fail-Loud Policy:** Missing target resources or parser errors in pre-flight differential verification trigger explicit errors rather than silent pass states.
- **Live-Cluster Webhook Verification:** Single live integration test run against an ephemeral `kind` cluster with TLS cert / CA bundle registration, demonstrating genuine API server `kubectl apply` rejection (`unsafe-configmap.yaml`) and admission (`safe-configmap.yaml`). Handler unit testing is continuously automated in `pytest` (`TestClient`).

