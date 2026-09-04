# IaC Verifier — Project Status

## Current Phase
**Current Status:** Phase 11 Azure Governance Benchmark & Policy Encoder Verified (206 Tests Passing, 1.0 Precision/Recall)
**Next Planned Phase:** Multi-Cloud GCP Provider Integration & Policy Synthesis Engine

## Exit Criteria Status
- [x] Phase 0: Project Scaffolding & Repository Governance Structure
- [x] Phase 1: AST Parsing & Structural Resource Graph Engine
- [x] Phase 2: Symbolic SMT Encoders & Hardened Solver Engine (Security Groups & IAM Wildcards)
- [x] Phase 3: Cross-Account Privilege Escalation Reachability Engine (BMC SMT Solver)
- [x] Phase 4: Hardened Benchmark Harness & Ground-Truth Labeled Public Corpora Evaluation (Terragoat & Sadcloud)
- [x] Phase 5: Multi-Cloud Expansion — Azure NSG SMT Priority & Explicit Allow/Deny Encoder (`encoder/azure_nsg_encoder.py`) [Fully Integrated with HCL Resource Graph, Multi-Port Unified UNSAT Proof Generation, Recursive Unresolved Gating]
- [x] Phase 6: Azure RBAC Privilege Escalation Reachability Engine (`graph/azure_trust_graph.py`) [Precise Scope Inheritance, Resolved Role Names, AD Group Fail-Closed Gating]
- [x] Phase 7: AST-Aware Auto-Repair Engine & Proof Certification (Format-preserving Lark AST node deletion)
- [x] Phase 8: CLI Interface & Integration
- [x] Phase 9: GitHub Action CI/CD Integration
- [x] Phase 10: ARM Native Template Support (`parser/arm_parser.py`) [JSON Template Extraction, Variable/Parameter Resolution, Dynamic Expression Fail-Closed Gating, Cross-Format RBAC/NSG Equivalence]
- [x] Phase 11: Azure Governance Rule Set Integration & Benchmark Corpus (`encoder/azure_policy_encoder.py`, `fixtures/phase11/azure_ground_truth.json`) [28-Case Ground-Truth Corpus: 16 SAT, 11 UNSAT, 1 UNRESOLVABLE; Decidable Metrics: 1.0 Precision, 1.0 Recall, 1.0 F1 Score; 100% Unresolvable Accuracy]
- [x] Tier 3 Part A: Compositional Incremental Verification (`verify_incremental` & subgraph cache invalidation)
- [x] Tier 3 Part B: Kubernetes Validating Admission Webhook (Live `kind` cluster `kubectl apply` verification)
- [x] Z3 Performance Benchmarking: SMT Solver Overhead & Scaling Performance Baseline (`docs/z3_performance_report.md`)

*Note: Phase 11 precision and recall metrics reflect evaluation on an author-written synthetic ground-truth corpus designed for specification verification, distinct from third-party public benchmark suites (e.g. Terragoat/Sadcloud).

## Test Suite Status
- **Pass Count:** 206 passed in ~6.8s
- **Line Coverage:** 89% overall across 206 tests
- **Verification Command:** `python -m pytest --cov=. --cov-report=term-missing`



## Active Scope & Design Decisions
- **Azure Scope Inheritance & Isolation:** Refactored `is_scope_subsumed` in `graph/azure_trust_graph.py` to eliminate over-approximation string prefix bugs. Subscription-level and management-group scopes validate resource-specific metadata (`subscription_id`, `management_group_id`) to ensure strict isolation between distinct Azure subscriptions and prevent false-positive reachability findings across environments.
- **Role Name Resolution in Witness Output:** Implemented `_resolve_role_def_name` in `graph/azure_trust_graph.py` to resolve custom `azurerm_role_definition` references to their clean human-readable names (`CustomAuthAdmin`) prior to constructing trust statements, eliminating raw `ResourceReference` object leaks in witness output.
- **Fail-Closed Posture for Active Directory Groups:** Assignments using `azuread_group` or `azuread_group_member` principals are routed to `UNRESOLVABLE` status. Static group membership expansion requires runtime Microsoft Graph API calls; evaluating group permissions statically without directory state would violate zero-trust guarantees.
- **Cache-Key Parameter Compound Integration:** Extended `compute_cache_key` in `solver/engine.py` to compound `configured_cap` and `entry_principal` parameters into the verification hash, preventing stale cache returns when verifying the same graph across differing execution constraints.
- **Azure NSG Multi-Port UNSAT Proof Certificate Aggregation:** Refactored `verify_azure_nsg` in `solver/engine.py` to employ a two-step validation model. A unified SMT formula checking all sensitive ports (21, 22, 23, 445, 3389) simultaneously is executed first; on `UNSAT`, Z3 captures the unified proof object and returns non-empty `z3_proof_sexpr` for formal proof certification. On `SAT`, a secondary per-port analysis is executed to isolate specific violating sensitive ports for fine-grained witness generation.
- **AST-Aware Format-Preserving Auto-Repair:** Auto-repair engine replaces line-level regex patching with Lark AST span deletion (`solver/ast_repair.py`), eliminating HCL formatting corruption across brace-in-comment blocks, list attributes, and `jsonencode`-wrapped IAM policy statements while maintaining `REMEDIATED_MINIMAL` governance standards.
- **Fail-Closed Unresolved Trust Gating:** Any unresolved role or principal reference anywhere in the infrastructure graph yields `UNRESOLVABLE` status globally for privilege escalation reachability.
- **Bounded Unreachability Proofs:** Complete proofs (`UNSAT`) guaranteed when `role_count <= configured_cap`. Graph sizes exceeding `configured_cap` output `UNSAT_BOUNDED`.
- **Pre-flight Differential Verification:** All benchmark evaluations gate on §10 differential verification check passing to ensure encoder correctness against raw SMT satisfiability.
- **Strict Fail-Loud Policy:** Missing target resources or parser errors in pre-flight differential verification trigger explicit errors rather than silent pass states.
- **ARM JSON Scope & Bicep Transpilation Strategy:** Native parsing support is implemented specifically for ARM JSON templates (`parser/arm_parser.py`). Direct Bicep `.bicep` parsing is explicitly deferred; Bicep templates must be transpiled to ARM JSON via `bicep build <file.bicep>` prior to verification, preserving standard ARM JSON evaluation pipelines. Auto-repair for ARM JSON templates falls back to logical-only remediation to prevent structural AST corruption.
- **ARM Dynamic Function & `copy` Loop Fail-Closed Policy:** In `parser/arm_parser.py`, expressions containing unresolved dynamic runtime functions (`resourceId()`, `reference()`) or unsupported `copy` iteration loops evaluate to `Unresolved`. Templates containing unresolvable parameters, dynamic runtime functions, or `copy` loops yield `UNRESOLVABLE` verification status.
- **ARM `dependsOn` Dependency Parsing:** `dependsOn` arrays are parsed for resource reference strings to populate graph dependency edges. Dynamic or computed `dependsOn` expressions that cannot be statically resolved yield `Unresolved` and trigger fail-closed verification gating.
- **Fail-Closed Security Gating Unit Test Suite:** Implemented `tests/test_fail_closed_gating.py` to rigorously validate fail-closed logic across `sg_encoder.py` (unresolved rule sources, protocols, CIDRs, non-string CIDRs), `trust_graph.py` (dangling `ResourceReference` principals), `azure_trust_graph.py` (Active Directory group fail-closed trapping), `reachability_encoder.py` (empty entry-point or target-role sets short-circuiting to UNSAT), and `solver/engine.py` (Unresolved SG encoding -> UNRESOLVABLE status).
- **Diagnostic Script Organization & Coverage Attribution:** Moved standalone diagnostic and comparative analysis scripts (`compare.py`, `debug_*.py`, `get_checkov.py`, `scratch_repair.py`) into `scripts/debug/` to maintain clean repository layout. Aggregate coverage measurement (89%) reflects both the removal of diagnostic scripts from the coverage scan denominator and the introduction of the fail-closed security gating test suite (`tests/test_fail_closed_gating.py`).
