# IaC Verifier — Project Status

## Current Phase
**Current Status:** Fully Audited & Verified (215 Tests Passing, 1.0 Precision/Recall across AWS & Azure corpora)
**Next Planned Phase:** Repository archived/shelved in production-verified state.

## Exit Criteria Status
- [x] Phase 0: Project Scaffolding & Repository Governance Structure
- [x] Phase 1: AST Parsing & Structural Resource Graph Engine
- [x] Phase 2: Symbolic SMT Encoders & Hardened Solver Engine (Security Groups & IAM Wildcards)
- [x] Phase 3: Cross-Account Privilege Escalation Reachability Engine (BMC SMT Solver)
- [x] Phase 4: Hardened Benchmark Harness & Ground-Truth Labeled Public Corpora Evaluation (AWS Corpus: 28 total JSON entries / 27 evaluated cases + 1 ambiguous excluded fixture; 19 SAT, 6 UNSAT, 2 UNRESOLVABLE; 1.0 Precision, 1.0 Recall)
- [x] Phase 5: Multi-Cloud Expansion — Azure NSG SMT Priority & Explicit Allow/Deny Encoder (`encoder/azure_nsg_encoder.py`) [Fully Integrated with HCL Resource Graph, Multi-Port Unified UNSAT Proof Generation, Recursive Unresolved Gating]
- [x] Phase 6: Azure RBAC Privilege Escalation Reachability Engine (`graph/azure_trust_graph.py`) [Precise Scope Inheritance, Resolved Role Names, AD Group Fail-Closed Gating]
- [x] Phase 7: AST-Aware Auto-Repair Engine & Proof Certification (Format-preserving Lark AST node deletion)
- [x] Phase 8: CLI Interface & Integration
- [x] Phase 9: GitHub Action CI/CD Integration
- [x] Phase 10: ARM Native Template Support (`parser/arm_parser.py`) [JSON Template Extraction, Variable/Parameter Resolution, Dynamic Expression Fail-Closed Gating, Cross-Format RBAC/NSG Equivalence]
- [x] Phase 11: Azure Governance Rule Set Integration & Benchmark Corpus (`encoder/azure_policy_encoder.py`, `fixtures/phase11/azure_ground_truth.json`, `benchmark/azure_real_world_ground_truth.json`) [Azure Synthetic Corpus: 32 total JSON entries / 32 evaluated cases; 27 binary decidable (16 SAT, 11 UNSAT) + 5 UNRESOLVABLE; 1.0 Precision, 1.0 Recall, 100% Unresolvable Accuracy | Azure Real-World Corpus: 3 total entries / 3 evaluated cases; 3 binary decidable (1 SAT, 2 UNSAT); 1.0 Precision, 1.0 Recall]
- [x] Tier 1 Audit: Complete Corpus Audit & IAM Encoder Remediation (Heredoc parser bug fix, `NotAction` `z3.Not(z3.Or(...))` SMT encoding, fail-closed `is_unsupported_glob` for mid-string globs, verb-level wildcard spec reconciliation — **verified in commits `b915fb0`, `3b2a4a0`, `8f5d8a9`, `e8da6b3` / 2026-09-04**)
- [x] Tier 3 Part A: Compositional Incremental Verification (`verify_incremental` & subgraph cache invalidation)
- [x] Tier 3 Part B: Kubernetes Validating Admission Webhook (Live `kind` cluster `kubectl apply` verification — **verified live in commit `0081cd5` [supersedes `34f9df9`] / 2026-09-04**)
  > ✅ *Live Verification (commit `0081cd5`, 2026-09-04):* Re-provisioned `kind` cluster, deployed `iac-webhook` container, registered `ValidatingWebhookConfiguration`, and empirically verified admission pipeline: `unsafe_manifest.yaml` rejected with `[SG_OVER_EXPOSURE]` denial message, `safe_manifest.yaml` admitted successfully.
- [x] Z3 Performance Benchmarking: SMT Solver Overhead & Scaling Performance Baseline (`docs/z3_performance_report.md`)

*Note: AWS corpus comprises 28 total file entries (27 evaluated cases + 1 ambiguous case excluded per §4 spec). Azure synthetic corpus comprises 32 total file entries (all 32 evaluated: 27 binary decidable + 5 unresolvable cases). Azure real-world corpus comprises 3 case templates from Terragoat (`networking.tf`, `roles.tf`, `policies.tf`). Scope inheritance (e.g. management group overrides/exemptions) has zero real-world open-source coverage in public vulnerable repos and is documented as a permanent corpus limitation. Phase 11 precision and recall metrics reflect evaluation on both an author-written synthetic ground-truth corpus designed for specification verification, and a real-world corpus (Terragoat) for external validation, measuring different things but both achieving 1.0 precision and recall.

*Note on GCP Status: GCP parser scaffolding (`parser/gcp_parser.py`) is implemented for AST graph ingestion. SMT verification encoding for GCP is explicitly paused/deferred per ADR guidelines ("Azure real-world gap must be closed before GCP SMT solver implementation"). GCP SMT encoder functions remain unbuilt stub signatures (0% SMT precision/recall coverage).

## Test Suite Status
- **Pass Count:** 215 passed in ~8.4s
- **Line Coverage:** 89% overall across 215 tests
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
