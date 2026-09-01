# Master Plan v3 — IaC Symbolic SMT Verifier & Auto-Repair Engine

## §1 Executive Summary & Core Objectives
Static Infrastructure-as-Code (IaC) security verifier utilizing Z3 SMT constraint solving for exact, cryptographic-grade reachability proofs, minimal deletion-based auto-repair, and proof certificate generation on Terraform infrastructure graphs.

---

## §2 Architecture & Core Components
1. **Parser & Graph Engine (`parser/`)**: HCL2 AST parsing, resource reference resolution, attachment merging, module expansion, and JSON string unwrapping.
2. **Trust Graph & Reachability Engine (`graph/`, `encoder/`)**: Dual-policy trust graph builder (`sts:AssumeRole`), dynamic BMC hop bound calculator, and Z3 String-theory reachability encoder.
3. **Solver Engine & Auto-Repair (`solver/`)**: Verification engine wrapping Z3 `Solver()`, deletion-based auto-repair implementing iterative subset-minimal search, and proof certificate generator (`SAT_WITNESS_TRACE` and `UNSAT_PROOF_CERTIFICATE`).
4. **CLI & GitHub Action (`cli/main.py`, `action.yml`)**: Automated verification and auto-repair interface with strict exit code gating (0/1/2).

---

## §8 Benchmark Methodology & Corpus Scale
The evaluation dataset consists of **26 total ground-truth cases** (18 real-world vulnerable and safe resources extracted from public benchmark corpora `bridgecrewio/terragoat` and `nccgroup/sadcloud`, plus 8 synthetic edge-case fixtures).
- **Corpus Resource Count**: Terragoat contains 86 total resources; Sadcloud contains 42 total resources (128 total resources).
- **Bounded Checkpoint Methodology**: The 26-case dataset is a bounded evaluation checkpoint specifically targeting all resources within the scope of the three modeled invariant classes (Security Group Over-Exposure, IAM Wildcard Allow, and Cross-Account Privilege Escalation Reachability).

---

## §9 Integration & Exit Code Specification
The CLI (`cli/main.py`) and GitHub Action (`action.yml`) enforce strict, deterministic exit codes per §9:
- `0`: **Success / Safe**: All checked invariants are verified UNSAT (safe), or auto-repair achieved `REMEDIATED_MINIMAL`.
- `1`: **Finding / SAT Vulnerability**: One or more invariants evaluated to SAT (vulnerability detected), or auto-repair failed.
- `2`: **Error / UNRESOLVABLE**: Engine exception, missing target, or unresolvable policy dependency.

---

## §13 Tier 3 Decision & Project Completion
Per §13 ("optional stretch"), Tier 3 features (Compositional Incremental Verification and Kubernetes Admission Webhook) are designated as optional stretch goals. Because all core Tier 1 (parsing, SMT encoding, privilege escalation reachability, benchmark evaluation) and Tier 2 (auto-repair, proof certification, CLI, GitHub Action integration) requirements are 100% complete and verified, the project cleanly concludes at Tier 2.

---

## §14 Phase Architecture & Plan Reconciliation
The table below reconciles the original Master Plan §14 phase structure with the actual build sessions:

| Plan §14 Phase | Original Plan Description | Actual Build Phase & Session | Status |
|---|---|---|---|
| Phase 0 | Scaffolding & Repository Governance | Phase 0 (Session 1) | DONE |
| Phase 1 | AST Parser & Structural Resource Graph Engine | Phase 1 (Session 1) | DONE |
| Phase 2 | Symbolic SMT Encoders (SG & IAM) | Phase 2 (Session 1) | DONE |
| Phase 3 | CLI Interface & Integration | Phase 7 (Session 9) | DONE |
| Phase 4 | Privilege Escalation Reachability Engine | Phase 3 & 5 (Sessions 1 & 8) | DONE |
| Phase 5 | Benchmark Harness & Comparative Evaluation | Phase 4 (Sessions 2, 3, 5, 6, 7) | DONE |
| Phase 6 | Auto-Repair Engine & Proof Certification | Phase 6 (Session 9) | DONE |
| Phase 7 | GitHub Action CI/CD Integration | Phase 8 (Session 10) | DONE |
| Phase 8 (Tier 3) | Incremental Verification / K8s Webhook | Tier 3 (Session 10) | UNTOUCHED (Declined per §13) |

---

## §16 Known Limitations (Consolidated)
1. **Account-ID Scope Boundary**: Static HCL resolution extracts and matches role targets via role resource names / ARNs (`aws_iam_role.<name>`). Account IDs declared within ARNs (e.g. `111122223333`) serve as entry point anchors, but cross-account ID validation across external AWS accounts is an accepted static analysis limitation of §7 modeling.
2. **IAM Precision Evaluation Circularity**: Support for `aws_iam_user_policy` and `aws_iam_group_policy` in the verification engine router was added in the same session as the true-negative test cases for those types. Consequently, IAM user/group policy precision against true negatives was not evaluated against a pre-existing held-out engine state.
3. **Benchmark Sample Size / Bounded Checkpoint**: The real-world evaluation dataset comprises 26 total cases (18 real-world resources from Terragoat/Sadcloud + 8 fixture edge-cases) out of 128 total resources in the corpora. This represents a bounded evaluation checkpoint over modeled SMT invariants rather than an exhaustive audit of all unmodeled terraform resource types.
4. **Candidate Prefiltering Heuristic vs True Z3 `unsat_core`**: The candidate prefiltering function `_prefilter_candidates_via_unsat_core` in `solver/repair.py` implements a heuristic pattern-matching prefilter based on vulnerability classes rather than extracting actual Z3 assumption-based SMT `unsat_core()` literals. If no heuristic rule matches, it safely falls back to evaluating all candidate rules, guaranteeing that subset-minimality is preserved.
5. **IAM Wildcard Pattern Scope Boundary**: Middle wildcards (e.g. `s3:Get*`) and suffix glob patterns (e.g. `arn:aws:s3:::*-logs`) fall through to exact string matching in v1, whereas full (`*`), service (`s3:*`), and trailing-prefix (`bucket/*`) wildcards are symbolically evaluated.
6. **Fail-Closed Unresolved Trust Gating**: Any unresolvable reference or invalid JSON expression in any `assume_role_policy` across the infrastructure graph causes the privilege escalation reachability verifier to return `UNRESOLVABLE` globally.

---

## §17 Terminology & Word-Choice Discipline
- `REMEDIATED_MINIMAL`: Strictly reserved for deletion-based repairs proven to be subset-minimal through full Z3 SMT re-verification.
- `UNSAT`: Mathematical proof of invariant safety within the modeled search bound.
- `SAT`: Mathematical proof of invariant violation with explicit counterexample witness trace.

---

## §18 Tier 3 Status
Tier 3 development is declined per §13 optional stretch rationale. All Tier 1 and Tier 2 exit criteria are fully satisfied.
