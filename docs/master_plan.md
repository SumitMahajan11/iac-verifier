# Master Plan v3 — IaC Symbolic SMT Verifier & Auto-Repair Engine

## §1 Executive Summary & Core Objectives
Static Infrastructure-as-Code (IaC) security verifier utilizing Z3 SMT constraint solving for exact, cryptographic-grade reachability proofs, minimal deletion-based auto-repair, and proof certificate generation on Terraform infrastructure graphs.

The verifier translates Terraform HCL configurations (`aws_security_group`, `aws_security_group_rule`, `aws_iam_role`, `aws_iam_policy`, `aws_iam_role_policy`) into first-order logic formulas to decide three security property classes:
1. **Security Group Over-Exposure (`SG_OVER_EXPOSURE`)**: Reachability of sensitive ports (21, 22, 23, 445, 3389) from public IPv4 ranges (`0.0.0.0/0`).
2. **IAM Wildcard Permissions (`IAM_WILDCARD_ALLOW`)**: Granting unscoped wildcard action (`*` or `service:*`) and resource (`*`) permissions without narrowing `Deny` statements.
3. **Cross-Account Privilege Escalation Reachability (`PRIVILEGE_ESCALATION_PATH`)**: Multi-hop `sts:AssumeRole` reachability paths from entry-point roles to high-privilege target roles via Bounded Model Checking (BMC).

---

## §2 Architecture & Core Components
1. **Parser & Graph Engine (`parser/`)**: HCL2 AST parsing, resource reference resolution, attachment merging, module expansion (`count`, `for_each`), and JSON string unwrapping (`jsonencode`).
2. **Trust Graph & Reachability Engine (`graph/`, `encoder/`)**: Dual-policy trust graph builder (`sts:AssumeRole`), dynamic BMC hop bound calculator ($k = \min(\text{cap}, \text{role\_count})$), and Z3 String-theory reachability encoder.
3. **Solver Engine & Auto-Repair (`solver/`)**: Verification engine wrapping Z3 `Solver()`, deletion-based auto-repair implementing iterative subset-minimal search, and proof certificate generator (`SAT_WITNESS_TRACE` and `UNSAT_PROOF_CERTIFICATE`).
4. **CLI & GitHub Action (`cli/main.py`, `action.yml`)**: Automated verification and auto-repair interface with strict exit code gating (0/1/2).

---

## §3 Context & Problem Statement
Traditional IaC static analyzers (e.g. Checkov, TFSec) rely on pattern-matching linters and regex rules. This leads to two major failure modes:
1. **High False Positive Rates**: Linters flag safe resources due to unrelated missing fields (e.g. missing descriptions or unattached security groups) rather than genuine property violations.
2. **Inability to Reason About Reachability**: Linters cannot prove multi-step transitive trust relationships across IAM role assumptions or evaluate BitVector CIDR arithmetic containment.

The IaC SMT Verifier resolves these limitations by transforming infrastructure definitions into formal mathematical constraints and querying Z3 for exact satisfiability (`SAT` = vulnerability witness, `UNSAT` = formal proof of safety).

---

## §4 Goals & Non-Goals

### Goals
- Cryptographic-grade mathematical proofs of unreachability (`UNSAT`) within specified search bounds.
- Counterexample witness generation (`SAT_WITNESS_TRACE`) providing concrete paths for detected vulnerabilities.
- Subset-minimal deletion-based auto-repair with full re-verification gating.
- Fail-closed security posture on unresolved data or unparseable expressions (`UNRESOLVABLE`).
- Zero false positives on evaluated security group and IAM invariants.

### Non-Goals
- Runtime state analysis or live AWS cloud environment querying (static HCL code analysis only).
- Dynamic HCL expression evaluation for arbitrary arbitrary third-party Terraform provider plugins outside AWS core IAM/Network resources.
- Heuristic best-practice linter checks (e.g. tagging enforcement, description formatting).

---

## §5 IAM, Network & Role Reachability Scope Boundaries

### Network CIDR Semantics
- IPv4 address space is evaluated symbolically using 32-bit BitVector arithmetic (`z3.BitVecVal`).
- Unaligned host IP addresses (e.g. `10.0.0.5/24`) are normalized to strict network CIDR boundaries (`10.0.0.0/24`).

### IAM Wildcard Pattern Matching (v1 Scope)
- **Supported Wildcard Patterns**:
  - Full wildcards: `*`, `*/*`
  - Service wildcards: `s3:*`, `ec2:*`, `iam:*`
  - Trailing-prefix wildcards: `arn:aws:s3:::my-bucket/*`
- **v1 Scope Boundary**: Middle wildcards (e.g. `s3:Get*`) or suffix/arbitrary glob patterns (e.g. `arn:aws:s3:::*-logs`) fall through to exact string matching.
- **Deny Precedence**: Explicit `Deny` statements override `Allow` statements on matching actions and resources while leaving non-denied wildcard permissions active for SMT reachability queries.

### Privilege Escalation & Trust Graph Design
- **Global Unresolved-Role Gating**: If any IAM role in the resource graph contains unresolvable references or invalid expressions in its `assume_role_policy`, the reachability verifier returns `UNRESOLVABLE` globally.
- **Account-ID Scope Boundary**: Role targets are resolved and matched via role resource names / ARNs (`aws_iam_role.<name>`). Account IDs declared within ARNs serve as entry point anchors; cross-account ID validation across external AWS accounts is an accepted static analysis scope boundary.

---

## §6 CIDR & IP Address SMT Encoding Semantics
- Security Group ingress/egress rules are converted into Z3 BitVector range constraints (`ip >= net_start AND ip <= net_end`).
- Sensitive port ranges (21, 22, 23, 445, 3389) are checked against public range `0.0.0.0/0` via BitVector intersection disjuncts.
- Contiguous and adjacent CIDR blocks (e.g., `10.0.0.0/24` and `10.0.1.0/24`) are proven safe if they do not intersect public IPv4 space (`0.0.0.0/0`).

---

## §7 Privilege-Escalation Resolution & Graph Construction
- **Dual-Policy Verification**: An assumption edge `Role_A -> Role_B` requires BOTH:
  1. Target `Role_B`'s `assume_role_policy` allows `sts:AssumeRole` to `Role_A` (or wildcard/account principal).
  2. Source `Role_A`'s identity policy allows `sts:AssumeRole` targeting `Role_B` (or wildcard resource ARN).
- **BMC Hop Bound Calculation**: Dynamically computes bound $k = \min(\text{configured\_cap}, \text{role\_count})$.
- **Completeness Proof**: If $\text{role\_count} \le \text{configured\_cap}$, an `UNSAT` result guarantees complete unreachability. If $\text{role\_count} > \text{configured\_cap}$, an `UNSAT` result is reported as `UNSAT_BOUNDED`.

---

## §8 Benchmark Methodology & Corpus Scale
The evaluation dataset consists of **26 total ground-truth cases** (18 real-world vulnerable and safe resources extracted from public benchmark corpora `bridgecrewio/terragoat` and `nccgroup/sadcloud`, plus 8 synthetic edge-case fixtures).
- **Corpus File & Resource Count**:
  - `bridgecrewio/terragoat`: 47 `.tf` files containing **133 parsed HCL AST resources** (4 Security Group, 5 IAM).
  - `nccgroup/sadcloud`: 72 `.tf` files containing **90 parsed HCL AST resources** (14 Security Group, 12 IAM).
  - **Total Corpus Resource Count**: **223 total resources** across 119 Terraform files.
- **Bounded Checkpoint Methodology**: The 26-case dataset is a bounded evaluation checkpoint specifically targeting all resources within the scope of the three modeled invariant classes (Security Group Over-Exposure, IAM Wildcard Allow, and Cross-Account Privilege Escalation Reachability).

---

## §9 Integration & Exit Code Specification
The CLI (`cli/main.py`) and GitHub Action (`action.yml`) enforce strict, deterministic exit codes per §9:
- `0`: **Success / Safe**: All checked invariants are verified UNSAT (safe), or auto-repair achieved `REMEDIATED_MINIMAL`.
- `1`: **Finding / SAT Vulnerability**: One or more invariants evaluated to SAT (vulnerability detected), or auto-repair failed.
- `2`: **Error / UNRESOLVABLE**: Engine exception, missing target, or unresolvable policy dependency.

---

## §10 Encoder Correctness & Differential Verification
- Pre-flight differential verification (`benchmark/differential_check.py`) executes prior to benchmark metrics reporting.
- Verifies that high-level verifier outputs (`SAT`/`UNSAT`) strictly match direct Z3 AST solver satisfiability check results.
- Gated on a strict fail-loud policy: any parser error or missing target resource triggers an explicit error rather than a silent pass.

---

## §11 Terraform Variable Resolution & Module Expansion
- **Module Expansion**: Expands `count` (literal integers & variable expressions) and `for_each` (maps & sets) into concrete AST resource instances (`resource.name[0]`, `resource.name["key"]`).
- **Local & Variable Chaining**: Resolves variable defaults, `terraform.tfvars`, chained `locals`, and module input/output parameters across local module directories (`./`, `../`).
- **Unresolved Handling**: External data sources (`data.aws_...`) and uninstantiated remote module inputs return `Unresolved` instances, maintaining fail-closed posture (`UNRESOLVABLE`).

---

## §12 N:1 Attachment Cardinality & Attachment Merging
- **Security Group Rules**: Merges inline `ingress`/`egress` blocks and standalone `aws_security_group_rule` resources attaching via `security_group_id`.
- **IAM Policy Attachments**: Merges inline `policy` blocks, standalone `aws_iam_role_policy`, `aws_iam_user_policy`, and `aws_iam_group_policy` resources.
- **Ambiguity Policy**: If an attachment reference cannot be uniquely resolved to a single target resource, attachment merging fails safely, flagging the resource for fail-closed evaluation.

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

## §15 Dev Workflow Loop & Testing Discipline
- **TDD Requirement**: All features and fixes follow strict Test-Driven Development (Red-Green-Refactor).
- **Mandatory Verification**: Every code modification must end with running the full pytest suite (`.\.venv\Scripts\python -m pytest -v`) with 100% pass rate.
- **Fixture Discipline**: Unit and integration test fixtures are stored in structured subdirectories under `fixtures/phaseX/`.

---

## §16 Known Limitations (Consolidated)
1. **Account-ID Scope Boundary**: Static HCL resolution extracts and matches role targets via role resource names / ARNs (`aws_iam_role.<name>`). Account IDs declared within ARNs (e.g. `111122223333`) serve as entry point anchors, but cross-account ID validation across external AWS accounts is an accepted static analysis limitation of §7 modeling.
2. **IAM Precision Evaluation Circularity**: Support for `aws_iam_user_policy` and `aws_iam_group_policy` in the verification engine router was added in the same session as the true-negative test cases for those types. Consequently, IAM user/group policy precision against true negatives was not evaluated against a pre-existing held-out engine state.
3. **Benchmark Sample Size / Bounded Checkpoint**: The real-world evaluation dataset comprises 26 total cases (18 real-world resources from Terragoat/Sadcloud + 8 fixture edge-cases) out of 223 total resources in the corpora. This represents a bounded evaluation checkpoint over modeled SMT invariants rather than an exhaustive audit of all unmodeled terraform resource types.
4. **Candidate Prefiltering Heuristic vs True Z3 `unsat_core`**: The candidate prefiltering function `_prefilter_candidates_via_unsat_core` in `solver/repair.py` implements a heuristic pattern-matching prefilter based on vulnerability classes rather than extracting actual Z3 assumption-based SMT `unsat_core()` literals. If no heuristic rule matches, it safely falls back to evaluating all candidate rules, guaranteeing that subset-minimality is preserved.
5. **IAM Wildcard Pattern Scope Boundary**: Middle wildcards (e.g. `s3:Get*`) and suffix glob patterns (e.g. `arn:aws:s3:::*-logs`) fall through to exact string matching in v1, whereas full (`*`), service (`s3:*`), and trailing-prefix (`bucket/*`) wildcards are symbolically evaluated.
6. **Fail-Closed Unresolved Trust Gating**: Any unresolvable reference or invalid JSON expression in any `assume_role_policy` across the infrastructure graph causes the privilege escalation reachability verifier to return `UNRESOLVABLE` globally.

---

## §17 Terminology & Word-Choice Discipline
- `REMEDIATED_MINIMAL`: Strictly reserved for deletion-based repairs proven to be subset-minimal through full Z3 SMT re-verification.
- `UNSAT`: Mathematical proof of invariant safety within the modeled search bound.
- `SAT`: Mathematical proof of invariant violation with explicit counterexample witness trace.

---

## §18 Tier 3 Status & Exit Criteria
Tier 3 development is declined per §13 optional stretch rationale. All Tier 1 and Tier 2 exit criteria are fully satisfied.
