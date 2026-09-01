# IaC Verifier (`iac-verifier`)

Static IaC verifier using Z3 for SMT-based reachability proofs on Terraform infrastructure graphs.

---

## Current Status: Phase 6 Complete — Auto-Repair Engine & Proof Certification

### Core Architecture

1. **Parser & Graph Engine (`parser/`)**:
   * HCL2 parsing for Terraform resources (`aws_security_group`, `aws_security_group_rule`, `aws_iam_role`, `aws_iam_policy`, `aws_iam_role_policy`).
   * Explicit `ResourceReference` modeling for structural graph dependencies.
   * Standalone attachment merging (Security Group ingress/egress rules and IAM role policy attachments).
   * Module expansion (`count`, `for_each`) and environment variable / local resolution.
   * Native JSON string unwrapping (`jsonencode(...)`) with fail-closed safety posture on unparseable expressions (`Unresolved`).

2. **Trust Graph & Reachability Engine (`graph/`, `encoder/`)**:
   * **Dual-Policy Trust Graph Construction (`graph/trust_graph.py`)**: Models `sts:AssumeRole` assumptions as an intersection of target role trust policies (`assume_role_policy`) and source role identity policies (attached `aws_iam_role_policy`). Maps internal roles, external AWS account entry points (`account:<account_id>`), and directed assumption edges.
   * **Bounded Model Checking Hop Bound (`encoder/hop_bound.py`)**: Dynamically computes hop bound `k = min(configured_cap, role_count)` and complete proof flag `is_complete = role_count <= configured_cap`.
   * **Reachability BMC SMT Encoding (`encoder/reachability_encoder.py`)**: Encodes multi-hop reachability over Z3 String variables `[hop_0, ..., hop_k]` representing node state at each step, with valid transition disjuncts and self-loops (stuttering steps).

3. **Solver Engine & Auto-Repair (`solver/`)**:
   * Verification engine wrapping Z3 `Solver()` with an iterative shortening loop (`k=1..N`) to guarantee shortest-reachable path extraction.
   * **Auto-Repair Engine (`solver/repair.py`)**: Deletion-based repair implementing iterative subset-minimal search ($k=1, 2, \dots$). Adheres to §17 word-choice discipline (`REMEDIATED_MINIMAL` strictly reserved for subset-minimal fixes verified via full re-verification).
   * **Proof Certification (`solver/certificates.py`)**: Generates structured JSON certificates (`SAT_WITNESS_TRACE` and `UNSAT_PROOF_CERTIFICATE`) with genuine Z3 proof s-expressions and tracked rule-to-literal mappings (`track__<resource_id>__<statement_index>`).
   * Produces structured `VerificationResult` outputs (`SAT`, `UNSAT`, `UNSAT_BOUNDED`, `UNKNOWN`, `UNRESOLVABLE`).

---

## §5 IAM, Network & Role Reachability Scope Boundaries

### Environment Note: Z3 Version
* **Z3 Package**: Uses `z3-solver==5.1.0.0` wheel (`z3.get_version()` returns tuple `(5, 1, 0, 0)`). Note that PyPI distribution versions for `z3-solver` may use 5.x versioning tags.

### Network CIDR Semantics
* Evaluates IPv4 address space symbolically using 32-bit BitVector arithmetic.
* Unaligned host IP addresses (e.g. `10.0.0.5/24`) are normalized to strict network CIDR boundaries (`10.0.0.0/24`).

### IAM Wildcard Pattern Matching (v1 Scope Boundary)
* **Supported Wildcard Patterns**:
  * Full wildcards: `*`, `*/*`
  * Service wildcards: `s3:*`, `ec2:*`, `iam:*`, etc.
  * Trailing-prefix wildcards: `arn:aws:s3:::my-bucket/*`
* **v1 Scope Boundary**: Middle wildcards (e.g. `s3:Get*`) or suffix/arbitrary glob patterns (e.g. `arn:aws:s3:::*-logs`) fall through to exact string matching.
* **Deny Precedence**: Explicit `Deny` statements override `Allow` statements on matching actions and resources while leaving non-denied wildcard permissions active for SMT reachability queries.

### Privilege Escalation & Trust Graph Design Decisions
* **Global Unresolved-Role Gating**: If any IAM role in the resource graph contains unresolvable references or invalid expressions in its `assume_role_policy`, the reachability verifier returns `UNRESOLVABLE` globally. This enforces a strict fail-closed safety posture across the infrastructure graph.
* **Account-ID Scope Boundary**: Static HCL resolution extracts and matches role targets via role resource names / ARNs (`aws_iam_role.<name>`). Account IDs declared within ARNs (e.g., `111122223333`) serve as entry point anchors, but account-ID cross-validation across static roles is an accepted, documented limitation of §7 static analysis (modeling role-name reachability within the analyzed IaC scope).
* **Bounded Unreachability**: Complete proofs of unreachability (`UNSAT`) are guaranteed when `role_count <= configured_cap`. For graphs exceeding the hop cap, non-reachability within $k$ steps is reported as `UNSAT_BOUNDED`.

---

## Verification & Testing

* Full test suite: **91 passing tests** (`.\.venv\Scripts\python -m pytest -v`).
* Golden Terraform fixtures for SG over-exposure, adjacent CIDRs, IAM wildcard permissions, Deny narrowing, JSON unwrapping, direct privilege escalation, chained escalation, safe isolated graphs, realistic 3+ hop adversarial chains with blocked hops, unresolvable trust references, multi-rule vulnerability deletion, and deterministic minimal fix selection.

