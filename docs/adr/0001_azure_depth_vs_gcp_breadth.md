# ADR 0001: Prioritizing Azure Validation Rigor & Benchmark Depth Over Immediate GCP Expansion

* **Status:** Accepted
* **Date:** 2026-09-04
* **Deciders:** Principal Architect / Maintainer
* **Technical Context:** Z3 SMT-Based IaC Verification Engine (Python/Z3, AWS IAM/NSG, Azure NSG/RBAC/ARM)

---

## 1. Context and Problem Statement

The IaC Verifier project is a formal verification engine built using Z3 SMT to prove security reachability and IAM privilege-escalation invariants in Infrastructure-as-Code (Terraform HCL and Azure ARM JSON). The target positioning for this solo-developer portfolio project is **Senior/Staff-Level Software Engineering** (Infrastructure / Security / Formal Verification), where all engineering claims must be **evidence-gated and empirically backed**.

As of September 2026, the project status is as follows:
* **AWS (HCL):** Fully mature. Supported by a 27-case ground-truth benchmark corpus (Terragoat, Sadcloud, adversarial fixtures) achieving **1.0 Precision / 1.0 Recall** against Checkov/TFSec baselines.
* **Azure (HCL + ARM JSON):** Functionally complete SMT logic encoders for NSG rule evaluation and RBAC trust graph reachability (`encoder/azure_nsg_encoder.py`, `graph/azure_trust_graph.py`), supported by 195 passing unit/integration tests. **However, Azure currently lacks an equivalent ground-truth benchmark corpus.** This represents a real, named empirical validation gap.
* **GCP:** Zero existing code, zero parser integration, zero SMT encoders, and zero trust graph semantics.

### Strategic Question
Should the next major scope addition to this IaC verifier be:
1. **Option A:** GCP support as a new cloud provider tier (Breadth-First)?
2. **Option B:** Deepening Azure/ARM validation rigor (27-case ground-truth benchmark corpus, Azure Governance policy integration) before adding a third cloud (Depth-First)?
3. **Option C:** Deferring both in favor of the internal AWS edge-case backlog (Internal Refactoring)?

---

## 2. Decision Drivers

1. **Evidence-Gated Claim Integrity:** The project's core differentiator is mathematical rigor backed by empirical precision/recall evidence. Documenting support for a cloud provider without an empirical ground-truth benchmark compromises staff-level credibility.
2. **Portfolio Impact & Interview Vulnerability:** In senior/staff technical interviews, claiming "multi-cloud support" with unverified solvers creates a critical weakness if an interviewer asks for benchmark validation data on Azure or GCP.
3. **Cross-Format Verification Rigor:** Azure is unique in requiring dual-format parity (Terraform HCL and native Azure ARM JSON). Proving zero-drift SMT equivalence across formats is a high-value technical highlight.
4. **Timeline & Solo Developer Bandwidth:** As a CSE student progressing toward graduation in March 2028, engineering bandwidth must be spent on high-ROI depth rather than maintaining a shallow multi-cloud facade.

---

## 3. Detailed Evaluation of Options

### Option A: Add GCP Support Now (Breadth-First)

* **Implementation Cost:** **Extremely High (~120–160 hours)**. Requires building a Google Cloud HCL parser wrapper, GCP resource graph generator, GCP firewall SMT encoder (priority rules, target tags, service accounts), GCP IAM trust graph model (Service Account Impersonation, Workload Identity Federation), and GCP benchmark harness integration from scratch.
* **Portfolio Claim:** *"Tri-cloud (AWS, Azure, GCP) formal IaC verifier."*
* **Risk of Leaving Azure Benchmark Gap Unaddressed:** **Critical Risk**. Introduces a third cloud provider while Azure remains empirically unbenchmarked. The repository would contain one verified cloud (AWS with 27 benchmark cases) and two unverified clouds (Azure with 0 benchmark cases, GCP with 0 benchmark cases). This directly violates the project's "evidence-gated claims only" principle.
* **Portfolio Credibility Critique:** In a staff-level interview, an interviewer reviewing the benchmark harness will quickly discover that 66% of the supported cloud providers have no ground-truth benchmark validation. The "tri-cloud verifier" claim collapses into a shallow multi-cloud demo.
* **Timeline Fit (Sept 2026 – March 2028):** Consumes massive solo bandwidth early on, accumulating significant technical and benchmark debt across both Azure and GCP.

---

### Option B: Deepen Azure/ARM Validation Rigor First (Depth-First) — RECOMMENDED

* **Implementation Cost:** **Moderate / Low Risk (~30–45 hours)**. Azure NSG and RBAC encoders are already implemented and passing 195 unit/integration tests. The technical design for Phase 11 (Azure Governance Rule Set & 27-Case Corpus) is fully specified in `docs/azure_governance_benchmark_design.md`.
* **Portfolio Claim:** *"Dual-cloud (AWS + Azure) formal verification engine backed by empirical ground-truth benchmark corpora (54 total cases: 27 AWS + 27 Azure) proving 1.0 Precision / 1.0 Recall across Terraform HCL and Azure ARM JSON."*
* **Risk of Leaving Azure Benchmark Gap Unaddressed:** **Zero Risk**. Completely closes the Azure empirical validation gap. Upgrades Azure from "unit-tested" to "ground-truth benchmark certified" alongside AWS.
* **Portfolio Credibility Critique:** Exceptional staff-level positioning. Demonstrates engineering discipline: *the maintainer refuses to declare a cloud provider fully supported until an empirical ground-truth benchmark is published*. Proves dual-format AST-to-SMT parity between HCL and ARM JSON.
* **Timeline Fit (Sept 2026 – March 2028):** Ideal fit. Completing Phase 11 by Q4 2026 establishes a bulletproof AWS+Azure core with 54 ground-truth benchmark cases, leaving 2027 open for advanced capabilities (e.g., live cluster webhook scaling, dynamic evaluation, or GCP as an optional Phase 12).

---

### Option C: Defer Both in Favor of AWS Edge-Case Backlog (Internal Hardening)

* **Implementation Cost:** **Low (~20–30 hours)**. Focuses on AWS IAM `Condition` block evaluation edge cases and internal refactoring.
* **Portfolio Claim:** *"Deep single-cloud (AWS) formal verifier with advanced IAM condition evaluation."*
* **Risk of Leaving Azure Benchmark Gap Unaddressed:** **High Risk**. Leaves the existing Azure encoders (`encoder/azure_nsg_encoder.py`) in an incomplete state from a benchmarking standpoint, wasting the investment already made in Azure SMT logic.
* **Portfolio Credibility Critique:** Reduces multi-cloud narrative without adding significant new formal verification primitives.
* **Timeline Fit (Sept 2026 – March 2028):** Fits easily into the timeline, but underutilizes available engineering capacity.

---

## 4. Summary Matrix

| Metric / Dimension | Option A: GCP Support Now (Breadth) | Option B: Deepen Azure First (Depth) | Option C: AWS Backlog (Defer Both) |
| :--- | :--- | :--- | :--- |
| **Implementation Cost** | High (120–160 hrs) | Moderate (30–45 hrs) | Low (20–30 hrs) |
| **Ground-Truth Benchmark Parity** | ❌ 1 of 3 Clouds Verified (33%) | ✅ 2 of 2 Clouds Verified (100%) | ❌ 1 of 2 Clouds Verified (50%) |
| **Evidence-Gated Portfolio Claim** | Weak (Shallow 3-cloud facade) | Strong (54-case empirical proof) | Moderate (AWS-only depth) |
| **Cross-Format Parity (HCL vs JSON)** | No | Yes (HCL vs ARM JSON proved) | No |
| **Risk of Unverified Claims** | High (Azure & GCP unverified) | None (All claimed clouds benchmarked) | Moderate (Azure unbenchmarked) |
| **Timeline Alignment (Thru Mar 2028)** | High risk of burnout/debt | Optimal (Solid base by Q4 2026) | Low ROI on solo bandwidth |

---

## 5. Decision & Recommendation

### Decision
**We explicitly select Option B: Deepening Azure/ARM Validation Rigor (Phase 11) before considering GCP expansion.**

### Architectural Rationale
1. **Closing the Named Gap:** Azure code exists in the codebase today (`encoder/azure_nsg_encoder.py`, `graph/azure_trust_graph.py`) and passes 195 tests. Shipping GCP without a ground-truth benchmark for Azure leaves an explicit, named gap in the repository's evaluation framework.
2. **Empirical Integrity Over Marketing Breadth:** In senior engineering roles, depth of verification and empirical proof beat superficial feature counts. A verifier with 54 ground-truth benchmark cases across AWS and Azure achieving 1.0 precision/recall is defensible under rigorous technical questioning.
3. **Proving Cross-Format Parity:** Azure allows the project to demonstrate formal verification across two distinct IaC syntaxes—Terraform HCL and native Azure ARM JSON—proving that the underlying Z3 SMT graph abstractions are format-agnostic.

### Explicit Trade-Offs Accepted
* **Deferred GCP Marketing Claim:** GCP will not be supported in Phase 11. Any mention of GCP in documentation will be categorized under *Future Roadmap (Phase 12+)*.
* **Opportunity Cost of Third Cloud:** Development effort will be directed toward constructing 27 Azure ground-truth cases and Azure Policy SMT encoding rather than writing GCP parser primitives.

---

## 6. Consequences & Next Actions

### Positive Consequences
* Establishes a 54-case multi-cloud ground-truth benchmark suite (27 AWS + 27 Azure).
* Validates dual-format SMT translation parity (HCL vs ARM JSON).
* Eliminates all unverified claims from `portfolio_summary.md` and `PROJECT_STATUS.md`.

### Next Actions
1. Execute Phase 11 as specified in `docs/azure_governance_benchmark_design.md`.
2. Construct the 27 Azure ground-truth cases in `fixtures/phase11/azure_corpus/`.
3. Implement `encoder/azure_policy_encoder.py` for Azure Governance rule evaluation.
4. Update `benchmark/harness.py` to run differential benchmarking on `benchmark/azure_ground_truth.json`.
