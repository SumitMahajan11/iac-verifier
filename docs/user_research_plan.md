# User Research & Usability Validation Plan: IaC SMT Verifier

* **Status:** Draft / Active Plan
* **Date:** 2026-09-04
* **Target Audience:** Platform Engineers, DevSecOps Engineers, Cloud Security Architects
* **Goal:** Validate usability, trustworthiness, and legibility of Z3-SMT verification output (SAT/UNSAT verdicts, witness traces, UNSAT-core repair diffs) before investing further in solver encoders and benchmark expansion.

---

## 1. Developer Interview Guide (6 Core Questions)

This short interview guide is designed for 20-30 minute qualitative interviews with platform and security engineers who currently use static IaC linters (Checkov, tfsec, Trivy, Sentinel, OPA/Rego).

### Question 1: Signal vs. Noise & Trust Thresholds
> *"When an IaC scanner flags a security issue in a Pull Request (e.g., S3 bucket over-exposure or Security Group ingress), what specific information in the alert makes you immediately trust or dismiss it?"*
* **Target Insight:** Identifies the minimum evidence required for an engineer to act without re-investigating manually.

### Question 2: Traceability of Multi-Hop Vulnerabilities
> *"If a tool flags a complex attack path (e.g. an IAM role in Account A can be assumed by an EC2 instance in Account B through a chain of 3 trust relationships), how would you want that attack path visualized in a PR comment so you don't have to trace it yourself?"*
* **Target Insight:** Informs how raw SMT witness paths should be transformed into readable text/graph representations.

### Question 3: Actionability of Auto-Remediation Diffs
> *"When a security tool suggests an automated code fix or git diff, under what conditions do you approve/apply it versus rejecting it? What safety guarantees or explanations must accompany the diff?"*
* **Target Insight:** Determines if automated AST repair diffs (`ast_repair.py`) are trusted in CI, or if engineers prefer suggested code snippets with rationale.

### Question 4: Value of Mathematical Proofs (UNSAT Cores)
> *"Traditional linters report 'Rule X failed on Resource Y'. Our verifier can mathematically prove that closing an exposure requires modifying multiple rules simultaneously (a minimal UNSAT core). Is seeing proof of why single-rule fixes fail valuable to you, or does it add cognitive overhead?"*
* **Target Insight:** Tests whether UNSAT-core remediation precision is perceived as high-value clarity or confusing formal-methods jargon.

### Question 5: Dynamic Resolution & Fail-Closed Behavior
> *"IaC code often contains dynamic references that static analyzers cannot resolve (e.g., external AD groups or runtime variables). Would you prefer a verifier to fail-closed (`UNRESOLVABLE / ERROR`), attempt a heuristic fallback, or skip the check?"*
* **Target Insight:** Evaluates real-world appetite for strict zero-trust SMT soundness versus permissive linter behavior.

### Question 6: Linters vs. Formal Verification Boundaries
> *"Where do current pattern-matching linters (Checkov/tfsec) completely fail your team today, such that you would tolerate a slightly slower solver (5-10 sec latency) for 100% precision?"*
* **Target Insight:** Defines the exact boundary where SMT verification provides undeniable ROI over standard AST pattern matching.

---

## 2. Top 3 Riskiest Untested Assumptions

### Assumption 1: SMT Witness Traces and UNSAT Cores are Legible to Non-Experts
* **The Assumption:** Platform engineers will find Z3 witness models (e.g., variable assignments proving reachability) and UNSAT-core boundary traces self-explanatory.
* **The Risk:** Raw SMT solver outputs look like mathematical logic formulas or variable bindings (`dest_ip_sym == 0x00000000`). If unformatted, engineers will perceive them as cryptic noise and dismiss the tool despite its mathematical accuracy.

### Assumption 2: Engineers Want Automated Multi-Rule Code Fixes Generated Directly in CI
* **The Assumption:** Automatically generating HCL/ARM AST repair diffs in PR comments is a high-value feature.
* **The Risk:** Platform engineers strongly distrust automated tools mutating infrastructure code—especially multi-rule diffs—without understanding potential side effects (e.g., breaking legitimate production traffic).

### Assumption 3: Teams Value Mathematical Soundness (Zero False Positives) Over Speed & Existing SARIF Tooling
* **The Assumption:** DevSecOps teams will adopt a Z3 SMT verifier because it guarantees zero false positives on modeled logic, even if execution takes seconds longer than AST linters.
* **The Risk:** If output is not rendered natively in familiar formats (GitHub Code Scanning SARIF, PR inline review comments), teams will reject the tool regardless of its mathematical superiority.

---

## 3. Lightweight Research Strategy & Proxy Validation Protocol

To validate or invalidate these assumptions rapidly without requiring access to live interview subjects, we define a **Proxy Research Protocol** leveraging open-source telemetry and community feedback.

### Proxy Method: Mining Open-Source Linter Issues & Discussions (Cost: 0$, Time: 4-6 Hours)

#### Target Repositories
* `bridgecrewio/checkov` (GitHub Issues & Discussions)
* `aquasecurity/tfsec` / `aquasecurity/trivy`
* `open-policy-agent/opa` / `hashicorp/sentinel`

#### Search Query Taxonomy
1. **False Positive Frustration:** `"false positive"` OR `"incorrect alert"` OR `"suppress"`
2. **Cryptic Explanation Complaints:** `"unclear error"` OR `"what does this mean"` OR `"documentation missing"`
3. **Auto-Fix Distrust:** `"auto fix"` OR `"remediation broke"` OR `"incorrect patch"`
4. **Multi-Hop / Complex IAM Limits:** `"assume role"` OR `"cross account"` OR `"multi rule"`

#### Extraction & Synthesis Protocol
1. Sample 50 relevant GitHub issues/discussions across the target repositories.
2. Categorize user complaints into a matrix:
   - *Legibility Gaps* (Unable to understand why a rule fired)
   - *Linter Limitation Gaps* (Linter failed to trace complex logic)
   - *Fix Safety Gaps* (Suggested fix broke template syntax or environment behavior)
3. Benchmark our verifier's proposed output formatting directly against the top 3 user pain points identified.

### Secondary Method: Asynchronous Output Mockup A/B Testing

Create 3 lightweight markdown PR comment mockups and share them asynchronously on practitioner forums (`r/DevOps`, `r/CloudSecurity`, DevSecOps Slack communities):

* **Mockup A (Traditional Linter):** Standard Checkov rule alert (`FAILED: CKV_AWS_24`).
* **Mockup B (Raw SMT Output):** Z3 SAT witness model (`SAT: dest_ip=0.0.0.0/0, port=22`).
* **Mockup C (Human-Centric SMT Trace + Minimal UNSAT Fix):** Narrative attack path explanation + minimal multi-rule diff with blast-radius notice.

**Success Criterion:** If 75%+ of respondents select Mockup C and confirm that the narrative attack path eliminates manual re-investigation, Assumption 1 & 2 are validated.
