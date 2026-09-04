# Azure Governance Rule Set Integration & Multi-Cloud Benchmark Corpus Expansion
## System Architecture and Component/Data-Flow Design Document

---

### Executive Summary

This document specifies the technical design for the next planned phase of the Z3-SMT-based IaC verifier: **Azure Governance Rule Set Integration and Multi-Cloud Benchmark Corpus Expansion**.

Currently, the engine provides high-precision SMT verification for AWS (IAM escalation, SGs) and Azure (NSG rule precedence, RBAC trust reachability) across 195 tests with 90% code coverage. However, the existing Tier 1 ground-truth benchmark (27 cases with 1.0 precision/recall) is exclusively AWS/HCL-focused.

This phase achieves two core objectives:
1. **Ground-Truth Benchmark Corpus Expansion for Azure/ARM**: A 27-case ground-truth dataset matching the rigor of the AWS corpus, spanning both Terraform HCL and native ARM JSON formats across 4 distinct vulnerability categories.
2. **Azure Governance Rule Set Integration**: Symbolic SMT encoding of Azure Policy definitions and assignments (`azurerm_policy_assignment`, `azurerm_policy_definition`, `azurerm_management_group_policy_assignment`, ARM `Microsoft.Authorization/policyAssignments`), integrated cleanly into `solver/engine.py` and connected with the 4-level Azure scope hierarchy in `graph/azure_trust_graph.py`.

---

### System Architecture & Data-Flow Diagram

The diagram below illustrates how new Azure Governance and ARM/HCL benchmark components interface with the existing AST parsers, trust graph engines, SMT encoders, solver dispatch, and benchmark harness:

```mermaid
flowchart TD
    subgraph Inputs ["1. Input Infrastructure & Corpora"]
        HCL["Terraform HCL Manifests (.tf)<br/>(fixtures/phase11/azure_corpus/*)"]
        ARM["ARM JSON Templates (.json)<br/>(fixtures/phase11/azure_corpus/*)"]
        GT["Azure Ground-Truth Corpus<br/>(benchmark/azure_ground_truth.json)"]
    end

    subgraph Parsers ["2. Parser & AST Normalization"]
        HCLP["HCL Parser<br/>(parser/hcl_parser.py)"]
        ARMP["ARM JSON Parser<br/>(parser/arm_parser.py)"]
        RG["ResourceGraph Generator<br/>(parser/graph.py)"]
        REF["Reference & Attachment Resolver<br/>(parser/references.py, attachments.py)"]
    end

    subgraph Graphs ["3. Scope Hierarchy & Trust Modeling"]
        ATG["Azure Trust Graph Engine<br/>(graph/azure_trust_graph.py)"]
        IS ["Scope Subsumption Matrix<br/>(is_scope_subsumed: MG -> Sub -> RG -> Res)"]
    end

    subgraph Encoders ["4. Symbolic SMT Encoders"]
        NSGE["Azure NSG Encoder<br/>(encoder/azure_nsg_encoder.py)"]
        POLE["NEW: Azure Policy Encoder<br/>(encoder/azure_policy_encoder.py)"]
        BMCE["Reachability BMC Encoder<br/>(encoder/reachability_encoder.py)"]
    end

    subgraph Engine ["5. Solver Dispatch Engine"]
        VE["VerificationEngine.verify_graph()<br/>(solver/engine.py)"]
        CACHE["VerificationCache<br/>(.iac_cache/ sha256)"]
        Z3["Z3 SMT Solver<br/>(z3.Solver with proof=True)"]
    end

    subgraph Harness ["6. Benchmark Harness & Metrics"]
        BH["BenchmarkHarness<br/>(benchmark/harness.py)"]
        DIFF["Pre-Flight §10 Check<br/>(benchmark/differential_check.py)"]
        METRICS["Precision / Recall / F1 Telemetry<br/>(harness_output.json)"]
    end

    HCL --> HCLP
    ARM --> ARMP
    HCLP --> RG
    ARMP --> RG
    RG --> REF
    REF --> ATG
    ATG --> IS

    RG --> VE
    IS --> POLE
    IS --> BMCE

    VE --> CACHE
    VE --> NSGE
    VE --> POLE
    VE --> BMCE

    NSGE --> Z3
    POLE --> Z3
    BMCE --> Z3

    GT --> BH
    BH --> DIFF
    DIFF --> VE
    Z3 --> BH
    BH --> METRICS
```

---

### Component Design

#### 1. Ground-Truth Benchmark Corpus for Azure/ARM (27 Cases)

To provide a credible, verifiable precision/recall claim (target: 1.0 precision, 1.0 recall) equivalent in rigor to the 27-case AWS corpus, the Azure ground-truth corpus consists of **27 real-world test cases** split evenly across Terraform HCL and native ARM JSON.

##### Category Breakdown & Case Allocation

| Category | # Cases | Focus Areas / Vulnerability Patterns | Formats Covered | Expected SMT States |
| :--- | :---: | :--- | :--- | :--- |
| **1. NSG Over-Exposure** | **8** | Open sensitive ports (SSH 22, RDP 3389, SMB 445, FTP 21, Telnet 23) from `*` or `Internet` to private subnets; priority collisions (high priority allow overriding low priority deny); range/wildcard array ports (`3380-3390`, `*`). | HCL & ARM JSON | 4 SAT, 3 UNSAT, 1 UNRESOLVABLE |
| **2. RBAC Privilege Escalation** | **8** | Custom role definition with `Microsoft.Authorization/*/write` or `*` actions; managed identity (VM / Web App / Function App) with `Owner`/`Contributor` assignment; Active Directory group fail-closed trapping (`azuread_group`); multi-hop workload escalation. | HCL & ARM JSON | 4 SAT, 3 UNSAT, 1 UNRESOLVABLE |
| **3. Scope Inheritance & Isolation** | **6** | Management Group root scope (`/providers/Microsoft.Management/managementGroups/mg-root`) subsuming underlying subscriptions/workloads; subscription isolation (`/subscriptions/sub-prod-001` vs `/subscriptions/sub-dev-002`); Resource Group scope isolation (`rg-finance` vs `rg-analytics`). | HCL & ARM JSON | 3 SAT, 3 UNSAT |
| **4. Azure Policy Guardrails** | **5** | Azure Policy `Deny` enforcement (missing NSG subnet attachment, public IP creation, unauthorized location/SKU); Management Group policy inheritance down to resource group scopes; policy exemptions handling. | HCL & ARM JSON | 3 SAT, 2 UNSAT |
| **TOTAL** | **27** | **Rigorous, multi-format Azure security verification suite** | **HCL (14) / ARM (13)** | **14 SAT, 11 UNSAT, 2 UNRESOLVABLE** |

##### Ground-Truth Case Schema Specification (`benchmark/azure_ground_truth.json`)

Each case adheres strictly to the benchmark harness schema:
```json
{
  "corpus": "azure_benchmark",
  "file": "fixtures/phase11/azure_corpus/nsg/nsg_open_rdp.tf",
  "resource_id": "azurerm_network_security_group.open_rdp",
  "vulnerability_class": "NSG_EXPOSURE",
  "expected_engine_state": "SAT",
  "expected_witness": {
    "sensitive_ports": [3389],
    "smt_counterexample_ip": "198.51.100.1"
  },
  "ambiguity": {
    "is_ambiguous": false,
    "reason": null
  }
}
```

---

#### 2. Azure Governance Rule Set Integration Architecture

##### Concrete Scope Definition
"Azure Governance Rule Set Integration" is defined as **symbolic SMT modeling of Azure Policy Definitions and Assignments** (`azurerm_policy_definition`, `azurerm_policy_assignment`, `azurerm_management_group_policy_assignment`, ARM `Microsoft.Authorization/policyDefinitions`, `Microsoft.Authorization/policyAssignments`).

Azure Policy rules define declarative `if/then` conditions over resource properties (e.g., `field == 'Microsoft.Network/networkSecurityGroups/securityRules/destinationPortRange'`, `equals == '22'`). Rather than using imperative string linters, our SMT Policy Encoder converts Azure Policy JSON/HCL conditions into symbolic Z3 logical formulas and tests whether a target resource configuration violates the policy constraint.

##### SMT Policy Encoder Design (`encoder/azure_policy_encoder.py`)

```python
"""
encoder/azure_policy_encoder.py

Encodes Azure Policy rule conditions (if/then blocks) into Z3 symbolic boolean logic.
Evaluates compliance against target resource configurations and scope inheritance rules.
"""

from typing import Dict, Any, Tuple, Optional
import z3
from parser.graph import Resource, ResourceGraph, Unresolved
from graph.azure_trust_graph import is_scope_subsumed

class AzurePolicyEncoder:
    """Translates Azure Policy rule logic into symbolic SMT constraints."""

    def encode_policy_condition(
        self,
        policy_rule: Dict[str, Any],
        target_resource: Resource,
    ) -> Tuple[z3.BoolRef, Optional[Dict[str, Any]]]:
        """
        Converts policy 'if' conditions (field, equals, in, contains, not, allOf, anyOf)
        into a Z3 constraint representing POLICY_VIOLATION.
        
        Returns:
            (violation_formula, symbolic_variables)
        """
        # Symbolic logic construction for Azure Policy fields
        ...
```

##### Integration into `VerificationEngine` (`solver/engine.py`)

1. **Pattern Registration**: Add `AZURE_GOVERNANCE_POLICY_VIOLATION` to `verify_graph()` and `verify_incremental()`.
2. **Dispatch Logic**:
```python
# Check Pattern 4: Azure Governance Policy Violation
if resource.type in (
    "azurerm_policy_assignment",
    "azurerm_management_group_policy_assignment",
    "azurerm_subscription_policy_assignment",
    "Microsoft.Authorization/policyAssignments",
):
    res = None
    cache_key = None
    if self.cache:
        cache_key = compute_cache_key(graph, address, "AZURE_GOVERNANCE_POLICY_VIOLATION")
        res = self.cache.get(cache_key)
    if not res:
        res = self.verify_azure_policy(resource, graph, timeout_ms=eff_timeout)
        if res and self.cache and cache_key:
            self.cache.put(cache_key, res)
    if res:
        results.append(res)
```

3. **Scope Matching via `graph/azure_trust_graph.py`**:
   `verify_azure_policy` uses `is_scope_subsumed(policy_assignment.scope, target_resource.scope, graph)` to determine whether a policy assignment applies to a target resource across Management Group, Subscription, and Resource Group scopes.

---

#### 3. Repository Layout & Benchmark Harness Integration

##### Directory Structure
```
fixtures/phase11/
├── azure_corpus/
│   ├── nsg/
│   │   ├── open_rdp.tf
│   │   ├── priority_collision.tf
│   │   ├── arm_nsg_open_ssh.json
│   │   └── ... (8 cases total)
│   ├── rbac/
│   │   ├── custom_role_admin.tf
│   │   ├── vm_identity_escalation.tf
│   │   ├── arm_role_assignment.json
│   │   └── ... (8 cases total)
│   ├── scope/
│   │   ├── mg_sub_inheritance.tf
│   │   ├── sub_isolation.tf
│   │   ├── arm_mg_scope.json
│   │   └── ... (6 cases total)
│   └── governance/
│       ├── policy_deny_nsg.tf
│       ├── policy_allowed_skus.tf
│       ├── arm_policy_assignment.json
│       └── ... (5 cases total)
benchmark/
├── azure_ground_truth.json      # 27 Azure Ground-Truth Cases
├── harness.py                   # Multi-format (HCL + ARM) Harness
└── differential_check.py        # §10 Pre-flight Differential Check
encoder/
├── azure_policy_encoder.py      # SMT Azure Policy Encoder
```

##### Benchmark Harness Enhancements (`benchmark/harness.py`)
- **Dual Parser Support**: Route `.tf` files to `parse_file` + `build_graph`, and `.json` files to `parse_arm_template` + `arm_build_graph`.
- **Vulnerability Class Dispatch**:
  - `NSG_EXPOSURE` -> `engine.verify_azure_nsg`
  - `AZURE_RBAC_ESCALATION` -> `engine.verify_privilege_escalation`
  - `AZURE_SCOPE_INHERITANCE` -> `engine.verify_privilege_escalation` / `is_scope_subsumed`
  - `AZURE_POLICY_VIOLATION` -> `engine.verify_azure_policy`

---

#### 4. Explicit Non-Goals & Scope Boundaries

To prevent scope creep and maintain engine focus, the following items are **explicitly deferred to future phases**:

1. **Direct Bicep (`.bicep`) Parsing**: Bicep files must be pre-compiled to ARM JSON via `bicep build` before ingestion. Native `.bicep` AST parsing is a Non-Goal.
2. **Dynamic Live Microsoft Graph API Expansion**: Active Directory groups (`azuread_group`) will remain fail-closed `UNRESOLVABLE`. Live API calls to Microsoft Graph during static verification are strictly excluded to preserve offline zero-trust operation.
3. **Dynamic Custom Policy JavaScript Engine**: Policy expressions containing unresolvable dynamic functions (`resourceGroup().location`, runtime parameters) evaluate to `Unresolved` and trigger fail-closed `UNRESOLVABLE` status.
4. **AWS GuardDuty / AWS Organizations Policy Integration**: This phase focuses exclusively on Azure Governance. AWS SCP / GuardDuty policy modeling is deferred.

---

### Data-Flow & Interaction Contract Summary

```
Input Manifest (HCL / ARM JSON)
   │
   ├─► HCL / ARM Parser ──► ResourceGraph
   │                           │
   │                           ├──► azure_trust_graph.py ──► Scope Hierarchy & Identity Edges
   │                           │
   │                           └──► solver/engine.py (verify_graph dispatch)
   │                                   │
   │                                   ├─► verify_azure_nsg() ────► AzureNSGEncoder ────► Z3 SMT Solver
   │                                   ├─► verify_azure_policy() ──► AzurePolicyEncoder ──► Z3 SMT Solver
   │                                   └─► verify_privilege_esc()► ReachabilityEncoder► Z3 SMT Solver
   │                                                                                         │
   └─► benchmark/harness.py ◄────────────────────────────── Results / Witness / Proof ◄──────┘
           │
           └─► Pre-Flight §10 Check ──► Ground Truth Validation ──► Precision: 1.0, Recall: 1.0
```

---
*Document Status: Drafted & Clearance Granted for Implementation*
