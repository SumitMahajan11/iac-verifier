# Contributing to IaC Verifier

Thank you for your interest in contributing to **IaC Verifier**! This repository is a portfolio and research project focused on SMT-based formal verification for Infrastructure-as-Code (IaC) and Kubernetes Admission Control.

Because this is a solo/portfolio project, contribution processes are light and streamlined rather than governed by formal committees or voting structures.

---

## 1. Prerequisites & Environment Setup

### Supported Python Versions
IaC Verifier is tested in CI across Python versions:
- **Python 3.10**
- **Python 3.11** (Primary target)
- **Python 3.12**

### Repository Checkout (Submodules Required)
The benchmark test suite relies on real-world vulnerability corpora (`sadcloud` and `terragoat`) tracked as Git submodules in `fixtures/corpora/`.

When cloning the repository, you **must** use `--recursive`:
```bash
git clone --recursive https://github.com/SumitMahajan11/iac-verifier.git
cd iac-verifier
```

If you cloned without `--recursive`, initialize submodules manually before running tests:
```bash
git submodule update --init --recursive
```

### Local Development Installation
1. Create and activate a virtual environment:
   ```bash
   python -m venv .venv
   # Windows (PowerShell):
   .\.venv\Scripts\Activate.ps1
   # Linux/macOS:
   source .venv/bin/activate
   ```

2. Install dependencies in editable mode:
   ```bash
   pip install --upgrade pip
   pip install -e .[dev]
   ```

---

## 2. Running Tests

### Running the Pytest Suite
Run the full test suite using `pytest`:
```bash
pytest -v
```
All 110+ unit and integration tests must pass cleanly prior to submitting changes.

### Running the Live Kubernetes Webhook Test (via KinD)
To verify the `ValidatingAdmissionWebhook` end-to-end in a real local Kubernetes cluster:

1. Ensure [Docker](https://www.docker.com/) and [KinD](https://kind.sigs.k8s.io/) are installed.
2. Build the webhook container image:
   ```bash
   docker build -t iac-webhook:latest -f Dockerfile.webhook .
   ```
3. Spin up a KinD cluster and load the image:
   ```bash
   kind create cluster --name kind
   kind load docker-image iac-webhook:latest --name kind
   ```
4. Install `cert-manager` for dynamic TLS certificate injection:
   ```bash
   kubectl apply -f https://github.com/cert-manager/cert-manager/releases/download/v1.17.0/cert-manager.yaml
   kubectl wait --for=condition=Ready pod -l app.kubernetes.io/instance=cert-manager -n cert-manager --timeout=120s
   ```
5. Deploy `cert-manager` Issuer and Certificate resources:
   ```bash
   kubectl apply -f k8s/cert-manager-issuer-cert.yaml
   kubectl wait --for=condition=Ready certificate/iac-webhook-cert --timeout=60s
   ```
6. Enforce Restricted Pod Security Standards on `default` namespace:
   ```bash
   kubectl label --overwrite namespace default pod-security.kubernetes.io/enforce=restricted pod-security.kubernetes.io/enforce-version=latest
   ```
7. Deploy the Webhook service, NetworkPolicy, and ValidatingWebhookConfiguration:
   ```bash
   kubectl apply -f k8s/webhook-deployment.yaml
   kubectl apply -f k8s/webhook-networkpolicy.yaml
   kubectl apply -f k8s/webhook-configuration.yaml
   kubectl wait --for=condition=ready pod -l app=iac-webhook --timeout=60s
   ```
8. Verify admission responses:
   - **Reject case (Unsafe ConfigMap with exposed SSH)**:
     ```bash
     kubectl apply -f k8s/unsafe-configmap.yaml # Expect rejection (exit code 1)
     ```
   - **Admit case (Safe ConfigMap)**:
     ```bash
     kubectl apply -f k8s/safe-configmap.yaml # Expect successful admission
     ```
   - **Bypass case (Unlabeled ConfigMap)**:
     ```bash
     kubectl apply -f k8s/unlabeled-configmap.yaml # Expect bypass via objectSelector
     ```
9. Clean up the cluster:
   ```bash
   kind delete cluster --name kind
   ```

---

## 3. Core Architectural Conventions

Before introducing new rules or modifying existing verification logic, align with the following core architectural patterns:

### The `VerificationResult` Contract (`solver/engine.py`)
All verification checks must return a structured `VerificationResult` dataclass with one of the following explicit status values:
- `SAT`: Vulnerability or unsafe state detected; solver found a satisfying counterexample assignment (witness attached).
- `UNSAT`: Safety invariant proven; no counterexample exists within search bounds (Z3 proof attached if available).
- `UNSAT_BOUNDED`: No vulnerability found within bounded $k$-hop search (for privilege escalation reachability).
- `UNKNOWN` / `TIMEOUT`: SMT solver exceeded time limit or returned undecided state.
- `UNRESOLVABLE`: Missing or ambiguous resource references prevented symbolic formula generation.

### Fail-Closed Webhook Semantics (`cli/webhook.py`)
The admission webhook operates on a zero-trust, fail-closed policy:
- If a solver check returns `SAT`, `UNKNOWN`, `UNRESOLVABLE`, or `TIMEOUT`, admission is **denied** (`allowed: false`).
- Internal webhook execution enforces `WEBHOOK_TIMEOUT_SECONDS` (default `8.0s`) to fail closed before the default 10s API server admission timeout.

### Ground-Truth Fixture Requirement
When adding support for a new Terraform resource type, security rule, or solver feature:
1. Always add corresponding ground-truth `.tf` fixtures under `fixtures/` (e.g., `fixtures/phase2/` or `tests/`).
2. Add explicit pytest cases confirming expected `SAT` / `UNSAT` outcomes for both positive and negative scenarios.

---

## 4. Submitting Pull Requests

1. Fork the repo and create a topic branch (`git checkout -b feat/my-new-rule`).
2. Ensure `pytest -v` succeeds locally.
3. Submit a Pull Request targeting `main`. Fill out the PR template checklist to confirm tests and fixtures are included.
