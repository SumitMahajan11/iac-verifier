---
name: Bug report
about: Report an incorrect verification result, parser error, or webhook failure
title: '[BUG] '
labels: 'bug'
assignees: ''
---

### Description
A clear and concise description of what the bug is.

### Reproduction Steps
1. Create a Terraform fixture with the following snippet:
   ```hcl
   # Paste minimal Terraform snippet here
   ```
2. Run `iac-verifier` CLI or admission webhook against the fixture:
   ```bash
   iac-verify --path <path_to_fixture>
   ```
3. Observe the outcome.

### Expected Behavior
What status did you expect (`UNSAT`, `SAT`, `UNRESOLVABLE`) and why?

### Actual Behavior
What status was returned, or what exception/log was raised? Include relevant logs or `VerificationResult` output.

### Environment
- **OS**: [e.g. Ubuntu 24.04, macOS 14, Windows 11]
- **Python Version**: [e.g. 3.11.8]
- **Z3 Version**: [e.g. z3-solver 4.12.2]
- **Execution Mode**: [CLI / Python API / K8s Admission Webhook]
