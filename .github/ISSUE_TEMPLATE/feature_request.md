---
name: Feature request
about: Propose a new security rule, SMT encoder extension, or CLI feature
title: '[FEAT] '
labels: 'enhancement'
assignees: ''
---

### Feature Summary
A clear and concise description of the proposed capability (e.g. new AWS resource type, SMT reachability rule, or CLI option).

### Security Invariant & Target Constraint
Describe the formal security invariant to enforce (e.g. "Ensure no IAM role with wildcards can assume another role transitively across accounts").

### Proposed SMT Encoding / Approach
How should this translate into Z3 symbolic constraints or parser logic?

### Target Fixtures & Verification
- What Terraform resource structures need to be parsed?
- What positive (safe) and negative (vulnerable) fixtures will prove correctness?
