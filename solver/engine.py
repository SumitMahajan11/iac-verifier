from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from typing import Any, Dict, List, Optional
import z3

z3.set_param("proof", True)

from encoder.hop_bound import compute_hop_bound
from encoder.iam_encoder import (
    encode_iam_scope_symbolic,
    is_full_wildcard_action,
    is_full_wildcard_resource,
)
from encoder.reachability_encoder import (
    encode_reachability_bmc,
    extract_witness_from_model,
)
from encoder.sg_encoder import (
    encode_sg_resource_symbolic,
    is_cidr_private,
    is_port_sensitive,
    SENSITIVE_PORTS,
)
from graph.trust_graph import build_trust_graph
from parser.graph import (
    ExternalManagedPolicy,
    IamPolicyStatement,
    Resource,
    ResourceGraph,
    SecurityGroupRule,
    Unresolved,
)


@dataclass(frozen=True)
class VerificationResult:
    """
    Structured outcome of an SMT safety verification check on a resource.
    Must branch cleanly on SAT, UNSAT, UNSAT_BOUNDED, UNKNOWN, or UNRESOLVABLE.
    """

    status: str  # "SAT" | "UNSAT" | "UNSAT_BOUNDED" | "UNKNOWN" | "UNRESOLVABLE"
    resource_address: str
    pattern: str
    message: str
    witness: Optional[Dict[str, Any]] = None
    unsat_core: Optional[List[str]] = None
    z3_proof_sexpr: Optional[str] = None


class VerificationEngine:
    """
    Z3 SMT Solver interface and verification orchestrator.
    Encodes resource graphs into symbolic Z3 SMT constraints and checks safety.
    """

    def verify_graph(self, graph: ResourceGraph) -> List[VerificationResult]:
        results: List[VerificationResult] = []

        for address, resource in graph.resources.items():
            # Skip resources that were merged into a parent resource
            if resource.merged_into is not None:
                continue

            # Check Pattern 1: Security Group Over-Exposure
            if resource.type in ("aws_security_group", "aws_security_group_rule"):
                res = self.verify_security_group(resource)
                if res:
                    results.append(res)

            # Check Pattern 2: IAM Wildcard Privileges
            if resource.type in ("aws_iam_role", "aws_iam_policy", "aws_iam_role_policy", "aws_iam_user_policy", "aws_iam_group_policy", "aws_s3_bucket_policy"):
                res = self.verify_iam_policy(resource)
                if res:
                    results.append(res)

        return results

    def verify_security_group(self, resource: Resource) -> Optional[VerificationResult]:
        encoded = encode_sg_resource_symbolic(resource)

        if isinstance(encoded, Unresolved):
            return VerificationResult(
                status="UNRESOLVABLE",
                resource_address=resource.address,
                pattern="SG_OVER_EXPOSURE",
                message=f"Unable to verify security group due to unresolved data: {encoded.reason}",
            )

        src_ip_var, unsafe_formula = encoded

        z3.set_param("proof", True)
        solver = z3.Solver()
        solver.add(unsafe_formula)
        check_res = solver.check()

        if check_res == z3.sat:
            model = solver.model()
            counterexample_ip_int = model[src_ip_var].as_long() if src_ip_var in model else 0
            counterexample_ip_str = str(ipaddress.IPv4Address(counterexample_ip_int))

            witness_rules = []
            for rule_src in resource.rule_sources:
                if isinstance(rule_src, SecurityGroupRule):
                    if rule_src.direction.lower() in ("ingress", "egress") and is_port_sensitive(
                        rule_src.from_port, rule_src.to_port
                    ):
                        if any(not is_cidr_private(c) for c in rule_src.cidr_blocks):
                            witness_rules.append(
                                {
                                    "direction": rule_src.direction,
                                    "from_port": rule_src.from_port,
                                    "to_port": rule_src.to_port,
                                    "cidr_blocks": rule_src.cidr_blocks,
                                }
                            )

            return VerificationResult(
                status="SAT",
                resource_address=resource.address,
                pattern="SG_OVER_EXPOSURE",
                message=f"Security group '{resource.address}' exposes sensitive ports to public IP range",
                witness={
                    "resource": resource.address,
                    "sensitive_ports": list(SENSITIVE_PORTS),
                    "smt_counterexample_ip": counterexample_ip_str,
                    "violating_rules": witness_rules,
                },
            )

        elif check_res == z3.unsat:
            proof_str = None
            try:
                if solver.proof() is not None:
                    proof_str = str(solver.proof().sexpr())
            except Exception:
                proof_str = None

            return VerificationResult(
                status="UNSAT",
                resource_address=resource.address,
                pattern="SG_OVER_EXPOSURE",
                message=f"Security group '{resource.address}' is safe from sensitive port over-exposure",
                z3_proof_sexpr=proof_str,
            )

        else:
            return VerificationResult(
                status="UNKNOWN",
                resource_address=resource.address,
                pattern="SG_OVER_EXPOSURE",
                message=f"Z3 solver returned UNKNOWN for security group '{resource.address}'",
            )

    def verify_iam_policy(self, resource: Resource) -> Optional[VerificationResult]:
        encoded = encode_iam_scope_symbolic(resource.rule_sources, scope_id=resource.address)

        if isinstance(encoded, Unresolved):
            return VerificationResult(
                status="UNRESOLVABLE",
                resource_address=resource.address,
                pattern="IAM_WILDCARD_ALLOW",
                message=f"Unable to verify IAM policy due to unresolved data: {encoded.reason}",
            )

        action_var, resource_var, unsafe_formula = encoded

        z3.set_param("proof", True)
        solver = z3.Solver()
        solver.add(unsafe_formula)
        check_res = solver.check()

        if check_res == z3.sat:
            model = solver.model()
            action_counterexample = str(model[action_var]) if action_var in model else "*"
            resource_counterexample = str(model[resource_var]) if resource_var in model else "*"

            witness_stmts = []
            for stmt in resource.rule_sources:
                if isinstance(stmt, IamPolicyStatement):
                    if stmt.effect.lower() == "allow":
                        has_act_wildcard = any(is_full_wildcard_action(act) for act in stmt.actions)
                        has_res_wildcard = any(is_full_wildcard_resource(res) for res in stmt.resources) or not stmt.resources
                        if has_act_wildcard or has_res_wildcard:
                            witness_stmts.append(
                                {
                                    "effect": stmt.effect,
                                    "actions": stmt.actions,
                                    "resources": stmt.resources,
                                }
                            )

            return VerificationResult(
                status="SAT",
                resource_address=resource.address,
                pattern="IAM_WILDCARD_ALLOW",
                message=f"IAM resource '{resource.address}' grants wildcard permissions",
                witness={
                    "resource": resource.address,
                    "smt_counterexample_action": action_counterexample,
                    "smt_counterexample_resource": resource_counterexample,
                    "wildcard_statements": witness_stmts,
                },
            )

        elif check_res == z3.unsat:
            proof_str = None
            try:
                if solver.proof() is not None:
                    proof_str = str(solver.proof().sexpr())
            except Exception:
                proof_str = None

            return VerificationResult(
                status="UNSAT",
                resource_address=resource.address,
                pattern="IAM_WILDCARD_ALLOW",
                message=f"IAM resource '{resource.address}' is safe from wildcard permissions",
                z3_proof_sexpr=proof_str,
            )

        else:
            return VerificationResult(
                status="UNKNOWN",
                resource_address=resource.address,
                pattern="IAM_WILDCARD_ALLOW",
                message=f"Z3 solver returned UNKNOWN for IAM resource '{resource.address}'",
            )

    def verify_privilege_escalation(
        self,
        graph: ResourceGraph,
        target_resource: Optional[str] = None,
        configured_cap: int = 10,
        timeout_ms: Optional[int] = None,
    ) -> VerificationResult:
        """Verifies cross-account privilege escalation reachability using BMC SMT encoding.

        Branches cleanly on:
        - SAT: Privilege escalation path found, witness attached.
        - UNSAT: Complete proof of unreachability (role count <= cap).
        - UNSAT_BOUNDED: No path found within k hops, not proven beyond (role count > cap).
        - UNKNOWN: Solver timeout or undecided.
        - UNRESOLVABLE: Unresolved trust data or unresolvable references in role policies.
        """
        trust_graph = build_trust_graph(graph)

        if trust_graph.unresolvable_roles:
            reasons_summary = "; ".join(trust_graph.unresolvable_reasons)
            return VerificationResult(
                status="UNRESOLVABLE",
                resource_address=target_resource or "graph",
                pattern="PRIVILEGE_ESCALATION_REACHABILITY",
                message=f"Privilege escalation verification unresolvable due to bad/unresolved trust data: {reasons_summary}",
            )

        # Identify target roles
        target_roles: set[str] = set()
        if target_resource:
            if target_resource in trust_graph.nodes:
                target_roles.add(target_resource)
            else:
                return VerificationResult(
                    status="UNRESOLVABLE",
                    resource_address=target_resource,
                    pattern="PRIVILEGE_ESCALATION_REACHABILITY",
                    message=f"Target resource '{target_resource}' not found in trust graph nodes",
                )
        else:
            # Auto-detect roles with wildcard permissions (excluding pure assume_role_policy statements)
            for address, res in graph.resources.items():
                if res.type == "aws_iam_role":
                    perm_sources = [
                        rs for rs in res.rule_sources
                        if not (
                            isinstance(rs, IamPolicyStatement)
                            and len(rs.actions) == 1
                            and str(rs.actions[0]).lower() in ("sts:assumerole", "sts:*")
                        )
                    ]
                    if perm_sources:
                        encoded_scope = encode_iam_scope_symbolic(perm_sources, scope_id=res.address)
                        if not isinstance(encoded_scope, Unresolved):
                            _, _, unsafe_formula = encoded_scope
                            s = z3.Solver()
                            s.add(unsafe_formula)
                            if s.check() == z3.sat:
                                target_roles.add(address)

        role_count = len([n for n in trust_graph.nodes if not n.startswith("account:")])
        k, is_complete = compute_hop_bound(role_count, configured_cap)

        if not target_roles or not trust_graph.external_entry_points:
            return VerificationResult(
                status="UNSAT",
                resource_address=target_resource or "graph",
                pattern="PRIVILEGE_ESCALATION_REACHABILITY",
                message="Privilege escalation complete proof of unreachability (no target roles or external entry points found)",
            )

        if k == 0:
            return VerificationResult(
                status="UNSAT" if is_complete else "UNSAT_BOUNDED",
                resource_address=target_resource or "graph",
                pattern="PRIVILEGE_ESCALATION_REACHABILITY",
                message="Privilege escalation unreachability proof (0 role nodes in graph)",
            )

        # Iterative shortening / shortest-reachable-path query (1 to k bounds)
        for current_k in range(1, k + 1):
            hop_vars, formula = encode_reachability_bmc(trust_graph, target_roles, current_k)

            z3.set_param("proof", True)
            solver = z3.Solver()
            if timeout_ms is not None:
                solver.set("timeout", timeout_ms)

            solver.add(formula)
            check_res = solver.check()

            if check_res == z3.sat:
                model = solver.model()
                witness = extract_witness_from_model(model, hop_vars, trust_graph)
                return VerificationResult(
                    status="SAT",
                    resource_address=witness.get("target_resource", target_resource or "graph"),
                    pattern="PRIVILEGE_ESCALATION_REACHABILITY",
                    message=f"Privilege escalation path found from '{witness['entry_point']}' to '{witness['target_resource']}' in {witness['path_length']} hop(s)",
                    witness=witness,
                )
            elif check_res == z3.unknown:
                return VerificationResult(
                    status="UNKNOWN",
                    resource_address=target_resource or "graph",
                    pattern="PRIVILEGE_ESCALATION_REACHABILITY",
                    message=f"Z3 solver returned UNKNOWN during reachability check at hop {current_k}",
                )

        # If we exhausted k hops without finding a path
        proof_str = None
        try:
            if solver.proof() is not None:
                proof_str = str(solver.proof().sexpr())
        except Exception:
            proof_str = None

        if is_complete:
            return VerificationResult(
                status="UNSAT",
                resource_address=target_resource or "graph",
                pattern="PRIVILEGE_ESCALATION_REACHABILITY",
                message=f"Privilege escalation complete proof of unreachability (searched {k} hops across {role_count} roles)",
                z3_proof_sexpr=proof_str,
            )
        else:
            return VerificationResult(
                status="UNSAT_BOUNDED",
                resource_address=target_resource or "graph",
                pattern="PRIVILEGE_ESCALATION_REACHABILITY",
                message=f"No privilege escalation path found within bounded limit of {k} hops ({role_count} roles total)",
                z3_proof_sexpr=proof_str,
            )

