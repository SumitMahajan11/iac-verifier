from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from typing import Any, Dict, List, Optional
import z3
import json
import hashlib
import dataclasses
import os
import threading

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
from encoder.cidr import make_ip_in_private_ranges_expr
from graph.trust_graph import build_trust_graph
from parser.graph import (
    ExternalManagedPolicy,
    IamPolicyStatement,
    Resource,
    ResourceGraph,
    ResourceReference,
    SecurityGroupRule,
    AzureNsgRule,
    Unresolved,
)
from encoder.azure_nsg_encoder import AzureNSGEncoder
from encoder.azure_policy_encoder import AzurePolicyEncoder
from encoder.gcp_firewall_encoder import encode_gcp_firewall
from encoder.gcp_iam_encoder import encode_gcp_iam
from graph.azure_trust_graph import build_azure_trust_graph
from graph.gcp_trust_graph import build_gcp_trust_graph



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


def _default_encoder(obj):
    if dataclasses.is_dataclass(obj):
        return dataclasses.asdict(obj)
    if isinstance(obj, set):
        return sorted(list(obj))
    return str(obj)

def compute_cache_key(
    graph: ResourceGraph,
    resource_address: str,
    pattern: str,
    configured_cap: Optional[int] = None,
    entry_principal: Optional[str] = None,
) -> str:
    res_list = [resource_address]
    
    if pattern in ("PRIVILEGE_ESCALATION_REACHABILITY", "AZURE_GOVERNANCE_POLICY_VIOLATION"):
        res_list = sorted(list(graph.resources.keys()))
    else:
        deps = set([resource_address])
        resource = graph.resources.get(resource_address)
        if resource:
            for addr, r in graph.resources.items():
                if r.merged_into == resource_address:
                    deps.add(addr)
                    policy_arn = r.attributes.get("policy_arn")
                    if isinstance(policy_arn, ResourceReference):
                        deps.add(policy_arn.target_address)
            
            for rs in resource.rule_sources:
                if isinstance(rs, SecurityGroupRule):
                    if isinstance(rs.referenced_security_group_id, ResourceReference):
                        deps.add(rs.referenced_security_group_id.target_address)
                    elif isinstance(rs.referenced_security_group_id, str):
                        deps.add(rs.referenced_security_group_id)
        
        res_list = sorted(list(deps))
    
    state = [
        ("meta_pattern", pattern),
        ("meta_address", resource_address),
        ("meta_configured_cap", str(configured_cap)),
        ("meta_entry_principal", str(entry_principal)),
    ]
    for addr in res_list:
        r = graph.resources.get(addr)
        if r:
            state.append((addr, dataclasses.asdict(r)))
    
    data_str = json.dumps(state, default=_default_encoder, sort_keys=True)
    key = hashlib.sha256(data_str.encode("utf-8")).hexdigest()
    return key


class VerificationCache:
    def __init__(self, cache_dir: str = ".iac_cache"):
        self.cache_dir = cache_dir
        if not os.path.exists(self.cache_dir):
            os.makedirs(self.cache_dir, exist_ok=True)

    def get(self, key: str) -> Optional[VerificationResult]:
        path = os.path.join(self.cache_dir, f"{key}.json")
        if os.path.exists(path):
            try:
                with open(path, "r") as f:
                    data = json.load(f)
                    return VerificationResult(**data)
            except Exception:
                pass
        return None

    def put(self, key: str, result: VerificationResult):
        path = os.path.join(self.cache_dir, f"{key}.json")
        try:
            with open(path, "w") as f:
                json.dump(dataclasses.asdict(result), f, indent=2)
        except Exception:
            pass

class VerificationEngine:
    """
    Z3 SMT Solver interface and verification orchestrator.
    Encodes resource graphs into symbolic Z3 SMT constraints and checks safety.
    """
    def __init__(self, use_cache: bool = True, timeout_ms: Optional[int] = None):
        self.cache = VerificationCache() if use_cache else None
        self.timeout_ms = timeout_ms
        self._current_solver: Optional[z3.Solver] = None

    def interrupt(self):
        """
        Triggers native C++ interruption on the active Z3 solver context.
        Forces immediate preemption of long-running SMT solver calculations.
        """
        if self._current_solver is not None:
            try:
                self._current_solver.ctx.interrupt()
            except Exception:
                pass
        try:
            z3.main_ctx().interrupt()
        except Exception:
            pass

    def _check_solver_with_timeout(
        self, solver: z3.Solver, timeout_ms: Optional[int] = None
    ) -> z3.CheckResult:
        eff_timeout = timeout_ms or self.timeout_ms
        timer = None
        if eff_timeout is not None and eff_timeout > 0:
            solver.set("timeout", eff_timeout)
            timeout_sec = eff_timeout / 1000.0
            timer = threading.Timer(timeout_sec, lambda: solver.ctx.interrupt())
            timer.daemon = True
            timer.start()

        self._current_solver = solver
        try:
            res = solver.check()
            return res
        finally:
            self._current_solver = None
            if timer is not None:
                timer.cancel()

    def verify_graph(self, graph: ResourceGraph, timeout_ms: Optional[int] = None) -> List[VerificationResult]:
        results: List[VerificationResult] = []
        eff_timeout = timeout_ms or self.timeout_ms

        for address, resource in graph.resources.items():
            # Skip resources that were merged into a parent resource
            if resource.merged_into is not None:
                continue

            # Check Pattern 1: Security Group Over-Exposure
            if resource.type in ("aws_security_group", "aws_security_group_rule"):
                res = None
                cache_key = None
                if self.cache:
                    cache_key = compute_cache_key(graph, address, "SG_OVER_EXPOSURE")
                    res = self.cache.get(cache_key)
                if not res:
                    res = self.verify_security_group(resource, timeout_ms=eff_timeout)
                    if res and self.cache and cache_key:
                        self.cache.put(cache_key, res)
                if res:
                    results.append(res)

            # Check Pattern 2: IAM Wildcard Privileges
            if resource.type in ("aws_iam_role", "aws_iam_policy", "aws_iam_role_policy", "aws_iam_user_policy", "aws_iam_group_policy", "aws_s3_bucket_policy"):
                res = None
                cache_key = None
                if self.cache:
                    cache_key = compute_cache_key(graph, address, "IAM_WILDCARD_ALLOW")
                    res = self.cache.get(cache_key)
                if not res:
                    res = self.verify_iam_policy(resource, timeout_ms=eff_timeout)
                    if res and self.cache and cache_key:
                        self.cache.put(cache_key, res)
                if res:
                    results.append(res)
                    
            # Check Pattern 3: Azure NSG Over-Exposure
            if resource.type in ("azurerm_network_security_group", "azurerm_network_security_rule"):
                res = None
                cache_key = None
                if self.cache:
                    cache_key = compute_cache_key(graph, address, "NSG_OVER_EXPOSURE")
                    res = self.cache.get(cache_key)
                if not res:
                    res = self.verify_azure_nsg(resource, timeout_ms=eff_timeout)
                    if res and self.cache and cache_key:
                        self.cache.put(cache_key, res)
                if res:
                    results.append(res)

            # Check Pattern 4: Azure Governance Policy Violation
            has_policy_assignments = any(
                "policy_assignment" in r.type.lower() or "policyassignments" in r.type.lower()
                for r in graph.resources.values()
            )
            is_policy_meta_resource = (
                "policy_definition" in resource.type.lower()
                or "policydefinitions" in resource.type.lower()
                or "policy_assignment" in resource.type.lower()
                or "policyassignments" in resource.type.lower()
            )
            if has_policy_assignments and not is_policy_meta_resource:
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

        # Detect provider and build appropriate trust graph
        has_aws = any(r.type.startswith("aws_") for r in graph.resources.values())
        has_azure = any(r.type.startswith("azurerm_") or r.type == "Microsoft.Authorization/policyAssignments" for r in graph.resources.values())
        has_gcp = any(r.type.startswith("google_") for r in graph.resources.values())

        trust_graph_mock = getattr(graph, "trust_graph", None)
        
        # Check Pattern 5: Privilege Escalation Reachability (AWS IAM & Azure RBAC)
        if any(r.type in ("aws_iam_role", "azurerm_role_assignment", "google_project_iam_binding") for r in graph.resources.values()) or trust_graph_mock:
            res = None
            cache_key = None
            if self.cache:
                cache_key = compute_cache_key(graph, "graph", "PRIVILEGE_ESCALATION_REACHABILITY")
                res = self.cache.get(cache_key)
            if not res:
                res = self.verify_privilege_escalation(graph, timeout_ms=eff_timeout)
                if res and self.cache and cache_key:
                    self.cache.put(cache_key, res)
            if res:
                results.append(res)

        return results

    def verify_security_group(
        self, resource: Resource, timeout_ms: Optional[int] = None
    ) -> Optional[VerificationResult]:
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
        eff_timeout = timeout_ms or self.timeout_ms

        solver.add(unsafe_formula)
        check_res = self._check_solver_with_timeout(solver, eff_timeout)

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
            reason = solver.reason_unknown()
            is_timeout = reason in ("timeout", "interrupted", "canceled")
            status = "TIMEOUT" if is_timeout else "UNKNOWN"
            msg = f"Z3 solver timed out for security group '{resource.address}'" if is_timeout else f"Z3 solver returned UNKNOWN for security group '{resource.address}'"
            return VerificationResult(
                status=status,
                resource_address=resource.address,
                pattern="SG_OVER_EXPOSURE",
                message=msg,
            )

    def verify_azure_nsg(
        self, resource: Resource, timeout_ms: Optional[int] = None
    ) -> Optional[VerificationResult]:
        def is_unresolved(val):
            if isinstance(val, (Unresolved, ResourceReference)):
                return True
            if isinstance(val, list):
                return any(is_unresolved(item) for item in val)
            return False

        # Unresolved data check on original dataclasses
        if any(is_unresolved(getattr(rs, f.name)) for rs in resource.rule_sources if isinstance(rs, AzureNsgRule) for f in dataclasses.fields(rs)):
            return VerificationResult(
                status="UNRESOLVABLE",
                resource_address=resource.address,
                pattern="NSG_OVER_EXPOSURE",
                message="Unable to verify NSG due to unresolved data",
            )
            
        # Convert AzureNsgRule objects to dicts for the encoder
        rules_dict_list = []
        for rs in resource.rule_sources:
            if isinstance(rs, AzureNsgRule):
                rule_dict = dataclasses.asdict(rs)
                # Clean up None values
                rule_dict = {k: v for k, v in rule_dict.items() if v is not None}
                rules_dict_list.append(rule_dict)
            
        encoder = AzureNSGEncoder()
        
        chain_expr, ip_sym, port_sym, dest_ip_sym, src_port_sym, sorted_rules = encoder.encode_nsg_rules(
            rules_dict_list, target_protocol="Tcp"
        )

        sensitive_port_cond = z3.Or([port_sym == port for port in SENSITIVE_PORTS])

        unsafe_formula = z3.And(
            chain_expr,
            sensitive_port_cond,
            z3.Not(make_ip_in_private_ranges_expr(ip_sym, ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "168.63.129.16/32"]))
        )

        z3.set_param("proof", True)
        solver = z3.Solver()
        eff_timeout = timeout_ms or self.timeout_ms

        solver.add(unsafe_formula)
        check_res = self._check_solver_with_timeout(solver, eff_timeout)

        if check_res == z3.sat:
            violating_ports = []
            counterexample_ip_str = None

            for port in SENSITIVE_PORTS:
                port_solver = z3.Solver()
                port_formula = z3.And(
                    chain_expr,
                    port_sym == port,
                    z3.Not(make_ip_in_private_ranges_expr(ip_sym, ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "168.63.129.16/32"]))
                )
                port_solver.add(port_formula)
                port_check = self._check_solver_with_timeout(port_solver, eff_timeout)

                if port_check == z3.sat:
                    violating_ports.append(port)
                    if not counterexample_ip_str:
                        model = port_solver.model()
                        counterexample_ip_int = model[ip_sym].as_long() if ip_sym in model else 0
                        counterexample_ip_str = str(ipaddress.IPv4Address(counterexample_ip_int))

            return VerificationResult(
                status="SAT",
                resource_address=resource.address,
                pattern="NSG_OVER_EXPOSURE",
                message=f"Azure NSG '{resource.address}' exposes sensitive ports ({', '.join(map(str, violating_ports))}) to public IP range",
                witness={
                    "resource": resource.address,
                    "sensitive_ports": violating_ports,
                    "smt_counterexample_ip": counterexample_ip_str or "0.0.0.0",
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
                pattern="NSG_OVER_EXPOSURE",
                message=f"Azure NSG '{resource.address}' is safe from sensitive port over-exposure",
                z3_proof_sexpr=proof_str,
            )

        else:
            reason = solver.reason_unknown()
            is_timeout = reason in ("timeout", "interrupted", "canceled")
            status = "TIMEOUT" if is_timeout else "UNKNOWN"
            msg = f"Z3 solver timed out for NSG '{resource.address}'" if is_timeout else f"Z3 solver returned UNKNOWN for NSG '{resource.address}'"
            return VerificationResult(
                status=status,
                resource_address=resource.address,
                pattern="NSG_OVER_EXPOSURE",
                message=msg,
            )

    def verify_azure_policy(
        self,
        resource: Resource,
        graph: ResourceGraph,
        timeout_ms: Optional[int] = None,
    ) -> Optional[VerificationResult]:
        policy_assignments = [
            r
            for r in graph.resources.values()
            if "policy_assignment" in r.type.lower() or "policyassignments" in r.type.lower()
        ]

        if not policy_assignments:
            return None

        policy_encoder = AzurePolicyEncoder()

        for assign in policy_assignments:
            pol_def_id = assign.attributes.get("policy_definition_id")
            pol_def_str = str(pol_def_id) if pol_def_id is not None else ""
            if isinstance(pol_def_id, ResourceReference):
                pol_def_str += " " + pol_def_id.target_address
            elif isinstance(pol_def_id, Unresolved):
                pol_def_str += " " + getattr(pol_def_id, "expression", "") + " " + getattr(pol_def_id, "reason", "")

            policy_def = None
            for r in graph.resources.values():
                if "policy_definition" in r.type.lower() or "policydefinitions" in r.type.lower():
                    res_leaf = r.address.split("/")[-1].split(".")[-1]
                    res_name = r.attributes.get("name")
                    if (
                        r.address in pol_def_str
                        or r.address == pol_def_str
                        or (res_name and str(res_name) in pol_def_str)
                        or (res_leaf and res_leaf in pol_def_str)
                    ):
                        policy_def = r
                        break

            if policy_def is None:
                continue

            violation_expr, err = policy_encoder.encode_policy_violation(policy_def, assign, resource, graph)

            if err:
                return VerificationResult(
                    status="UNRESOLVABLE",
                    resource_address=resource.address,
                    pattern="AZURE_GOVERNANCE_POLICY_VIOLATION",
                    message=f"Unable to evaluate Azure policy for {resource.address}: {err}",
                )

            solver = z3.Solver()
            eff_timeout = timeout_ms or self.timeout_ms
            solver.add(violation_expr)
            check_res = self._check_solver_with_timeout(solver, eff_timeout)

            if check_res == z3.sat:
                policy_rule_attr = policy_def.attributes.get("policy_rule")
                rule_dict = {}
                if isinstance(policy_rule_attr, str):
                    try:
                        rule_dict = json.loads(policy_rule_attr)
                    except Exception:
                        pass
                elif isinstance(policy_rule_attr, dict):
                    rule_dict = policy_rule_attr

                if_cond = rule_dict.get("if", {})

                return VerificationResult(
                    status="SAT",
                    resource_address=resource.address,
                    pattern="AZURE_GOVERNANCE_POLICY_VIOLATION",
                    message=f"Resource '{resource.address}' violates Azure Governance Policy '{policy_def.address}' assigned at scope '{assign.attributes.get('scope')}'",
                    witness={
                        "target_resource": resource.address,
                        "policy_definition": policy_def.address,
                        "policy_assignment": assign.address,
                        "scope": assign.attributes.get("scope"),
                        "violating_condition": if_cond,
                        "effect": "Deny",
                    },
                )

        return VerificationResult(
            status="UNSAT",
            resource_address=resource.address,
            pattern="AZURE_GOVERNANCE_POLICY_VIOLATION",
            message=f"Resource '{resource.address}' complies with all assigned Azure Governance Policies",
        )

    def verify_iam_policy(
        self, resource: Resource, timeout_ms: Optional[int] = None
    ) -> Optional[VerificationResult]:
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
        eff_timeout = timeout_ms or self.timeout_ms

        solver.add(unsafe_formula)
        check_res = self._check_solver_with_timeout(solver, eff_timeout)

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
            reason = solver.reason_unknown()
            is_timeout = reason in ("timeout", "interrupted", "canceled")
            status = "TIMEOUT" if is_timeout else "UNKNOWN"
            msg = f"Z3 solver timed out for IAM resource '{resource.address}'" if is_timeout else f"Z3 solver returned UNKNOWN for IAM resource '{resource.address}'"
            return VerificationResult(
                status=status,
                resource_address=resource.address,
                pattern="IAM_WILDCARD_ALLOW",
                message=msg,
            )

    def verify_privilege_escalation(
        self,
        graph: ResourceGraph,
        target_resource: Optional[str] = None,
        configured_cap: int = 10,
        entry_principal: Optional[str] = None,
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
        trust_graph = getattr(graph, "trust_graph", None)
        if trust_graph is None or not trust_graph.nodes:
            trust_graph = build_trust_graph(graph)

        cache_key = None
        if self.cache:
            cache_key = compute_cache_key(
                graph,
                target_resource or "graph",
                "PRIVILEGE_ESCALATION_REACHABILITY",
                configured_cap=configured_cap,
                entry_principal=entry_principal,
            )
            cached_res = self.cache.get(cache_key)
            if cached_res:
                return cached_res


        if trust_graph.unresolvable_roles:
            reasons_summary = "; ".join(trust_graph.unresolvable_reasons)
            res = VerificationResult(
                status="UNRESOLVABLE",
                resource_address=target_resource or "graph",
                pattern="PRIVILEGE_ESCALATION_REACHABILITY",
                message=f"Privilege escalation verification unresolvable due to bad/unresolved trust data: {reasons_summary}",
            )
            if self.cache and cache_key:
                self.cache.put(cache_key, res)
            return res

        # Identify target roles
        target_roles: set[str] = set()
        eff_timeout = timeout_ms or self.timeout_ms
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
                            if self._check_solver_with_timeout(s, eff_timeout) == z3.sat:
                                target_roles.add(address)

            if trust_graph.target_roles:
                target_roles.update(trust_graph.target_roles)

        role_count = len([n for n in trust_graph.nodes if not n.startswith("account:")])
        k, is_complete = compute_hop_bound(role_count, configured_cap)

        if not target_roles or not trust_graph.external_entry_points:
            res = VerificationResult(
                status="UNSAT",
                resource_address=target_resource or "graph",
                pattern="PRIVILEGE_ESCALATION_REACHABILITY",
                message="Privilege escalation complete proof of unreachability (no target roles or external entry points found)",
            )
            if self.cache and cache_key:
                self.cache.put(cache_key, res)
            return res

        if k == 0:
            res = VerificationResult(
                status="UNSAT" if is_complete else "UNSAT_BOUNDED",
                resource_address=target_resource or "graph",
                pattern="PRIVILEGE_ESCALATION_REACHABILITY",
                message="Privilege escalation unreachability proof (0 role nodes in graph)",
            )
            if self.cache and cache_key:
                self.cache.put(cache_key, res)
            return res

        ep_set: Optional[Set[str]] = None
        if entry_principal:
            if entry_principal in trust_graph.nodes:
                ep_set = {entry_principal}
            elif f"account:{entry_principal}" in trust_graph.nodes:
                ep_set = {f"account:{entry_principal}"}
            else:
                ep_set = {entry_principal}

        # Iterative shortening / shortest-reachable-path query (1 to k bounds)
        for current_k in range(1, k + 1):
            hop_vars, formula = encode_reachability_bmc(
                trust_graph, target_roles, current_k, entry_points=ep_set
            )


            z3.set_param("proof", True)
            solver = z3.Solver()

            solver.add(formula)
            check_res = self._check_solver_with_timeout(solver, eff_timeout)

            if check_res == z3.sat:
                model = solver.model()
                witness = extract_witness_from_model(model, hop_vars, trust_graph)
                res = VerificationResult(
                    status="SAT",
                    resource_address=witness.get("target_resource", target_resource or "graph"),
                    pattern="PRIVILEGE_ESCALATION_REACHABILITY",
                    message=f"Privilege escalation path found from '{witness['entry_point']}' to '{witness['target_resource']}' in {witness['path_length']} hop(s)",
                    witness=witness,
                )
                if self.cache and cache_key:
                    self.cache.put(cache_key, res)
                return res
            elif check_res == z3.unknown:
                reason = solver.reason_unknown()
                is_timeout = reason in ("timeout", "interrupted", "canceled")
                status = "TIMEOUT" if is_timeout else "UNKNOWN"
                msg = f"Z3 solver timed out during reachability check at hop {current_k}" if is_timeout else f"Z3 solver returned UNKNOWN during reachability check at hop {current_k}"
                res = VerificationResult(
                    status=status,
                    resource_address=target_resource or "graph",
                    pattern="PRIVILEGE_ESCALATION_REACHABILITY",
                    message=msg,
                )
                if self.cache and cache_key:
                    self.cache.put(cache_key, res)
                return res

        # If we exhausted k hops without finding a path
        proof_str = None
        try:
            if solver.proof() is not None:
                proof_str = str(solver.proof().sexpr())
        except Exception:
            proof_str = None

        if is_complete:
            res = VerificationResult(
                status="UNSAT",
                resource_address=target_resource or "graph",
                pattern="PRIVILEGE_ESCALATION_REACHABILITY",
                message=f"Privilege escalation complete proof of unreachability (searched {k} hops across {role_count} roles)",
                z3_proof_sexpr=proof_str,
            )
        else:
            res = VerificationResult(
                status="UNSAT_BOUNDED",
                resource_address=target_resource or "graph",
                pattern="PRIVILEGE_ESCALATION_REACHABILITY",
                message=f"No privilege escalation path found within bounded limit of {k} hops ({role_count} roles total)",
                z3_proof_sexpr=proof_str,
            )
            
        if self.cache and cache_key:
            self.cache.put(cache_key, res)
        return res

    def verify_incremental(self, graph: ResourceGraph, changed_files: List[str]) -> List[VerificationResult]:
        """
        Incrementally verify only the resources affected by changed_files.
        This relies on the dependency-aware VerificationCache to detect which
        cache keys have changed. It returns ONLY the VerificationResult for
        resources that needed re-verification.
        """
        results = []
        changed_files_set = set(os.path.abspath(f) for f in changed_files)
        
        # Identify resources whose file_path is in changed_files
        directly_modified = set()
        for address, resource in graph.resources.items():
            if resource.file_path and os.path.abspath(resource.file_path) in changed_files_set:
                directly_modified.add(address)

        for address, resource in graph.resources.items():
            if resource.merged_into is not None:
                continue

            if resource.type in ("aws_security_group", "aws_security_group_rule"):
                cache_key = compute_cache_key(graph, address, "SG_OVER_EXPOSURE")
                deps = set([address])
                for addr, r in graph.resources.items():
                    if r.merged_into == address:
                        deps.add(addr)
                        policy_arn = r.attributes.get("policy_arn")
                        if isinstance(policy_arn, ResourceReference):
                            deps.add(policy_arn.target_address)
                for rs in resource.rule_sources:
                    if getattr(rs, "referenced_security_group_id", None):
                        if isinstance(rs.referenced_security_group_id, ResourceReference):
                            deps.add(rs.referenced_security_group_id.target_address)
                        elif isinstance(rs.referenced_security_group_id, str):
                            deps.add(rs.referenced_security_group_id)
                
                is_affected = any(dep in directly_modified for dep in deps)
                
                if is_affected or not self.cache or not self.cache.get(cache_key):
                    res = self.verify_security_group(resource)
                    if res:
                        if self.cache:
                            self.cache.put(cache_key, res)
                        results.append(res)
                        
            elif resource.type in ("aws_iam_role", "aws_iam_policy", "aws_iam_role_policy", "aws_iam_user_policy", "aws_iam_group_policy", "aws_s3_bucket_policy"):
                cache_key = compute_cache_key(graph, address, "IAM_WILDCARD_ALLOW")
                deps = set([address])
                for addr, r in graph.resources.items():
                    if r.merged_into == address:
                        deps.add(addr)
                        policy_arn = r.attributes.get("policy_arn")
                        if isinstance(policy_arn, ResourceReference):
                            deps.add(policy_arn.target_address)
                
                is_affected = any(dep in directly_modified for dep in deps)
                
                if is_affected or not self.cache or not self.cache.get(cache_key):
                    res = self.verify_iam_policy(resource)
                    if res:
                        if self.cache:
                            self.cache.put(cache_key, res)
                        results.append(res)
                        
            elif resource.type in ("azurerm_network_security_group", "azurerm_network_security_rule"):
                cache_key = compute_cache_key(graph, address, "NSG_OVER_EXPOSURE")
                deps = set([address])
                for addr, r in graph.resources.items():
                    if r.merged_into == address:
                        deps.add(addr)
                for rs in resource.rule_sources:
                    if getattr(rs, "destination_address_prefix", None):
                        if isinstance(rs.destination_address_prefix, ResourceReference):
                            deps.add(rs.destination_address_prefix.target_address)
                        elif isinstance(rs.destination_address_prefix, str):
                            deps.add(rs.destination_address_prefix)
                
                is_affected = any(dep in directly_modified for dep in deps)
                
                if is_affected or not self.cache or not self.cache.get(cache_key):
                    res = self.verify_azure_nsg(resource)
                    if res:
                        if self.cache:
                            self.cache.put(cache_key, res)
                        results.append(res)

                        
        # Privilege escalation is global, if its cache key changed, re-run
        cache_key = compute_cache_key(graph, "graph", "PRIVILEGE_ESCALATION_REACHABILITY")
        if not self.cache or not self.cache.get(cache_key):
            res = self.verify_privilege_escalation(graph)
            if res:
                if self.cache:
                    self.cache.put(cache_key, res)
                results.append(res)

        return results
