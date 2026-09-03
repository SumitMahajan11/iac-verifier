from __future__ import annotations

import datetime
from typing import Any, Dict, List, Optional
import z3


def generate_sat_certificate(resource_address: str, pattern: str, witness: Dict[str, Any]) -> Dict[str, Any]:
    """Generates a SAT witness trace proof certificate JSON object."""
    return {
        "certificate_type": "SAT_WITNESS_TRACE",
        "status": "SAT",
        "pattern": pattern,
        "resource_address": resource_address,
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "solver_info": {
            "engine": "Z3 SMT Solver (VerificationEngine)",
            "z3_version": z3.get_version_string(),
        },
        "witness": witness,
    }


def generate_unsat_certificate(
    resource_address: str,
    pattern: str,
    unsat_core_literals: Optional[List[str]] = None,
    tracked_rule_mappings: Optional[List[Dict[str, Any]]] = None,
    z3_proof_sexpr: Optional[str] = None,
    unreachability_invariant: Optional[str] = None,
    hop_bound_k: Optional[int] = None,
    is_complete_proof: bool = True,
) -> Dict[str, Any]:
    """Generates an UNSAT proof certificate JSON object."""
    return {
        "certificate_type": "UNSAT_PROOF_CERTIFICATE",
        "status": "UNSAT" if is_complete_proof else "UNSAT_BOUNDED",
        "pattern": pattern,
        "resource_address": resource_address,
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "solver_info": {
            "engine": "Z3 SMT Solver (VerificationEngine)",
            "z3_version": z3.get_version_string(),
            "hop_bound_k": hop_bound_k,
            "is_complete_proof": is_complete_proof,
        },
        "unsat_proof": {
            "unsat_core_literals": unsat_core_literals or [],
            "tracked_rule_mappings": tracked_rule_mappings or [],
            "z3_proof_object_sexpr": z3_proof_sexpr or "(proof-not-logged)",
            "unreachability_invariant": unreachability_invariant
            or f"No symbolic assignment satisfies the unsafe predicate for '{pattern}' on resource '{resource_address}'.",
        },
    }


def generate_certificate_from_result(result: Any) -> Dict[str, Any]:
    """Converts a VerificationResult instance into a formal proof certificate JSON structure."""
    status = getattr(result, "status", "UNKNOWN")
    resource_address = getattr(result, "resource_address", "graph")
    pattern = getattr(result, "pattern", "UNKNOWN_PATTERN")
    message = getattr(result, "message", "")

    if status == "SAT":
        return generate_sat_certificate(
            resource_address=resource_address,
            pattern=pattern,
            witness=getattr(result, "witness", {}) or {},
        )
    elif status in ("UNSAT", "UNSAT_BOUNDED"):
        return generate_unsat_certificate(
            resource_address=resource_address,
            pattern=pattern,
            unsat_core_literals=getattr(result, "unsat_core", None),
            z3_proof_sexpr=getattr(result, "z3_proof_sexpr", None),
            unreachability_invariant=message,
            is_complete_proof=(status == "UNSAT"),
        )
    else:
        return {
            "certificate_type": "VERIFICATION_ERROR_CERTIFICATE",
            "status": status,
            "pattern": pattern,
            "resource_address": resource_address,
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "solver_info": {
                "engine": "Z3 SMT Solver (VerificationEngine)",
                "z3_version": z3.get_version_string(),
            },
            "error_details": {"message": message},
        }

