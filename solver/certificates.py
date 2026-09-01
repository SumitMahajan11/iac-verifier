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
            "z3_version": ".".join(map(str, z3.get_version())),
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
            "z3_version": ".".join(map(str, z3.get_version())),
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
