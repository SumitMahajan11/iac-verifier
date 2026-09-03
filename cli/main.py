"""
Phase 7 Command-Line Interface (cli/main.py).

Provides automated verification and deletion-based auto-repair for Terraform HCL configurations.
Exit Codes:
  0 - Success: Safe / UNSAT Invariant Verified / REMEDIATED_MINIMAL
  1 - Finding / Failure: SAT Vulnerability Detected / Auto-Repair Failed
  2 - Engine Exception / Unresolvable Dependency
"""

import argparse
from dataclasses import asdict
import json
import os
import sys
from typing import Dict, Any, List, Optional

from parser.hcl_parser import parse_file, build_graph
from parser.references import resolve_resource_references
from parser.attachments import resolve_rule_attachments
from solver.certificates import generate_certificate_from_result
from solver.engine import VerificationEngine
from solver.repair import AutoRepairEngine


def run_verify(target_path: str, json_output: bool = False, export_certificate_path: Optional[str] = None) -> int:
    """Runs verification on target Terraform HCL file or directory."""
    if not os.path.exists(target_path):
        print(f"Error: Target path '{target_path}' does not exist.", file=sys.stderr)
        return 2

    files_to_process = []
    if os.path.isfile(target_path):
        files_to_process.append(target_path)
    else:
        for root, _, files in os.walk(target_path):
            for file in files:
                if file.endswith(".tf"):
                    files_to_process.append(os.path.join(root, file))

    if not files_to_process:
        print(f"Error: No .tf files found at '{target_path}'.", file=sys.stderr)
        return 2

    engine = VerificationEngine()
    overall_results: List[Dict[str, Any]] = []
    certificates: List[Dict[str, Any]] = []
    has_sat = False
    has_unresolvable = False

    for file_path in files_to_process:
        try:
            parsed = parse_file(file_path)
            graph = build_graph(parsed, file_path=file_path)
            graph = resolve_resource_references(graph)
            graph = resolve_rule_attachments(graph)

            results = engine.verify_graph(graph)
            
            # Graph-level privilege escalation check if IAM roles present
            iam_roles = [r for r in graph.resources.values() if r.type == "aws_iam_role"]
            if len(iam_roles) >= 2:
                esc_eval = engine.verify_privilege_escalation(graph)
                if esc_eval:
                    results.append(esc_eval)
            
            for res_eval in results:
                overall_results.append(asdict(res_eval))
                certificates.append(generate_certificate_from_result(res_eval))
                if res_eval.status == "SAT":
                    has_sat = True
                elif res_eval.status in ("UNRESOLVABLE", "UNKNOWN"):
                    has_unresolvable = True

        except Exception as e:
            overall_results.append({
                "status": "UNRESOLVABLE",
                "file": file_path,
                "message": f"Parsing/building error: {str(e)}"
            })
            has_unresolvable = True

    if export_certificate_path:
        os.makedirs(os.path.dirname(os.path.abspath(export_certificate_path)), exist_ok=True)
        with open(export_certificate_path, "w", encoding="utf-8") as f:
            json.dump(certificates if len(certificates) > 1 else (certificates[0] if certificates else {}), f, indent=2)

    if json_output:
        print(json.dumps({
            "target": target_path,
            "total_verifications": len(overall_results),
            "results": overall_results
        }, indent=2))
    else:
        print(f"=== Verification Report: {target_path} ===")
        for res in overall_results:
            status = res.get("status")
            addr = res.get("resource_address", res.get("file", "graph"))
            msg = res.get("message", "")
            print(f"[{status}] {addr}: {msg}")
        if export_certificate_path:
            print(f"Exported {len(certificates)} proof certificate(s) to '{export_certificate_path}'")

    if has_unresolvable:
        return 2
    elif has_sat:
        return 1
    return 0


def run_repair(target_path: str, resource_address: str, pattern: str, json_output: bool = False) -> int:
    """Runs auto-repair on specified resource address and vulnerability pattern."""
    if not os.path.exists(target_path):
        print(f"Error: Target path '{target_path}' does not exist.", file=sys.stderr)
        return 2

    try:
        target_file = target_path if os.path.isfile(target_path) else os.path.join(target_path, "main.tf")
        parsed = parse_file(target_file)
        graph = build_graph(parsed, file_path=target_file)
        graph = resolve_resource_references(graph)
        graph = resolve_rule_attachments(graph)

        repair_engine = AutoRepairEngine()
        result = repair_engine.repair_resource(graph, resource_address, pattern)

        if json_output:
            print(json.dumps(asdict(result), indent=2))
        else:
            print(f"=== Auto-Repair Report ===")
            print(f"Resource: {result.resource_address}")
            print(f"Pattern:  {result.pattern}")
            print(f"Status:   {result.status}")
            print(f"Message:  {result.message}")
            if result.deleted_rules:
                print(f"Deleted Rules ({len(result.deleted_rules)}):")
                for d in result.deleted_rules:
                    print(f"  - [{d.get('resource_address')}] Index {d.get('statement_index')}: {d.get('rule_type')}")
            if result.patch:
                print("\n=== Unified Diff Patch (Human-in-the-Loop Review) ===")
                print(result.patch)

        if result.status in ("REMEDIATED_MINIMAL", "NO_VULNERABILITY"):
            return 0
        return 1

    except Exception as e:
        if json_output:
            print(json.dumps({"status": "FAILED", "error": str(e)}, indent=2))
        else:
            print(f"Error during repair execution: {str(e)}", file=sys.stderr)
        return 2


def main():
    parser = argparse.ArgumentParser(description="IaC Symbolic SMT Verifier & Auto-Repair Engine")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # verify subcommand
    verify_parser = subparsers.add_parser("verify", help="Verify Terraform HCL file or directory")
    verify_parser.add_argument("path", help="Path to .tf file or directory containing .tf files")
    verify_parser.add_argument("--json", action="store_true", help="Output verification report in JSON")
    verify_parser.add_argument("--export-certificate", help="Export formal SMT proof certificate(s) as JSON file")

    # repair subcommand
    repair_parser = subparsers.add_parser("repair", help="Run auto-repair on a target vulnerable resource")
    repair_parser.add_argument("path", help="Path to .tf file or directory")
    repair_parser.add_argument("--resource", required=True, help="Target resource address (e.g. aws_security_group.sg_open_ssh)")
    repair_parser.add_argument("--pattern", required=True, choices=["SG_OVER_EXPOSURE", "IAM_WILDCARD_ALLOW", "PRIVILEGE_ESCALATION_PATH"], help="Vulnerability pattern")
    repair_parser.add_argument("--json", action="store_true", help="Output repair report in JSON")

    args = parser.parse_args()

    if args.command == "verify":
        code = run_verify(args.path, json_output=args.json, export_certificate_path=args.export_certificate)
        sys.exit(code)
    elif args.command == "repair":
        code = run_repair(args.path, resource_address=args.resource, pattern=args.pattern, json_output=args.json)
        sys.exit(code)



if __name__ == "__main__":
    main()
