"""
Phase 4 Benchmark Harness & Comparative Evaluation Runner.

Evaluates iac-verifier against ground-truth labeled public corpora (terragoat, sadcloud),
excluding ambiguous cases into an AMBIGUOUS_EXCLUDED bucket, and calculating Precision,
Recall, F1-Score, and comparative differential stats against baseline static analyzers.
"""

import json
import os
from typing import Dict, Any, List, Tuple

from parser.hcl_parser import parse_file, build_graph
from parser.references import resolve_resource_references
from parser.attachments import resolve_rule_attachments
from solver.engine import VerificationEngine
from benchmark.differential_check import run_differential_check


class BenchmarkHarness:
    def __init__(self, ground_truth_file: str):
        self.ground_truth_file = ground_truth_file
        self.engine = VerificationEngine()
        self.cases: List[Dict[str, Any]] = []
        self.load_ground_truth()

    def load_ground_truth(self) -> None:
        if os.path.exists(self.ground_truth_file):
            with open(self.ground_truth_file, "r", encoding="utf-8") as f:
                self.cases = json.load(f)

    def run_preflight_differential_check(self) -> bool:
        print("=== Running §10 Pre-flight Differential Verification Check ===")
        success, errors = run_differential_check(self.cases)
        if not success:
            print("ERROR: Pre-flight §10 Differential Verification Failed!")
            for err in errors:
                print(f"  - {err}")
            return False
        print("SUCCESS: Pre-flight §10 Differential Check Passed Cleanly.\n")
        return True

    def evaluate(self) -> Dict[str, Any]:
        if not self.run_preflight_differential_check():
            raise RuntimeError("Pre-flight differential check failed. Benchmark aborted to prevent invalid metrics.")

        tp, fp, fn, tn = 0, 0, 0, 0
        ambiguous_excluded: List[Dict[str, Any]] = []
        evaluated_cases: List[Dict[str, Any]] = []

        for case in self.cases:
            ambiguity = case.get("ambiguity", {})
            if ambiguity.get("is_ambiguous", False):
                ambiguous_excluded.append({
                    "corpus": case.get("corpus"),
                    "file": case.get("file"),
                    "resource_id": case.get("resource_id"),
                    "reason": ambiguity.get("reason", "Unspecified ambiguity")
                })
                continue

            file_path = case.get("file")
            expected = case.get("expected_engine_state")
            vuln_class = case.get("vulnerability_class")
            target_resource_id = case.get("resource_id")

            if not file_path or not os.path.exists(file_path):
                # File not present on local filesystem (or test environment stub)
                ambiguous_excluded.append({
                    "corpus": case.get("corpus"),
                    "file": file_path,
                    "resource_id": case.get("resource_id"),
                    "reason": "File path does not exist locally"
                })
                continue

            try:
                parsed = parse_file(file_path)
                graph = build_graph(parsed)
                graph = resolve_resource_references(graph)
                graph = resolve_rule_attachments(graph)

                actual = "UNSAT"
                if vuln_class == "SG_EXPOSURE":
                    target_res = graph.resources.get(target_resource_id) if target_resource_id else None
                    if not target_res:
                        sg_resources = [r for r in graph.resources.values() if r.type in ("aws_security_group", "aws_security_group_rule")]
                        target_res = sg_resources[0] if sg_resources else None
                    
                    if target_res:
                        res_eval = self.engine.verify_security_group(target_res)
                        actual = res_eval.status
                        
                elif vuln_class == "IAM_WILDCARD_GRANT":
                    target_res = graph.resources.get(target_resource_id) if target_resource_id else None
                    if not target_res:
                        iam_resources = [r for r in graph.resources.values() if r.type in ("aws_iam_policy", "aws_iam_role_policy")]
                        target_res = iam_resources[0] if iam_resources else None
                        
                    if target_res:
                        res_eval = self.engine.verify_iam_policy(target_res)
                        actual = res_eval.status
                        
                elif vuln_class == "PRIVILEGE_ESCALATION_PATH":
                    res_eval = self.engine.verify_privilege_escalation(graph)
                    actual = res_eval.status

            except Exception as e:
                actual = "UNRESOLVABLE"

            # Binary classification mapping for vulnerability detection metrics:
            # Positive (Vulnerable): expected == "SAT"
            # Negative (Safe/Clean): expected in ("UNSAT", "UNSAT_BOUNDED")
            is_expected_positive = (expected == "SAT")
            is_actual_positive = (actual == "SAT")

            if is_expected_positive and is_actual_positive:
                tp += 1
            elif not is_expected_positive and is_actual_positive:
                fp += 1
            elif is_expected_positive and not is_actual_positive:
                fn += 1
            else:
                tn += 1

            evaluated_cases.append({
                "file": file_path,
                "resource_id": target_resource_id,
                "expected": expected,
                "actual": actual,
                "status": "PASS" if expected == actual else "FAIL"
            })

        precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        f1 = (2 * precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0

        summary = {
            "total_cases": len(self.cases),
            "evaluated_count": len(evaluated_cases),
            "ambiguous_excluded_count": len(ambiguous_excluded),
            "ambiguous_excluded_details": ambiguous_excluded,
            "metrics": {
                "true_positives": tp,
                "false_positives": fp,
                "false_negatives": fn,
                "true_negatives": tn,
                "precision": round(precision, 4),
                "recall": round(recall, 4),
                "f1_score": round(f1, 4)
            },
            "evaluated_cases": evaluated_cases
        }
        return summary


if __name__ == "__main__":
    gt_path = os.path.join(os.path.dirname(__file__), "ground_truth.json")
    if os.path.exists(gt_path):
        harness = BenchmarkHarness(gt_path)
        metrics = harness.evaluate()
        out_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "harness_output.json")
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(metrics, f, indent=2)
        print(json.dumps(metrics, indent=2))
    else:
        print(f"Ground truth dataset not found at {gt_path}")
