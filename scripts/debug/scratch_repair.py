import json
import os
from solver.repair import AutoRepairEngine
from parser.hcl_parser import parse_file, build_graph
from solver.engine import VerificationEngine

cases = [
    ("fixtures/corpora/terragoat/terraform/aws/ec2.tf", "aws_security_group.web-node", "SG_OVER_EXPOSURE"),
    ("fixtures/corpora/sadcloud/modules/aws/iam/main.tf", "aws_iam_policy.policy", "IAM_WILDCARD_ALLOW"),
    ("fixtures/corpora/sadcloud/modules/aws/ec2/main.tf", "aws_security_group.all_ports_to_all", "SG_OVER_EXPOSURE")
]

for f, r, v in cases:
    parsed = parse_file(f)
    graph = build_graph(parsed)
    print(f"=== {f} | {r} ===")
    eng = VerificationEngine()
    results = eng.verify_graph(graph)
    for res in results:
        if res.resource_address == r:
            print(f"Before-status: {res.status} (SAT means vulnerable)")
            break
    else:
        print("Before-status: NOT FOUND")
    
    rep = AutoRepairEngine()
    try:
        remediation_res = rep.repair_resource(graph, r, v)
        print(f"Deleted rules: {remediation_res.deleted_rules}")
        print(f"After-status: {remediation_res.reverified_status} (UNSAT means safe)")
    except Exception as e:
        import traceback
        traceback.print_exc()
        print(f"Error repairing: {e}")
    print()
