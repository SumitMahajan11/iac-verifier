from parser.hcl_parser import parse_file, build_graph
from solver.engine import VerificationEngine

def test_s3_bucket_policy_sat_and_unsat():
    parsed = parse_file("fixtures/phase7/s3_bucket_policy.tf")
    graph = build_graph(parsed)
    eng = VerificationEngine()
    results = eng.verify_graph(graph)
    
    sat_res = next((r for r in results if r.resource_address == "aws_s3_bucket_policy.wildcard_sat"), None)
    assert sat_res is not None
    assert sat_res.status == "SAT"
    
    unsat_res = next((r for r in results if r.resource_address == "aws_s3_bucket_policy.scoped_unsat"), None)
    assert unsat_res is not None
    assert unsat_res.status == "UNSAT"
