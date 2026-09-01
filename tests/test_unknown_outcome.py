from parser.hcl_parser import parse_file, build_graph
from solver.engine import VerificationEngine
import z3

def test_genuine_unknown():
    parsed = parse_file("fixtures/phase2/sg_open_ssh.tf")
    graph = build_graph(parsed)
    eng = VerificationEngine()
    
    res = graph.resources["aws_security_group.open_ssh"]
    
    # We want to force UNKNOWN. We can monkey-patch z3.Solver to always set timeout to 1
    # and provide a very hard formula.
    original_solver = z3.Solver
    
    def mock_solver(*args, **kwargs):
        s = original_solver(*args, **kwargs)
        s.set("timeout", 1)
        # add a hard non-linear arithmetic problem
        x, y = z3.Ints('x y')
        s.add(x * x * x + y * y * y == 114)
        return s
        
    z3.Solver = mock_solver
    try:
        ver_res = eng.verify_security_group(res)
        assert ver_res.status == "UNKNOWN"
    finally:
        z3.Solver = original_solver
