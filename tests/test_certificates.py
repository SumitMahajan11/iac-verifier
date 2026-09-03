from pathlib import Path
import json
import tempfile
import pytest

from parser.hcl_parser import parse_file, build_graph
from parser.references import resolve_resource_references
from parser.attachments import resolve_rule_attachments
from solver.engine import VerificationEngine
from solver.certificates import generate_certificate_from_result
from cli.main import run_verify

FIXTURES_DIR = Path(__file__).parent.parent / "fixtures"

def test_simple_unsat_proof_certificate():
    file_path = FIXTURES_DIR / "phase2" / "sg_restricted_ssh.tf"
    parsed = parse_file(file_path)
    graph = build_graph(parsed)
    engine = VerificationEngine()
    results = engine.verify_graph(graph)

    assert len(results) == 1
    res = results[0]
    assert res.status == "UNSAT"

    cert = generate_certificate_from_result(res)
    assert cert["certificate_type"] == "UNSAT_PROOF_CERTIFICATE"
    assert cert["status"] == "UNSAT"
    assert cert["resource_address"] == "aws_security_group.restricted_ssh"

    proof_sexpr = cert["unsat_proof"]["z3_proof_object_sexpr"]
    assert proof_sexpr != "(proof-not-logged)"
    assert len(proof_sexpr) > 100
    assert "let" in proof_sexpr or "unit-resolution" in proof_sexpr or "asserted" in proof_sexpr


def test_complex_multi_hop_unsat_proof_certificate():
    file_path = FIXTURES_DIR / "phase5" / "realistic_escalation.tf"
    parsed = parse_file(file_path)
    graph = build_graph(parsed)
    graph = resolve_resource_references(graph)
    graph = resolve_rule_attachments(graph)

    engine = VerificationEngine()
    res = engine.verify_privilege_escalation(graph, target_resource="aws_iam_role.role_blocked")

    assert res.status in ("UNSAT", "UNSAT_BOUNDED")

    cert = generate_certificate_from_result(res)
    assert cert["certificate_type"] == "UNSAT_PROOF_CERTIFICATE"

    proof_sexpr = cert["unsat_proof"]["z3_proof_object_sexpr"]
    assert proof_sexpr != "(proof-not-logged)"
    assert len(proof_sexpr) > 1000
    assert "hop_" in proof_sexpr or "aws_iam_role" in proof_sexpr


def test_cli_export_certificate():
    file_path = FIXTURES_DIR / "phase2" / "sg_restricted_ssh.tf"
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
        tmp_path = tmp.name

    try:
        exit_code = run_verify(str(file_path), export_certificate_path=tmp_path)
        assert exit_code == 0

        with open(tmp_path, "r", encoding="utf-8") as f:
            data = json.load(f)

        assert data["certificate_type"] == "UNSAT_PROOF_CERTIFICATE"
        assert data["status"] == "UNSAT"
        assert len(data["unsat_proof"]["z3_proof_object_sexpr"]) > 100
    finally:
        if Path(tmp_path).exists():
            Path(tmp_path).unlink()


def test_sat_witness_trace_certificate():
    file_path = FIXTURES_DIR / "phase2" / "sg_open_ssh.tf"
    parsed = parse_file(file_path)
    graph = build_graph(parsed)
    engine = VerificationEngine()
    results = engine.verify_graph(graph)

    assert len(results) == 1
    res = results[0]
    assert res.status == "SAT"

    cert = generate_certificate_from_result(res)
    assert cert["certificate_type"] == "SAT_WITNESS_TRACE"
    assert cert["status"] == "SAT"
    assert cert["resource_address"] == "aws_security_group.open_ssh"
    assert "witness" in cert
    assert cert["witness"]["smt_counterexample_ip"] == "0.0.0.0"

