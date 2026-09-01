from pathlib import Path
from parser.hcl_parser import parse_file, build_graph
from solver.engine import VerificationEngine

FIXTURES_DIR = Path(__file__).parent.parent / "fixtures" / "phase2"


def test_fixture_sg_open_ssh():
    path = str(FIXTURES_DIR / "sg_open_ssh.tf")
    parsed = parse_file(path)
    graph = build_graph(parsed)

    engine = VerificationEngine()
    results = engine.verify_graph(graph)

    assert len(results) == 1
    res = results[0]

    # Outcome verification: MUST be SAT (unsafe) with witness detailing resource and sensitive port
    assert res.status == "SAT"
    assert res.resource_address == "aws_security_group.open_ssh"
    assert res.pattern == "SG_OVER_EXPOSURE"
    assert res.witness is not None
    assert res.witness["resource"] == "aws_security_group.open_ssh"
    assert 22 in res.witness["sensitive_ports"]
    assert len(res.witness["violating_rules"]) == 1
    assert res.witness["violating_rules"][0]["cidr_blocks"] == ["0.0.0.0/0"]


def test_fixture_sg_restricted_ssh():
    path = str(FIXTURES_DIR / "sg_restricted_ssh.tf")
    parsed = parse_file(path)
    graph = build_graph(parsed)

    engine = VerificationEngine()
    results = engine.verify_graph(graph)

    assert len(results) == 1
    res = results[0]

    # Outcome verification: MUST be UNSAT (safe)
    assert res.status == "UNSAT"
    assert res.resource_address == "aws_security_group.restricted_ssh"
    assert res.pattern == "SG_OVER_EXPOSURE"
    assert res.witness is None


def test_fixture_sg_adjacent_cidr_safe():
    path = str(FIXTURES_DIR / "sg_adjacent_cidr_safe.tf")
    parsed = parse_file(path)
    graph = build_graph(parsed)

    engine = VerificationEngine()
    results = engine.verify_graph(graph)

    assert len(results) == 1
    res = results[0]

    # Outcome verification: MUST be UNSAT (safe)
    assert res.status == "UNSAT"
    assert res.resource_address == "aws_security_group.adjacent_safe"
    assert res.pattern == "SG_OVER_EXPOSURE"


def test_fixture_iam_wildcard_allow():
    path = str(FIXTURES_DIR / "iam_wildcard_allow.tf")
    parsed = parse_file(path)
    graph = build_graph(parsed)

    engine = VerificationEngine()
    results = engine.verify_graph(graph)

    assert len(results) == 1
    res = results[0]

    # Outcome verification: MUST be SAT (unsafe)
    assert res.status == "SAT"
    assert res.resource_address == "aws_iam_policy.wildcard_allow"
    assert res.pattern == "IAM_WILDCARD_ALLOW"
    assert res.witness is not None
    assert res.witness["resource"] == "aws_iam_policy.wildcard_allow"
    assert len(res.witness["wildcard_statements"]) == 1
    assert res.witness["wildcard_statements"][0]["actions"] == ["*"]


def test_fixture_iam_wildcard_with_deny():
    path = str(FIXTURES_DIR / "iam_wildcard_with_deny.tf")
    parsed = parse_file(path)
    graph = build_graph(parsed)

    engine = VerificationEngine()
    results = engine.verify_graph(graph)

    assert len(results) == 1
    res = results[0]

    # Outcome verification: MUST be UNSAT (safe) because Deny overrides Allow
    assert res.status == "UNSAT"
    assert res.resource_address == "aws_iam_policy.wildcard_with_deny"
    assert res.pattern == "IAM_WILDCARD_ALLOW"


def test_fixture_iam_unresolved_mixed():
    path = str(FIXTURES_DIR / "iam_unresolved_mixed.tf")
    parsed = parse_file(path)
    graph = build_graph(parsed)

    engine = VerificationEngine()
    results = engine.verify_graph(graph)

    assert len(results) == 1
    res = results[0]

    # Outcome verification: MUST be UNRESOLVABLE (unable to verify, NOT safe or UNSAT)
    assert res.status == "UNRESOLVABLE"
    assert res.resource_address == "aws_iam_policy.unresolved_mixed"
    assert res.pattern == "IAM_WILDCARD_ALLOW"
    assert "unresolved" in res.message.lower()
