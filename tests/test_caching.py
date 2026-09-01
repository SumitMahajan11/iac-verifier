import time
import shutil
from pathlib import Path
from parser.modules import parse_directory
from parser.expansion import build_graph_with_expansion
from parser.references import resolve_resource_references
from parser.attachments import resolve_rule_attachments
from solver.engine import VerificationEngine
import pytest
import os

def test_cache_invalidation_transitive():
    test_dir = Path("scratch/cache_test")
    test_dir.mkdir(parents=True, exist_ok=True)
    tf_path = test_dir / "main.tf"
    tf_path.write_text("""
resource "aws_iam_role" "b" {
  name = "role_b"
  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Principal": {"AWS": "*"},
      "Action": "sts:AssumeRole",
      "Resource": "arn:aws:iam::123:root"
    }
  ]
}
EOF
}

resource "aws_iam_role_policy" "a" {
  name   = "policy_a"
  role   = aws_iam_role.b.id
  policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": "s3:GetObject",
      "Resource": "arn:aws:s3:::safe-bucket"
    }
  ]
}
EOF
}
""")
    engine = VerificationEngine(use_cache=True)
    if os.path.exists(".iac_cache"):
        shutil.rmtree(".iac_cache")

    # Run 1: Cold cache
    t0 = time.time()
    parsed = parse_directory(str(test_dir))
    graph = build_graph_with_expansion(parsed, str(test_dir))
    graph = resolve_resource_references(graph)
    graph = resolve_rule_attachments(graph)
    res1 = engine.verify_graph(graph)
    t1 = time.time()
    cold_time = t1 - t0

    assert res1[0].status == "UNSAT"

    # Run 2: Hot cache, no changes
    t0 = time.time()
    parsed = parse_directory(str(test_dir))
    graph = build_graph_with_expansion(parsed, str(test_dir))
    graph = resolve_resource_references(graph)
    graph = resolve_rule_attachments(graph)
    res2 = engine.verify_graph(graph)
    t1 = time.time()
    hot_time = t1 - t0

    assert res2[0].status == "UNSAT"

    # Run 3: Modify resource A (the policy), should invalidate cache for B (the role)
    tf_path.write_text("""
resource "aws_iam_role" "b" {
  name = "role_b"
  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Principal": {"AWS": "*"},
      "Action": "sts:AssumeRole",
      "Resource": "arn:aws:iam::123:root"
    }
  ]
}
EOF
}

resource "aws_iam_role_policy" "a" {
  name   = "policy_a"
  role   = aws_iam_role.b.id
  policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": "s3:GetObject",
      "Resource": "*"
    }
  ]
}
EOF
}
""")
    t0 = time.time()
    parsed = parse_directory(str(test_dir))
    graph = build_graph_with_expansion(parsed, str(test_dir))
    graph = resolve_resource_references(graph)
    graph = resolve_rule_attachments(graph)
    res3 = engine.verify_graph(graph)
    t1 = time.time()
    invalidation_time = t1 - t0

    # Resource B (aws_iam_role) should now be SAT because the attached policy grants s3:* on *
    assert res3[0].status == "SAT"
    
    print(f"Cold Time: {cold_time}")
    print(f"Hot Time (cached): {hot_time}")
    print(f"Invalidation Time (re-verify): {invalidation_time}")
    
    assert hot_time < cold_time

    # Run 4: Fresh re-verification (no cache) to ensure exact equality with cached-then-invalidated result
    engine_fresh = VerificationEngine(use_cache=False)
    res_fresh = engine_fresh.verify_graph(graph)
    
    assert len(res3) == len(res_fresh)
    for r3, rf in zip(res3, res_fresh):
        assert r3.status == rf.status
        assert r3.pattern == rf.pattern
        assert r3.witness == rf.witness
        assert r3.z3_proof_sexpr == rf.z3_proof_sexpr
