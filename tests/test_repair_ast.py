"""
tests/test_repair_ast.py

Comprehensive regression test suite for AST-based auto-repair engine (solver/ast_repair.py).
Validates format-preserving remediation across:
  - Mode 1: Standalone blocks with comments containing braces }
  - Mode 2: HCL list attributes (ingress = [ { ... } ])
  - Mode 3: IAM jsonencode statements (policy = jsonencode({ Statement = [ { ... } ] }))
"""

import os
import pytest
import hcl2
from solver.ast_repair import ASTRepairEngine
from solver.repair import generate_unified_diff, AutoRepairEngine
from parser.hcl_parser import parse_file, build_graph
from solver.engine import VerificationEngine


def test_ast_repair_mode1_comment_brace():
    """Mode 1: Ensures comments containing braces } are preserved during block deletion."""
    hcl = '''resource "aws_security_group" "web_sg" {
  name = "web_sg"
  # Comment closing brace } here
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/16"]
  }
}
'''
    repaired = ASTRepairEngine.repair_hcl(hcl, "aws_security_group", "web_sg", [0])

    assert '# Comment closing brace } here' in repaired
    assert 'from_port   = 22' not in repaired
    assert 'from_port   = 80' in repaired
    assert repaired.strip().endswith('}')

    # Validate HCL re-parsing
    parsed = hcl2.loads(repaired)
    res_block = parsed.get("resource", [{}])[0]
    assert "aws_security_group" in res_block or '"aws_security_group"' in res_block


def test_ast_repair_mode2_list_attribute():
    """Mode 2: Ensures list attributes (ingress = [ ... ]) can be repaired element-wise."""
    hcl = '''resource "aws_security_group" "web_sg" {
  name = "web_sg"
  ingress = [
    {
      from_port   = 22
      to_port     = 22
      protocol    = "tcp"
      cidr_blocks = ["0.0.0.0/0"]
    },
    {
      from_port   = 80
      to_port     = 80
      protocol    = "tcp"
      cidr_blocks = ["10.0.0.0/16"]
    }
  ]
}
'''
    repaired = ASTRepairEngine.repair_hcl(hcl, "aws_security_group", "web_sg", [0])

    assert 'from_port   = 22' not in repaired
    assert 'from_port   = 80' in repaired

    # Validate HCL re-parsing
    parsed = hcl2.loads(repaired)
    res_block = parsed.get("resource", [{}])[0]
    sg_key = "aws_security_group" if "aws_security_group" in res_block else '"aws_security_group"'
    web_sg_key = "web_sg" if "web_sg" in res_block.get(sg_key, {}) else '"web_sg"'
    rules = res_block[sg_key][web_sg_key]["ingress"]
    if isinstance(rules[0], list):
        rules = rules[0]
    assert len(rules) == 1
    assert rules[0]["from_port"] == 80


def test_ast_repair_mode3_iam_jsonencode():
    """Mode 3: Ensures IAM policy statements inside jsonencode are repaired cleanly."""
    hcl = '''resource "aws_iam_policy" "admin_policy" {
  name = "admin_policy"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = "*"
        Resource = "*"
      },
      {
        Effect   = "Allow"
        Action   = "s3:GetObject"
        Resource = "arn:aws:s3:::mybucket/*"
      }
    ]
  })
}
'''
    repaired = ASTRepairEngine.repair_hcl(hcl, "aws_iam_policy", "admin_policy", [0])

    assert 'Action   = "*"' not in repaired
    assert 's3:GetObject' in repaired

    # Validate HCL re-parsing
    parsed = hcl2.loads(repaired)
    res_block = parsed.get("resource", [{}])[0]
    iam_key = "aws_iam_policy" if "aws_iam_policy" in res_block else '"aws_iam_policy"'
    admin_key = "admin_policy" if "admin_policy" in res_block.get(iam_key, {}) else '"admin_policy"'
    policy_str = str(res_block[iam_key][admin_key]["policy"])
    assert "s3:GetObject" in policy_str


def test_generate_unified_diff_ast_integration(tmp_path):
    """Verifies that generate_unified_diff outputs a valid unified diff using AST repair."""
    tf_file = tmp_path / "main.tf"
    tf_file.write_text('''resource "aws_security_group" "web_sg" {
  name = "web_sg"
  # Comment with } brace
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
''', encoding="utf-8")

    deleted_rules = [
        {
            "resource_address": "aws_security_group.web_sg",
            "statement_index": 0,
            "rule_type": "IngressRule",
            "rule_details": "0.0.0.0/0 port 22",
        }
    ]

    diff = generate_unified_diff(str(tf_file), deleted_rules, "aws_security_group.web_sg")
    assert "--- a/main.tf" in diff
    assert "+++ b/main.tf" in diff
    assert "-    from_port   = 22" in diff
    assert "-  # Comment with } brace" not in diff  # Comment is retained, not deleted


def test_end_to_end_auto_repair_reverification(tmp_path):
    """End-to-end test: auto-repair engine remediates a file and reverifies it to REMEDIATED_MINIMAL."""
    tf_file = tmp_path / "vulnerable.tf"
    tf_file.write_text('''resource "aws_security_group" "web_sg" {
  name = "web_sg"
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/16"]
  }
}
''', encoding="utf-8")

    parsed = parse_file(str(tf_file))
    graph = build_graph(parsed, file_path=str(tf_file))

    repair_engine = AutoRepairEngine()
    result = repair_engine.repair_resource(graph, "aws_security_group.web_sg", pattern="SG_OVER_EXPOSURE")

    assert result.status == "REMEDIATED_MINIMAL"
    assert result.reverified_status == "UNSAT"
    assert result.patch is not None
    assert "-    from_port   = 22" in result.patch


def test_hcl2_grammar_drift_detection():
    """Drift Detection: Ensures ASTRepairEngine.HCL2_GRAMMAR matches installed python-hcl2 grammar rules."""
    upstream_grammar = getattr(hcl2, "LARK_GRAMMAR", None)
    if upstream_grammar is None and hasattr(hcl2, "parser"):
        upstream_grammar = getattr(hcl2.parser, "LARK_GRAMMAR", None)

    if upstream_grammar and isinstance(upstream_grammar, str):
        # Normalize whitespace for comparison
        embedded_norm = "".join(ASTRepairEngine.HCL2_GRAMMAR.split())
        upstream_norm = "".join(upstream_grammar.split())
        assert embedded_norm == upstream_norm, "ASTRepairEngine.HCL2_GRAMMAR has drifted from installed python-hcl2 LARK_GRAMMAR!"


