import pytest
import os
from parser.hcl_parser import parse_file, build_graph
from solver.engine import VerificationEngine

def test_incremental_cross_file(tmp_path):
    # Setup files
    file_a = tmp_path / "file_a.tf"
    file_b = tmp_path / "file_b.tf"
    
    file_a.write_text("""
    resource "aws_security_group_rule" "rule1" {
      type              = "ingress"
      from_port         = 22
      to_port           = 22
      protocol          = "tcp"
      cidr_blocks       = ["10.0.0.0/8"]
      security_group_id = aws_security_group.sg1.id
    }
    """)
    
    file_b.write_text("""
    resource "aws_security_group" "sg1" {
      name = "my_sg"
    }
    """)
    
    from parser.modules import parse_directory
    from parser.attachments import resolve_rule_attachments
    from parser.references import resolve_resource_references
    
    def build_full_graph(dir_path):
        parsed = parse_directory(dir_path)
        from parser.expansion import build_graph_with_expansion
        graph = build_graph_with_expansion(parsed, dir_path)
        resolve_resource_references(graph)
        resolve_rule_attachments(graph)
        return graph

    graph1 = build_full_graph(tmp_path)
    
    cache_dir = tmp_path / ".iac_cache"
    engine1 = VerificationEngine(use_cache=True)
    engine1.cache.cache_dir = str(cache_dir)
    os.makedirs(cache_dir, exist_ok=True)
    
    # Run full verification first
    results1 = engine1.verify_graph(graph1)
    
    # Now modify file A to make the rule unsafe
    file_a.write_text("""
    resource "aws_security_group_rule" "rule1" {
      type              = "ingress"
      from_port         = 22
      to_port           = 22
      protocol          = "tcp"
      cidr_blocks       = ["0.0.0.0/0"]
      security_group_id = aws_security_group.sg1.id
    }
    """)
    
    graph2 = build_full_graph(tmp_path)
    
    # Run incremental verification
    engine2 = VerificationEngine(use_cache=True)
    engine2.cache.cache_dir = str(cache_dir)
    
    incremental_results = engine2.verify_incremental(graph2, [str(file_a)])
    
    # The incremental results should contain sg1 and the global privilege escalation check.
    # sg1 because rule1 is merged into sg1 and rule1's change affects sg1's cache key.
    # The global check because its cache key depends on all resources.
    assert len(incremental_results) == 2
    addresses = {res.resource_address for res in incremental_results}
    assert "aws_security_group.sg1" in addresses
    assert "graph" in addresses
    
    sg_res = next(r for r in incremental_results if r.resource_address == "aws_security_group.sg1")
    assert sg_res.status == "SAT"  # Now unsafe


def test_incremental_multi_resource_skips_untouched(tmp_path, monkeypatch):
    file_0 = tmp_path / "file_0.tf"
    file_1 = tmp_path / "file_1.tf"
    file_2 = tmp_path / "file_2.tf"

    file_0.write_text("""
    resource "aws_security_group" "sg_0" {
      name = "sg_0"
    }
    """)

    file_1.write_text("""
    resource "aws_security_group" "sg_1" {
      name = "sg_1"
    }
    """)

    file_2.write_text("""
    resource "aws_security_group" "sg_2" {
      name = "sg_2"
    }
    """)

    from parser.modules import parse_directory
    from parser.attachments import resolve_rule_attachments
    from parser.references import resolve_resource_references
    from parser.expansion import build_graph_with_expansion

    def build_full_graph(dir_path):
        parsed = parse_directory(dir_path)
        graph = build_graph_with_expansion(parsed, dir_path)
        resolve_resource_references(graph)
        resolve_rule_attachments(graph)
        return graph

    graph1 = build_full_graph(tmp_path)
    cache_dir = tmp_path / ".iac_cache"
    os.makedirs(cache_dir, exist_ok=True)

    engine1 = VerificationEngine(use_cache=True)
    engine1.cache.cache_dir = str(cache_dir)
    results1 = engine1.verify_graph(graph1)
    assert len(results1) == 3

    # Touch only file_0.tf
    file_0.write_text("""
    resource "aws_security_group" "sg_0" {
      name = "sg_0_modified"
    }
    """)

    graph2 = build_full_graph(tmp_path)
    engine2 = VerificationEngine(use_cache=True)
    engine2.cache.cache_dir = str(cache_dir)

    # Spy on verify_security_group to count solver calls
    call_count = 0
    orig_verify_sg = engine2.verify_security_group

    def spied_verify_sg(resource):
        nonlocal call_count
        call_count += 1
        return orig_verify_sg(resource)

    monkeypatch.setattr(engine2, "verify_security_group", spied_verify_sg)

    incremental_results = engine2.verify_incremental(graph2, [str(file_0)])

    # Assert only sg_0 and graph reachability are returned
    returned_addresses = {res.resource_address for res in incremental_results}
    assert "aws_security_group.sg_0" in returned_addresses
    assert "graph" in returned_addresses
    assert "aws_security_group.sg_1" not in returned_addresses
    assert "aws_security_group.sg_2" not in returned_addresses

    # Assert verify_security_group solver computation was invoked EXACTLY ONCE (only for sg_0)
    assert call_count == 1

