import os
import pytest
from parser.hcl_parser import parse_file, build_graph
from solver.engine import VerificationEngine
from solver.repair import AutoRepairEngine

@pytest.fixture
def temp_nsg_file(tmp_path):
    def _create(content: str) -> str:
        f = tmp_path / "nsg.tf"
        f.write_text(content, encoding="utf-8")
        return str(f)
    return _create

def test_azure_nsg_sat(temp_nsg_file):
    tf = """
resource "azurerm_network_security_group" "vuln_nsg" {
  name                = "vuln_nsg"
  location            = "East US"
  resource_group_name = "rg-test"

  security_rule {
    name                       = "allow_ssh_any"
    priority                   = 100
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "22"
    source_address_prefix      = "*"
    destination_address_prefix = "*"
  }
}
"""
    f = temp_nsg_file(tf)
    parsed = parse_file(f)
    graph = build_graph(parsed, file_path=f)
    
    engine = VerificationEngine(use_cache=False)
    results = engine.verify_graph(graph)
    
    assert len(results) == 1
    res = results[0]
    assert res.status == "SAT"
    assert res.pattern == "NSG_OVER_EXPOSURE"
    assert "exposes sensitive ports (22) to public IP range" in res.message

def test_azure_nsg_unsat_shadowed(temp_nsg_file):
    tf = """
resource "azurerm_network_security_group" "safe_nsg" {
  name                = "safe_nsg"
  location            = "East US"
  resource_group_name = "rg-test"

  security_rule {
    name                       = "deny_ssh_any"
    priority                   = 99
    direction                  = "Inbound"
    access                     = "Deny"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "22"
    source_address_prefix      = "*"
    destination_address_prefix = "*"
  }

  security_rule {
    name                       = "allow_ssh_any"
    priority                   = 100
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "22"
    source_address_prefix      = "*"
    destination_address_prefix = "*"
  }
}
"""
    f = temp_nsg_file(tf)
    parsed = parse_file(f)
    graph = build_graph(parsed, file_path=f)
    
    engine = VerificationEngine(use_cache=False)
    results = engine.verify_graph(graph)
    
    assert len(results) == 1
    res = results[0]
    assert res.status == "UNSAT"
    assert res.pattern == "NSG_OVER_EXPOSURE"
    assert "safe from sensitive port over-exposure" in res.message


def test_azure_nsg_standalone_rule(temp_nsg_file):
    tf = """
resource "azurerm_network_security_group" "my_nsg" {
  name                = "my_nsg"
  location            = "East US"
  resource_group_name = "rg-test"
}

resource "azurerm_network_security_rule" "allow_ssh" {
  name                        = "allow_ssh"
  priority                    = 200
  direction                   = "Inbound"
  access                      = "Allow"
  protocol                    = "Tcp"
  source_port_range           = "*"
  destination_port_range      = "22"
  source_address_prefix       = "*"
  destination_address_prefix  = "*"
  resource_group_name         = "rg-test"
  network_security_group_name = azurerm_network_security_group.my_nsg.name
}
"""
    f = temp_nsg_file(tf)
    parsed = parse_file(f)
    graph = build_graph(parsed, file_path=f)
    
    from parser.references import resolve_resource_references
    from parser.attachments import resolve_rule_attachments
    graph = resolve_resource_references(graph)
    graph = resolve_rule_attachments(graph)
    
    engine = VerificationEngine(use_cache=False)
    results = engine.verify_graph(graph)
    
    # One for the NSG
    assert len(results) == 1
    res = results[0]
    assert res.status == "SAT"
    assert res.resource_address == "azurerm_network_security_group.my_nsg"


def test_azure_nsg_auto_repair(temp_nsg_file):
    tf = """
resource "azurerm_network_security_group" "vuln_nsg" {
  name                = "vuln_nsg"
  location            = "East US"
  resource_group_name = "rg-test"

  security_rule {
    name                       = "allow_ssh_any"
    priority                   = 100
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "22"
    source_address_prefix      = "*"
    destination_address_prefix = "*"
  }
}
"""
    f = temp_nsg_file(tf)
    parsed = parse_file(f)
    graph = build_graph(parsed, file_path=f)
    
    repair_engine = AutoRepairEngine()
    result = repair_engine.repair_resource(graph, "azurerm_network_security_group.vuln_nsg", "NSG_OVER_EXPOSURE")
    
    assert result.status == "REMEDIATED_MINIMAL"
    assert result.patch is not None
    assert "security_rule {" in result.patch
    
    # We can write the patched text directly or use a patched version if we want,
    # but let's just use ASTRepairEngine directly to apply the patch text for the test.
    from solver.ast_repair import ASTRepairEngine
    repaired_hcl = ASTRepairEngine.repair_hcl(tf, "azurerm_network_security_group", "vuln_nsg", [r["statement_index"] for r in result.deleted_rules])
    assert "security_rule {" not in repaired_hcl
    
    # Save repaired content
    with open(f, "w") as out:
        out.write(repaired_hcl)
        
    # Re-verify
    parsed2 = parse_file(f)
    graph2 = build_graph(parsed2, file_path=f)
    engine = VerificationEngine(use_cache=False)
    results2 = engine.verify_graph(graph2)
    
    assert len(results2) == 1
    res = results2[0]
    # No vulnerable rules left, so it should be UNSAT
    assert res.status == "UNSAT"


def test_azure_nsg_unresolved_reference_in_list(temp_nsg_file):
    tf = """
resource "azurerm_network_security_group" "vuln_nsg" {
  name                = "vuln_nsg"
  location            = "East US"
  resource_group_name = "rg-test"

  security_rule {
    name                       = "allow_ssh_any"
    priority                   = 100
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "22"
    source_address_prefixes    = ["10.0.0.0/8", azurerm_subnet.unresolved.address_prefix]
    destination_address_prefix = "*"
  }
}
"""
    f = temp_nsg_file(tf)
    parsed = parse_file(f)
    graph = build_graph(parsed, file_path=f)
    
    from parser.references import resolve_resource_references
    graph = resolve_resource_references(graph)
    
    engine = VerificationEngine(use_cache=False)
    results = engine.verify_graph(graph)
    
    assert len(results) == 1
    res = results[0]
    assert res.status == "UNRESOLVABLE"


def test_azure_nsg_standalone_rule_auto_repair_fallback(temp_nsg_file):
    tf = """
resource "azurerm_network_security_group" "vuln_nsg" {
  name                = "vuln_nsg"
  location            = "East US"
  resource_group_name = "rg-test"
}
resource "azurerm_network_security_rule" "allow_ssh_any" {
  name                        = "allow_ssh_any"
  priority                    = 100
  direction                   = "Inbound"
  access                      = "Allow"
  protocol                    = "Tcp"
  source_port_range           = "*"
  destination_port_range      = "22"
  source_address_prefix       = "*"
  destination_address_prefix  = "*"
  resource_group_name         = "rg-test"
  network_security_group_name = azurerm_network_security_group.vuln_nsg.name
}
"""
    f = temp_nsg_file(tf)
    parsed = parse_file(f)
    graph = build_graph(parsed, file_path=f)
    
    from parser.references import resolve_resource_references
    from parser.attachments import resolve_rule_attachments
    graph = resolve_resource_references(graph)
    graph = resolve_rule_attachments(graph)
    
    from solver.repair import AutoRepairEngine
    repair_engine = AutoRepairEngine()
    result = repair_engine.repair_resource(graph, "azurerm_network_security_group.vuln_nsg", "NSG_OVER_EXPOSURE")
    
    # AutoRepairEngine returns REMEDIATED_MINIMAL for logical graph deletion of attached standalone rules
    assert result.status == "REMEDIATED_MINIMAL"
    
    # Apply via ASTRepairEngine - it should be a no-op because the rule is standalone, not inside the NSG body
    from solver.ast_repair import ASTRepairEngine
    repaired_hcl = ASTRepairEngine.repair_hcl(tf, "azurerm_network_security_group", "vuln_nsg", [r["statement_index"] for r in result.deleted_rules])
    
    # Standalone rule block should STILL be in the repaired_hcl! (Nothing actually deleted from text)
    assert "azurerm_network_security_rule" in repaired_hcl
    assert "allow_ssh_any" in repaired_hcl
    
    # Result matches original text exactly (no-op patch applied to the NSG body)
    assert repaired_hcl.strip() == tf.strip()


def test_azure_nsg_multi_port_rdp_sat(temp_nsg_file):
    """Verifies that an NSG opening port 3389 (RDP) while port 22 is omitted/closed triggers SAT with port 3389 in witness."""
    tf = """
resource "azurerm_network_security_group" "rdp_nsg" {
  name                = "rdp_nsg"
  location            = "East US"
  resource_group_name = "rg-test"

  security_rule {
    name                       = "allow_rdp_any"
    priority                   = 100
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "3389"
    source_address_prefix      = "*"
    destination_address_prefix = "*"
  }
}
"""
    f = temp_nsg_file(tf)
    parsed = parse_file(f)
    graph = build_graph(parsed, file_path=f)

    engine = VerificationEngine(use_cache=False)
    results = engine.verify_graph(graph)

    assert len(results) == 1
    res = results[0]
    assert res.status == "SAT"
    assert res.pattern == "NSG_OVER_EXPOSURE"
    assert 3389 in res.witness["sensitive_ports"]
    assert 22 not in res.witness["sensitive_ports"]


def test_azure_nsg_multi_port_ssh_sat_rdp_closed(temp_nsg_file):
    """Verifies that an NSG opening port 22 while port 3389 is explicitly denied triggers SAT with only port 22 in witness."""
    tf = """
resource "azurerm_network_security_group" "ssh_only_nsg" {
  name                = "ssh_only_nsg"
  location            = "East US"
  resource_group_name = "rg-test"

  security_rule {
    name                       = "deny_rdp"
    priority                   = 90
    direction                  = "Inbound"
    access                     = "Deny"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "3389"
    source_address_prefix      = "*"
    destination_address_prefix = "*"
  }

  security_rule {
    name                       = "allow_ssh_any"
    priority                   = 100
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "22"
    source_address_prefix      = "*"
    destination_address_prefix = "*"
  }
}
"""
    f = temp_nsg_file(tf)
    parsed = parse_file(f)
    graph = build_graph(parsed, file_path=f)

    engine = VerificationEngine(use_cache=False)
    results = engine.verify_graph(graph)

    assert len(results) == 1
    res = results[0]
    assert res.status == "SAT"
    assert res.pattern == "NSG_OVER_EXPOSURE"
    assert 22 in res.witness["sensitive_ports"]
    assert 3389 not in res.witness["sensitive_ports"]


def test_azure_nsg_unsat_proof_certification(temp_nsg_file):
    """Verifies that an UNSAT Azure NSG returns a non-empty Z3 proof s-expression certificate."""
    tf = """
resource "azurerm_network_security_group" "safe_nsg" {
  name                = "safe_nsg"
  location            = "East US"
  resource_group_name = "rg-test"

  security_rule {
    name                       = "deny_all_sensitive"
    priority                   = 100
    direction                  = "Inbound"
    access                     = "Deny"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_ranges    = ["21", "22", "23", "445", "3389"]
    source_address_prefix      = "*"
    destination_address_prefix = "*"
  }
}
"""
    f = temp_nsg_file(tf)
    parsed = parse_file(f)
    graph = build_graph(parsed, file_path=f)

    engine = VerificationEngine(use_cache=False)
    results = engine.verify_graph(graph)

    assert len(results) == 1
    res = results[0]
    assert res.status == "UNSAT"
    assert res.pattern == "NSG_OVER_EXPOSURE"
    assert res.z3_proof_sexpr is not None
    assert isinstance(res.z3_proof_sexpr, str)
    assert len(res.z3_proof_sexpr) > 0
    assert res.z3_proof_sexpr.startswith("(") or "let" in res.z3_proof_sexpr


def test_azure_nsg_unsat_certificate_export(temp_nsg_file):
    """Verifies that generate_certificate_from_result incorporates the Azure NSG z3_proof_sexpr into certificate payload."""
    from solver.certificates import generate_certificate_from_result

    tf = """
resource "azurerm_network_security_group" "safe_nsg" {
  name                = "safe_nsg"
  location            = "East US"
  resource_group_name = "rg-test"

  security_rule {
    name                       = "deny_all"
    priority                   = 100
    direction                  = "Inbound"
    access                     = "Deny"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_ranges    = ["21", "22", "23", "445", "3389"]
    source_address_prefix      = "*"
    destination_address_prefix = "*"
  }
}
"""
    f = temp_nsg_file(tf)
    parsed = parse_file(f)
    graph = build_graph(parsed, file_path=f)

    engine = VerificationEngine(use_cache=False)
    results = engine.verify_graph(graph)

    assert len(results) == 1
    res = results[0]
    assert res.status == "UNSAT"

    cert = generate_certificate_from_result(res)
    assert cert["certificate_type"] == "UNSAT_PROOF_CERTIFICATE"
    assert cert["unsat_proof"]["z3_proof_object_sexpr"] == res.z3_proof_sexpr
    assert len(cert["unsat_proof"]["z3_proof_object_sexpr"]) > 0



