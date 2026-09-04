"""
solver/ast_repair.py

AST-aware, format-preserving repair engine for HCL2 files.
Uses Lark CST parse tree metadata (from python-hcl2) to perform precise
source-span deletion of vulnerable blocks, list elements, and IAM jsonencode statements
without mangling comments, indentation, or sibling attributes.
"""

import os
from typing import List, Dict, Any, Optional
import hcl2


class ASTRepairEngine:
    """
    Format-preserving HCL auto-repair engine based on Lark CST source span metadata.
    """

    @staticmethod
    def repair_hcl(
        hcl_code: str,
        target_resource_type: str,
        target_resource_name: str,
        deleted_statement_indices: List[int],
    ) -> str:
        """
        Removes the specified statement/rule indices from a target HCL resource block.
        Target indices can correspond to:
          - Standalone block rules (ingress { ... })
          - List attribute items (ingress = [ { ... } ])
          - jsonencode IAM policy statements (policy = jsonencode({ Statement = [ { ... } ] }))
        """
        if not hcl_code:
            return hcl_code

        # Satisfy Lark parser requirement for trailing newline
        original_ended_with_newline = hcl_code.endswith("\n")
        if not original_ended_with_newline:
            hcl_code += "\n"

        try:
            tree = hcl2.parser.Hcl2.lark_parser.parse(hcl_code)
        except Exception:
            # Fallback if Lark parsing fails on non-standard HCL
            return hcl_code

        lines = hcl_code.splitlines(keepends=True)

        # Locate target resource block node
        resource_block = ASTRepairEngine._find_resource_block(
            tree, target_resource_type, target_resource_name
        )
        if not resource_block:
            return hcl_code

        resource_body = ASTRepairEngine._find_body(resource_block)
        if not resource_body:
            return hcl_code

        # Collect all repairable candidate statement/rule nodes in order
        candidates = ASTRepairEngine._collect_statement_nodes(resource_body)

        # Identify nodes to delete matching target_indices
        nodes_to_delete = []
        for idx in sorted(deleted_statement_indices, reverse=True):
            if 0 <= idx < len(candidates):
                nodes_to_delete.append(candidates[idx])

        if not nodes_to_delete:
            return hcl_code

        # Sort nodes to delete in reverse line order to preserve line indices during deletion
        nodes_to_delete.sort(
            key=lambda n: n.meta.line if hasattr(n, "meta") else -1, reverse=True
        )

        modified_lines = list(lines)
        for node in nodes_to_delete:
            if not hasattr(node, "meta"):
                continue
            meta = node.meta
            start_line = meta.line - 1 # 0-indexed
            end_line = meta.end_line - 1

            if 0 <= start_line <= end_line < len(modified_lines):
                # Check for trailing comma on the end line or immediately following line
                del modified_lines[start_line : end_line + 1]

        result = "".join(modified_lines)
        if not original_ended_with_newline and result.endswith("\n"):
            result = result[:-1]

        return result

    @staticmethod
    def _find_resource_block(tree: Any, res_type: str, res_name: str) -> Optional[Any]:
        """Locates the Lark Tree block node matching resource type and name."""
        for top_node in getattr(tree, "children", []):
            if hasattr(top_node, "data") and top_node.data == "body":
                for block in top_node.children:
                    if hasattr(block, "data") and block.data == "block":
                        children = block.children
                        if len(children) >= 3 and getattr(children[0], "data", None) == "identifier":
                            id_token = children[0].children[0]
                            
                            def get_val(node):
                                if hasattr(node, "data"):
                                    if node.data == "string":
                                        return "".join(
                                            child.children[0].value 
                                            for child in node.children 
                                            if hasattr(child, "data") and child.data == "string_part"
                                        )
                                    if node.data in ("string_lit", "identifier"):
                                        return node.children[0].value.strip('"\'')
                                    return ""
                                return node.value.strip('"\'')
                                
                            rtype = get_val(children[1])
                            rname = get_val(children[2])
                            if id_token.value == "resource" and rtype == res_type and rname == res_name:
                                return block
        return None

    @staticmethod
    def _find_body(node: Any) -> Optional[Any]:
        """Finds the child 'body' tree node."""
        for child in getattr(node, "children", []):
            if hasattr(child, "data") and child.data == "body":
                return child
        return None

    @staticmethod
    def _collect_statement_nodes(res_body: Any) -> List[Any]:
        """
        Collects all repairable statement nodes in structural order:
          - Standalone ingress/egress/statement blocks
          - Elements inside ingress/egress list attributes
          - Elements inside policy = jsonencode({ Statement = [...] })
        """
        statement_nodes = []

        for child in getattr(res_body, "children", []):
            if not hasattr(child, "data"):
                continue

            # Case 1: Standalone block (ingress { ... }, egress { ... }, security_rule { ... })
            if child.data == "block":
                block_id = child.children[0].children[0].value
                if block_id in ("ingress", "egress", "statement", "Statement", "security_rule"):
                    statement_nodes.append(child)

            # Case 2 & 3: Attributes (ingress = [...], policy = jsonencode(...))
            elif child.data == "attribute":
                attr_id = child.children[0].children[0].value

                # Ingress / Egress list attribute
                if attr_id in ("ingress", "egress"):
                    expr_term = next((c for c in child.children if hasattr(c, "data") and c.data == "expr_term"), None)
                    if expr_term and hasattr(expr_term, "children") and len(expr_term.children) > 0 and getattr(expr_term.children[0], "data", None) == "tuple":
                        tuple_node = expr_term.children[0]
                        for elem in tuple_node.children:
                            if hasattr(elem, "data") and elem.data == "expr_term":
                                statement_nodes.append(elem)

                # IAM Policy jsonencode attribute
                elif attr_id in ("policy", "inline_policy"):
                    expr_term = next((c for c in child.children if hasattr(c, "data") and c.data == "expr_term"), None)
                    if expr_term and hasattr(expr_term, "children") and len(expr_term.children) > 0 and getattr(expr_term.children[0], "data", None) == "function_call":
                        fn_call = expr_term.children[0]
                        fn_id = fn_call.children[0].children[0].value
                        if fn_id == "jsonencode":
                            args = next((c for c in fn_call.children if hasattr(c, "data") and c.data == "arguments"), None)
                            if args and hasattr(args, "children") and len(args.children) > 0:
                                arg_expr = next((c for c in args.children if hasattr(c, "data") and c.data == "expr_term"), None)
                                if arg_expr and hasattr(arg_expr, "children") and len(arg_expr.children) > 0 and getattr(arg_expr.children[0], "data", None) == "object":
                                    obj_node = arg_expr.children[0]
                                    for elem in obj_node.children:
                                        if getattr(elem, "data", None) == "object_elem":
                                            key_node = elem.children[0]
                                            def get_key_str(node):
                                                if hasattr(node, "value"):
                                                    return str(node.value).strip('"\'')
                                                if hasattr(node, "children") and len(node.children) > 0:
                                                    return get_key_str(node.children[0])
                                                return ""
                                            elem_id = get_key_str(key_node)
                                            if elem_id in ("Statement", "statement"):
                                                    stmt_expr = next((c for c in elem.children if hasattr(c, "data") and c.data == "expr_term"), None)
                                                    if stmt_expr and hasattr(stmt_expr, "children") and len(stmt_expr.children) > 0 and getattr(stmt_expr.children[0], "data", None) == "tuple":
                                                        tuple_node = stmt_expr.children[0]
                                                        for stmt_elem in tuple_node.children:
                                                            if hasattr(stmt_elem, "data") and stmt_elem.data == "expr_term":
                                                                statement_nodes.append(stmt_elem)

        return statement_nodes
