"""
solver/ast_repair.py

AST-aware, format-preserving repair engine for HCL2 files.
Uses Lark CST parse tree metadata (from python-hcl2) to perform precise
source-span deletion of vulnerable blocks, list elements, and IAM jsonencode statements
without mangling comments, indentation, or sibling attributes.
"""

import os
import logging
from typing import List, Dict, Any, Optional
import hcl2


def _get_val(node: Any) -> str:
    """Recursively extracts raw text value from Lark Tree or Token nodes, stripping quotes."""
    if not node:
        return ""
    if isinstance(node, str):
        return node.strip('"\'')
    if hasattr(node, "value"):
        return str(node.value).strip('"\'')
    if hasattr(node, "children"):
        parts = [_get_val(c) for c in node.children if c is not None]
        return "".join(p for p in parts if p).strip('"\'')
    return ""


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

        target_resource_type = target_resource_type.strip('"\'')
        target_resource_name = target_resource_name.strip('"\'')

        # Normalize CRLF to LF for consistent line indexing
        has_crlf = "\r\n" in hcl_code
        normalized_code = hcl_code.replace("\r\n", "\n")

        # Satisfy Lark parser requirement for trailing newline
        original_ended_with_newline = normalized_code.endswith("\n")
        if not original_ended_with_newline:
            normalized_code += "\n"

        try:
            tree = hcl2.parser.Hcl2().lark_parser.parse(normalized_code)
        except Exception as err:
            logging.warning(f"ASTRepairEngine: Lark CST parsing failed ({err}); falling back.")
            return hcl_code

        lines = normalized_code.splitlines(keepends=True)

        # Locate target resource block node
        resource_block = ASTRepairEngine._find_resource_block(
            tree, target_resource_type, target_resource_name
        )
        if not resource_block:
            logging.warning(f"ASTRepairEngine: Resource block '{target_resource_type}.{target_resource_name}' not found in CST.")
            return hcl_code

        resource_body = ASTRepairEngine._find_body(resource_block)
        if not resource_body:
            logging.warning(f"ASTRepairEngine: Resource body for '{target_resource_type}.{target_resource_name}' not found in CST.")
            return hcl_code

        # Collect all repairable candidate statement/rule nodes in order
        candidates = ASTRepairEngine._collect_statement_nodes(resource_body)

        # Identify nodes to delete matching target_indices
        nodes_to_delete = []
        for idx in sorted(deleted_statement_indices, reverse=True):
            if 0 <= idx < len(candidates):
                nodes_to_delete.append(candidates[idx])

        if not nodes_to_delete:
            logging.warning(f"ASTRepairEngine: Target statement indices {deleted_statement_indices} yielded no candidate nodes.")
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
            start_line = meta.line - 1  # 0-indexed
            end_line = meta.end_line - 1

            if 0 <= start_line <= end_line < len(modified_lines):
                del modified_lines[start_line : end_line + 1]

        result = "".join(modified_lines)
        if not original_ended_with_newline and result.endswith("\n"):
            result = result[:-1]

        if has_crlf:
            result = result.replace("\n", "\r\n")

        return result

    @staticmethod
    def _find_resource_block(tree: Any, res_type: str, res_name: str) -> Optional[Any]:
        """Locates the Lark Tree block node matching resource type and name."""
        res_type_clean = res_type.strip('"\'')
        res_name_clean = res_name.strip('"\'')

        def _search_body(body_node):
            for block in getattr(body_node, "children", []):
                if hasattr(block, "data") and block.data == "block":
                    children = block.children
                    if len(children) >= 3:
                        id_token_val = _get_val(children[0]).strip().lower()
                        rtype = _get_val(children[1]).strip()
                        rname = _get_val(children[2]).strip()
                        if id_token_val == "resource" and rtype == res_type_clean and rname == res_name_clean:
                            return block
            return None

        if getattr(tree, "data", None) == "body":
            res = _search_body(tree)
            if res:
                return res

        for top_node in getattr(tree, "children", []):
            if hasattr(top_node, "data"):
                if top_node.data == "body":
                    res = _search_body(top_node)
                    if res:
                        return res
                elif top_node.data == "start":
                    res = ASTRepairEngine._find_resource_block(top_node, res_type_clean, res_name_clean)
                    if res:
                        return res
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
                block_id = _get_val(child.children[0]).strip().lower() if len(child.children) > 0 else ""
                if block_id in ("ingress", "egress", "statement", "security_rule"):
                    statement_nodes.append(child)

            # Case 2 & 3: Attributes (ingress = [...], policy = jsonencode(...))
            elif child.data == "attribute":
                attr_id = _get_val(child.children[0]).strip().lower() if len(child.children) > 0 else ""

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
                        fn_id = _get_val(fn_call.children[0]).strip().lower() if len(fn_call.children) > 0 else ""
                        if fn_id == "jsonencode":
                            args = next((c for c in fn_call.children if hasattr(c, "data") and c.data == "arguments"), None)
                            if args and hasattr(args, "children") and len(args.children) > 0:
                                arg_expr = next((c for c in args.children if hasattr(c, "data") and c.data == "expr_term"), None)
                                if arg_expr and hasattr(arg_expr, "children") and len(arg_expr.children) > 0 and getattr(arg_expr.children[0], "data", None) == "object":
                                    obj_node = arg_expr.children[0]
                                    for elem in obj_node.children:
                                        if getattr(elem, "data", None) == "object_elem":
                                            key_node = elem.children[0]
                                            elem_id = _get_val(key_node).strip().lower()
                                            if elem_id == "statement":
                                                stmt_expr = next((c for c in elem.children if hasattr(c, "data") and c.data == "expr_term"), None)
                                                if stmt_expr and hasattr(stmt_expr, "children") and len(stmt_expr.children) > 0 and getattr(stmt_expr.children[0], "data", None) == "tuple":
                                                    tuple_node = stmt_expr.children[0]
                                                    for stmt_elem in tuple_node.children:
                                                        if hasattr(stmt_elem, "data") and stmt_elem.data == "expr_term":
                                                            statement_nodes.append(stmt_elem)

        return statement_nodes
