"""
solver/ast_repair.py

AST-aware, format-preserving repair engine for HCL2 files.
Uses Lark CST parse tree metadata (from python-hcl2) to perform precise
source-span deletion of vulnerable blocks, list elements, and IAM jsonencode statements
without mangling comments, indentation, or sibling attributes.
"""

import os
import logging
from typing import List, Dict, Any, Optional, Tuple
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


def _get_node_line_range(node: Any) -> Optional[Tuple[int, int]]:
    """
    Returns 1-indexed (start_line, end_line) for a Lark Tree or Token node.
    Extracts line metadata from tree.meta, token.line/end_line, or token.meta.line/end_line.
    """
    if node is None:
        return None

    lines: List[int] = []

    def _add_line(start: Optional[int], end: Optional[int]):
        if start is not None and isinstance(start, int) and start > 0:
            lines.append(start)
            lines.append(end if (end is not None and isinstance(end, int) and end > 0) else start)

    def _scan(n: Any):
        if hasattr(n, "meta") and n.meta is not None:
            _add_line(getattr(n.meta, "line", None), getattr(n.meta, "end_line", None))

        _add_line(getattr(n, "line", None), getattr(n, "end_line", None))

        if hasattr(n, "children"):
            for c in getattr(n, "children", []):
                _scan(c)

    _scan(node)

    if lines:
        return (min(lines), max(lines))

    return None


class ASTRepairEngine:
    """
    Format-preserving HCL auto-repair engine based on Lark CST source span metadata.
    """

    @staticmethod
    def _get_lark_parser():
        import hcl2.parser

        # 1. Check Hcl2 class attributes or instance
        hcl2_cls = getattr(hcl2.parser, "Hcl2", None)
        if hcl2_cls is not None:
            p = getattr(hcl2_cls, "lark_parser", None) or getattr(hcl2_cls, "parser", None)
            if p is not None:
                return p
            try:
                inst = hcl2_cls()
                p = getattr(inst, "lark_parser", None) or getattr(inst, "parser", None)
                if p is not None:
                    return p
            except Exception:
                pass

        # 2. Check hcl2 instance attribute
        hcl2_inst = getattr(hcl2.parser, "hcl2", None)
        if hcl2_inst is not None:
            p = getattr(hcl2_inst, "lark_parser", None) or getattr(hcl2_inst, "parser", None)
            if p is not None:
                return p

        # 3. Direct instantiation from LARK_GRAMMAR
        grammar = getattr(hcl2.parser, "LARK_GRAMMAR", None)
        if grammar is not None:
            from lark import Lark
            return Lark(grammar=grammar, parser="lalr", propagate_positions=True, cache=True)

        raise RuntimeError("Unable to resolve Lark parser from hcl2 package")

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
            parser = ASTRepairEngine._get_lark_parser()
            tree = parser.parse(normalized_code)
        except Exception as err:
            logging.warning(f"ASTRepairEngine: Lark CST parsing failed ({err}); falling back.")
            return hcl_code

        lines = normalized_code.splitlines(keepends=True)

        # Locate target resource block node recursively across all CST branches
        resource_block = ASTRepairEngine._find_resource_block(
            tree, target_resource_type, target_resource_name
        )
        if not resource_block:
            import sys
            sys.stderr.write(f"DEBUG_AST: Resource block '{target_resource_type}.{target_resource_name}' NOT found in CST.\n")
            return hcl_code

        resource_body = ASTRepairEngine._find_body(resource_block)
        if not resource_body:
            import sys
            sys.stderr.write(f"DEBUG_AST: Resource body for '{target_resource_type}.{target_resource_name}' NOT found in CST.\n")
            return hcl_code

        # Collect all repairable candidate statement/rule nodes in order
        candidates = ASTRepairEngine._collect_statement_nodes(resource_body)

        # Identify nodes to delete matching target_indices
        nodes_to_delete = []
        for idx in sorted(deleted_statement_indices, reverse=True):
            if 0 <= idx < len(candidates):
                nodes_to_delete.append(candidates[idx])

        if not nodes_to_delete:
            import sys
            sys.stderr.write(f"DEBUG_AST: Target statement indices {deleted_statement_indices} yielded no candidate nodes (len candidates: {len(candidates)}).\n")
            return hcl_code

        # Map nodes to their line ranges
        node_ranges: List[Tuple[Any, Tuple[int, int]]] = []
        for node in nodes_to_delete:
            lrange = _get_node_line_range(node)
            if lrange:
                start_l, end_l = lrange
                # If node is a block (e.g. ingress { ... }), check if the closing brace is on next line when end_l doesn't already contain '}'
                if getattr(node, "data", None) == "block":
                    curr_line = lines[end_l - 1].strip() if 0 <= end_l - 1 < len(lines) else ""
                    if "}" not in curr_line:
                        if end_l < len(lines) and lines[end_l].strip().startswith("}"):
                            end_l += 1
                node_ranges.append((node, (start_l, end_l)))

        if not node_ranges:
            logging.warning("ASTRepairEngine: Could not extract line ranges for target nodes.")
            return hcl_code

        # Sort nodes to delete in reverse line order to preserve line indices during deletion
        node_ranges.sort(key=lambda item: item[1][0], reverse=True)

        modified_lines = list(lines)
        for node, (start_l, end_l) in node_ranges:
            start_line = start_l - 1  # 0-indexed
            end_line = end_l - 1

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
        """Locates the Lark Tree block node matching resource type and name using recursive DFS."""
        if not tree:
            return None

        res_type_clean = res_type.strip('"\'')
        res_name_clean = res_name.strip('"\'')

        if hasattr(tree, "data") and tree.data == "block":
            non_body_children = [c for c in getattr(tree, "children", []) if getattr(c, "data", None) != "body"]
            tokens = [_get_val(c).strip().strip('"\'') for c in non_body_children if _get_val(c).strip()]
            if len(tokens) >= 3:
                if tokens[0].lower() == "resource" and tokens[1] == res_type_clean and tokens[2] == res_name_clean:
                    return tree

        for child in getattr(tree, "children", []):
            if hasattr(child, "data"):
                found = ASTRepairEngine._find_resource_block(child, res_type_clean, res_name_clean)
                if found:
                    return found

        return None

    @staticmethod
    def _find_body(node: Any) -> Optional[Any]:
        """Finds the child 'body' tree node."""
        if not node:
            return None
        if hasattr(node, "data") and node.data == "body":
            return node
        for child in getattr(node, "children", []):
            if hasattr(child, "data"):
                found = ASTRepairEngine._find_body(child)
                if found:
                    return found
        return None

    @staticmethod
    def _unwrap_node(node: Any) -> Any:
        """Recursively unwraps wrapper CST nodes until reaching block or attribute tree node."""
        if not hasattr(node, "data"):
            return node
        if hasattr(node, "data") and node.data in ("block", "attribute"):
            return node
        if hasattr(node, "children"):
            for sub in node.children:
                if hasattr(sub, "data"):
                    unwrapped = ASTRepairEngine._unwrap_node(sub)
                    if hasattr(unwrapped, "data") and unwrapped.data in ("block", "attribute"):
                        return unwrapped
        return node

    @staticmethod
    def _collect_statement_nodes(res_body: Any) -> List[Any]:
        """
        Collects all repairable statement nodes in structural order:
          - Standalone ingress/egress/statement/security_rule blocks
          - Elements inside ingress/egress list attributes
          - Elements inside policy = jsonencode({ Statement = [...] })
        """
        statement_nodes = []

        for child in getattr(res_body, "children", []):
            child = ASTRepairEngine._unwrap_node(child)
            if not hasattr(child, "data"):
                continue

            # Case 1: Standalone block (ingress { ... }, egress { ... }, security_rule { ... })
            if child.data == "block":
                block_id = ""
                for c in getattr(child, "children", []):
                    if getattr(c, "data", None) == "body":
                        continue
                    v = _get_val(c).strip().strip('"\'').lower()
                    if v in ("ingress", "egress", "statement", "security_rule", "rule", "rules", "custom_rules"):
                        block_id = v
                        break
                if block_id:
                    statement_nodes.append(child)

            # Case 2 & 3: Attributes (ingress = [...], policy = jsonencode(...))
            elif child.data == "attribute":
                attr_id = ""
                for c in getattr(child, "children", []):
                    v = _get_val(c).strip().strip('"\'').lower()
                    if v in ("ingress", "egress", "security_rule", "rules", "security_rules", "policy", "inline_policy"):
                        attr_id = v
                        break

                # Ingress / Egress list attribute
                if attr_id in ("ingress", "egress", "security_rule", "rules", "security_rules"):
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
                        fn_tokens = [_get_val(c).strip().strip('"\'') for c in fn_call.children if _get_val(c).strip()]
                        fn_id = next((t.lower() for t in fn_tokens[:3] if t.lower() == "jsonencode"), "")
                        if fn_id == "jsonencode":
                            args = next((c for c in fn_call.children if hasattr(c, "data") and c.data == "arguments"), None)
                            if args and hasattr(args, "children") and len(args.children) > 0:
                                arg_expr = next((c for c in args.children if hasattr(c, "data") and c.data == "expr_term"), None)
                                if arg_expr and hasattr(arg_expr, "children") and len(arg_expr.children) > 0 and getattr(arg_expr.children[0], "data", None) == "object":
                                    obj_node = arg_expr.children[0]
                                    for elem in obj_node.children:
                                        if getattr(elem, "data", None) == "object_elem":
                                            elem_tokens = [_get_val(c).strip().strip('"\'') for c in elem.children if _get_val(c).strip()]
                                            elem_id = next((t.lower() for t in elem_tokens[:3] if t.lower() == "statement"), "")
                                            if elem_id == "statement":
                                                stmt_expr = next((c for c in elem.children if hasattr(c, "data") and c.data == "expr_term"), None)
                                                if stmt_expr and hasattr(stmt_expr, "children") and len(stmt_expr.children) > 0 and getattr(stmt_expr.children[0], "data", None) == "tuple":
                                                    tuple_node = stmt_expr.children[0]
                                                    for stmt_elem in tuple_node.children:
                                                        if hasattr(stmt_elem, "data") and stmt_elem.data == "expr_term":
                                                            statement_nodes.append(stmt_elem)

        return statement_nodes


        return statement_nodes
