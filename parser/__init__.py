from parser.attachments import resolve_rule_attachments
from parser.expansion import (
    build_graph_with_expansion,
    expand_count,
    expand_for_each,
)
from parser.graph import (
    AttributeValue,
    ExternalManagedPolicy,
    IamPolicyStatement,
    Resource,
    ResourceGraph,
    ResourceReference,
    RuleSource,
    SecurityGroupRule,
    Unresolved,
)
from parser.hcl_parser import HclParseError, build_graph, parse_file
from parser.modules import (
    build_graph_with_modules,
    find_module_blocks,
    inline_module,
    merge_into_parent,
    parse_directory,
)
from parser.references import resolve_resource_references
from parser.variables import (
    build_graph_with_variables,
    load_local_values,
    load_variable_values,
    resolve_attribute,
)

__all__ = [
    "Unresolved",
    "ResourceReference",
    "ExternalManagedPolicy",
    "AttributeValue",
    "RuleSource",
    "SecurityGroupRule",
    "IamPolicyStatement",
    "Resource",
    "ResourceGraph",
    "parse_file",
    "parse_directory",
    "build_graph",
    "build_graph_with_variables",
    "build_graph_with_expansion",
    "build_graph_with_modules",
    "resolve_resource_references",
    "resolve_rule_attachments",
    "expand_count",
    "expand_for_each",
    "find_module_blocks",
    "inline_module",
    "merge_into_parent",
    "HclParseError",
    "load_variable_values",
    "load_local_values",
    "resolve_attribute",
]
