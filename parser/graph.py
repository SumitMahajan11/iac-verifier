from __future__ import annotations

from dataclasses import dataclass, field, is_dataclass
from typing import Any, Union


@dataclass(frozen=True)
class Unresolved:
    """Represents an attribute value that could not be statically resolved at parse time."""

    reason: str
    expression: str | None = None


@dataclass(frozen=True)
class ResourceReference:
    """A structural reference to another resource's attribute, e.g. aws_security_group.web_sg.id.

    Distinct from Unresolved: we don't know the runtime VALUE, but we DO know exactly
    which resource this points to, which is enough to resolve graph topology.
    """

    target_address: str  # e.g. "aws_security_group.web_sg"
    attribute: str  # e.g. "id"


class RuleSource:
    """Abstract base class/concept for a source of access control rules."""

    pass



@dataclass(frozen=True)
class ExternalManagedPolicy(RuleSource):
    """An IAM policy attachment referencing an AWS-managed policy by ARN (e.g. arn:aws:iam::aws:policy/ReadOnlyAccess).

    Its actual permission content is not declared in the analyzed IaC source.
    """

    policy_arn: str


# Attribute values can be primitive literals, collections of literals, Unresolved, ResourceReference, or ExternalManagedPolicy
AttributeValue = Union[
    str,
    int,
    float,
    bool,
    list[Any],
    dict[str, Any],
    Unresolved,
    ResourceReference,
    ExternalManagedPolicy,
    None,
]


@dataclass
class SecurityGroupRule(RuleSource):
    """Represents a security group rule granting or restricting network access."""

    direction: str  # "ingress" or "egress"
    protocol: str  # e.g., "tcp", "udp", "-1", "icmp"
    from_port: int | None = None
    to_port: int | None = None
    cidr_blocks: list[str | Unresolved | ResourceReference] = field(
        default_factory=list
    )
    referenced_security_group_id: str | ResourceReference | Unresolved | None = None


@dataclass
class IamPolicyStatement(RuleSource):
    """Represents an IAM policy statement granting or denying permissions."""

    effect: str  # "Allow" or "Deny"
    actions: list[str | Unresolved] = field(default_factory=list)
    resources: list[str | Unresolved | ResourceReference] = field(
        default_factory=list
    )
    principal: str | dict[str, Any] | Unresolved | ResourceReference | None = None


@dataclass
class Resource:
    """Represents an Infrastructure-as-Code resource node in the resource graph."""

    address: str
    type: str
    attributes: dict[str, AttributeValue] = field(default_factory=dict)
    rule_sources: list[RuleSource] = field(default_factory=list)
    merged_into: str | None = None
    file_path: str | None = None


def _has_unresolved(val: Any) -> bool:
    """Recursively checks if a value or dataclass is or contains an Unresolved instance."""
    if isinstance(val, Unresolved):
        return True
    if isinstance(val, list):
        return any(_has_unresolved(item) for item in val)
    if isinstance(val, dict):
        return any(_has_unresolved(v) for v in val.values())
    if is_dataclass(val) and not isinstance(
        val, (Unresolved, ResourceReference, ExternalManagedPolicy)
    ):
        for field_name in val.__dataclass_fields__:
            field_val = getattr(val, field_name)
            if _has_unresolved(field_val):
                return True
    return False


@dataclass
class ResourceGraph:
    """Holds a graph of Infrastructure-as-Code resources keyed by Terraform address."""

    resources: dict[str, Resource] = field(default_factory=dict)

    def add_resource(self, resource: Resource) -> None:
        """Adds or updates a resource in the graph."""
        self.resources[resource.address] = resource

    def unresolved_resources(self) -> list[Resource]:
        """Returns all resources that contain at least one Unresolved attribute value or rule source value."""
        return [
            res
            for res in self.resources.values()
            if any(_has_unresolved(val) for val in res.attributes.values())
            or any(_has_unresolved(rs) for rs in res.rule_sources)
        ]
