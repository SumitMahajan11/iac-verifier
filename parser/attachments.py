from __future__ import annotations

import logging
from typing import Any

from parser.graph import (
    ExternalManagedPolicy,
    Resource,
    ResourceGraph,
    ResourceReference,
)

logger = logging.getLogger("iac_verifier.attachments")


def _find_tier_b_candidates(
    target_type: str, literal_val: str, graph: ResourceGraph
) -> list[Resource]:
    """Scans graph for resources of target_type matching literal_val by address, name, or id."""
    clean_val = str(literal_val).strip().strip('"\'')
    candidates: list[Resource] = []

    for res in graph.resources.values():
        if res.type != target_type:
            continue

        # Check address match (e.g. 'aws_security_group.web_sg' or 'web_sg')
        res_name_from_addr = res.address.rsplit(".", 1)[-1]
        if res.address == clean_val or res_name_from_addr == clean_val:
            candidates.append(res)
            continue

        # Check attribute match ('name' or 'id')
        name_attr = res.attributes.get("name")
        if isinstance(name_attr, str) and name_attr.strip().strip('"\'') == clean_val:
            candidates.append(res)
            continue

        id_attr = res.attributes.get("id")
        if isinstance(id_attr, str) and id_attr.strip().strip('"\'') == clean_val:
            candidates.append(res)
            continue

    return candidates


def resolve_rule_attachments(graph: ResourceGraph) -> ResourceGraph:
    """Merges standalone rule-declaring resources into the resource they attach to.

    Uses structural Tier A (ResourceReference) matching first, and Tier B (unique literal name) fallback when unique.
    """
    for address, res in list(graph.resources.items()):
        if res.merged_into is not None:
            continue

        # 1. Handle aws_security_group_rule
        if res.type == "aws_security_group_rule":
            sg_ref = res.attributes.get("security_group_id")
            if sg_ref is None and res.rule_sources:
                # Fallback to field on SecurityGroupRule dataclass
                rs = res.rule_sources[0]
                sg_ref = getattr(rs, "referenced_security_group_id", None)

            if isinstance(sg_ref, ResourceReference):
                # Tier A match
                target = graph.resources.get(sg_ref.target_address)
                if target:
                    target.rule_sources.extend(res.rule_sources)
                    res.merged_into = target.address
                    print(
                        f"[Tier A Merge] Merged {address} into {target.address} via structural reference {sg_ref.target_address}.{sg_ref.attribute}"
                    )
            elif isinstance(sg_ref, str):
                # Tier B fallback
                candidates = _find_tier_b_candidates("aws_security_group", sg_ref, graph)
                if len(candidates) == 1:
                    target = candidates[0]
                    target.rule_sources.extend(res.rule_sources)
                    res.merged_into = target.address
                    print(
                        f"[Tier B Merge] Merged {address} into {target.address} via unique declared value match '{sg_ref}'"
                    )
                else:
                    print(
                        f"[Tier B Ambiguous] Could not merge {address}: {len(candidates)} candidates found for '{sg_ref}'"
                    )

        # 2. Handle aws_iam_role_policy
        elif res.type == "aws_iam_role_policy":
            role_ref = res.attributes.get("role")
            if isinstance(role_ref, ResourceReference):
                # Tier A match
                target = graph.resources.get(role_ref.target_address)
                if target and target.type == "aws_iam_role":
                    target.rule_sources.extend(res.rule_sources)
                    res.merged_into = target.address
                    print(
                        f"[Tier A Merge] Merged {address} into {target.address} via structural reference {role_ref.target_address}.{role_ref.attribute}"
                    )
            elif isinstance(role_ref, str):
                # Tier B fallback
                candidates = _find_tier_b_candidates("aws_iam_role", role_ref, graph)
                if len(candidates) == 1:
                    target = candidates[0]
                    target.rule_sources.extend(res.rule_sources)
                    res.merged_into = target.address
                    print(
                        f"[Tier B Merge] Merged {address} into {target.address} via unique declared value match '{role_ref}'"
                    )
                else:
                    print(
                        f"[Tier B Ambiguous] Could not merge {address}: {len(candidates)} candidates found for '{role_ref}'"
                    )

        # 3. Handle aws_iam_role_policy_attachment
        elif res.type == "aws_iam_role_policy_attachment":
            role_ref = res.attributes.get("role")
            policy_arn = res.attributes.get("policy_arn")

            target_role: Resource | None = None
            merge_tier: str | None = None

            if isinstance(role_ref, ResourceReference):
                target = graph.resources.get(role_ref.target_address)
                if target and target.type == "aws_iam_role":
                    target_role = target
                    merge_tier = "Tier A"
            elif isinstance(role_ref, str):
                candidates = _find_tier_b_candidates("aws_iam_role", role_ref, graph)
                if len(candidates) == 1:
                    target_role = candidates[0]
                    merge_tier = "Tier B"
                else:
                    print(
                        f"[Tier B Ambiguous] Could not merge {address}: {len(candidates)} candidates found for role '{role_ref}'"
                    )

            if target_role and merge_tier:
                # Check AWS-managed policy ARN
                if isinstance(policy_arn, str) and policy_arn.startswith(
                    "arn:aws:iam::aws:policy/"
                ):
                    target_role.rule_sources.append(
                        ExternalManagedPolicy(policy_arn=policy_arn)
                    )
                    res.merged_into = target_role.address
                    print(
                        f"[{merge_tier} Merge] Attached ExternalManagedPolicy({policy_arn}) to {target_role.address}"
                    )
                elif isinstance(policy_arn, ResourceReference):
                    target_policy = graph.resources.get(policy_arn.target_address)
                    if target_policy:
                        target_role.rule_sources.extend(target_policy.rule_sources)
                        res.merged_into = target_role.address
                        print(
                            f"[{merge_tier} Merge] Merged policy {target_policy.address} into role {target_role.address}"
                        )
                elif isinstance(policy_arn, str):
                    policy_candidates = _find_tier_b_candidates(
                        "aws_iam_policy", policy_arn, graph
                    )
                    if len(policy_candidates) == 1:
                        target_role.rule_sources.extend(
                            policy_candidates[0].rule_sources
                        )
                        res.merged_into = target_role.address
                        print(
                            f"[{merge_tier} Merge] Merged policy {policy_candidates[0].address} into role {target_role.address}"
                        )

    return graph
