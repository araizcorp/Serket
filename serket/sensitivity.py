"""Tier-0 sensitivity propagation over AD containment relationships."""
from __future__ import annotations

from enum import IntEnum

from serket.graph.builder import ADGraph


class Sensitivity(IntEnum):
    NONE = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


def _downgrade(value: Sensitivity) -> Sensitivity:
    return Sensitivity(max(Sensitivity.LOW, int(value) - 1))


def propagate_sensitivity(ag: ADGraph) -> dict[str, str]:
    """Annotate intrinsic and inherited sensitivity without changing reachability."""
    graph = ag.G
    levels: dict[str, Sensitivity] = {}

    for node_id, data in graph.nodes(data=True):
        if data.get("high_value") or data.get("is_dc") or data.get("type") == "Domain":
            levels[str(node_id)] = Sensitivity.CRITICAL
        elif data.get("type") == "CertTemplate" and data.get("esc1"):
            levels[str(node_id)] = Sensitivity.HIGH

    changed = True
    while changed:
        changed = False
        for source, target, edge in graph.edges(data=True):
            if edge.get("traversable", True) is False:
                continue
            relation = edge.get("type")
            target_level = levels.get(str(target), Sensitivity.NONE)
            if target_level == Sensitivity.NONE:
                continue

            candidate = Sensitivity.NONE
            source_data = graph.nodes.get(source, {})
            target_data = graph.nodes.get(target, {})
            if relation == "Contains":
                if source_data.get("type") == "OU" and target_data.get("is_dc"):
                    candidate = Sensitivity.CRITICAL
                else:
                    candidate = _downgrade(target_level)
            elif relation == "MemberOf":
                candidate = _downgrade(target_level)
            elif relation == "GPOLink":
                candidate = Sensitivity.HIGH if target_level >= Sensitivity.HIGH else target_level

            source_key = str(source)
            if candidate > levels.get(source_key, Sensitivity.NONE):
                levels[source_key] = candidate
                changed = True

    result = {}
    for node_id in graph.nodes:
        label = levels.get(str(node_id), Sensitivity.NONE).name.lower()
        graph.nodes[node_id]["sensitivity"] = label
        result[str(node_id)] = label
    return result
