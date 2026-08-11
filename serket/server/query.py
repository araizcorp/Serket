"""Read-only path queries over the graph already stored in a Serket result."""
from __future__ import annotations

from typing import Any


def _endpoint_id(value: Any) -> str:
    if isinstance(value, dict):
        return str(value.get("id", ""))
    return str(value if value is not None else "")


def _build_graph(data: dict[str, Any]):
    import networkx as nx

    raw = data.get("graph") or {}
    graph = nx.DiGraph()
    for node in raw.get("nodes") or []:
        node_id = _endpoint_id(node.get("id"))
        if node_id:
            graph.add_node(node_id, **{key: value for key, value in node.items() if key != "id"})

    for edge in raw.get("edges") or raw.get("links") or []:
        source = _endpoint_id(edge.get("source"))
        target = _endpoint_id(edge.get("target"))
        if source and target:
            graph.add_edge(
                source,
                target,
                **{key: value for key, value in edge.items() if key not in {"source", "target"}},
            )
    return graph


def _high_value_nodes(graph, data: dict[str, Any]) -> set[str]:
    targets = {str(item) for item in data.get("high_value") or []}
    names = {"domain admins", "enterprise admins", "schema admins", "administrators", "krbtgt"}
    for node_id, node in graph.nodes(data=True):
        if (
            node.get("high_value")
            or node.get("is_dc")
            or node.get("type") == "Domain"
            or str(node.get("name", "")).lower() in names
        ):
            targets.add(str(node_id))
    return targets


def _describe(graph, nodes: list[str]) -> list[dict[str, Any]]:
    steps: list[dict[str, Any]] = []
    for source, target in zip(nodes, nodes[1:]):
        edge = graph.get_edge_data(source, target) or {}
        source_data = graph.nodes.get(source, {})
        target_data = graph.nodes.get(target, {})
        steps.append(
            {
                "src": source,
                "src_name": source_data.get("name", source),
                "src_type": source_data.get("type", "?"),
                "tgt": target,
                "tgt_name": target_data.get("name", target),
                "tgt_type": target_data.get("type", "?"),
                "edge_type": edge.get("type", "Relationship"),
                "noise": edge.get("noise", "unknown"),
                "opsec": int(edge.get("opsec_score", 5) or 5),
                "mitre": edge.get("mitre"),
                "detail": edge.get("detail", ""),
                "commands": [],
            }
        )
    return steps


def _path_result(graph, nodes: list[str]) -> dict[str, Any]:
    source = nodes[0]
    target = nodes[-1]
    source_data = graph.nodes.get(source, {})
    target_data = graph.nodes.get(target, {})
    steps = _describe(graph, nodes)
    return {
        "src": source,
        "src_name": source_data.get("name", source),
        "src_type": source_data.get("type", "?"),
        "target": target,
        "target_name": target_data.get("name", target),
        "hops": len(nodes) - 1,
        "cost": sum(step["opsec"] for step in steps),
        "noise": max((step["opsec"] for step in steps), default=0),
        "steps": steps,
        "computed": True,
    }


def install_query_route(app, data: dict[str, Any]) -> None:
    """Attach an in-memory path-query endpoint to the FastAPI application."""
    from fastapi import Body, HTTPException
    import networkx as nx

    graph = _build_graph(data)
    high_value = _high_value_nodes(graph, data)

    @app.post("/api/query-paths")
    async def query_paths(payload: dict[str, Any] = Body(default_factory=dict)):
        source = str(payload.get("source") or "")
        target = str(payload.get("target") or "tier0")
        include_edge = str(payload.get("include_edge") or "all")
        max_hops_raw = payload.get("max_hops")
        max_hops = None if max_hops_raw in (None, "", "all") else int(max_hops_raw)
        limit = max(1, min(int(payload.get("limit") or 25), 50))

        if not source or source == "all":
            raise HTTPException(status_code=400, detail="A concrete source node is required")
        if source not in graph:
            raise HTTPException(status_code=404, detail="Source node is not present in the loaded graph")

        targets = high_value if target in {"tier0", "all", ""} else {target}
        candidates: list[dict[str, Any]] = []
        for candidate in targets:
            if candidate == source or candidate not in graph:
                continue
            try:
                nodes = nx.shortest_path(graph, source=source, target=candidate)
            except (nx.NetworkXNoPath, nx.NodeNotFound):
                continue
            if max_hops is not None and len(nodes) - 1 > max_hops:
                continue
            result = _path_result(graph, nodes)
            if include_edge != "all" and not any(
                step.get("edge_type") == include_edge for step in result["steps"]
            ):
                continue
            candidates.append(result)

        candidates.sort(key=lambda item: (item["hops"], item["cost"], item["target_name"]))
        return {
            "paths": candidates[:limit],
            "source": source,
            "target": target,
            "algorithm": "shortest-hop path over the loaded graph",
            "queried_directory": False,
        }
