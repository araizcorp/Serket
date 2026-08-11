"""Universal search and node details over a loaded Serket graph."""
from __future__ import annotations

from typing import Any


def _endpoint_id(value: Any) -> str:
    if isinstance(value, dict):
        return str(value.get("id", ""))
    return str(value if value is not None else "")


def install_search_routes(app, data: dict[str, Any]) -> None:
    from fastapi import HTTPException, Query

    raw_graph = data.get("graph") or {}
    nodes = raw_graph.get("nodes") or []
    edges = raw_graph.get("edges") or raw_graph.get("links") or []
    node_map = {str(node.get("id")): node for node in nodes if node.get("id") is not None}

    def public_node(node: dict[str, Any]) -> dict[str, Any]:
        return {
            key: value
            for key, value in node.items()
            if key not in {"managed_password", "password", "unicodePwd", "supplementalCredentials"}
        }

    @app.get("/api/search")
    async def search_nodes(q: str = Query(default="", max_length=300), limit: int = Query(default=20, ge=1, le=100)):
        query = q.strip().casefold()
        if not query:
            return {"query": q, "count": 0, "results": []}

        ranked: list[tuple[int, str, dict[str, Any]]] = []
        fields = ("name", "id", "upn", "dn", "dns", "sam_account_name", "sam")
        for node in nodes:
            values = [str(node.get(field, "")) for field in fields if node.get(field)]
            lowered = [value.casefold() for value in values]
            if not any(query in value for value in lowered):
                continue
            if any(value == query for value in lowered):
                score = 0
            elif any(value.startswith(query) for value in lowered):
                score = 1
            elif any(query in value.split("=", 1)[-1] for value in lowered):
                score = 2
            else:
                score = 3
            ranked.append((score, str(node.get("name") or node.get("id") or ""), public_node(node)))

        ranked.sort(key=lambda item: (item[0], item[1].casefold()))
        results = [item[2] for item in ranked[:limit]]
        return {"query": q, "count": len(results), "results": results}

    @app.get("/api/nodes/{node_id:path}")
    async def node_details(node_id: str):
        node = node_map.get(node_id)
        if node is None:
            raise HTTPException(status_code=404, detail="Node is not present in the loaded graph")

        incoming = []
        outgoing = []
        for edge in edges:
            source = _endpoint_id(edge.get("source"))
            target = _endpoint_id(edge.get("target"))
            relation = {
                "source": source,
                "source_name": (node_map.get(source) or {}).get("name", source),
                "target": target,
                "target_name": (node_map.get(target) or {}).get("name", target),
                "type": edge.get("type") or edge.get("edge_type") or "Relationship",
                "detail": edge.get("detail", ""),
                "opsec_score": edge.get("opsec_score", edge.get("opsec", 0)),
                "mitre": edge.get("mitre"),
            }
            if source == node_id:
                outgoing.append(relation)
            if target == node_id:
                incoming.append(relation)

        paths_from = [path for path in data.get("paths") or [] if str(path.get("src")) == node_id]
        memberships = [relation for relation in outgoing if relation["type"] == "MemberOf"]
        return {
            "node": public_node(node),
            "controls": outgoing,
            "controlled_by": incoming,
            "memberships": memberships,
            "paths_from": paths_from,
        }
