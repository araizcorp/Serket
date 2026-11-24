"""
Embedded FastAPI server for the Serket Workbench interface.

The server is deliberately local-only in native mode. Result files may contain
sensitive directory metadata, so the runtime disables caching and exposes no
interactive API documentation. Mutation routes only apply validated sanitized
bridges to the current process; they never write a result package.
"""
from __future__ import annotations

import json
import os
import threading
import webbrowser
from typing import Any

_UI_HTML_PATH = os.path.join(os.path.dirname(__file__), "..", "ui", "simple.html")
_CLASSIC_HTML_PATH = os.path.join(os.path.dirname(__file__), "..", "ui", "workbench.html")


def _load_ui(path: str) -> str:
    html_path = os.path.normpath(path)
    if not os.path.isfile(html_path):
        raise FileNotFoundError(f"Web UI not found: {html_path}")
    with open(html_path, encoding="utf-8") as fh:
        return fh.read()


def _normalise_graph(data: dict[str, Any]) -> dict[str, Any]:
    """Return one stable graph shape across NetworkX node-link versions."""
    graph = data.get("graph") or {}
    nodes = graph.get("nodes") or []
    edges = graph.get("edges") or graph.get("links") or []
    return {
        "directed": bool(graph.get("directed", True)),
        "nodes": nodes,
        "edges": edges,
        "available": bool(nodes),
    }


def create_app(data: dict[str, Any]):
    """Create the local API used by Serket Workbench."""
    try:
        from fastapi import FastAPI, HTTPException, Request
        from fastapi.responses import HTMLResponse
        from fastapi.staticfiles import StaticFiles
    except ImportError as exc:
        raise ImportError(
            "FastAPI and uvicorn are required for --serve mode.\n"
            "Install with:  pip install fastapi uvicorn"
        ) from exc

    html = _load_ui(_UI_HTML_PATH)
    classic_html = _load_ui(_CLASSIC_HTML_PATH)
    # FastAPI resolves postponed annotations through module globals, while
    # optional server imports intentionally live inside create_app().
    globals()["Request"] = Request
    app = FastAPI(title="Serket Workbench", docs_url=None, redoc_url=None)
    assets_dir = os.path.normpath(os.path.join(os.path.dirname(__file__), "..", "ui"))
    app.mount("/assets", StaticFiles(directory=assets_dir), name="assets")

    @app.middleware("http")
    async def local_security_headers(request: Request, call_next):
        response = await call_next(request)
        response.headers["Cache-Control"] = "no-store, max-age=0"
        response.headers["Pragma"] = "no-cache"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; script-src 'self'; "
            "style-src 'self' 'unsafe-inline'; img-src 'self' data:; "
            "connect-src 'self'; object-src 'none'; base-uri 'none'; "
            "form-action 'none'; frame-ancestors 'none'"
        )
        return response

    @app.get("/", response_class=HTMLResponse)
    async def ui():
        return html

    @app.get("/classic", response_class=HTMLResponse)
    async def classic_ui():
        return classic_html

    @app.get("/healthz")
    async def health():
        return {"status": "ok", "product": "serket"}

    @app.get("/api/domain")
    async def api_domain():
        return data.get("domain", {})

    @app.get("/api/stats")
    async def api_stats():
        stats = dict(data.get("stats", {}))
        stats["systems"] = data.get("system_counts", {})
        stats["quality"] = data.get("quality", {})
        return stats

    @app.get("/api/coverage")
    async def api_coverage():
        return data.get("coverage", {})

    @app.get("/api/surface")
    async def api_surface():
        return data.get("surface", {})

    @app.get("/api/paths")
    async def api_paths():
        return data.get("paths", [])

    @app.get("/api/findings")
    async def api_findings(
        badge: str = "",
        severity: str = "",
        tier0_reachable: str = "",
        object_id: str = "",
        offset: int = 0,
        limit: int = 500,
    ):
        if offset < 0 or limit < 1 or limit > 2000:
            raise HTTPException(
                status_code=400,
                detail="offset must be non-negative and limit must be between 1 and 2000",
            )
        tier0 = tier0_reachable.strip().casefold()
        if tier0 not in {"", "true", "false", "1", "0"}:
            raise HTTPException(status_code=400, detail="tier0_reachable must be true or false")
        findings = list(data.get("findings", []))
        if badge:
            findings = [item for item in findings if str(item.get("badge", "")).casefold() == badge.casefold()]
        if severity:
            findings = [item for item in findings if str(item.get("severity", "")).casefold() == severity.casefold()]
        if object_id:
            findings = [item for item in findings if str(item.get("object_id", "")) == object_id]
        if tier0:
            expected = tier0 in {"true", "1"}
            findings = [item for item in findings if bool(item.get("tier0_reachable")) is expected]
        total = len(findings)
        return {
            "snapshot_id": data.get("snapshot_id") or data.get("meta", {}).get("snapshot_id", ""),
            "risk_summary": data.get("risk_summary", {}),
            "total": total,
            "offset": offset,
            "limit": limit,
            "returned": len(findings[offset:offset + limit]),
            "findings": findings[offset:offset + limit],
        }

    @app.get("/api/graph")
    async def api_graph():
        return _normalise_graph(data)

    @app.post("/api/enrich")
    async def api_enrich(request: Request):
        """Apply a validated Keyring bridge to this in-memory local session."""
        from serket.enrichment import (
            MAX_BRIDGE_BYTES,
            EnrichmentError,
            apply_bridge,
            validate_bridge,
        )

        declared = request.headers.get("content-length")
        if declared and (not declared.isdigit() or int(declared) > MAX_BRIDGE_BYTES):
            raise HTTPException(status_code=413, detail="bridge exceeds the 8 MiB safety limit")
        content_type = request.headers.get("content-type", "").split(";", 1)[0].strip().casefold()
        if content_type != "application/json":
            raise HTTPException(status_code=415, detail="application/json is required")
        body = bytearray()
        async for chunk in request.stream():
            body.extend(chunk)
            if len(body) > MAX_BRIDGE_BYTES:
                raise HTTPException(status_code=413, detail="bridge exceeds the 8 MiB safety limit")
        try:
            bridge = json.loads(body.decode("utf-8"))
            validate_bridge(bridge)
            return apply_bridge(data, bridge)
        except (UnicodeError, json.JSONDecodeError, EnrichmentError) as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @app.post("/api/external-enrich")
    async def api_external_enrich(request: Request):
        """Apply a validated Portico bridge to this in-memory local session."""
        from serket.enrichment import MAX_BRIDGE_BYTES, EnrichmentError
        from serket.external_surface import apply_external_bridge, validate_external_bridge

        declared = request.headers.get("content-length")
        if declared and (not declared.isdigit() or int(declared) > MAX_BRIDGE_BYTES):
            raise HTTPException(status_code=413, detail="bridge exceeds the 8 MiB safety limit")
        content_type = request.headers.get("content-type", "").split(";", 1)[0].strip().casefold()
        if content_type != "application/json":
            raise HTTPException(status_code=415, detail="application/json is required")
        body = bytearray()
        async for chunk in request.stream():
            body.extend(chunk)
            if len(body) > MAX_BRIDGE_BYTES:
                raise HTTPException(status_code=413, detail="bridge exceeds the 8 MiB safety limit")
        try:
            bridge = json.loads(body.decode("utf-8"))
            validate_external_bridge(bridge)
            return apply_external_bridge(data, bridge)
        except (UnicodeError, json.JSONDecodeError, EnrichmentError) as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @app.get("/api/adcs")
    async def api_adcs():
        return data.get("adcs", {})

    @app.get("/api/trusts")
    async def api_trusts():
        return data.get("trusts", [])

    @app.get("/api/sid_name")
    async def api_sid_name():
        return data.get("sid_name", {})

    @app.get("/api/meta")
    async def api_meta():
        return data.get("meta", {})

    @app.get("/api/detection-catalog")
    async def api_detection_catalog():
        from serket.detection_catalog import catalog_payload
        return catalog_payload()

    from serket.server.query import install_query_route

    install_query_route(app, data)

    from serket.server.search import install_search_routes

    install_search_routes(app, data)
    return app


def run_server(data: dict, port: int = 8080) -> None:
    """Start Serket Workbench locally or inside the official container."""
    try:
        import uvicorn
    except ImportError as exc:
        raise ImportError(
            "FastAPI and uvicorn are required for --serve mode.\n"
            "Install with:  pip install fastapi uvicorn"
        ) from exc

    app = create_app(data)
    in_container = os.environ.get("SERKET_CONTAINER", "").strip() == "1"
    no_browser = os.environ.get("SERKET_NO_BROWSER", "").strip() == "1"
    bind_host = "0.0.0.0" if in_container else "127.0.0.1"
    url = f"http://127.0.0.1:{port}"
    if not no_browser and not in_container:
        threading.Timer(0.9, lambda: webbrowser.open(url)).start()

    print(
        f"\n  Serket Workbench -> {url}\n"
        "  Local-only session. Keyring API enrichment stays in memory.\n"
        "  Press Ctrl+C to stop.\n"
    )

    # Native runs bind to loopback. The container binds internally to all
    # interfaces and must be published as 127.0.0.1:8080:8080 on the host.
    uvicorn.run(app, host=bind_host, port=port, log_level="warning")
