"""
saver.py — Persist and reload Serket collection results.

Graph is serialized alongside the AD data using networkx node_link format
so --load can reconstruct the attack graph and re-run pathfinding.

AraizCorp LLC — Serket
"""
from __future__ import annotations

import json
import os
from datetime import datetime
from typing import Any, Optional

_STAMP = lambda: datetime.now().strftime("%Y%m%d_%H%M%S")


def _json_safe(obj: Any) -> Any:
    """Recursively convert non-JSON-serializable values."""
    if isinstance(obj, bytes):
        return obj.hex()
    if isinstance(obj, set):
        return list(obj)
    if isinstance(obj, dict):
        return {k: _json_safe(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_json_safe(v) for v in obj]
    return obj


def save_results(
    ad_data: dict,
    graph_stats: dict,
    analysis: dict,
    output_dir: str,
    ag=None,              # ADGraph — if provided, graph is serialized for --load
) -> str:
    """
    Save full collection and analysis to output_dir.
    Returns the directory path where files were written.

    When ag is provided the networkx DiGraph is serialized using node_link_data
    format. On --load the graph can be fully reconstructed and pathfinding
    re-executed against the saved data.
    """
    domain_name = ad_data.get("domain", {}).get("name", "unknown").replace(".", "_")
    stamp       = _STAMP()
    base_name   = f"serket_{domain_name}_{stamp}"

    os.makedirs(output_dir, exist_ok=True)

    # ── JSON: full dataset ────────────────────────────────────────────────────
    json_path = os.path.join(output_dir, f"{base_name}.json")
    payload: dict = {
        "meta": {
            "tool":      "Serket",
            "version":   "2.0.0",
            "vendor":    "AraizCorp LLC",
            "generated": datetime.now().isoformat(),
            "domain":    ad_data.get("domain", {}).get("name", ""),
            "collection": ad_data.get("telemetry", {}),
        },
        "domain":    ad_data.get("domain", {}),
        "stats":     graph_stats,
        "surface":   analysis.get("surface", {}),
        "paths":     analysis.get("paths", []),
        "adcs":      ad_data.get("adcs", {}),
        "trusts":    ad_data.get("trusts", []),
        "gpos":      ad_data.get("gpos", []),
        "sid_name":  ad_data.get("sid_name", {}),
    }

    # Serialize networkx graph so --load can re-run pathfinding
    if ag is not None:
        try:
            from networkx.readwrite import json_graph as nx_jg
            payload["graph"] = nx_jg.node_link_data(ag.G)
            payload["high_value"] = list(ag.high_value)
        except Exception:
            pass   # graceful: skip graph serialization if networkx version differs

    with open(json_path, "w", encoding="utf-8") as fh:
        json.dump(_json_safe(payload), fh, indent=2)

    # ── TXT: human-readable report ────────────────────────────────────────────
    txt_path = os.path.join(output_dir, f"{base_name}_report.txt")
    _write_text_report(txt_path, ad_data, graph_stats, analysis)

    return output_dir


def _write_text_report(path: str, ad_data: dict, graph_stats: dict, analysis: dict):
    surface = analysis.get("surface", {})
    paths   = analysis.get("paths", [])
    domain  = ad_data.get("domain", {})

    lines = [
        "=" * 70,
        "  SERKET — AD Attack Path Mapper  v2.0",
        "  AraizCorp LLC | Authorized Security Testing Only",
        "=" * 70,
        f"  Generated : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        f"  Domain    : {domain.get('name', '?')}",
        f"  SID       : {domain.get('sid', '?')}",
        "",
        "── OBJECT COUNTS ──────────────────────────────────────────────────",
        f"  Users     : {len(ad_data.get('users', {}))}",
        f"  Groups    : {len(ad_data.get('groups', {}))}",
        f"  Computers : {len(ad_data.get('computers', {}))}",
        f"  Graph edges: {graph_stats.get('edges', 0)}",
        "",
        "── ATTACK SURFACE ─────────────────────────────────────────────────",
    ]

    kerb = surface.get("kerberoastable", [])
    if kerb:
        lines.append(f"\n  Kerberoastable ({len(kerb)}):")
        for u in kerb:
            lines.append(f"    - {u['name']} | SPNs: {', '.join(u['spns'][:2])}")

    asrep = surface.get("asreproastable", [])
    if asrep:
        lines.append(f"\n  ASREPRoastable ({len(asrep)}):")
        for u in asrep:
            lines.append(f"    - {u['name']}")

    dcsync = surface.get("dcsync", [])
    if dcsync:
        lines.append(f"\n  DCSync rights ({len(dcsync)}):")
        for d in dcsync:
            lines.append(f"    - {d['name']} on {d['target']}")

    esc1 = surface.get("adcs_esc1", [])
    if esc1:
        lines.append(f"\n  ADCS ESC1 ({len(esc1)} enrollment vectors):")
        for e in esc1:
            lines.append(f"    - {e['enroller']} → template {e['template']}")

    pwd_desc = surface.get("password_in_desc", [])
    if pwd_desc:
        lines.append(f"\n  Password in description ({len(pwd_desc)}):")
        for u in pwd_desc:
            lines.append(f"    - {u['name']}")

    laps = surface.get("laps_readable", [])
    if laps:
        lines.append(f"\n  LAPS password readable ({len(laps)}):")
        for c in laps:
            lines.append(f"    - {c['name']} ({c.get('dns', '')})")

    acl = [a for a in surface.get("acl_abuse", []) if a.get("target_high_value")]
    if acl:
        lines.append(f"\n  ACL abuses on high-value targets ({len(acl)}):")
        for a in acl[:20]:
            lines.append(f"    - {a['name']} --[{a['edge']}]--> {a['target_name']}")

    lines += ["", "── ATTACK PATHS ───────────────────────────────────────────────────"]

    for i, p in enumerate(paths, 1):
        noise_label = {1: "SILENT", 2: "LOW", 3: "LOW", 4: "MEDIUM", 5: "HIGH"}.get(
            p.get("noise", 5), "?"
        )
        lines.append(
            f"\n  [{i}] {p['src_name']} [{p['src_type']}] → {p['target_name']}  "
            f"({p['hops']} hops, cost={p['cost']}, noise={noise_label})"
        )
        for step in p["steps"]:
            mitre  = f" ({step['mitre']['id']})" if step.get("mitre") else ""
            detail = f" — {step['detail']}" if step.get("detail") else ""
            lines.append(
                f"      {step['src_name']} --[{step['edge_type']}]--> "
                f"{step['tgt_name']}{detail}{mitre}"
            )

    lines += ["", "=" * 70]

    with open(path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")


def load_results(json_path: str) -> dict:
    """
    Load a previously saved Serket JSON result.
    If graph data is present, the ADGraph can be reconstructed via reconstruct_graph().
    """
    with open(json_path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def reconstruct_graph(data: dict):
    """
    Reconstruct an ADGraph from serialized data.
    Returns None if no graph data is present (older saves).
    """
    graph_data = data.get("graph")
    if not graph_data:
        return None

    try:
        import networkx as nx
        from networkx.readwrite import json_graph as nx_jg
        from serket.graph.builder import ADGraph

        G = nx_jg.node_link_graph(graph_data)
        ag = ADGraph()
        ag.G = G
        ag.high_value  = set(data.get("high_value", []))
        ag.sid_name    = data.get("sid_name", {})
        return ag
    except Exception:
        return None
