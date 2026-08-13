"""
saver.py — Persist and reload Serket collection results.

Graph is serialized alongside the AD data using networkx node_link format
so --load can reconstruct the attack graph and re-run pathfinding.

AraizCorp LLC — Serket
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import tempfile
import zipfile
from datetime import datetime
from pathlib import Path
from typing import Any

_STAMP = lambda: datetime.now().strftime("%Y%m%d_%H%M%S")
PACKAGE_SCHEMA_VERSION = 1


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
    Save a multi-file collection bundle below output_dir and return its path.

    The manifest is written last so an interrupted collection is never presented
    as complete. load_results() composes the files into the historical in-memory
    result structure.
    """
    raw_domain = str(ad_data.get("domain", {}).get("name", "unknown"))
    domain_name = re.sub(r"[^A-Za-z0-9_-]+", "_", raw_domain).strip("_") or "unknown"
    stamp       = _STAMP()
    base_name   = f"serket_{domain_name}_{stamp}"

    os.makedirs(output_dir, exist_ok=True)
    bundle_dir = os.path.join(output_dir, base_name)
    os.makedirs(bundle_dir, exist_ok=False)

    meta = {
        "tool": "Serket",
        "version": "2.1.0",
        "vendor": "AraizCorp LLC",
        "generated": datetime.now().isoformat(),
        "domain": ad_data.get("domain", {}).get("name", ""),
        "collection": ad_data.get("telemetry", {}),
    }
    graph_component: dict = {"graph": {}, "high_value": []}
    if ag is not None:
        try:
            from networkx.readwrite import json_graph as nx_jg
            graph_component["graph"] = nx_jg.node_link_data(ag.G)
            graph_component["high_value"] = sorted(ag.high_value)
        except Exception:
            pass

    components = {
        "domain": ad_data.get("domain", {}),
        "users": ad_data.get("users", {}),
        "groups": ad_data.get("groups", {}),
        "computers": ad_data.get("computers", {}),
        "directory_objects": ad_data.get("directory_objects", {}),
        "gpos": ad_data.get("gpos", []),
        "trusts": ad_data.get("trusts", []),
        "permissions": ad_data.get("acls", []),
        "adcs": ad_data.get("adcs", {}),
        "summary": {
            "stats": graph_stats,
            "sid_name": ad_data.get("sid_name", {}),
            "quality": ad_data.get("quality", {}),
            "coverage": ad_data.get("coverage", {}),
            "system_counts": ad_data.get("system_counts", {}),
        },
        "analysis": {
            "surface": analysis.get("surface", {}),
            "paths": analysis.get("paths", []),
        },
        "graph": graph_component,
        "interchange": _build_interchange(ad_data),
    }
    files: dict[str, str] = {}
    for category, value in components.items():
        filename = f"{category}.json"
        files[category] = filename
        _write_json(
            os.path.join(bundle_dir, filename),
            {"category": category, "data": value},
        )

    txt_path = os.path.join(bundle_dir, "report.txt")
    _write_text_report(txt_path, ad_data, graph_stats, analysis)

    integrity = {
        filename: _file_integrity(Path(bundle_dir) / filename)
        for filename in [*files.values(), "report.txt"]
    }
    _write_json(os.path.join(bundle_dir, "manifest.json"), {
        "format": "serket-collection-bundle",
        "schema_version": 1,
        "meta": meta,
        "files": files,
        "integrity": {"algorithm": "sha256", "files": integrity},
    })
    create_serket_package(bundle_dir)
    return bundle_dir


def _build_interchange(ad_data: dict) -> dict:
    identities = []
    for family, object_type in (
        ("users", "User"), ("groups", "Group"), ("computers", "Computer"),
    ):
        for object_id, value in ad_data.get(family, {}).items():
            identities.append({
                "id": object_id,
                "type": object_type,
                "name": value.get("name", ""),
                "dn": value.get("dn", ""),
            })
    return {
        "schema": "araizcorp-identity-bridge/v1",
        "consumer": "Reliquary",
        "domain": ad_data.get("domain", {}),
        "identities": identities,
        "sensitive_values_included": False,
    }


def _file_integrity(path: Path) -> dict:
    raw = path.read_bytes()
    return {"sha256": hashlib.sha256(raw).hexdigest(), "size": len(raw)}


def _verify_integrity(root: Path, manifest: dict) -> None:
    integrity = manifest.get("integrity")
    if integrity is None:
        return
    if integrity.get("algorithm") != "sha256" or not isinstance(integrity.get("files"), dict):
        raise ValueError("Invalid Serket bundle integrity metadata")
    for filename, expected in integrity["files"].items():
        path = (root / filename).resolve()
        try:
            path.relative_to(root)
        except ValueError as exc:
            raise ValueError("Bundle integrity member escapes its collection directory") from exc
        if not path.is_file() or _file_integrity(path) != expected:
            raise ValueError(f"Serket bundle integrity check failed: {filename}")


def create_serket_package(bundle_dir: str | Path, output_path: str | Path | None = None) -> str:
    root = Path(bundle_dir).expanduser().resolve()
    manifest_path = root / "manifest.json"
    if not root.is_dir() or not manifest_path.is_file():
        raise ValueError("A complete Serket bundle directory is required")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    _verify_integrity(root, manifest)
    destination = (Path(output_path).expanduser() if output_path else root.with_suffix(".serket")).resolve()
    temporary = destination.with_suffix(".serket.tmp")
    members = ["manifest.json", *manifest.get("files", {}).values(), "report.txt"]
    with zipfile.ZipFile(temporary, "w", zipfile.ZIP_DEFLATED) as archive:
        for name in sorted(dict.fromkeys(members)):
            path = (root / name).resolve()
            path.relative_to(root)
            archive.write(path, arcname=name)
    os.replace(temporary, destination)
    return str(destination)


def _write_json(path: str, value: Any) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(_json_safe(value), fh, indent=2)


def _write_text_report(path: str, ad_data: dict, graph_stats: dict, analysis: dict):
    surface = analysis.get("surface", {})
    paths   = analysis.get("paths", [])
    domain  = ad_data.get("domain", {})
    systems = ad_data.get("system_counts", {})

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
        f"  Workstations       : {systems.get('workstation', 0)}",
        f"  Servers            : {systems.get('server', 0)}",
        f"  Domain controllers : {systems.get('domain_controller', 0)}",
        f"  OU/containers      : {len(ad_data.get('directory_objects', {}))}",
        f"  GPOs               : {len(ad_data.get('gpos', []))}",
        f"  Graph edges: {graph_stats.get('edges', 0)}",
        f"  ACL relationships: {len(ad_data.get('acls', []))}",
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
    Load a Serket bundle (directory or manifest) or a legacy single JSON result.
    If graph data is present, the ADGraph can be reconstructed via reconstruct_graph().
    """
    source = Path(json_path).expanduser()
    if source.is_file() and source.suffix.casefold() == ".serket":
        data = _load_package(source)
        _repair_legacy_binary_sids(data)
        return data
    if source.is_dir():
        source = source / "manifest.json"
    with source.open("r", encoding="utf-8") as fh:
        data = json.load(fh)
    if data.get("format") == "serket-collection-bundle":
        data = _load_bundle(source, data)
    _repair_legacy_binary_sids(data)
    return data


def _load_bundle(manifest_path: Path, manifest: dict) -> dict:
    if manifest.get("schema_version") != 1:
        raise ValueError(
            f"Unsupported Serket bundle schema: {manifest.get('schema_version')!r}"
        )
    files = manifest.get("files")
    if not isinstance(files, dict):
        raise ValueError("Invalid Serket bundle: files map is missing")

    root = manifest_path.resolve().parent
    _verify_integrity(root, manifest)
    components: dict[str, Any] = {}
    for category, filename in files.items():
        if not isinstance(category, str) or not isinstance(filename, str):
            raise ValueError("Invalid Serket bundle component entry")
        component_path = (root / filename).resolve()
        try:
            component_path.relative_to(root)
        except ValueError as exc:
            raise ValueError("Bundle component escapes its collection directory") from exc
        with component_path.open("r", encoding="utf-8") as fh:
            component = json.load(fh)
        if (
            not isinstance(component, dict)
            or component.get("category") != category
            or "data" not in component
        ):
            raise ValueError(f"Invalid Serket bundle component: {filename}")
        components[category] = component["data"]

    required = {
        "domain", "users", "groups", "computers", "directory_objects",
        "gpos", "trusts", "permissions", "adcs", "summary", "analysis",
        "graph",
    }
    missing = sorted(required.difference(components))
    if missing:
        raise ValueError(f"Incomplete Serket bundle: missing {', '.join(missing)}")

    summary = components["summary"]
    analysis = components["analysis"]
    graph = components["graph"]
    if not all(isinstance(item, dict) for item in (summary, analysis, graph)):
        raise ValueError("Invalid Serket bundle summary, analysis or graph component")

    return {
        "meta": manifest.get("meta", {}),
        "domain": components["domain"],
        "users": components["users"],
        "groups": components["groups"],
        "computers": components["computers"],
        "directory_objects": components["directory_objects"],
        "gpos": components["gpos"],
        "trusts": components["trusts"],
        "acls": components["permissions"],
        "adcs": components["adcs"],
        "interchange": components.get("interchange", {}),
        **summary,
        **analysis,
        **graph,
    }


def _load_package(package_path: Path) -> dict:
    try:
        archive = zipfile.ZipFile(package_path, "r")
    except (OSError, zipfile.BadZipFile) as exc:
        raise ValueError("Invalid Serket assessment package") from exc
    with archive, tempfile.TemporaryDirectory(prefix="serket-package-") as temp:
        names = archive.namelist()
        if len(names) != len(set(names)) or "manifest.json" not in names:
            raise ValueError("Invalid Serket package member list")
        for name in names:
            member = Path(name)
            if member.is_absolute() or ".." in member.parts or len(member.parts) != 1:
                raise ValueError("Serket package contains an unsafe member path")
        archive.extractall(temp)
        manifest_path = Path(temp) / "manifest.json"
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        if manifest.get("schema_version") != PACKAGE_SCHEMA_VERSION:
            raise ValueError(f"Unsupported Serket package schema: {manifest.get('schema_version')!r}")
        return _load_bundle(manifest_path, manifest)


def _repair_legacy_binary_sids(data: dict) -> bool:
    """Repair v2.0 results that serialized binary SID values as text.

    The repair is in-memory and intentionally limited to identity/edge IDs.
    ACL relationships absent from the original result cannot be recovered.
    """
    graph = data.get("graph") or {}
    nodes = graph.get("nodes") or []
    if not nodes:
        return False

    identity_types = {"User", "Group", "Computer", "Domain"}
    identity_nodes = [node for node in nodes if node.get("type") in identity_types]
    if not identity_nodes or any(
        str(node.get("id", "")).startswith("S-1-") for node in identity_nodes
    ):
        return False

    from serket.collector.ldap_collector import _sid_value

    mapping = {
        str(node.get("id", "")): _sid_value(node.get("id"))
        for node in identity_nodes
    }
    if not mapping or any(not sid for sid in mapping.values()):
        return False
    if len(set(mapping.values())) != len(mapping):
        return False

    high_rids = {
        "500", "502", "512", "516", "518", "519", "520", "521",
        "544", "548", "549", "550", "551",
    }
    high_value: set[str] = set()
    domain_controllers: set[str] = set()
    admin_groups: set[str] = set()
    systems = {"workstation": 0, "server": 0, "domain_controller": 0}

    for node in nodes:
        old_id = str(node.get("id", ""))
        if old_id in mapping:
            node["id"] = mapping[old_id]
        node_id = str(node.get("id", ""))
        if node.get("type") == "Computer":
            if node.get("is_dc"):
                role = "domain_controller"
                node["type"] = "DomainController"
                domain_controllers.add(node_id)
            elif "server" in str(node.get("os", "")).casefold():
                role = "server"
                node["type"] = "Server"
            else:
                role = "workstation"
                node["type"] = "Workstation"
            node["ldap_type"] = "Computer"
            node["computer_role"] = role
            systems[role] += 1

        rid = node_id.rsplit("-", 1)[-1]
        is_high = (
            rid in high_rids
            or node.get("is_dc") is True
            or node.get("type") == "Domain"
        )
        node["high_value"] = bool(is_high)
        if is_high:
            high_value.add(node_id)
        if rid in {"512", "519"} or node_id == "S-1-5-32-544":
            admin_groups.add(node_id)

    edges = graph.get("edges") or graph.get("links") or []
    for edge in edges:
        for endpoint in ("source", "target"):
            value = edge.get(endpoint)
            if isinstance(value, dict):
                old_id = str(value.get("id", ""))
                if old_id in mapping:
                    value["id"] = mapping[old_id]
            else:
                old_id = str(value if value is not None else "")
                if old_id in mapping:
                    edge[endpoint] = mapping[old_id]

    existing = {
        (str(edge.get("source")), str(edge.get("target")), edge.get("type"))
        for edge in edges
    }
    for admin_sid in admin_groups:
        for dc_sid in domain_controllers:
            key = (admin_sid, dc_sid, "AdminTo")
            if key not in existing:
                edges.append({
                    "source": admin_sid,
                    "target": dc_sid,
                    "type": "AdminTo",
                    "opsec_score": 2,
                    "noise": "low",
                    "traversable": True,
                    "detail": "Built-in administrative control over a domain controller",
                })

    domain = data.get("domain") or {}
    old_domain_sid = str(domain.get("sid", ""))
    if old_domain_sid in mapping:
        domain["sid"] = mapping[old_domain_sid]

    sid_name = data.get("sid_name") or {}
    data["sid_name"] = {
        mapping.get(str(key), str(key)): value for key, value in sid_name.items()
    }
    data["high_value"] = sorted(high_value)
    data["system_counts"] = systems
    data["quality"] = {
        "status": "legacy-recovered-partial",
        "canonical_sids": len(mapping),
        "identity_objects": len(mapping),
        "acl_relationships": 0,
        "acl_scope": "missing-from-original-result",
    }
    data.setdefault("coverage", {})["legacy_recovery"] = {
        "status": "identity-and-membership-recovered",
        "missing": "ACLs require a new collection",
    }
    data.setdefault("meta", {})["legacy_sid_recovery"] = True
    return True


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
