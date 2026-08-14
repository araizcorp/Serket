from __future__ import annotations

import hashlib
import json
import math
import os
from pathlib import Path
import tempfile
from typing import Any
import zipfile


BRIDGE_VERSION = "1.0"
MAX_BRIDGE_BYTES = 8 * 1024 * 1024
MAX_ENRICHMENTS = 100_000
_FORBIDDEN_KEYS = {
    "secret_value",
    "password",
    "plaintext",
    "ntlm_hash",
    "lm_hash",
    "api_key",
    "access_token",
    "refresh_token",
    "private_key",
}


class EnrichmentError(ValueError):
    pass


def load_bridge(path: str | Path) -> dict[str, Any]:
    source = Path(path).expanduser()
    if source.is_symlink() or not source.is_file():
        raise EnrichmentError("bridge must be a regular non-symbolic-link file")
    if source.stat().st_size > MAX_BRIDGE_BYTES:
        raise EnrichmentError("bridge exceeds the 8 MiB safety limit")
    try:
        bridge = json.loads(source.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise EnrichmentError(f"invalid bridge JSON: {exc}") from exc
    validate_bridge(bridge)
    return bridge


def validate_bridge(bridge: Any) -> dict[str, Any]:
    if not isinstance(bridge, dict):
        raise EnrichmentError("bridge root must be an object")
    if bridge.get("bridge_version") != BRIDGE_VERSION:
        raise EnrichmentError("unsupported bridge_version")
    enrichments = bridge.get("enrichments")
    if not isinstance(enrichments, list):
        raise EnrichmentError("bridge enrichments must be an array")
    if len(enrichments) > MAX_ENRICHMENTS:
        raise EnrichmentError("bridge contains too many enrichments")
    _reject_sensitive_keys(bridge)
    for index, item in enumerate(enrichments):
        if not isinstance(item, dict):
            raise EnrichmentError(f"enrichment {index} must be an object")
        identity_key = item.get("identity_key")
        if not isinstance(identity_key, str) or not identity_key.strip() or len(identity_key) > 512:
            raise EnrichmentError(f"enrichment {index} has an invalid identity_key")
        if item.get("enrichment_type") not in {"credential_reuse", "credential_hygiene", "laps_reuse"}:
            raise EnrichmentError(f"enrichment {index} has an unsupported enrichment_type")
        if item.get("severity") not in {"low", "medium", "high", "critical"}:
            raise EnrichmentError(f"enrichment {index} has an invalid severity")
        if not isinstance(item.get("details"), dict):
            raise EnrichmentError(f"enrichment {index} details must be an object")
        _validate_details(item["enrichment_type"], item["details"], index)
    return bridge


def apply_bridge(data: dict[str, Any], bridge: dict[str, Any]) -> dict[str, Any]:
    validate_bridge(bridge)
    graph = data.get("graph")
    if not isinstance(graph, dict) or not isinstance(graph.get("nodes"), list):
        raise EnrichmentError("Serket result does not contain a node-link graph")

    aliases: dict[str, list[dict[str, Any]]] = {}
    for node in graph["nodes"]:
        if not isinstance(node, dict):
            continue
        for alias in _node_aliases(node):
            aliases.setdefault(alias, []).append(node)

    matched = 0
    unmatched: list[str] = []
    ambiguous: list[str] = []
    for enrichment in bridge["enrichments"]:
        identity_key = enrichment["identity_key"].strip()
        candidates = aliases.get(identity_key.casefold(), [])
        if not candidates:
            for fallback in _identity_key_fallbacks(identity_key):
                candidates.extend(aliases.get(fallback, []))
        if not candidates:
            unmatched.append(identity_key)
            continue
        unique = {id(node): node for node in candidates}
        if len(unique) != 1:
            ambiguous.append(identity_key)
            continue
        node = next(iter(unique.values()))
        _apply_to_node(
            node,
            enrichment,
            domain_policy=data.get("domain", {}).get("password_policy", {}),
        )
        matched += 1

    report = {
        "bridge_version": BRIDGE_VERSION,
        "generated": bridge.get("generated", ""),
        "domain": bridge.get("domain", ""),
        "received": len(bridge["enrichments"]),
        "matched": matched,
        "unmatched": len(unmatched),
        "ambiguous": len(ambiguous),
        "unmatched_identity_keys": unmatched[:100],
        "ambiguous_identity_keys": ambiguous[:100],
    }
    data["credential_enrichment"] = report
    data.setdefault("meta", {})["credential_enrichment"] = {
        key: value for key, value in report.items() if not key.endswith("identity_keys")
    }
    return report


def save_enriched_package(data: dict[str, Any], output_path: str | Path) -> Path:
    destination = Path(output_path).expanduser()
    if destination.suffix.casefold() != ".serket":
        destination = destination.with_suffix(".serket")
    destination.parent.mkdir(parents=True, exist_ok=True)

    components = {
        "domain": data.get("domain", {}),
        "users": data.get("users", {}),
        "groups": data.get("groups", {}),
        "computers": data.get("computers", {}),
        "directory_objects": data.get("directory_objects", {}),
        "gpos": data.get("gpos", []),
        "trusts": data.get("trusts", []),
        "permissions": data.get("acls", []),
        "adcs": data.get("adcs", {}),
        "sysvol": data.get("sysvol", {}),
        "summary": {
            "stats": data.get("stats", {}),
            "sid_name": data.get("sid_name", {}),
            "quality": data.get("quality", {}),
            "coverage": data.get("coverage", {}),
            "system_counts": data.get("system_counts", {}),
        },
        "analysis": {
            "surface": data.get("surface", {}),
            "paths": data.get("paths", []),
            "findings": data.get("findings", []),
            "risk_summary": data.get("risk_summary", {}),
            "posture": data.get("posture", {}),
            "snapshot_id": data.get("snapshot_id", ""),
            "sensitivity": data.get("sensitivity", {}),
        },
        "graph": {"graph": data.get("graph", {}), "high_value": data.get("high_value", [])},
        "interchange": data.get("interchange", {}),
        "external_surface": data.get("external_surface_enrichment", {}),
    }
    with tempfile.TemporaryDirectory(prefix="serket-enriched-") as temporary:
        root = Path(temporary)
        files: dict[str, str] = {}
        for category, value in components.items():
            filename = f"{category}.json"
            files[category] = filename
            (root / filename).write_text(
                json.dumps({"category": category, "data": value}, indent=2, default=_json_default),
                encoding="utf-8",
            )
        credential_report = data.get("credential_enrichment", {})
        external_report = data.get("external_surface_enrichment", {})
        (root / "report.txt").write_text(
            "SERKET - Sanitized enrichment\n"
            f"Keyring matched identities: {credential_report.get('matched', 0)}\n"
            f"Portico matched assets: {external_report.get('matched', 0)}\n"
            f"Portico external findings: {external_report.get('findings', 0)}\n"
            "No secret values are included.\n",
            encoding="utf-8",
        )
        members = [*files.values(), "report.txt"]
        integrity = {name: _integrity(root / name) for name in members}
        manifest = {
            "format": "serket-collection-bundle",
            "schema_version": 1,
            "meta": data.get("meta", {}),
            "files": files,
            "integrity": {"algorithm": "sha256", "files": integrity},
        }
        (root / "manifest.json").write_text(json.dumps(manifest, indent=2, default=_json_default), encoding="utf-8")
        temporary_output = destination.with_suffix(destination.suffix + ".tmp")
        try:
            with zipfile.ZipFile(temporary_output, "w", zipfile.ZIP_DEFLATED) as archive:
                for name in sorted(["manifest.json", *members]):
                    archive.write(root / name, arcname=name)
            os.replace(temporary_output, destination)
        finally:
            if temporary_output.exists():
                temporary_output.unlink()
    return destination


def _apply_to_node(
    node: dict[str, Any],
    enrichment: dict[str, Any],
    *,
    domain_policy: dict[str, Any],
) -> None:
    details = enrichment["details"]
    safe_details = json.loads(json.dumps(details))
    entry = {
        "type": enrichment["enrichment_type"],
        "severity": enrichment["severity"],
        "details": safe_details,
    }
    existing = node.setdefault("credential_enrichments", [])
    existing[:] = [item for item in existing if item.get("type") != entry["type"]]
    existing.append(entry)
    if enrichment["enrichment_type"] == "credential_reuse":
        node["credential_reuse"] = True
        node["credential_reuse_severity"] = enrichment["severity"]
        node["reuse_count"] = int(details.get("shared_identity_count", details.get("shared_secret_count", 0)))
        node["shared_secret_count"] = int(details.get("shared_secret_count", 0))
        node["cloud_linked"] = bool(details.get("cloud_linked", False))
        node["cloud_identities"] = list(details.get("cloud_identities", []))[:1000]
        node["shared_with_names"] = list(details.get("shared_with_names", []))[:1000]
    elif enrichment["enrichment_type"] == "credential_hygiene":
        password_age = details.get("password_age_days")
        if password_age is None:
            password_age = node.get("pwd_age_days")
        max_age = domain_policy.get("max_age_days")
        policy_match = details.get("matches_domain_policy")
        if policy_match is None and password_age is not None and max_age not in (None, 0, "0"):
            policy_match = int(password_age) <= int(max_age)
        node["credential_hygiene"] = True
        node["password_reused_in"] = int(details.get("password_reused_in", 0))
        node["keyring_password_age_days"] = password_age
        node["matches_domain_policy"] = policy_match
        node["crackability_score"] = details.get("crackability_score")
    else:
        node["laps_reuse"] = True
        node["laps_reuse_count"] = int(details.get("laps_password_reused_in", 0))


def _node_aliases(node: dict[str, Any]) -> set[str]:
    aliases = {
        str(node.get("id", "")).strip().casefold(),
        str(node.get("sid", "")).strip().casefold(),
        str(node.get("name", "")).strip().casefold(),
    }
    name = str(node.get("name", "")).strip()
    domain = str(node.get("domain", "")).strip()
    if name and domain:
        aliases.add(f"{name}@{domain}".casefold())
    return {alias for alias in aliases if alias}


def _identity_key_fallbacks(identity_key: str) -> set[str]:
    """Resolve name-based forensic identities only when the result is unique."""
    fallbacks: set[str] = set()
    if "@" in identity_key:
        fallbacks.add(identity_key.split("@", 1)[0].strip().casefold())
    if "\\" in identity_key:
        fallbacks.add(identity_key.split("\\", 1)[1].strip().casefold())
    return {value for value in fallbacks if value}


def _reject_sensitive_keys(value: Any) -> None:
    if isinstance(value, dict):
        for key, nested in value.items():
            if str(key).casefold() in _FORBIDDEN_KEYS:
                raise EnrichmentError(f"bridge contains prohibited sensitive field: {key}")
            _reject_sensitive_keys(nested)
    elif isinstance(value, list):
        for nested in value:
            _reject_sensitive_keys(nested)


def _validate_details(enrichment_type: str, details: dict[str, Any], index: int) -> None:
    def count(name: str) -> None:
        value = details.get(name, 0)
        if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= 1_000_000:
            raise EnrichmentError(f"enrichment {index} has invalid {name}")

    def string_list(name: str) -> None:
        value = details.get(name, [])
        if (
            not isinstance(value, list)
            or len(value) > 1000
            or any(not isinstance(item, str) or len(item) > 1024 for item in value)
        ):
            raise EnrichmentError(f"enrichment {index} has invalid {name}")

    if enrichment_type == "credential_reuse":
        count("shared_secret_count")
        count("shared_identity_count")
        if not isinstance(details.get("cloud_linked", False), bool):
            raise EnrichmentError(f"enrichment {index} has invalid cloud_linked")
        for field in ("shared_with_sids", "shared_with_names", "cloud_identities"):
            string_list(field)
    elif enrichment_type == "credential_hygiene":
        count("password_reused_in")
        age = details.get("password_age_days")
        if age is not None and (isinstance(age, bool) or not isinstance(age, int) or not 0 <= age <= 100_000):
            raise EnrichmentError(f"enrichment {index} has invalid password_age_days")
        policy = details.get("matches_domain_policy")
        if policy is not None and not isinstance(policy, bool):
            raise EnrichmentError(f"enrichment {index} has invalid matches_domain_policy")
        score = details.get("crackability_score")
        if score is not None and (
            isinstance(score, bool)
            or not isinstance(score, (int, float))
            or not math.isfinite(float(score))
            or not 0 <= float(score) <= 10
        ):
            raise EnrichmentError(f"enrichment {index} has invalid crackability_score")
    else:
        count("laps_password_reused_in")
        string_list("other_systems")
def _integrity(path: Path) -> dict[str, Any]:
    raw = path.read_bytes()
    return {"sha256": hashlib.sha256(raw).hexdigest(), "size": len(raw)}


def _json_default(value: Any) -> Any:
    if isinstance(value, (set, tuple)):
        return list(value)
    if isinstance(value, bytes):
        return value.hex()
    raise TypeError(f"not JSON serializable: {type(value).__name__}")
