"""Strict Portico external-identity-surface bridge consumer."""
from __future__ import annotations

from collections import Counter, defaultdict
import json
from pathlib import Path
import re
from typing import Any
from urllib.parse import urlsplit

from serket.enrichment import EnrichmentError, MAX_BRIDGE_BYTES, _reject_sensitive_keys
from serket.finding import Evidence, Finding, RiskComponents, RISK_MODEL, stable_token


BRIDGE_TYPE = "external_identity_surface"
BRIDGE_VERSION = "1.0"
MAX_EXPOSURES = 100_000
_HOST_RE = re.compile(
    r"(?=.{1,253}\Z)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*"
    r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z",
    re.IGNORECASE,
)
_AUTH_SCHEMES = {"basic", "bearer", "digest", "negotiate", "ntlm"}
_TOP_LEVEL_KEYS = {
    "bridge_version", "bridge_type", "source", "generated", "domain",
    "external_exposures",
}


def load_external_bridge(path: str | Path) -> dict[str, Any]:
    source = Path(path).expanduser()
    if source.is_symlink() or not source.is_file():
        raise EnrichmentError("bridge must be a regular non-symbolic-link file")
    if source.stat().st_size > MAX_BRIDGE_BYTES:
        raise EnrichmentError("bridge exceeds the 8 MiB safety limit")
    try:
        bridge = json.loads(
            source.read_text(encoding="utf-8"),
            parse_constant=lambda value: (_ for _ in ()).throw(
                ValueError(f"non-finite JSON value: {value}")
            ),
        )
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as exc:
        raise EnrichmentError(f"invalid bridge JSON: {exc}") from exc
    return validate_external_bridge(bridge)


def validate_external_bridge(bridge: Any) -> dict[str, Any]:
    if not isinstance(bridge, dict):
        raise EnrichmentError("bridge root must be an object")
    unknown = set(bridge).difference(_TOP_LEVEL_KEYS)
    if unknown:
        raise EnrichmentError(f"bridge contains unsupported fields: {', '.join(sorted(unknown))}")
    if bridge.get("bridge_version") != BRIDGE_VERSION:
        raise EnrichmentError("unsupported bridge_version")
    if bridge.get("bridge_type") != BRIDGE_TYPE or bridge.get("source") != "portico":
        raise EnrichmentError("bridge must be a Portico external_identity_surface export")
    domain = bridge.get("domain", "")
    if not isinstance(domain, str) or len(domain) > 253:
        raise EnrichmentError("bridge domain is invalid")
    exposures = bridge.get("external_exposures")
    if not isinstance(exposures, list):
        raise EnrichmentError("external_exposures must be an array")
    if len(exposures) > MAX_EXPOSURES:
        raise EnrichmentError("bridge contains too many external exposures")
    _reject_sensitive_keys(bridge)
    for index, exposure in enumerate(exposures):
        _validate_exposure(exposure, index)
    return bridge


def apply_external_bridge(data: dict[str, Any], bridge: dict[str, Any]) -> dict[str, Any]:
    validate_external_bridge(bridge)
    graph = data.get("graph")
    if not isinstance(graph, dict) or not isinstance(graph.get("nodes"), list):
        raise EnrichmentError("Serket result does not contain a node-link graph")
    serket_domain = str(data.get("domain", {}).get("name", "")).rstrip(".").casefold()
    bridge_domain = str(bridge.get("domain", "")).rstrip(".").casefold()
    if serket_domain and bridge_domain and serket_domain != bridge_domain:
        raise EnrichmentError("Portico and Serket domains do not match")

    spn_index: dict[str, list[dict[str, Any]]] = defaultdict(list)
    dns_index: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for node in graph["nodes"]:
        if not isinstance(node, dict):
            continue
        for spn in _string_values(node, "spns", "servicePrincipalName", "service_principal_names"):
            host = _spn_hostname(spn)
            if host:
                spn_index[host].append(node)
        for host in _string_values(node, "dns", "dNSHostName", "dns_hostname"):
            normalized = _hostname(host)
            if normalized:
                dns_index[normalized].append(node)

    snapshot_id = str(data.get("snapshot_id") or data.get("meta", {}).get("snapshot_id") or "legacy")
    created_at = str(bridge.get("generated", ""))
    imported: list[dict[str, Any]] = []
    match_counts: Counter[str] = Counter()
    ambiguous_hosts: list[str] = []
    unmatched_hosts: list[str] = []

    for exposure in bridge["external_exposures"]:
        hostname = _hostname(exposure["asset_key"])
        node, strategy, ambiguous = _match_node(hostname, spn_index, dns_index)
        if ambiguous:
            ambiguous_hosts.append(hostname)
        if node is None:
            if not ambiguous:
                unmatched_hosts.append(hostname)
            node = _external_node(graph["nodes"], hostname)
            strategy = "unmatched_external_asset" if not ambiguous else "ambiguous_external_asset"
        else:
            match_counts[strategy] += 1

        safe_exposure = json.loads(json.dumps(exposure))
        safe_exposure["correlation_strategy"] = strategy
        entries = node.setdefault("external_exposures", [])
        exposure_key = _exposure_key(safe_exposure)
        entries[:] = [item for item in entries if _exposure_key(item) != exposure_key]
        entries.append(safe_exposure)

        for badge, severity, technique, remediation in _detections(exposure):
            components = _risk(severity, informational=(badge == "MFA_UNKNOWN"))
            finding = Finding.create(
                snapshot_id=snapshot_id,
                object_id=str(node.get("id", hostname)),
                stable_object_id=str(node.get("object_guid") or node.get("id") or hostname),
                technique=f"Portico:{exposure_key}:{technique}",
                object_type=str(node.get("type", "ExternalAsset")),
                badge=badge,
                category="external_surface",
                severity=severity,
                confidence=str(exposure.get("evidence_strength", "high")),
                certainty="direct",
                coverage="external_probe",
                evidence=[Evidence(
                    type="external_probe",
                    source="Portico",
                    value={**safe_exposure, "asset_key": hostname},
                    interpretation=_interpretation(badge, hostname),
                )],
                tier0_reachable=False,
                mitre_technique=None,
                mitre_tactic="Initial Access",
                risk_components=components,
                created_at=created_at,
                remediation=remediation,
            ).to_dict()
            imported.append(finding)

    existing = [
        item for item in data.get("findings", [])
        if isinstance(item, dict) and item.get("category") != "external_surface"
    ]
    merged = sorted(
        existing + _deduplicate(imported),
        key=lambda item: (-int(item.get("risk_score", 0) or 0), str(item.get("id", ""))),
    )
    data["findings"] = merged
    _attach_findings(graph["nodes"], merged)
    _refresh_posture(data, merged, snapshot_id)

    report = {
        "bridge_version": BRIDGE_VERSION,
        "source": "portico",
        "generated": created_at,
        "domain": bridge.get("domain", ""),
        "received": len(bridge["external_exposures"]),
        "matched": sum(match_counts.values()),
        "matched_by_spn": match_counts["spn_exact"],
        "matched_by_dns": match_counts["dns_exact"],
        "unmatched": len(unmatched_hosts),
        "ambiguous": len(ambiguous_hosts),
        "findings": len(_deduplicate(imported)),
        "unmatched_hostnames": list(dict.fromkeys(unmatched_hosts))[:100],
        "ambiguous_hostnames": list(dict.fromkeys(ambiguous_hosts))[:100],
    }
    data["external_surface_enrichment"] = report
    data.setdefault("meta", {})["external_surface_enrichment"] = {
        key: value for key, value in report.items() if not key.endswith("hostnames")
    }
    data.setdefault("coverage", {})["external_surface"] = {
        "status": "observed", "mode": "portico_bridge", "source": "portico",
    }
    return report


def _validate_exposure(exposure: Any, index: int) -> None:
    if not isinstance(exposure, dict):
        raise EnrichmentError(f"external exposure {index} must be an object")
    allowed = {
        "asset_key", "match_strategy", "exposure_type", "endpoint_kind", "url",
        "auth_schemes", "product_hints", "mfa_status", "evidence_strength",
        "advisory_status", "port", "tls_valid",
    }
    unknown = set(exposure).difference(allowed)
    if unknown:
        raise EnrichmentError(f"external exposure {index} contains unsupported fields")
    host = _hostname(exposure.get("asset_key"))
    if not host:
        raise EnrichmentError(f"external exposure {index} has an invalid asset_key")
    if exposure.get("match_strategy") != "hostname_exact":
        raise EnrichmentError(f"external exposure {index} must use hostname_exact")
    kind = exposure.get("exposure_type")
    if kind not in {"external_auth_surface", "external_ldaps"}:
        raise EnrichmentError(f"external exposure {index} has an unsupported exposure_type")
    if exposure.get("evidence_strength") not in {"high", "medium", "low"}:
        raise EnrichmentError(f"external exposure {index} has invalid evidence_strength")
    if exposure.get("advisory_status") != "not_assessed":
        raise EnrichmentError(f"external exposure {index} overstates advisory assessment")
    if kind == "external_auth_surface":
        endpoint = exposure.get("endpoint_kind")
        if not isinstance(endpoint, str) or not endpoint.strip() or len(endpoint) > 80:
            raise EnrichmentError(f"external exposure {index} has invalid endpoint_kind")
        parsed = urlsplit(str(exposure.get("url", "")))
        if (
            parsed.scheme not in {"http", "https"} or parsed.hostname is None
            or _hostname(parsed.hostname) != host or parsed.username or parsed.password
            or parsed.query or parsed.fragment or len(str(exposure.get("url", ""))) > 2048
        ):
            raise EnrichmentError(f"external exposure {index} has an unsafe URL")
        schemes = exposure.get("auth_schemes")
        if (
            not isinstance(schemes, list) or len(schemes) > 16
            or any(not isinstance(value, str) or value.casefold() not in _AUTH_SCHEMES for value in schemes)
        ):
            raise EnrichmentError(f"external exposure {index} has invalid auth_schemes")
        hints = exposure.get("product_hints")
        if (
            not isinstance(hints, list) or len(hints) > 100
            or any(not isinstance(value, str) or len(value) > 256 for value in hints)
        ):
            raise EnrichmentError(f"external exposure {index} has invalid product_hints")
        if exposure.get("mfa_status") not in {"observed", "unknown"}:
            raise EnrichmentError(f"external exposure {index} has invalid mfa_status")
    else:
        port = exposure.get("port")
        if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
            raise EnrichmentError(f"external exposure {index} has invalid port")
        if not isinstance(exposure.get("tls_valid"), bool):
            raise EnrichmentError(f"external exposure {index} has invalid tls_valid")


def _hostname(value: Any) -> str:
    if not isinstance(value, str):
        return ""
    result = value.strip().rstrip(".").casefold()
    return result if _HOST_RE.fullmatch(result) else ""


def _string_values(node: dict[str, Any], *keys: str) -> list[str]:
    result: list[str] = []
    for key in keys:
        value = node.get(key, [])
        if isinstance(value, str):
            result.append(value)
        elif isinstance(value, (list, tuple, set)):
            result.extend(item for item in value if isinstance(item, str))
    return result


def _spn_hostname(spn: str) -> str:
    if "/" not in spn:
        return ""
    instance = spn.split("/", 1)[1].split("/", 1)[0].strip()
    if instance.count(":") == 1 and instance.rsplit(":", 1)[1].isdigit():
        instance = instance.rsplit(":", 1)[0]
    return _hostname(instance)


def _unique_nodes(nodes: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return list({id(node): node for node in nodes}.values())


def _match_node(hostname, spn_index, dns_index):
    spn = _unique_nodes(spn_index.get(hostname, []))
    if len(spn) == 1:
        return spn[0], "spn_exact", False
    if len(spn) > 1:
        return None, "", True
    dns = _unique_nodes(dns_index.get(hostname, []))
    if len(dns) == 1:
        return dns[0], "dns_exact", False
    if len(dns) > 1:
        return None, "", True
    return None, "", False


def _external_node(nodes: list[dict[str, Any]], hostname: str) -> dict[str, Any]:
    object_id = f"external://portico/{stable_token(hostname)}"
    for node in nodes:
        if isinstance(node, dict) and node.get("id") == object_id:
            return node
    node = {"id": object_id, "name": hostname, "dns": hostname, "type": "ExternalAsset", "source": "portico"}
    nodes.append(node)
    return node


def _exposure_key(exposure: dict[str, Any]) -> str:
    return stable_token(
        exposure.get("asset_key"), exposure.get("exposure_type"),
        exposure.get("endpoint_kind"), exposure.get("url"), exposure.get("port"),
        length=32,
    )


def _detections(exposure: dict[str, Any]):
    if exposure["exposure_type"] == "external_ldaps":
        yield "LDAPS_EXPOSED", "medium", "ExternalLDAPS", "Restrict LDAPS exposure to approved networks and monitor certificate posture."
        return
    endpoint = str(exposure.get("endpoint_kind", "")).casefold()
    if endpoint == "owa":
        yield "EXTERNAL_OWA", "medium", "ExternalOWA", "Restrict and harden the externally reachable OWA authentication surface."
    elif endpoint == "adfs":
        yield "EXTERNAL_ADFS", "medium", "ExternalADFS", "Harden externally reachable federation endpoints and enforce strong authentication controls."
    elif endpoint in {"vpn", "citrix", "anyconnect"}:
        yield "EXTERNAL_VPN", "medium", "ExternalVPN", "Restrict and harden the external remote-access service."
    schemes = {str(value).casefold() for value in exposure.get("auth_schemes", [])}
    if "ntlm" in schemes:
        yield "NTLM_EXPOSED_EXTERNALLY", "high", "ExternalNTLM", "Disable external NTLM where possible and require modern, phishing-resistant authentication."
    if "basic" in schemes:
        yield "BASIC_AUTH_EXPOSED", "critical", "ExternalBasicAuth", "Disable Basic authentication on the external endpoint."
    if exposure.get("mfa_status") == "unknown":
        yield "MFA_UNKNOWN", "info", "ExternalMFAUnknown", "Verify MFA enforcement directly; Portico did not establish its presence or absence."


def _interpretation(badge: str, hostname: str) -> str:
    messages = {
        "EXTERNAL_OWA": "OWA authentication surface was directly observed externally.",
        "EXTERNAL_ADFS": "ADFS authentication surface was directly observed externally.",
        "EXTERNAL_VPN": "Remote-access authentication surface was directly observed externally.",
        "NTLM_EXPOSED_EXTERNALLY": "An external endpoint advertised NTLM-compatible authentication.",
        "BASIC_AUTH_EXPOSED": "An external endpoint advertised Basic authentication.",
        "MFA_UNKNOWN": "MFA posture could not be established; absence is not inferred.",
        "LDAPS_EXPOSED": "An LDAPS listener was directly observed externally.",
    }
    return f"{messages[badge]} Asset: {hostname}."


def _risk(severity: str, *, informational: bool) -> RiskComponents:
    impact = {"critical": 40, "high": 32, "medium": 22, "info": 5}[severity]
    if informational:
        return RiskComponents(impact=impact, reachability=0, exploitability=4, exposure=5)
    return RiskComponents(impact=impact, reachability=30, exploitability=24, exposure=5)


def _deduplicate(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return list({item["correlation_id"]: item for item in findings}.values())


def _attach_findings(nodes: list[dict[str, Any]], findings: list[dict[str, Any]]) -> None:
    by_object: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for finding in findings:
        by_object[str(finding.get("object_id", ""))].append(finding)
    for node in nodes:
        if not isinstance(node, dict):
            continue
        preserved = [
            item for item in node.get("findings", [])
            if isinstance(item, dict) and item.get("category") != "external_surface"
        ]
        node["findings"] = preserved + [
            item for item in by_object.get(str(node.get("id", "")), [])
            if item.get("category") == "external_surface"
        ]


def _refresh_posture(data: dict[str, Any], findings: list[dict[str, Any]], snapshot_id: str) -> None:
    categories: Counter[str] = Counter()
    severities: Counter[str] = Counter()
    total = 0
    for finding in findings:
        score = int(finding.get("risk_score", 0) or 0)
        total += score
        categories[str(finding.get("category", "unknown"))] += score
        severities[str(finding.get("severity", "unknown"))] += 1
    risk_summary = {
        "risk_model": RISK_MODEL,
        "global_score": total,
        "max_finding_score": max((int(item.get("risk_score", 0) or 0) for item in findings), default=0),
        "findings_count": dict(sorted(severities.items())),
        "category_scores": dict(sorted(categories.items())),
    }
    data["risk_summary"] = risk_summary
    previous = data.get("posture", {}) if isinstance(data.get("posture"), dict) else {}
    data["posture"] = {
        **previous,
        "schema": "serket-posture/v1",
        "risk_model": RISK_MODEL,
        "global_score": total,
        "category_scores": dict(sorted(categories.items())),
        "findings_count": len(findings),
        "snapshot_id": snapshot_id,
    }
