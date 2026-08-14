"""Generate contextual, explainable findings from Serket graph evidence."""
from __future__ import annotations

from collections import Counter, defaultdict
from datetime import datetime, timezone
from typing import Any
import networkx as nx

from serket.detection_catalog import DETECTION_CATALOG
from serket.finding import Evidence, Finding, RiskComponents, RISK_MODEL, stable_token
from serket.graph.builder import ADGraph, MITRE_MAP
from serket.graph.pathfinder import get_all_paths, _resolve_high_value_nodes
from serket.graph.pathfinder import _traversable_projection


ACL_RELATIONS = {
    "GenericAll", "GenericWrite", "WriteDACL", "WriteOwner", "Owns",
    "AllExtendedRights", "ForceChangePassword", "AddMember", "AddSelf",
    "AddKeyCredentialLink", "AddAllowedToAct", "WriteSPN",
    "WriteAccountRestrictions", "WriteRBCD", "DCSync",
}

LEGACY_RULES = (
    ("has_key_credential_link", "SHADOW", "identity", "high", "ShadowCredentials"),
    ("kerberoastable", "KERBEROASTABLE", "kerberos", "medium", "Kerberoastable"),
    ("asreproastable", "ASREP_ROAST", "kerberos", "high", "ASREPRoastable"),
    ("unconstrained", "UNCONSTRAINED_DELEGATION", "kerberos", "high", "UnconstrainedDelegation"),
    ("constrained_kerberos_only", "CONSTRAINED_DELEGATION", "kerberos", "medium", "ConstrainedDelegation"),
    ("protocol_transition", "PROTOCOL_TRANSITION", "kerberos", "high", "ProtocolTransition"),
    ("rbcd_trustees", "RBCD", "kerberos", "high", "RBCD"),
    ("adminsdholder_drift", "SD_DRIFT", "acl", "high", "WriteDACL"),
    ("missing_protected_users", "NO_PROTECTED", "identity", "medium", "MemberOf"),
    ("rodc_tier0_exposure", "RODC_TIER0", "identity", "critical", "RODCCachedCredential"),
    ("prewin2000_exposure", "PREWIN_OPEN", "identity", "high", "PreWindows2000Access"),
    ("store_cleartext", "REVERSIBLE_ENCRYPTION", "operational", "high", "ReversibleEncryption"),
    ("use_des_key_only", "DES_ONLY", "kerberos", "high", "ASREPRoastable"),
)

TACTICS = {
    "acl": "Privilege Escalation",
    "identity": "Persistence",
    "kerberos": "Credential Access",
    "adcs": "Credential Access",
    "gpo": "Privilege Escalation",
    "trust": "Lateral Movement",
    "operational": "Defense Evasion",
}


def _snapshot_context(ad_data: dict) -> tuple[str, str]:
    telemetry = ad_data.get("telemetry", {})
    meta = ad_data.get("meta", {})
    created = str(
        telemetry.get("started_at") or telemetry.get("finished_at")
        or meta.get("generated")
        or datetime.now(timezone.utc).isoformat()
    )
    existing = ad_data.get("snapshot_id") or meta.get("snapshot_id")
    if existing:
        return str(existing), created
    domain = ad_data.get("domain", {})
    token = stable_token(
        domain.get("sid") or domain.get("name"), created,
        len(ad_data.get("users", {})), len(ad_data.get("computers", {})),
        length=16,
    )
    return token, created


def _mitre(relation: str) -> tuple[str | None, str | None]:
    item = MITRE_MAP.get(relation) or {}
    return item.get("id"), item.get("name")


def _remediation(relation: str) -> str | None:
    return (DETECTION_CATALOG.get(relation) or {}).get("remediation")


def classify_certainty(*, direct_target: bool = False, paths=None,
                       credential_required: bool = False,
                       conditional: bool = False) -> str:
    if direct_target:
        return "direct"
    if conditional:
        return "conditional"
    if paths and credential_required:
        return "credential_dependent"
    if paths:
        return "transitive"
    return "informational"


def _risk(severity: str, certainty: str, target_sensitivity: str = "none") -> RiskComponents:
    impact = {"critical": 40, "high": 32, "medium": 22, "low": 12, "info": 5}[severity]
    reachability = {
        "direct": 30, "transitive": 24, "credential_dependent": 18,
        "conditional": 10, "informational": 0,
    }[certainty]
    exploitability = {
        "direct": 24, "transitive": 19, "credential_dependent": 14,
        "conditional": 9, "informational": 4,
    }[certainty]
    exposure = 10 if target_sensitivity in {"critical", "high"} else 5
    return RiskComponents(impact, reachability, exploitability, exposure)


def _contextual_severity(base: str, certainty: str) -> str:
    if certainty == "direct":
        return "critical"
    if certainty in {"transitive", "credential_dependent"} and base in {"medium", "low"}:
        return "high"
    return base


def _confidence_adjusted_risk(components: RiskComponents, confidence: str) -> RiskComponents:
    """Discount candidate exploitability/exposure without hiding impact."""
    factor = {"high": 1.0, "medium": 0.8, "low": 0.6}.get(confidence, 0.5)
    return RiskComponents(
        components.impact,
        components.reachability,
        round(components.exploitability * factor),
        round(components.exposure * factor),
    )


def generate_findings(*, ad_data: dict, ag: ADGraph,
                      cheapest_paths: list[dict] | None = None) -> dict[str, Any]:
    graph = ag.G
    tier0 = _resolve_high_value_nodes(ag)
    snapshot_id, created_at = _snapshot_context(ad_data)
    findings: list[Finding] = []
    path_cache: dict[str, list] = {}
    projected = _traversable_projection(graph)
    reachable_to_tier0: set[str] = set()
    reverse = projected.reverse(copy=False)
    for target in tier0:
        if target in reverse:
            reachable_to_tier0.update(str(node) for node in nx.descendants(reverse, target))

    def paths_for(node_id: str):
        if node_id not in path_cache:
            path_cache[node_id] = (
                get_all_paths(ag, node_id, tier0, max_depth=5, max_paths=10)
                if str(node_id) in reachable_to_tier0 else []
            )
        return path_cache[node_id]

    for node_id, node in graph.nodes(data=True):
        node_paths = None
        for prop, badge, category, base_severity, relation in LEGACY_RULES:
            if not node.get(prop):
                continue
            if node_paths is None:
                node_paths = paths_for(node_id)
            credential = badge in {"KERBEROASTABLE", "ASREP_ROAST"}
            certainty = classify_certainty(
                paths=node_paths,
                credential_required=credential,
            )
            severity = _contextual_severity(base_severity, certainty)
            components = _risk(severity, certainty, node.get("sensitivity", "none"))
            mitre_id, _ = _mitre(relation)
            finding = Finding.create(
                snapshot_id=snapshot_id,
                object_id=str(node_id),
                stable_object_id=node.get("guid") or str(node_id),
                object_type=str(node.get("type", "unknown")).lower(),
                technique=relation,
                badge=badge,
                category=category,
                severity=severity,
                confidence="high",
                certainty=certainty,
                evidence=[Evidence(
                    type="ldap_attribute",
                    source=prop,
                    value=True,
                    interpretation=f"{prop} is asserted on {node.get('name', node_id)}",
                )],
                paths=node_paths or [],
                tier0_reachable=bool(node_paths),
                tier0_distance=min((len(path.edges) for path in node_paths), default=None),
                mitre_technique=mitre_id,
                mitre_tactic=TACTICS.get(category),
                risk_score=components.total,
                risk_components=components,
                created_at=created_at,
                remediation=_remediation(relation),
            )
            findings.append(finding)

        if node.get("type") == "GPO":
            sensitive_links = []
            for _, target, key, edge in graph.out_edges(node_id, keys=True, data=True):
                if (
                    str(edge.get("type", key)) != "GPOLink"
                    or edge.get("traversable", True) is False
                ):
                    continue
                target_data = graph.nodes.get(target, {})
                if target_data.get("sensitivity") not in {"high", "critical"}:
                    continue
                sensitive_links.append((target, target_data, edge))
            if sensitive_links:
                if node_paths is None:
                    node_paths = paths_for(node_id)
                target_level = (
                    "critical" if any(
                        target_data.get("sensitivity") == "critical"
                        for _, target_data, _ in sensitive_links
                    ) else "high"
                )
                components = _risk("high", "conditional", target_level)
                evidence = [Evidence(
                    type="gpo_link",
                    source="gPLink",
                    value={
                        "target_id": str(target),
                        "target_name": target_data.get("name", str(target)),
                        "target_sensitivity": target_data.get("sensitivity"),
                        "order": edge.get("link_order"),
                        "enforced": bool(edge.get("enforced")),
                        "target_blocks_inheritance": bool(edge.get("target_blocks_inheritance")),
                    },
                    interpretation=(
                        f"Enabled GPO link reaches sensitive container "
                        f"{target_data.get('name', target)}"
                    ),
                ) for target, target_data, edge in sensitive_links]
                findings.append(Finding.create(
                    snapshot_id=snapshot_id,
                    object_id=str(node_id),
                    stable_object_id=node.get("guid") or str(node_id),
                    object_type="gpo",
                    technique="GPO_TIER0_LINK",
                    badge="GPO_TIER0_LINK",
                    category="gpo",
                    severity="high",
                    confidence="medium",
                    certainty="conditional",
                    coverage="ldap_only",
                    evidence=evidence,
                    paths=node_paths or [],
                    tier0_reachable=bool(node_paths),
                    tier0_distance=min((len(path.edges) for path in node_paths), default=None),
                    mitre_technique="T1484.001",
                    mitre_tactic=TACTICS["gpo"],
                    risk_score=components.total,
                    risk_components=components,
                    created_at=created_at,
                    remediation=_remediation("GPO_TIER0_LINK"),
                ))
            sysvol = node.get("sysvol") or {}
            sysvol_issues = list(sysvol.get("issues", [])) if isinstance(sysvol, dict) else []
            if sysvol_issues:
                severity_order = {"critical": 4, "high": 3, "medium": 2, "low": 1}
                severity = max(
                    (str(issue.get("severity", "medium")) for issue in sysvol_issues),
                    key=lambda value: severity_order.get(value, 0),
                )
                node_paths = node_paths if node_paths is not None else paths_for(node_id)
                components = _risk(severity, "direct", node.get("sensitivity", "none"))
                findings.append(Finding.create(
                    snapshot_id=snapshot_id,
                    object_id=str(node_id),
                    stable_object_id=node.get("guid") or str(node_id),
                    object_type="gpo",
                    technique="GPO_ABUSE",
                    index=stable_token(node_id, *(
                        str(issue.get("kind", "")) for issue in sysvol_issues
                    )),
                    badge="GPO_ABUSE",
                    category="gpo",
                    severity=severity,
                    confidence="high",
                    certainty="direct",
                    coverage="sysvol_offline",
                    evidence=[Evidence(
                        type="sysvol_setting",
                        source=str(issue.get("kind", "SYSVOL")),
                        value=issue,
                        interpretation=str(issue.get("description", "Dangerous GPO content confirmed")),
                    ) for issue in sysvol_issues],
                    paths=node_paths or [],
                    tier0_reachable=bool(node_paths),
                    tier0_distance=min((len(path.edges) for path in node_paths), default=None),
                    mitre_technique="T1484.001",
                    mitre_tactic=TACTICS["gpo"],
                    risk_score=components.total,
                    risk_components=components,
                    created_at=created_at,
                    remediation=_remediation("GPO_ABUSE"),
                ))

        if node.get("type") == "CertTemplate":
            for candidate in node.get("adcs_findings", []):
                esc = str(candidate.get("id", ""))
                if esc not in {"ESC1", "ESC2", "ESC3", "ESC4"}:
                    continue
                if candidate.get("status") != "candidate":
                    continue
                relation = f"ADCS_{esc}"
                confidence = str(candidate.get("confidence", "low"))
                components = _confidence_adjusted_risk(
                    _risk("high", "conditional", node.get("sensitivity", "none")),
                    confidence,
                )
                reasons = list(candidate.get("reasons", []))
                principals = list(candidate.get("principals", []))
                findings.append(Finding.create(
                    snapshot_id=snapshot_id,
                    object_id=str(node_id),
                    stable_object_id=node.get("guid") or str(node_id),
                    object_type="certtemplate",
                    technique=relation,
                    index=stable_token(node_id, esc, *principals),
                    badge=f"{esc}_CANDIDATE",
                    category="adcs",
                    severity="high",
                    confidence=confidence,
                    certainty="conditional",
                    coverage="ldap_only",
                    evidence=[Evidence(
                        type="adcs_candidate",
                        source="LDAP certificate template",
                        value={
                            "published": node.get("published"),
                            "principals": principals,
                            "reasons": reasons,
                        },
                        interpretation=(
                            f"{esc} candidate; CA-side controls require authorized validation"
                        ),
                    )],
                    paths=[],
                    tier0_reachable=False,
                    tier0_distance=None,
                    mitre_technique="T1649",
                    mitre_tactic=TACTICS["adcs"],
                    risk_score=components.total,
                    risk_components=components,
                    created_at=created_at,
                    remediation=_remediation(relation),
                ))

        if node.get("maq_abuse_suspected"):
            node_paths = node_paths if node_paths is not None else paths_for(node_id)
            components = _risk("high", "conditional", node.get("sensitivity", "none"))
            findings.append(Finding.create(
                snapshot_id=snapshot_id,
                object_id=str(node_id),
                stable_object_id=node.get("guid") or str(node_id),
                object_type=str(node.get("type", "computer")).lower(),
                technique="MAQAbuseObserved",
                badge="MAQ_ABUSE_OBSERVED",
                category="operational",
                severity="high",
                confidence="medium",
                certainty="conditional",
                coverage="ldap_only",
                evidence=[Evidence(
                    type="ldap_correlation",
                    source="mS-DS-CreatorSID + whenCreated",
                    value={
                        "creator_sid": node.get("creator_sid"),
                        "created": node.get("created"),
                        "created_age_days": node.get("created_age_days"),
                        "creator_volume": node.get("maq_creator_volume", 0),
                    },
                    interpretation="Non-admin creator exceeded the recent machine-creation threshold",
                )],
                paths=node_paths or [],
                tier0_reachable=bool(node_paths),
                tier0_distance=min((len(path.edges) for path in node_paths), default=None),
                mitre_technique="T1136.002",
                mitre_tactic="Persistence",
                risk_score=components.total,
                risk_components=components,
                created_at=created_at,
                remediation=_remediation("MAQAbuseObserved"),
            ))

    for source, target, key, edge in graph.edges(keys=True, data=True):
        relation = str(edge.get("type", key))
        if relation not in ACL_RELATIONS:
            continue
        source_paths = paths_for(source)
        target_data = graph.nodes.get(target, {})
        target_sensitivity = target_data.get("sensitivity", "none")
        direct = target in tier0
        certainty = classify_certainty(direct_target=direct, paths=source_paths)
        badge = (
            "WRITE_DACL_TIER0"
            if relation == "WriteDACL" and (direct or target_sensitivity in {"critical", "high"})
            else "ACL_ABUSE"
        )
        severity = _contextual_severity("high", certainty)
        components = _risk(severity, certainty, target_sensitivity)
        mitre_id, _ = _mitre(relation)
        findings.append(Finding.create(
            snapshot_id=snapshot_id,
            object_id=str(source),
            stable_object_id=graph.nodes.get(source, {}).get("guid") or str(source),
            object_type=str(graph.nodes.get(source, {}).get("type", "unknown")).lower(),
            technique=relation,
            index=stable_token(source, target, relation),
            badge=badge,
            category="acl",
            severity=severity,
            confidence="high",
            certainty=certainty,
            evidence=[Evidence(
                type="ace",
                source=relation,
                value={
                    "target_id": str(target),
                    "target_name": target_data.get("name", str(target)),
                    "inherited": bool(edge.get("inherited", False)),
                    "mask": edge.get("mask"),
                },
                interpretation=f"{relation} over {target_data.get('name', target)}",
            )],
            paths=source_paths,
            tier0_reachable=bool(source_paths),
            tier0_distance=min((len(path.edges) for path in source_paths), default=None),
            mitre_technique=mitre_id,
            mitre_tactic=TACTICS["acl"],
            risk_score=components.total,
            risk_components=components,
            created_at=created_at,
            remediation=_remediation(relation),
        ))

    eligible_types = {"User", "Group", "Computer", "Workstation", "Server",
                      "DomainController", "GPO", "CertTemplate", "SpecialIdentity"}
    existing_tier0_sources = {finding.object_id for finding in findings if finding.tier0_reachable}
    for path in cheapest_paths or []:
        source = str(path.get("src", ""))
        node = graph.nodes.get(source, {})
        if not source or source in tier0 or source in existing_tier0_sources:
            continue
        if node.get("type") not in eligible_types:
            continue
        alternatives = paths_for(source)
        if not alternatives:
            continue
        certainty = "transitive"
        components = _risk("high", certainty, "critical")
        findings.append(Finding.create(
            snapshot_id=snapshot_id,
            object_id=source,
            stable_object_id=node.get("guid") or source,
            object_type=str(node.get("type", "unknown")).lower(),
            technique="Tier0Path",
            badge="TIER0_PATH",
            category="acl",
            severity="high",
            confidence="high",
            certainty=certainty,
            evidence=[Evidence(
                type="membership",
                source="attack_graph",
                value={"path_count": len(alternatives)},
                interpretation="At least one traversable path reaches Tier 0",
            )],
            paths=alternatives,
            tier0_reachable=True,
            tier0_distance=min(len(item.edges) for item in alternatives),
            mitre_tactic="Privilege Escalation",
            risk_score=components.total,
            risk_components=components,
            created_at=created_at,
            remediation="Break unnecessary memberships and delegated control in the shortest Tier 0 path.",
        ))

    payload = [finding.to_dict() for finding in findings]
    by_object = defaultdict(list)
    for finding in payload:
        by_object[finding["object_id"]].append(finding)
    for node_id in graph.nodes:
        graph.nodes[node_id]["findings"] = sorted(
            by_object.get(str(node_id), []),
            key=lambda item: (-item["risk_score"], item["badge"], item["id"]),
        )

    severity_counts = Counter(item["severity"] for item in payload)
    category_scores = Counter()
    for item in payload:
        category_scores[item["category"]] += item["risk_score"]
    risk_summary = {
        "risk_model": RISK_MODEL,
        "global_score": sum(item["risk_score"] for item in payload),
        "max_finding_score": max((item["risk_score"] for item in payload), default=0),
        "findings_count": dict(sorted(severity_counts.items())),
        "category_scores": dict(sorted(category_scores.items())),
    }
    posture = {
        "schema": "serket-posture/v1",
        "risk_model": RISK_MODEL,
        "global_score": risk_summary["global_score"],
        "category_scores": risk_summary["category_scores"],
        "findings_count": len(payload),
        "snapshot_id": snapshot_id,
    }
    return {
        "snapshot_id": snapshot_id,
        "findings": sorted(payload, key=lambda item: (-item["risk_score"], item["id"])),
        "risk_summary": risk_summary,
        "posture": posture,
    }
