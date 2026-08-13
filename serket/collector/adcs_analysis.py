"""Evidence-first AD CS classification for Serket v2.1.

The analyzer never treats data that LDAP cannot observe as safe. ESC6-ESC8 are
reported as not_assessed unless a future authorized collector supplies the CA
registry, CA security descriptor, or enrollment endpoint evidence.
"""
from __future__ import annotations

from typing import Any

CLIENT_AUTH_OIDS = {
    "1.3.6.1.5.5.7.3.2",
    "1.3.6.1.4.1.311.20.2.2",
    "1.3.6.1.5.2.3.4",
}
ANY_PURPOSE_OID = "2.5.29.37.0"
ENROLLMENT_AGENT_OID = "1.3.6.1.4.1.311.20.2.1"
DANGEROUS_CONTROL_RIGHTS = {"GenericAll", "GenericWrite", "WriteDACL", "WriteOwner"}
ENROLLEE_SUPPLIES_SUBJECT = 0x00000001
PEND_ALL_REQUESTS = 0x00000002


def _finding(esc: str, status: str, confidence: str, reasons: list[str],
             principals: list[str] | None = None) -> dict[str, Any]:
    return {
        "id": esc,
        "status": status,
        "confidence": confidence,
        "reasons": reasons,
        "principals": sorted(set(principals or [])),
    }


def analyze_template(
    *,
    name_flag: int,
    enrollment_flag: int,
    ekus: list[str],
    ra_signatures: int,
    enroll_sids: list[str],
    acl_aces: list[dict],
    published: bool | None,
) -> dict[str, Any]:
    """Classify ESC1-ESC4 from LDAP-visible template evidence."""
    eku_set = {str(value) for value in ekus if value}
    approval = bool(enrollment_flag & PEND_ALL_REQUESTS)
    signatures = int(ra_signatures or 0)
    issuance_unrestricted = not approval and signatures == 0
    can_enroll = bool(enroll_sids)
    findings: list[dict[str, Any]] = []

    if (
        name_flag & ENROLLEE_SUPPLIES_SUBJECT
        and bool(eku_set & CLIENT_AUTH_OIDS)
        and issuance_unrestricted
        and can_enroll
    ):
        findings.append(_finding(
            "ESC1", "candidate", "high",
            ["enrollee supplies subject", "authentication EKU", "no approval or authorized signatures"],
            enroll_sids,
        ))

    if (
        (ANY_PURPOSE_OID in eku_set or not eku_set)
        and issuance_unrestricted
        and can_enroll
    ):
        findings.append(_finding(
            "ESC2", "candidate", "medium",
            ["Any Purpose EKU or no EKU restriction", "no approval or authorized signatures"],
            enroll_sids,
        ))

    if (
        ENROLLMENT_AGENT_OID in eku_set
        and issuance_unrestricted
        and can_enroll
    ):
        findings.append(_finding(
            "ESC3", "candidate", "high",
            ["Certificate Request Agent EKU", "no approval or authorized signatures"],
            enroll_sids,
        ))

    controllers = [
        str(ace.get("sid"))
        for ace in acl_aces
        if ace.get("sid") and ace.get("edge_type") in DANGEROUS_CONTROL_RIGHTS
    ]
    if controllers:
        findings.append(_finding(
            "ESC4", "candidate", "medium",
            ["principal can modify the certificate template"],
            controllers,
        ))

    return {
        "findings": findings,
        "esc": {f"esc{number}": any(item["id"] == f"ESC{number}" for item in findings)
                for number in range(1, 5)},
        "published": published,
        "issuance": {
            "manager_approval": approval,
            "authorized_signatures": signatures,
        },
    }


def analyze_ca(acl_aces: list[dict], published_templates: list[str]) -> dict[str, Any]:
    """Classify LDAP-visible CA evidence and preserve explicit unknowns."""
    controllers = [
        str(ace.get("sid"))
        for ace in acl_aces
        if ace.get("sid") and ace.get("edge_type") in DANGEROUS_CONTROL_RIGHTS
    ]
    findings: list[dict[str, Any]] = []
    if controllers:
        findings.append(_finding(
            "ESC5", "candidate", "low",
            ["dangerous control over the LDAP enrollment-service object"],
            controllers,
        ))
    findings.extend([
        _finding("ESC6", "not_assessed", "unknown",
                 ["requires CA registry flag EDITF_ATTRIBUTESUBJECTALTNAME2"]),
        _finding("ESC7", "not_assessed", "unknown",
                 ["requires CA service ManageCA/ManageCertificates security evidence"]),
        _finding("ESC8", "not_assessed", "unknown",
                 ["requires authorized discovery of AD CS HTTP enrollment endpoints and relay protections"]),
    ])
    return {
        "findings": findings,
        "published_templates": sorted(set(published_templates)),
        "coverage": {
            "ldap": "collected",
            "ca_registry": "not_collected",
            "ca_service_security": "not_collected",
            "web_enrollment": "not_collected",
        },
    }


def summarize(cas: list[dict], templates: list[dict]) -> dict[str, Any]:
    counts = {f"ESC{number}": 0 for number in range(1, 9)}
    not_assessed = set()
    for item in [*cas, *templates]:
        for finding in item.get("findings", []):
            esc = finding.get("id")
            if esc in counts:
                if finding.get("status") == "not_assessed":
                    not_assessed.add(esc)
                else:
                    counts[esc] += 1
    return {
        "counts": counts,
        "not_assessed": sorted(not_assessed),
        "statement": "Candidates require authorized validation; zero is not proof of absence when coverage is incomplete.",
    }
