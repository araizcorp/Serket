"""
builder.py — Constructs the AD attack graph from collected LDAP data.

Each node is an AD object (user / group / computer / domain).
Each directed edge is an exploitable relationship, annotated with:
  - edge type  (MemberOf, Kerberoastable, DCSync, GenericAll, ADCS_ESC1, ...)
  - OPSEC noise level  (low / medium / high)
  - MITRE ATT&CK technique

AraizCorp LLC — Serket
"""
from __future__ import annotations

from typing import Optional
import networkx as nx

# ── OPSEC cost per edge type (lower = quieter) ────────────────────────────────
EDGE_OPSEC: dict[str, tuple[int, str]] = {
    # score, noise label
    "MemberOf":                 (1,  "low"),
    "Kerberoastable":           (2,  "low"),
    "ASREPRoastable":           (2,  "low"),
    "UnconstrainedDelegation":  (2,  "low"),
    "ConstrainedDelegation":    (2,  "low"),
    "ProtocolTransition":       (2,  "low"),
    "RBCD":                     (2,  "low"),
    "HasSIDHistory":            (2,  "low"),
    "DCSync":                   (3,  "low"),
    "Enroll":                   (2,  "low"),
    "ADCS_ESC1":                (2,  "low"),
    "ADCS_ESC2":                (2,  "low"),
    "ADCS_ESC3":                (2,  "low"),
    "ADCS_ESC4":                (4,  "medium"),
    "ADCS_ESC5":                (4,  "medium"),
    "GPOLink":                  (2,  "low"),
    "MAQAbuse":                 (2,  "low"),
    "MAQAbuseObserved":         (2,  "low"),
    "DNSAdmin":                 (2,  "low"),
    "ExchangePermissions":      (2,  "low"),
    "RODCCachedCredential":     (2,  "low"),
    "PreWindows2000Access":     (1,  "low"),
    "Trust":                    (1,  "low"),
    "ForestTrust":              (1,  "low"),
    "NonTransitiveTrust":       (1,  "low"),
    "CanRDP":                   (2,  "low"),
    "CanPSRemote":              (2,  "low"),
    "HasPasswordInDescription": (2,  "low"),
    "AllExtendedRights":        (4,  "medium"),
    "GenericAll":               (4,  "medium"),
    "GenericWrite":             (4,  "medium"),
    "WriteDACL":                (4,  "medium"),
    "WriteOwner":               (4,  "medium"),
    "ForceChangePassword":      (4,  "medium"),
    "AddMember":                (4,  "medium"),
    "AddSelf":                  (4,  "medium"),
    "ShadowCredentials":        (4,  "medium"),
    "WriteRBCD":                (4,  "medium"),
    "AddKeyCredentialLink":     (4,  "medium"),
    "AddAllowedToAct":          (4,  "medium"),
    "WriteSPN":                 (4,  "medium"),
    "WriteAccountRestrictions": (4,  "medium"),
    "Owns":                    (4,  "medium"),
    "AdminTo":                 (2,  "low"),
    "Contains":                (1,  "low"),
    "GPLink":                  (2,  "low"),
    "GetChanges":              (5,  "medium"),
    "GetChangesAll":           (5,  "medium"),
    "GetChangesInFilteredSet": (5,  "medium"),
    "ReadLAPSPassword":        (2,  "low"),
    "ReadGMSAPassword":        (2,  "low"),
}

MITRE_MAP = {
    "Kerberoastable":           {"id": "T1558.003", "name": "Kerberoasting"},
    "ASREPRoastable":           {"id": "T1558.004", "name": "AS-REP Roasting"},
    "UnconstrainedDelegation":  {"id": "T1558.001", "name": "Unconstrained Delegation Abuse"},
    "ConstrainedDelegation":    {"id": "T1558.002", "name": "S4U2Proxy Abuse"},
    "ProtocolTransition":       {"id": "T1558.002", "name": "S4U2Proxy Abuse"},
    "RBCD":                     {"id": "T1558",     "name": "Steal or Forge Kerberos Tickets"},
    "DCSync":                   {"id": "T1003.006", "name": "OS Credential Dumping: DCSync"},
    "ADCS_ESC1":                {"id": "T1649",     "name": "Steal or Forge Authentication Certificates"},
    "ADCS_ESC2":                {"id": "T1649",     "name": "Steal or Forge Authentication Certificates"},
    "ADCS_ESC3":                {"id": "T1649",     "name": "Steal or Forge Authentication Certificates"},
    "ADCS_ESC4":                {"id": "T1649",     "name": "Steal or Forge Authentication Certificates"},
    "ADCS_ESC5":                {"id": "T1649",     "name": "Steal or Forge Authentication Certificates"},
    "GenericAll":               {"id": "T1484.001", "name": "Domain Policy Modification"},
    "WriteDACL":                {"id": "T1222",     "name": "File & Directory Permissions Modification"},
    "WriteOwner":               {"id": "T1222",     "name": "File & Directory Permissions Modification"},
    "ForceChangePassword":      {"id": "T1098",     "name": "Account Manipulation"},
    "AddMember":                {"id": "T1098.001", "name": "Account Manipulation: Add Member"},
    "ShadowCredentials":        {"id": "T1098",     "name": "Account Manipulation"},
    "AddKeyCredentialLink":     {"id": "T1098",     "name": "Account Manipulation"},
    "AddAllowedToAct":          {"id": "T1558",     "name": "Steal or Forge Kerberos Tickets"},
    "WriteSPN":                 {"id": "T1558.003", "name": "Kerberoasting"},
    "WriteAccountRestrictions": {"id": "T1098",     "name": "Account Manipulation"},
    "HasSIDHistory":            {"id": "T1134.005", "name": "Access Token Manipulation: SID-History Injection"},
    "HasPasswordInDescription": {"id": "T1552.001", "name": "Unsecured Credentials: Credentials In Files"},
    "MAQAbuse":                 {"id": "T1136.002", "name": "Create Account: Domain Account"},
    "MAQAbuseObserved":         {"id": "T1136.002", "name": "Create Account: Domain Account"},
    "DNSAdmin":                 {"id": "T1574.002", "name": "Hijack Execution Flow: DLL Side-Loading"},
    "ExchangePermissions":      {"id": "T1222.001", "name": "Windows File and Directory Permissions Modification"},
    "RODCCachedCredential":     {"id": "T1003", "name": "OS Credential Dumping"},
    "PreWindows2000Access":     {"id": "T1087.002", "name": "Account Discovery: Domain Account"},
    "Owns":                    {"id": "T1222.001", "name": "Windows File & Directory Permissions Modification"},
    "ReadLAPSPassword":        {"id": "T1003.001", "name": "OS Credential Dumping: LSA Secrets"},
    "ReadGMSAPassword":        {"id": "T1003.001", "name": "OS Credential Dumping: LSA Secrets"},
}

# Groups whose SID suffix indicates a high-value target
_HIGH_VALUE_RIDS = {
    "500", "502", "512", "516", "518", "519", "520", "521", "525", "571", "572",
    "544", "548", "549", "550", "551",
}

# Built-in group names that are high-value
_HIGH_VALUE_NAMES = {
    "domain admins", "enterprise admins", "schema admins",
    "administrators", "account operators", "backup operators",
    "domain controllers", "read-only domain controllers",
    "print operators", "server operators", "group policy creator owners",
    "protected users", "key admins", "enterprise key admins",
    "dnsadmins", "dns admins", "exchange trusted subsystem",
    "exchange windows permissions", "exchange organization administrators",
    "exchange recipient administrators",
}


def _is_high_value(sid: str, name: str) -> bool:
    rid = sid.rsplit("-", 1)[-1]
    return rid in _HIGH_VALUE_RIDS or name.lower() in _HIGH_VALUE_NAMES


def _add_edge(G: nx.DiGraph, src: str, tgt: str, edge_type: str, **extra):
    score, noise = EDGE_OPSEC.get(edge_type, (5, "medium"))
    mitre = MITRE_MAP.get(edge_type)
    G.add_edge(src, tgt, key=edge_type,
               type=edge_type,
               opsec_score=score,
               noise=noise,
               mitre=mitre,
               **extra)


class ADGraph:
    """Directed attack graph built from an ADData dict."""

    def __init__(self):
        # Parallel permissions between the same two objects must not overwrite
        # each other (for example WriteDACL plus WriteOwner).
        self.G: nx.MultiDiGraph = nx.MultiDiGraph()
        self.sid_name: dict[str, str] = {}
        self.high_value: set[str] = set()

    # ── Public factory ────────────────────────────────────────────────────────

    @classmethod
    def build_from_data(cls, ad_data: dict) -> "ADGraph":
        ag = cls()
        ag.sid_name = ad_data.get("sid_name", {})
        ag._add_nodes(ad_data)
        ag._add_domain_policy_edges(ad_data)
        ag._add_trust_edges(ad_data)
        ag._add_membership_edges(ad_data)
        ag._add_structure_edges(ad_data)
        ag._add_dc_control_edges(ad_data)
        ag._add_user_attack_edges(ad_data)
        ag._add_computer_attack_edges(ad_data)
        ag._add_maq_activity_edges(ad_data)
        ag._add_acl_edges(ad_data)
        ag._add_adcs_edges(ad_data)
        ag._add_sid_history_edges(ad_data)
        ag._add_credential_edges(ad_data)
        return ag

    # ── Node helpers ──────────────────────────────────────────────────────────

    def _add_node(self, sid: str, name: str, node_type: str, **props):
        explicit_high_value = bool(props.pop("high_value", False))
        hv = (
            explicit_high_value
            or _is_high_value(sid, name)
            or node_type == "Domain"
            or props.get("is_dc") is True
        )
        if hv:
            self.high_value.add(sid)
        self.G.add_node(sid,
                        name=name,
                        type=node_type,
                        high_value=hv,
                        **props)

    # ── Nodes ────────────────────────────────────────────────────────────────

    def _add_nodes(self, ad_data: dict):
        domain = ad_data.get("domain", {})
        if domain.get("sid"):
            self._add_node(domain["sid"], domain.get("name", "domain"),
                           "Domain", dn=domain.get("dn", ""),
                           maq=domain.get("maq", 0),
                           password_policy=domain.get("password_policy", {}),
                           lockout_policy=domain.get("lockout_policy", {}),
                           store_cleartext=bool(
                               domain.get("password_policy", {}).get("store_cleartext")
                           ),
                           prewin2000_exposure=domain.get("prewin2000_exposure", False),
                           adminsdholder_drift_count=domain.get("adminsdholder_drift_count", 0),
                           rodc_count=domain.get("rodc_count", 0),
                           rodc_tier0_exposure_count=domain.get("rodc_tier0_exposure_count", 0),
                           operating_system_inventory=domain.get("operating_system_inventory", {}))

        for sid, u in ad_data.get("users", {}).items():
            self._add_node(sid, u["name"], "User",
                           dn=u["dn"],
                           guid=u.get("guid", ""),
                           enabled=u["enabled"],
                           kerberoastable=u["kerberoastable"],
                           asreproastable=u["asreproastable"],
                           unconstrained=u["unconstrained"],
                           constrained=u.get("constrained", False),
                           constrained_kerberos_only=u.get(
                               "constrained_kerberos_only",
                               u.get("constrained", False) and not u.get("protocol_transition", False),
                           ),
                           protocol_transition=u.get("protocol_transition", False),
                           delegation_mode=u.get("delegation_mode", "none"),
                           delegation_targets=u.get("delegation_targets", []),
                           rbcd_trustees=u.get("rbcd_trustees", []),
                           spns=u["spns"],
                           admin_count=u["admin_count"],
                           has_password_hint=u.get("has_password_hint", False),
                           is_gmsa=u.get("is_gmsa", False),
                           gmsa_password_readable=u.get("gmsa_password_readable", False),
                           pwd_last_set=u.get("pwd_last_set"),
                           pwd_age_days=u.get("pwd_age_days"),
                           pwd_never_expires=u.get("pwd_never_expires", False),
                           pwd_not_required=u.get("pwd_not_required", False),
                           reversible_encryption=u.get("reversible_encryption", False),
                           has_key_credential_link=u.get("has_key_credential_link", False),
                           adminsdholder_checked=u.get("adminsdholder_checked", False),
                           adminsdholder_drift=u.get("adminsdholder_drift", False),
                           missing_protected_users=u.get("missing_protected_users", False),
                           protected_user=u.get("protected_user", False),
                           smartcard_required=u.get("smartcard_required", False),
                           not_delegated=u.get("not_delegated", False),
                           use_des_key_only=u.get("use_des_key_only", False),
                           locked_out=u.get("locked_out", False),
                           lockout_time=u.get("lockout_time"),
                           logon_hours_restricted=u.get("logon_hours_restricted", False),
                           user_workstations=u.get("user_workstations", []),
                           primary_group_sid=u.get("primary_group_sid"),
                           assigned_authn_policy=u.get("assigned_authn_policy", ""),
                           authn_policy_assigned=u.get("authn_policy_assigned", False),
                           account_expires=u.get("account_expires"),
                           last_logon=u.get("last_logon"),
                           last_logon_timestamp=u.get("last_logon_timestamp"),
                           last_logon_age_days=u.get("last_logon_age_days"),
                           stale=u.get("stale", False))

        for sid, g in ad_data.get("groups", {}).items():
            self._add_node(sid, g["name"], "Group",
                           dn=g["dn"],
                           guid=g.get("guid", ""),
                           admin_count=g["admin_count"],
                           high_value=g.get("high_value", False),
                           is_dns_admins=g.get("is_dns_admins", False),
                           is_exchange_privileged=g.get("is_exchange_privileged", False),
                           is_protected_users=g.get("is_protected_users", False),
                           is_key_admin=g.get("is_key_admin", False),
                           is_prewin2000_compatible=g.get("is_prewin2000_compatible", False),
                           dangerous_members=g.get("dangerous_members", []),
                           prewin2000_exposure=g.get("prewin2000_exposure", False),
                           adminsdholder_checked=g.get("adminsdholder_checked", False),
                           adminsdholder_drift=g.get("adminsdholder_drift", False))

        for sid, c in ad_data.get("computers", {}).items():
            role = c.get("computer_role", "workstation")
            node_type = {
                "domain_controller": "DomainController",
                "server": "Server",
                "workstation": "Workstation",
            }.get(role, "Workstation")
            self._add_node(sid, c["name"], node_type,
                           dn=c["dn"],
                           guid=c.get("guid", ""),
                           dns=c["dns"],
                           spns=c.get("spns", []),
                           os=c["os"],
                           os_version=c.get("os_version", ""),
                           os_service_pack=c.get("os_service_pack", ""),
                           os_display=c.get("os_display", c.get("os", "Unknown")),
                           ldap_type="Computer",
                           computer_role=role,
                           is_dc=c["is_dc"],
                           unconstrained=c["unconstrained"],
                           constrained=c["constrained"],
                           constrained_kerberos_only=c.get(
                               "constrained_kerberos_only",
                               c.get("constrained", False) and not c.get("protocol_transition", False),
                           ),
                           protocol_transition=c.get("protocol_transition", False),
                           delegation_mode=c.get("delegation_mode", "none"),
                           delegation_targets=c.get("delegation_targets", []),
                           rbcd_trustees=c.get("rbcd_trustees", []),
                           laps_readable=c.get("laps_readable", False),
                           laps_encrypted=c.get("laps_encrypted", False),
                           is_gmsa=c.get("is_gmsa", False),
                           is_rodc=c.get("is_rodc", False),
                           rodc_revealed_users=c.get("rodc_revealed_users", []),
                           rodc_tier0_revealed_users=c.get("rodc_tier0_revealed_users", []),
                           rodc_tier0_exposure=c.get("rodc_tier0_exposure", False),
                           creator_sid=c.get("creator_sid", ""),
                           created=c.get("created"),
                           created_age_days=c.get("created_age_days"),
                           maq_created_by_non_admin=c.get("maq_created_by_non_admin", False),
                           maq_abuse_suspected=c.get("maq_abuse_suspected", False),
                           maq_creator_volume=c.get("maq_creator_volume", 0))

        for object_id, obj in ad_data.get("directory_objects", {}).items():
            self._add_node(
                object_id,
                obj.get("name", object_id),
                obj.get("type", "DirectoryObject"),
                dn=obj.get("dn", ""),
                guid=obj.get("guid", ""),
                parent_dn=obj.get("parent_dn", ""),
            )

        for gpo in ad_data.get("gpos", []):
            self._add_node(
                gpo["id"], gpo.get("name", gpo["id"]), "GPO",
                dn=gpo.get("dn", ""), guid=gpo.get("guid", ""),
                path=gpo.get("path", ""), flags=gpo.get("flags", 0),
                functionality_version=gpo.get("functionality_version", 0),
                version_number=gpo.get("version_number", 0),
                user_settings_enabled=gpo.get("user_settings_enabled", True),
                computer_settings_enabled=gpo.get("computer_settings_enabled", True),
                machine_extensions=gpo.get("machine_extensions", []),
                user_extensions=gpo.get("user_extensions", []),
                gpo_links=gpo.get("links", []), coverage=gpo.get("coverage", "ldap_only"),
                sysvol=gpo.get("sysvol"),
            )

    def _add_domain_policy_edges(self, ad_data: dict):
        """Represent non-zero MachineAccountQuota as an observed policy risk."""
        domain = ad_data.get("domain", {})
        domain_sid = domain.get("sid", "")
        maq = int(domain.get("maq", 0) or 0)
        if maq <= 0 or not domain_sid or domain_sid not in self.G:
            return
        authenticated_users = "S-1-5-11"
        if authenticated_users not in self.G:
            self._add_node(
                authenticated_users,
                "Authenticated Users",
                "SpecialIdentity",
                external=True,
            )
        _add_edge(
            self.G,
            authenticated_users,
            domain_sid,
            "MAQAbuse",
            detail=f"MachineAccountQuota permits up to {maq} computer accounts per principal",
            traversable=False,
            quota=maq,
        )

    def _add_trust_edges(self, ad_data: dict):
        """Represent trust direction and filtering posture without overclaiming risk."""
        domain_sid = ad_data.get("domain", {}).get("sid", "")
        if not domain_sid or domain_sid not in self.G:
            return
        for trust in ad_data.get("trusts", []):
            partner = trust.get("partner", "")
            if not partner:
                continue
            partner_id = trust.get("partner_sid") or f"domain:{partner.casefold()}"
            if partner_id not in self.G:
                self._add_node(
                    partner_id, partner, "ExternalDomain",
                    external=True,
                    netbios=trust.get("partner_netbios", ""),
                    domain_sid=trust.get("partner_sid", ""),
                )
            edge_type = (
                "ForestTrust" if trust.get("is_forest")
                else "NonTransitiveTrust" if not trust.get("is_transitive", True)
                else "Trust"
            )
            detail = (
                f"{trust.get('direction', 'Unknown')} {trust.get('trust_type', 'trust')}; "
                f"SID filtering: {trust.get('sid_filtering_status', 'unknown')}"
            )
            extra = {
                "detail": detail,
                "traversable": True,
                "sid_filtering_risk": trust.get("sid_filtering_risk", False),
                "cross_org": trust.get("is_cross_org", False),
            }
            direction = trust.get("direction")
            if direction in {"Outbound", "Bidirectional"}:
                _add_edge(self.G, domain_sid, partner_id, edge_type, **extra)
            if direction in {"Inbound", "Bidirectional"}:
                _add_edge(self.G, partner_id, domain_sid, edge_type, **extra)

    # ── Membership edges ──────────────────────────────────────────────────────

    def _add_membership_edges(self, ad_data: dict):
        """
        Add MemberOf edges using effective (transitive) membership if available,
        falling back to direct membership. This ensures paths through nested
        groups reach high-value targets correctly.
        """
        group_data = ad_data.get("groups", {})

        def relationship(group_sid: str) -> str:
            group = group_data.get(group_sid, {})
            if group.get("is_dns_admins"):
                return "DNSAdmin"
            if group.get("is_exchange_privileged"):
                return "ExchangePermissions"
            return "MemberOf"

        for sid, u in ad_data.get("users", {}).items():
            # Prefer transitive membership for graph reachability
            groups = u.get("effective_member_of") or u.get("member_of", [])
            for grp_sid in groups:
                if grp_sid in self.G:
                    _add_edge(self.G, sid, grp_sid, relationship(grp_sid))

        for sid, c in ad_data.get("computers", {}).items():
            groups = c.get("effective_member_of") or c.get("member_of", [])
            for grp_sid in groups:
                if grp_sid in self.G:
                    _add_edge(self.G, sid, grp_sid, relationship(grp_sid))

        for sid, g in ad_data.get("groups", {}).items():
            groups = g.get("effective_member_of") or g.get("member_of", [])
            for grp_sid in groups:
                if grp_sid in self.G:
                    _add_edge(self.G, sid, grp_sid, relationship(grp_sid))

        for group_sid, group in group_data.items():
            if not group.get("is_prewin2000_compatible") or group_sid not in self.G:
                continue
            for member_sid in group.get("dangerous_members", []):
                if member_sid not in self.G:
                    self._add_node(
                        member_sid,
                        self.sid_name.get(member_sid, member_sid),
                        "SpecialIdentity",
                        external=True,
                    )
                _add_edge(
                    self.G, member_sid, group_sid, "PreWindows2000Access",
                    detail="Broad principal is a member of Pre-Windows 2000 Compatible Access",
                    traversable=False,
                )

    def _add_structure_edges(self, ad_data: dict):
        """Add OU/container containment and GPO-link relationships."""
        dn_map = {str(k).lower(): v for k, v in ad_data.get("dn_map", {}).items()}
        objects = []
        objects.extend(ad_data.get("users", {}).values())
        objects.extend(ad_data.get("groups", {}).values())
        objects.extend(ad_data.get("computers", {}).values())
        objects.extend(ad_data.get("directory_objects", {}).values())
        objects.extend(ad_data.get("gpos", []))

        for obj in objects:
            child_id = obj.get("sid") or obj.get("id")
            dn = obj.get("dn", "")
            if not child_id or not dn:
                continue
            parent_dn = obj.get("parent_dn") or (
                dn.split(",", 1)[1] if "," in dn else ""
            )
            parent_id = dn_map.get(str(parent_dn).lower())
            if parent_id and parent_id in self.G and child_id in self.G and parent_id != child_id:
                _add_edge(self.G, parent_id, child_id, "Contains")

        for gpo in ad_data.get("gpos", []):
            if gpo.get("id") not in self.G:
                continue
            links = gpo.get("links") or [
                {"target_dn": target_dn, "enabled": True, "enforced": False,
                 "order": index, "options": 0}
                for index, target_dn in enumerate(gpo.get("linked_to", []), start=1)
            ]
            for link in links:
                target_dn = link.get("target_dn", "")
                target_id = dn_map.get(str(target_dn).lower())
                if target_id and target_id in self.G:
                    _add_edge(
                        self.G, gpo["id"], target_id, "GPOLink",
                        detail=(
                            f"GPO '{gpo.get('name', gpo['id'])}' linked to {target_dn} "
                            f"(order {link.get('order', '?')}, "
                            f"{'enforced' if link.get('enforced') else 'not enforced'}, "
                            f"{'enabled' if link.get('enabled', True) else 'disabled'})"
                        ),
                        traversable=bool(link.get("enabled", True)),
                        enabled=bool(link.get("enabled", True)),
                        enforced=bool(link.get("enforced", False)),
                        link_order=link.get("order"),
                        link_options=link.get("options", 0),
                        target_blocks_inheritance=bool(link.get("target_blocks_inheritance", False)),
                    )

    def _add_dc_control_edges(self, ad_data: dict):
        """Project built-in administrative control from Tier-0 groups to DCs."""
        privileged_groups = {
            sid for sid in ad_data.get("groups", {})
            if sid.rsplit("-", 1)[-1] in {"512", "519"}
            or sid == "S-1-5-32-544"
        }
        dc_sids = {
            sid for sid, computer in ad_data.get("computers", {}).items()
            if computer.get("is_dc")
        }
        for group_sid in privileged_groups:
            for dc_sid in dc_sids:
                if group_sid in self.G and dc_sid in self.G:
                    _add_edge(
                        self.G, group_sid, dc_sid, "AdminTo",
                        detail="Built-in administrative control over a domain controller",
                    )

    # ── User attack edges ─────────────────────────────────────────────────────

    def _add_user_attack_edges(self, ad_data: dict):
        domain_sid = ad_data.get("domain", {}).get("sid", "")

        for sid, u in ad_data.get("users", {}).items():
            if not self.G.has_node(sid):
                continue

            if u["kerberoastable"]:
                _add_edge(self.G, sid, sid, "Kerberoastable",
                          detail=f"SPN: {', '.join(u['spns'][:2])}")

            if u["asreproastable"]:
                _add_edge(self.G, sid, sid, "ASREPRoastable")

            if u.get("has_key_credential_link"):
                _add_edge(
                    self.G,
                    sid,
                    sid,
                    "ShadowCredentials",
                    detail="msDS-KeyCredentialLink is populated; validate that every key credential is authorized",
                    traversable=False,
                )

            if u["unconstrained"] and domain_sid and self.G.has_node(domain_sid):
                _add_edge(self.G, sid, domain_sid, "UnconstrainedDelegation",
                          detail="Ticket capture → DCSync or admin impersonation")

            # Constrained delegation on users (S4U2Proxy via msDS-AllowedToDelegateTo)
            kerberos_only = u.get(
                "constrained_kerberos_only",
                u.get("constrained", False) and not u.get("protocol_transition", False),
            )
            if kerberos_only or u.get("protocol_transition"):
                edge_type = (
                    "ProtocolTransition" if u.get("protocol_transition")
                    else "ConstrainedDelegation"
                )
                for target_spn in u.get("delegation_targets", []):
                    _add_edge(self.G, sid, sid, edge_type,
                              detail=f"S4U2Proxy to: {target_spn}")

            # RBCD: principals that can act through this user's resource-based delegation descriptor
            for trustee_sid in u.get("rbcd_trustees", []):
                if trustee_sid in self.G:
                    _add_edge(self.G, trustee_sid, sid, "RBCD",
                              detail="msDS-AllowedToActOnBehalfOfOtherIdentity → impersonate any user")

    # ── Computer attack edges ─────────────────────────────────────────────────

    def _add_computer_attack_edges(self, ad_data: dict):
        domain_sid = ad_data.get("domain", {}).get("sid", "")

        for sid, c in ad_data.get("computers", {}).items():
            if not self.G.has_node(sid):
                continue

            if c["unconstrained"] and not c["is_dc"]:
                if domain_sid and self.G.has_node(domain_sid):
                    _add_edge(self.G, sid, domain_sid, "UnconstrainedDelegation",
                              detail="Capture TGT of any user authenticating to this host")

            edge_type = (
                "ProtocolTransition" if c.get("protocol_transition")
                else "ConstrainedDelegation"
            )
            for target_spn in c.get("delegation_targets", []):
                _add_edge(self.G, sid, sid, edge_type,
                          detail=f"Delegate to: {target_spn}")

            for trustee_sid in c.get("rbcd_trustees", []):
                if trustee_sid in self.G:
                    _add_edge(self.G, trustee_sid, sid, "RBCD",
                              detail="msDS-AllowedToActOnBehalfOfOtherIdentity → impersonate any user")

            if c.get("is_rodc"):
                tier0_revealed = set(c.get("rodc_tier0_revealed_users", []))
                for revealed_sid in c.get("rodc_revealed_users", []):
                    if revealed_sid in self.G:
                        _add_edge(
                            self.G, sid, revealed_sid, "RODCCachedCredential",
                            detail=(
                                "RODC contains a replicated Tier-0 credential"
                                if revealed_sid in tier0_revealed
                                else "RODC contains a replicated credential for this principal"
                            ),
                            traversable=True,
                            tier0_exposure=revealed_sid in tier0_revealed,
                        )

    def _add_maq_activity_edges(self, ad_data: dict):
        """Represent LDAP-observed, thresholded non-admin machine creation."""
        activity = ad_data.get("domain", {}).get("maq_activity", {})
        for computer_sid, computer in ad_data.get("computers", {}).items():
            if not computer.get("maq_abuse_suspected") or computer_sid not in self.G:
                continue
            creator_sid = computer.get("creator_sid", "")
            if not creator_sid:
                continue
            if creator_sid not in self.G:
                self._add_node(
                    creator_sid,
                    self.sid_name.get(creator_sid, creator_sid),
                    "Principal",
                    external=True,
                )
            _add_edge(
                self.G, creator_sid, computer_sid, "MAQAbuseObserved",
                detail=(
                    f"Creator produced {computer.get('maq_creator_volume', 0)} computer "
                    f"accounts within {activity.get('window_days', 30)} days"
                ),
                traversable=True,
                created=computer.get("created"),
                creator_volume=computer.get("maq_creator_volume", 0),
                window_days=activity.get("window_days", 30),
            )

    # ── ACL edges ────────────────────────────────────────────────────────────

    def _add_acl_edges(self, ad_data: dict):
        for ace in ad_data.get("acls", []):
            src_sid  = ace.get("sid", "")
            tgt_sid  = ace.get("target_sid", "")
            etype    = ace.get("edge_type", "")

            if not (src_sid and tgt_sid and etype):
                continue
            if not self.G.has_node(src_sid):
                self._add_node(
                    src_sid,
                    ace.get("sid_name") or self.sid_name.get(src_sid, src_sid),
                    "Principal",
                    external=True,
                )
            if not self.G.has_node(tgt_sid):
                self._add_node(
                    tgt_sid,
                    ace.get("target_name") or self.sid_name.get(tgt_sid, tgt_sid),
                    ace.get("target_type", "DirectoryObject"),
                    dn=ace.get("target_dn", ""),
                )
            if src_sid == tgt_sid:
                continue

            _add_edge(self.G, src_sid, tgt_sid, etype,
                      mitre_override=ace.get("mitre"),
                      mask=ace.get("mask", 0),
                      object_guid=ace.get("object_guid"),
                      inherited=bool(ace.get("ace_flags", 0) & 0x10),
                      traversable=etype not in {
                          "GetChanges", "GetChangesAll",
                          "GetChangesInFilteredSet", "Enroll",
                          "ApplyGroupPolicy",
                      })

    # ── ADCS / ESC1 edges ────────────────────────────────────────────────────

    def _add_adcs_edges(self, ad_data: dict):
        adcs = ad_data.get("adcs", {})

        for ca in adcs.get("cas", []):
            ca_id = ca.get("id") or f"CA:{ca['name']}"
            self._add_node(
                ca_id, ca.get("name", ca_id), "CA",
                dn=ca.get("dn", ""), dns=ca.get("dns", ""),
            )
            self._add_embedded_acl_edges(ca_id, "CA", ca.get("acl_aces", []))

        for tmpl in adcs.get("templates", []):
            tmpl_id = tmpl.get("id") or f"TMPL:{tmpl['name']}"
            esc_flags = tmpl.get("esc", {})
            self._add_node(
                tmpl_id, tmpl["name"], "CertTemplate",
                high_value=bool(tmpl.get("esc1")),
                dn=tmpl["dn"], esc1=bool(tmpl.get("esc1")),
                esc2=bool(esc_flags.get("esc2")), esc3=bool(esc_flags.get("esc3")),
                esc4=bool(esc_flags.get("esc4")), published=tmpl.get("published"),
                adcs_findings=tmpl.get("findings", []), coverage="ldap_only",
            )
            self._add_embedded_acl_edges(
                tmpl_id, "CertTemplate", tmpl.get("acl_aces", [])
            )

            for finding in tmpl.get("findings", []):
                esc = finding.get("id")
                if esc not in {"ESC1", "ESC2", "ESC3", "ESC4"}:
                    continue
                for principal in finding.get("principals", []):
                    if not self.G.has_node(principal):
                        self._add_node(
                            principal,
                            self.sid_name.get(principal, principal),
                            "Principal",
                            external=True,
                        )
                    _add_edge(
                        self.G, principal, tmpl_id, f"ADCS_{esc}",
                        detail=f"{esc} candidate on template {tmpl['name']}",
                        traversable=esc == "ESC1",
                        confidence=finding.get("confidence", "unknown"),
                        published=tmpl.get("published"),
                    )

    def _add_embedded_acl_edges(self, target_id: str, target_type: str, aces: list[dict]):
        for ace in aces:
            source_id = ace.get("sid", "")
            edge_type = ace.get("edge_type", "")
            if not source_id or not edge_type or source_id == target_id:
                continue
            if not self.G.has_node(source_id):
                self._add_node(
                    source_id,
                    ace.get("sid_name") or self.sid_name.get(source_id, source_id),
                    "Principal",
                    external=True,
                )
            _add_edge(
                self.G, source_id, target_id, edge_type,
                mask=ace.get("mask", 0),
                object_guid=ace.get("object_guid"),
                inherited=bool(ace.get("ace_flags", 0) & 0x10),
                traversable=edge_type not in {
                    "GetChanges", "GetChangesAll", "GetChangesInFilteredSet", "Enroll"
                },
                target_type=target_type,
            )

    # ── SID History edges ─────────────────────────────────────────────────────

    def _add_sid_history_edges(self, ad_data: dict):
        for sid, u in ad_data.get("users", {}).items():
            for hist_sid in u.get("sid_history", []):
                if self.G.has_node(hist_sid):
                    _add_edge(self.G, sid, hist_sid, "HasSIDHistory",
                              detail=f"SIDHistory mimics {hist_sid}")

    # ── Credential exposure edges ─────────────────────────────────────────────

    def _add_credential_edges(self, ad_data: dict):
        """
        Add HasPasswordInDescription self-edges for users whose description
        field appears to contain a plaintext credential.
        """
        for sid, u in ad_data.get("users", {}).items():
            if u.get("has_password_hint") and self.G.has_node(sid):
                _add_edge(self.G, sid, sid, "HasPasswordInDescription",
                          detail=f"Credential hint found in description field")

    # ── Accessors ─────────────────────────────────────────────────────────────

    def node_name(self, sid: str) -> str:
        data = self.G.nodes.get(sid, {})
        return data.get("name", sid)

    def stats(self) -> dict:
        nodes     = self.G.nodes(data=True)
        by_type   = {}
        for _, d in nodes:
            t = d.get("type", "Unknown")
            by_type[t] = by_type.get(t, 0) + 1

        return {
            "nodes":      self.G.number_of_nodes(),
            "edges":      self.G.number_of_edges(),
            "by_type":    by_type,
            "high_value": len(self.high_value),
        }
