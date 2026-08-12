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
    "RBCD":                     (2,  "low"),
    "HasSIDHistory":            (2,  "low"),
    "DCSync":                   (3,  "low"),
    "Enroll":                   (2,  "low"),
    "ADCS_ESC1":                (2,  "low"),
    "GPOLink":                  (2,  "low"),
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
}

MITRE_MAP = {
    "Kerberoastable":           {"id": "T1558.003", "name": "Kerberoasting"},
    "ASREPRoastable":           {"id": "T1558.004", "name": "AS-REP Roasting"},
    "UnconstrainedDelegation":  {"id": "T1558.001", "name": "Unconstrained Delegation Abuse"},
    "ConstrainedDelegation":    {"id": "T1558.002", "name": "S4U2Proxy Abuse"},
    "RBCD":                     {"id": "T1558",     "name": "Steal or Forge Kerberos Tickets"},
    "DCSync":                   {"id": "T1003.006", "name": "OS Credential Dumping: DCSync"},
    "ADCS_ESC1":                {"id": "T1649",     "name": "Steal or Forge Authentication Certificates"},
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
    "Owns":                    {"id": "T1222.001", "name": "Windows File & Directory Permissions Modification"},
}

# Groups whose SID suffix indicates a high-value target
_HIGH_VALUE_RIDS = {
    "500", "502", "512", "516", "518", "519", "520", "521",
    "544", "548", "549", "550", "551",
}

# Built-in group names that are high-value
_HIGH_VALUE_NAMES = {
    "domain admins", "enterprise admins", "schema admins",
    "administrators", "account operators", "backup operators",
    "domain controllers", "read-only domain controllers",
    "print operators", "server operators", "group policy creator owners",
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
        ag._add_membership_edges(ad_data)
        ag._add_structure_edges(ad_data)
        ag._add_dc_control_edges(ad_data)
        ag._add_user_attack_edges(ad_data)
        ag._add_computer_attack_edges(ad_data)
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
                           "Domain", dn=domain.get("dn", ""))

        for sid, u in ad_data.get("users", {}).items():
            self._add_node(sid, u["name"], "User",
                           dn=u["dn"],
                           enabled=u["enabled"],
                           kerberoastable=u["kerberoastable"],
                           asreproastable=u["asreproastable"],
                           unconstrained=u["unconstrained"],
                           constrained=u.get("constrained", False),
                           spns=u["spns"],
                           admin_count=u["admin_count"],
                           has_password_hint=u.get("has_password_hint", False),
                           is_gmsa=u.get("is_gmsa", False),
                           gmsa_password_readable=u.get("gmsa_password_readable", False))

        for sid, g in ad_data.get("groups", {}).items():
            self._add_node(sid, g["name"], "Group",
                           dn=g["dn"],
                           admin_count=g["admin_count"])

        for sid, c in ad_data.get("computers", {}).items():
            role = c.get("computer_role", "workstation")
            node_type = {
                "domain_controller": "DomainController",
                "server": "Server",
                "workstation": "Workstation",
            }.get(role, "Workstation")
            self._add_node(sid, c["name"], node_type,
                           dn=c["dn"],
                           dns=c["dns"],
                           os=c["os"],
                           ldap_type="Computer",
                           computer_role=role,
                           is_dc=c["is_dc"],
                           unconstrained=c["unconstrained"],
                           constrained=c["constrained"],
                           laps_readable=c.get("laps_readable", False),
                           laps_encrypted=c.get("laps_encrypted", False),
                           is_gmsa=c.get("is_gmsa", False))

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
                path=gpo.get("path", ""),
            )

    # ── Membership edges ──────────────────────────────────────────────────────

    def _add_membership_edges(self, ad_data: dict):
        """
        Add MemberOf edges using effective (transitive) membership if available,
        falling back to direct membership. This ensures paths through nested
        groups reach high-value targets correctly.
        """
        for sid, u in ad_data.get("users", {}).items():
            # Prefer transitive membership for graph reachability
            groups = u.get("effective_member_of") or u.get("member_of", [])
            for grp_sid in groups:
                if grp_sid in self.G:
                    _add_edge(self.G, sid, grp_sid, "MemberOf")

        for sid, c in ad_data.get("computers", {}).items():
            groups = c.get("effective_member_of") or c.get("member_of", [])
            for grp_sid in groups:
                if grp_sid in self.G:
                    _add_edge(self.G, sid, grp_sid, "MemberOf")

        for sid, g in ad_data.get("groups", {}).items():
            groups = g.get("effective_member_of") or g.get("member_of", [])
            for grp_sid in groups:
                if grp_sid in self.G:
                    _add_edge(self.G, sid, grp_sid, "MemberOf")

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
            for target_dn in gpo.get("linked_to", []):
                target_id = dn_map.get(str(target_dn).lower())
                if target_id and target_id in self.G:
                    _add_edge(self.G, gpo["id"], target_id, "GPLink")

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

            if u["unconstrained"] and domain_sid and self.G.has_node(domain_sid):
                _add_edge(self.G, sid, domain_sid, "UnconstrainedDelegation",
                          detail="Ticket capture → DCSync or admin impersonation")

            # Constrained delegation on users (S4U2Proxy via msDS-AllowedToDelegateTo)
            if u.get("constrained"):
                for target_spn in u.get("delegation_targets", []):
                    _add_edge(self.G, sid, sid, "ConstrainedDelegation",
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

            for target_spn in c.get("delegation_targets", []):
                _add_edge(self.G, sid, sid, "ConstrainedDelegation",
                          detail=f"Delegate to: {target_spn}")

            for trustee_sid in c.get("rbcd_trustees", []):
                if trustee_sid in self.G:
                    _add_edge(self.G, trustee_sid, sid, "RBCD",
                              detail="msDS-AllowedToActOnBehalfOfOtherIdentity → impersonate any user")

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
            self._add_node(
                tmpl_id, tmpl["name"], "CertTemplate",
                high_value=bool(tmpl.get("esc1")),
                dn=tmpl["dn"], esc1=bool(tmpl.get("esc1")),
            )
            self._add_embedded_acl_edges(
                tmpl_id, "CertTemplate", tmpl.get("acl_aces", [])
            )

            if tmpl.get("esc1"):
                for enroll_sid in tmpl.get("enroll_sids", []):
                    if not self.G.has_node(enroll_sid):
                        self._add_node(
                            enroll_sid,
                            self.sid_name.get(enroll_sid, enroll_sid),
                            "Principal",
                            external=True,
                        )
                    _add_edge(self.G, enroll_sid, tmpl_id, "ADCS_ESC1",
                              detail=f"ESC1: enroll as any principal via {tmpl['name']}")

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
