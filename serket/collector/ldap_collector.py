"""
ldap_collector.py — Stealthy LDAP-only Active Directory enumerator.

Collects users, groups, computers, ACLs, ADCS templates, GPO links, and
domain trusts using a single LDAP session — no SMB, no NetWksta, no noise.

AraizCorp LLC — Serket
"""
from __future__ import annotations

import re
from datetime import datetime, timezone
import struct
import time
from typing import Optional

from ldap3 import (
    ALL, KERBEROS, NTLM, SIMPLE, SUBTREE, BASE,
    Connection, Server,
)
from ldap3.core.exceptions import LDAPBindError, LDAPException
from ldap3.protocol.microsoft import security_descriptor_control

from serket.collector.acl_parser import (
    parse_security_descriptor, parse_sid, WELL_KNOWN_SIDS,
)


# ── UAC flag masks ────────────────────────────────────────────────────────────
UAC_ACCOUNTDISABLE              = 0x00000002
UAC_DONT_REQ_PREAUTH            = 0x00400000
UAC_TRUSTED_FOR_DELEGATION      = 0x00080000   # Unconstrained
UAC_TRUSTED_TO_AUTH_FOR_DELEGATION = 0x01000000  # Constrained (S4U2Proxy)
UAC_NOT_DELEGATED               = 0x00100000
UAC_SERVER_TRUST                = 0x00002000   # Domain Controller

# ── ADCS ESC1 flags ───────────────────────────────────────────────────────────
ENROLLEE_SUPPLIES_SUBJECT       = 0x00000001   # msPKI-Certificate-Name-Flag
PEND_ALL_REQUESTS               = 0x00000002   # msPKI-Enrollment-Flag (manager approval)
CLIENT_AUTH_OID                 = "1.3.6.1.5.5.7.3.2"
SMARTCARD_LOGON_OID             = "1.3.6.1.4.1.311.20.2.2"

# ── Well-known high-value RID suffixes ────────────────────────────────────────
HIGH_VALUE_RIDS = {
    "500": "Administrator",
    "502": "krbtgt",
    "512": "Domain Admins",
    "516": "Domain Controllers",
    "518": "Schema Admins",
    "519": "Enterprise Admins",
    "520": "Group Policy Creator Owners",
    "521": "Read-Only Domain Controllers",
    "553": "RAS and IAS Servers",
}

# ── Objects whose ACLs we always collect ─────────────────────────────────────
_ACL_TARGET_FILTERS = [
    ("(&(objectClass=group)(adminCount=1))",  SUBTREE),   # protected groups
    ("(objectClass=domain)",                   BASE),      # domain root (DCSync)
    ("(cn=AdminSDHolder)",                     SUBTREE),   # AdminSDHolder template
]

# ── Password-in-description heuristic ────────────────────────────────────────
# Matches patterns like: "password=Abc123", "pwd: secret", "cred: P@ss"
_PASSWD_RE = re.compile(
    r'(?:pass(?:word|wd)?|pwd|cred(?:ential)?|secret|key|auth)\s*[=:]\s*\S+'
    r'|(?:pass(?:word|wd)?|pwd)\s+[A-Za-z0-9@#$!%^&*()_+\-=\[\]{};\':"\\|,.<>/?`~]{6,}',
    re.IGNORECASE,
)


def _has_password_hint(description: str) -> bool:
    return bool(_PASSWD_RE.search(description)) if description else False


def _first(val, default=None):
    """Return the first value for LDAP attributes represented as a list."""
    if isinstance(val, (list, tuple)):
        return val[0] if val else default
    return default if val is None else val


def _as_list(val) -> list:
    if val is None:
        return []
    if isinstance(val, list):
        return val
    return [val]


def _str(val) -> str:
    value = _first(val, "")
    return "" if value is None else str(value)


def _int(val, default: int = 0) -> int:
    """Normalize LDAP integer attributes returned as scalars or one-item lists."""
    value = _first(val, default)
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


class LDAPCollector:
    """
    Single-session, rate-limited, LDAP-only AD enumerator.

    All collection methods are QUIET (no SMB, no Kerberos roasting,
    no port scanning). The only traffic generated is standard LDAP
    paged searches against the DC.
    """

    def __init__(
        self,
        dc_host:    str,
        domain:     str,
        username:   str,
        password:   Optional[str] = None,
        hashes:     Optional[str] = None,
        kerberos:   bool = False,
        use_ldaps:  bool = False,
        rate_limit: float = 0.08,
    ):
        self.dc_host    = dc_host
        self.domain     = domain
        self.username   = username
        self.password   = password
        self.hashes     = hashes
        self.kerberos   = kerberos
        self.use_ldaps  = use_ldaps
        self.rate_limit = rate_limit

        self.conn:      Optional[Connection] = None
        self.base_dn:   str = ""
        self.config_dn: str = ""
        self.domain_sid: str = ""

        self._active_stage = "Connection"
        self._telemetry = {
            "profile": "low-impact",
            "transport": "LDAPS" if use_ldaps else "LDAP",
            "rate_limit_ms": round(rate_limit * 1000, 2),
            "page_size": 500,
            "searches": 0,
            "pages": 0,
            "entries": 0,
            "started_at": None,
            "completed_at": None,
            "duration_ms": 0,
            "skipped_schema_attributes": [],
            "stages": {},
        }

        self._dn_map:   dict[str, str] = {}   # lower(DN) → SID
        self._sid_name: dict[str, str] = {}   # SID → display name

    # ── Connection ────────────────────────────────────────────────────────────

    def connect(self) -> None:
        """Establish and bind the LDAP connection."""
        port   = 636 if self.use_ldaps else 389
        server = Server(self.dc_host, port=port, use_ssl=self.use_ldaps, get_info=ALL)

        # AD schema extensions such as legacy or Windows LAPS are not present
        # in every domain. Let the DC decide which requested attributes exist
        # instead of having ldap3 reject an optional attribute client-side.
        connection_options = {"check_names": False, "auto_bind": True}

        if self.kerberos:
            self.conn = Connection(
                server,
                authentication=KERBEROS,
                **connection_options,
            )
        elif self.hashes:
            lm, nt  = self._split_hash(self.hashes)
            self.conn = Connection(
                server,
                user=f"{self.domain}\\{self.username}",
                password=f"{lm}:{nt}",
                authentication=NTLM,
                **connection_options,
            )
        else:
            self.conn = Connection(
                server,
                user=f"{self.domain}\\{self.username}",
                password=self.password or "",
                authentication=NTLM,
                **connection_options,
            )

        info = self.conn.server.info
        self.base_dn   = _str(info.other.get("defaultNamingContext"))
        self.config_dn = _str(info.other.get("configurationNamingContext"))

        # Seed sid_name with well-known SIDs so ACE resolution works out of the box
        self._sid_name.update(WELL_KNOWN_SIDS)

    @staticmethod
    def _split_hash(hashes: str) -> tuple[str, str]:
        blank = "aad3b435b51404eeaad3b435b51404ee"
        if ":" in hashes:
            lm, nt = hashes.split(":", 1)
            return lm or blank, nt
        return blank, hashes

    # ── LDAP search helpers ───────────────────────────────────────────────────

    def _supported_attributes(self, attributes: list[str]) -> list[str]:
        """Return only attributes advertised by the connected DC schema.

        LAPS, gMSA, RBCD, and other AD features extend the directory schema.
        A collector must not abort merely because a particular extension is
        absent. If schema metadata is unavailable, the request is left intact
        and the DC remains authoritative.
        """
        try:
            attribute_types = self.conn.server.schema.attribute_types
        except AttributeError:
            return list(attributes)

        if not attribute_types:
            return list(attributes)

        known = {str(name).casefold() for name in attribute_types}
        supported: list[str] = []
        skipped: list[str] = []
        for attribute in attributes:
            base_attribute = attribute.split(";", 1)[0]
            if (
                base_attribute in {"*", "+", "1.1"}
                or base_attribute.casefold() in known
            ):
                supported.append(attribute)
            else:
                skipped.append(attribute)

        recorded = self._telemetry["skipped_schema_attributes"]
        for attribute in skipped:
            if attribute not in recorded:
                recorded.append(attribute)

        return supported or ["1.1"]

    def _search(
        self,
        base: str,
        ldap_filter: str,
        attributes: list[str],
        scope=SUBTREE,
        controls=None,
    ) -> list[dict]:
        """Paged LDAP search with configurable rate-limit between pages."""
        attributes = self._supported_attributes(attributes)
        results: list[dict] = []
        cookie  = None
        stage = self._telemetry["stages"].setdefault(
            self._active_stage,
            {"searches": 0, "pages": 0, "entries": 0},
        )
        self._telemetry["searches"] += 1
        stage["searches"] += 1

        while True:
            time.sleep(self.rate_limit)
            self._telemetry["pages"] += 1
            stage["pages"] += 1
            self.conn.search(
                search_base=base,
                search_filter=ldap_filter,
                search_scope=scope,
                attributes=attributes,
                paged_size=500,
                paged_cookie=cookie,
                controls=controls,
            )
            page_entries = 0
            for entry in self.conn.response:
                if entry.get("type") == "searchResEntry":
                    results.append(entry)
                    page_entries += 1
            self._telemetry["entries"] += page_entries
            stage["entries"] += page_entries
            try:
                cookie = (
                    self.conn.result["controls"]["1.2.840.113556.1.4.319"]["value"]["cookie"]
                )
                if not cookie:
                    break
            except (KeyError, TypeError):
                break

        return results

    def _acl_search(self, base: str, ldap_filter: str, scope=SUBTREE) -> list[dict]:
        """Search with SD_FLAGS control to retrieve DACL-only security descriptors."""
        sd_ctrl = security_descriptor_control(sdflags=0x04)
        return self._search(
            base, ldap_filter,
            ["nTSecurityDescriptor", "distinguishedName", "objectSid"],
            scope, sd_ctrl,
        )

    # ── Domain info ───────────────────────────────────────────────────────────

    def get_domain_info(self) -> dict:
        """Collect domain-level properties (SID, policies, functional level)."""
        entries = self._search(
            self.base_dn,
            "(objectClass=domain)",
            ["objectSid", "distinguishedName", "minPwdLength",
             "lockoutThreshold", "ms-DS-MachineAccountQuota"],
            scope=BASE,
        )
        if not entries:
            return {}

        attrs = entries[0]["attributes"]
        raw_sid = _first(attrs.get("objectSid"))
        self.domain_sid = (
            parse_sid(raw_sid) if isinstance(raw_sid, bytes) else _str(raw_sid)
        )

        result = {
            "name":              self.domain,
            "dn":                self.base_dn,
            "sid":               self.domain_sid,
            "min_pwd_length":    _int(attrs.get("minPwdLength")),
            "lockout_threshold": _int(attrs.get("lockoutThreshold")),
            "maq":               _int(attrs.get("ms-DS-MachineAccountQuota"), 10),
        }
        self._sid_name[self.domain_sid] = self.domain
        return result

    # ── Users ─────────────────────────────────────────────────────────────────

    def collect_users(self) -> dict[str, dict]:
        """Enumerate all user accounts and detect kerberoastable / ASREPRoastable."""
        entries = self._search(
            self.base_dn,
            "(&(objectClass=user)(!(objectClass=computer))(!(objectClass=msDS-GroupManagedServiceAccount)))",
            [
                "samAccountName", "userPrincipalName", "distinguishedName",
                "objectSid", "memberOf", "userAccountControl",
                "servicePrincipalName", "adminCount", "description",
                "mail", "pwdLastSet", "lastLogon",
                "msDS-AllowedToActOnBehalfOfOtherIdentity", "msDS-AllowedToDelegateTo",
                "sIDHistory",
            ],
        )

        users: dict[str, dict] = {}
        for entry in entries:
            attrs = entry["attributes"]
            raw_sid = _first(attrs.get("objectSid"))
            sid = parse_sid(raw_sid) if isinstance(raw_sid, bytes) else _str(raw_sid)
            if not sid:
                continue

            sam      = _str(attrs.get("samAccountName"))
            dn       = entry["dn"]
            uac      = _int(attrs.get("userAccountControl"))
            spns     = _as_list(attrs.get("servicePrincipalName"))
            members  = _as_list(attrs.get("memberOf"))
            enabled  = not bool(uac & UAC_ACCOUNTDISABLE)

            # RBCD trustees on this user (who can impersonate TO this account)
            rbcd_raw = _first(attrs.get("msDS-AllowedToActOnBehalfOfOtherIdentity"))
            rbcd_trustees = []
            if isinstance(rbcd_raw, bytes):
                for ace in parse_security_descriptor(rbcd_raw):
                    if ace.get("sid"):
                        rbcd_trustees.append(ace["sid"])

            # sIDHistory — token can impersonate previous domain identity
            sid_hist = []
            for raw in _as_list(attrs.get("sIDHistory")):
                if isinstance(raw, bytes):
                    s = parse_sid(raw)
                    if s:
                        sid_hist.append(s)

            description = _str(attrs.get("description"))

            users[sid] = {
                "sid":                    sid,
                "name":                   sam,
                "upn":                    _str(attrs.get("userPrincipalName")),
                "dn":                     dn,
                "uac":                    uac,
                "spns":                   spns,
                "member_of_dns":          members,
                "admin_count":            _int(attrs.get("adminCount")),
                "enabled":                enabled,
                "kerberoastable":         enabled and bool(spns) and not sam.endswith("$"),
                "asreproastable":         bool(uac & UAC_DONT_REQ_PREAUTH),
                "unconstrained":          bool(uac & UAC_TRUSTED_FOR_DELEGATION),
                "constrained":            bool(uac & UAC_TRUSTED_TO_AUTH_FOR_DELEGATION),
                "delegation_targets":     _as_list(attrs.get("msDS-AllowedToDelegateTo")),
                "rbcd_trustees":          rbcd_trustees,
                "sid_history":            sid_hist,
                "description":            description,
                "has_password_hint":      _has_password_hint(description),
                "mail":                   _str(attrs.get("mail")),
            }
            self._dn_map[dn.lower()]   = sid
            self._sid_name[sid]        = sam

        return users

    def collect_gmsa(self) -> dict[str, dict]:
        """
        Enumerate group Managed Service Accounts with a dedicated object-class
        query. The managed password blob is never persisted; only readability
        is recorded for the audit finding.
        """
        entries = self._search(
            self.base_dn,
            "(objectClass=msDS-GroupManagedServiceAccount)",
            [
                "samAccountName", "userPrincipalName", "distinguishedName",
                "objectSid", "memberOf", "userAccountControl",
                "servicePrincipalName", "adminCount",
                "msDS-ManagedPassword", "msDS-GroupMSAMembership",
                "msDS-AllowedToActOnBehalfOfOtherIdentity", "msDS-AllowedToDelegateTo",
            ],
        )

        accounts: dict[str, dict] = {}
        for entry in entries:
            attrs = entry["attributes"]
            raw_sid = _first(attrs.get("objectSid"))
            sid = parse_sid(raw_sid) if isinstance(raw_sid, bytes) else _str(raw_sid)
            if not sid:
                continue

            sam = _str(attrs.get("samAccountName"))
            dn = entry["dn"]
            uac = _int(attrs.get("userAccountControl"))

            rbcd_trustees = []
            rbcd_raw = _first(attrs.get("msDS-AllowedToActOnBehalfOfOtherIdentity"))
            if isinstance(rbcd_raw, bytes):
                for ace in parse_security_descriptor(rbcd_raw):
                    if ace.get("sid"):
                        rbcd_trustees.append(ace["sid"])

            accounts[sid] = {
                "sid": sid,
                "name": sam,
                "upn": _str(attrs.get("userPrincipalName")),
                "dn": dn,
                "uac": uac,
                "spns": _as_list(attrs.get("servicePrincipalName")),
                "member_of_dns": _as_list(attrs.get("memberOf")),
                "admin_count": _int(attrs.get("adminCount")),
                "enabled": not bool(uac & UAC_ACCOUNTDISABLE),
                # gMSA passwords are high-entropy and should not be treated as
                # ordinary Kerberoast targets merely because an SPN exists.
                "kerberoastable": False,
                "asreproastable": False,
                "unconstrained": bool(uac & UAC_TRUSTED_FOR_DELEGATION),
                "constrained": bool(uac & UAC_TRUSTED_TO_AUTH_FOR_DELEGATION),
                "delegation_targets": _as_list(attrs.get("msDS-AllowedToDelegateTo")),
                "rbcd_trustees": rbcd_trustees,
                "sid_history": [],
                "description": "",
                "has_password_hint": False,
                "mail": "",
                "is_gmsa": True,
                "gmsa_password_readable": bool(attrs.get("msDS-ManagedPassword")),
            }
            self._dn_map[dn.lower()] = sid
            self._sid_name[sid] = sam

        return accounts

    # ── Groups ────────────────────────────────────────────────────────────────

    def collect_groups(self) -> dict[str, dict]:
        """Enumerate all security groups, detect high-value ones."""
        entries = self._search(
            self.base_dn,
            "(objectClass=group)",
            [
                "samAccountName", "distinguishedName", "objectSid",
                "member", "memberOf", "adminCount", "description", "groupType",
            ],
        )

        groups: dict[str, dict] = {}
        for entry in entries:
            attrs   = entry["attributes"]
            raw_sid = _first(attrs.get("objectSid"))
            sid = parse_sid(raw_sid) if isinstance(raw_sid, bytes) else _str(raw_sid)
            if not sid:
                continue

            sam = _str(attrs.get("samAccountName"))
            dn  = entry["dn"]

            rid        = sid.rsplit("-", 1)[-1]
            high_value = rid in HIGH_VALUE_RIDS

            groups[sid] = {
                "sid":          sid,
                "name":         sam,
                "dn":           dn,
                "member_dns":   _as_list(attrs.get("member")),
                "member_of_dns": _as_list(attrs.get("memberOf")),
                "admin_count":  _int(attrs.get("adminCount")),
                "high_value":   high_value,
                "description":  _str(attrs.get("description")),
            }
            self._dn_map[dn.lower()] = sid
            self._sid_name[sid]      = sam

        return groups

    # ── Computers ─────────────────────────────────────────────────────────────

    def collect_computers(self) -> dict[str, dict]:
        """Enumerate computers, delegation, and legacy or modern LAPS."""
        entries = self._search(
            self.base_dn,
            "(objectClass=computer)",
            [
                "samAccountName", "dNSHostName", "distinguishedName",
                "objectSid", "userAccountControl", "operatingSystem",
                "memberOf", "msDS-AllowedToDelegateTo",
                "msDS-AllowedToActOnBehalfOfOtherIdentity",
                # Legacy Microsoft LAPS and modern Windows LAPS. Values are
                # returned only when the bound identity has read permission.
                "ms-Mcs-AdmPwd", "ms-Mcs-AdmPwdExpirationTime",
                "msLAPS-Password", "msLAPS-EncryptedPassword",
                "msLAPS-PasswordExpirationTime",
            ],
        )

        computers: dict[str, dict] = {}
        for entry in entries:
            attrs   = entry["attributes"]
            raw_sid = _first(attrs.get("objectSid"))
            sid = parse_sid(raw_sid) if isinstance(raw_sid, bytes) else _str(raw_sid)
            if not sid:
                continue

            sam = _str(attrs.get("samAccountName"))
            dn  = entry["dn"]
            uac = _int(attrs.get("userAccountControl"))

            is_dc         = bool(uac & UAC_SERVER_TRUST)
            unconstrained = bool(uac & UAC_TRUSTED_FOR_DELEGATION)
            constrained   = bool(uac & UAC_TRUSTED_TO_AUTH_FOR_DELEGATION)

            rbcd_raw = _first(attrs.get("msDS-AllowedToActOnBehalfOfOtherIdentity"))
            rbcd_trustees = []
            if isinstance(rbcd_raw, bytes):
                for ace in parse_security_descriptor(rbcd_raw):
                    if ace.get("sid"):
                        rbcd_trustees.append(ace["sid"])

            # Prefer modern Windows LAPS plaintext when readable, then
            # legacy Microsoft LAPS. Encrypted blobs are not persisted.
            legacy_laps_pwd = _str(attrs.get("ms-Mcs-AdmPwd"))
            windows_laps_pwd = _str(attrs.get("msLAPS-Password"))
            laps_pwd = windows_laps_pwd or legacy_laps_pwd
            laps_exp = _str(
                attrs.get("msLAPS-PasswordExpirationTime")
                or attrs.get("ms-Mcs-AdmPwdExpirationTime")
            )
            laps_scheme = (
                "Windows LAPS" if windows_laps_pwd
                else "Legacy LAPS" if legacy_laps_pwd
                else ""
            )

            computers[sid] = {
                "sid":                  sid,
                "name":                 sam,
                "dns":                  _str(attrs.get("dNSHostName")),
                "dn":                   dn,
                "uac":                  uac,
                "os":                   _str(attrs.get("operatingSystem")),
                "member_of_dns":        _as_list(attrs.get("memberOf")),
                "is_dc":                is_dc,
                "unconstrained":        unconstrained,
                "constrained":          constrained,
                "delegation_targets":   _as_list(attrs.get("msDS-AllowedToDelegateTo")),
                "rbcd_trustees":        rbcd_trustees,
                # LAPS
                "laps_readable":        bool(laps_pwd),
                "laps_password":        laps_pwd,
                "laps_expiry":          laps_exp,
                "laps_scheme":          laps_scheme,
                "laps_encrypted":       bool(attrs.get("msLAPS-EncryptedPassword")),
            }
            self._dn_map[dn.lower()] = sid
            self._sid_name[sid]      = sam

        return computers

    # ── ACLs on key objects ───────────────────────────────────────────────────

    def collect_acls(self) -> list[dict]:
        """
        Retrieve DACLs for the domain root and all adminCount=1 objects.
        Returns raw ACE records with target DN resolved.
        """
        all_aces: list[dict] = []
        sd_ctrl  = security_descriptor_control(sdflags=0x04)

        for ldap_filter, scope in _ACL_TARGET_FILTERS:
            entries = self._search(
                self.base_dn, ldap_filter,
                ["nTSecurityDescriptor", "distinguishedName", "objectSid", "samAccountName"],
                scope, sd_ctrl,
            )
            for entry in entries:
                attrs   = entry["attributes"]
                raw_sd  = _first(attrs.get("nTSecurityDescriptor"))
                tgt_dn  = entry["dn"]
                raw_sid = _first(attrs.get("objectSid"))
                tgt_sid = parse_sid(raw_sid) if isinstance(raw_sid, bytes) else _str(raw_sid)

                if not isinstance(raw_sd, bytes):
                    continue

                for ace in parse_security_descriptor(raw_sd):
                    all_aces.append({
                        **ace,
                        "target_dn":  tgt_dn,
                        "target_sid": tgt_sid,
                    })

        return all_aces

    # ── ADCS templates ────────────────────────────────────────────────────────

    def collect_adcs(self) -> dict:
        """
        Enumerate Certificate Authority services and certificate templates.
        Detects ESC1 (enrolleeSuppliesSubject + clientAuth EKU).

        Bug fixed (§2.1): CAs reside in CN=Enrollment Services, NOT in
        CN=Certificate Templates. The template search now uses the correct
        objectClass filter (pKICertificateTemplate, not pKIEnrollmentService).
        """
        if not self.config_dn:
            return {"cas": [], "templates": []}

        pk_base  = f"CN=Public Key Services,CN=Services,{self.config_dn}"
        # CAs live here, not in the Certificate Templates container
        ca_base  = f"CN=Enrollment Services,{pk_base}"
        tmpl_base = f"CN=Certificate Templates,{pk_base}"
        sd_ctrl  = security_descriptor_control(sdflags=0x04)

        # Certificate Authorities (correct base: Enrollment Services)
        ca_entries = self._search(
            ca_base,
            "(objectClass=pKIEnrollmentService)",
            ["cn", "distinguishedName", "dNSHostName", "cACertificateDN"],
        )
        cas = [
            {
                "name": _str(e["attributes"].get("cn")),
                "dn":   e["dn"],
                "dns":  _str(e["attributes"].get("dNSHostName")),
            }
            for e in ca_entries
        ]

        # Certificate templates (correct filter: pKICertificateTemplate)
        tmpl_entries = self._search(
            tmpl_base,
            "(objectClass=pKICertificateTemplate)",
            [
                "cn", "distinguishedName",
                "msPKI-Certificate-Name-Flag", "msPKI-Enrollment-Flag",
                "pKIExtendedKeyUsage", "msPKI-RA-Signature",
                "nTSecurityDescriptor",
            ],
            controls=sd_ctrl,
        )

        templates = []
        for entry in tmpl_entries:
            attrs   = entry["attributes"]
            name_flag  = _int(attrs.get("msPKI-Certificate-Name-Flag"))
            enroll_flag = _int(attrs.get("msPKI-Enrollment-Flag"))
            ekus       = _as_list(attrs.get("pKIExtendedKeyUsage"))
            ra_sigs    = _int(attrs.get("msPKI-RA-Signature"))

            # ESC1: enrolleeSuppliesSubject + clientAuth EKU + no manager approval
            esc1 = (
                bool(name_flag & ENROLLEE_SUPPLIES_SUBJECT) and
                (CLIENT_AUTH_OID in ekus or SMARTCARD_LOGON_OID in ekus) and
                not bool(enroll_flag & PEND_ALL_REQUESTS) and
                ra_sigs == 0
            )

            # Parse enrollment ACL
            raw_sd = _first(attrs.get("nTSecurityDescriptor"))
            enroll_aces = []
            if isinstance(raw_sd, bytes):
                for ace in parse_security_descriptor(raw_sd):
                    if ace.get("edge_type") in ("Enroll", "AllExtendedRights", "GenericAll"):
                        enroll_aces.append(ace["sid"])

            templates.append({
                "name":         _str(attrs.get("cn")),
                "dn":           entry["dn"],
                "esc1":         esc1,
                "ekus":         ekus,
                "enroll_sids":  enroll_aces,
            })

        return {"cas": cas, "templates": templates}

    # ── GPO links ─────────────────────────────────────────────────────────────

    def collect_gpos(self) -> list[dict]:
        """Collect GPO objects and their OU links."""
        gpo_entries = self._search(
            self.base_dn,
            "(objectClass=groupPolicyContainer)",
            ["displayName", "distinguishedName", "objectGUID", "gPCFileSysPath"],
        )
        gpos = {
            _str(e["attributes"].get("objectGUID")): {
                "name":     _str(e["attributes"].get("displayName")),
                "dn":       e["dn"],
                "guid":     _str(e["attributes"].get("objectGUID")),
                "path":     _str(e["attributes"].get("gPCFileSysPath")),
                "linked_to": [],
            }
            for e in gpo_entries
        }

        # Collect OU gPLink references
        ou_entries = self._search(
            self.base_dn,
            "(|(objectClass=organizationalUnit)(objectClass=domain))",
            ["distinguishedName", "gPLink"],
        )
        for entry in ou_entries:
            gp_link = _str(entry["attributes"].get("gPLink"))
            if not gp_link:
                continue
            for guid_match in re.finditer(r"\{([0-9A-Fa-f\-]+)\}", gp_link):
                guid = guid_match.group(1).lower()
                if guid in gpos:
                    gpos[guid]["linked_to"].append(entry["dn"])

        return list(gpos.values())

    # ── Trusts ────────────────────────────────────────────────────────────────

    def collect_trusts(self) -> list[dict]:
        """Enumerate domain trust relationships."""
        entries = self._search(
            self.base_dn,
            "(objectClass=trustedDomain)",
            ["trustPartner", "trustDirection", "trustType", "trustAttributes"],
        )
        directions = {1: "Inbound", 2: "Outbound", 3: "Bidirectional"}
        return [
            {
                "partner":    _str(e["attributes"].get("trustPartner")),
                "direction":  directions.get(_int(e["attributes"].get("trustDirection")), "Unknown"),
                "trust_type": _int(e["attributes"].get("trustType")),
                "attributes": _int(e["attributes"].get("trustAttributes")),
            }
            for e in entries
        ]

    # ── Transitive membership resolution ──────────────────────────────────────

    @staticmethod
    def _resolve_transitive_membership(
        users: dict, groups: dict, computers: dict
    ) -> None:
        """
        BFS over group memberships to compute effective (transitive) group set.

        Adds effective_member_of to each user, group, and computer object.
        This is essential for detecting DA-reachable paths through nested groups.

        Modifies objects in-place.
        """
        # Pre-build parent map for groups: group_sid → [parent_sids]
        group_parents: dict[str, list[str]] = {
            sid: g.get("member_of", []) for sid, g in groups.items()
        }

        def _all_groups(direct: list[str]) -> list[str]:
            visited: set[str] = set()
            queue = list(direct)
            while queue:
                gsid = queue.pop()
                if gsid in visited:
                    continue
                visited.add(gsid)
                for parent in group_parents.get(gsid, []):
                    if parent not in visited:
                        queue.append(parent)
            return list(visited)

        for u in users.values():
            u["effective_member_of"] = _all_groups(u.get("member_of", []))

        for c in computers.values():
            c["effective_member_of"] = _all_groups(c.get("member_of", []))

        for g in groups.values():
            g["effective_member_of"] = _all_groups(g.get("member_of", []))

    # ── Orchestrator ─────────────────────────────────────────────────────────

    def collect_all(self, progress_cb=None) -> dict:
        """
        Run the full collection pipeline and return a structured ADData dict.

        progress_cb: optional callable(stage: str) for progress display.
        """
        started = time.perf_counter()
        self._telemetry["started_at"] = datetime.now(timezone.utc).isoformat()

        def _step(label):
            self._active_stage = label
            if progress_cb:
                progress_cb(label)

        _step("Collecting domain info")
        domain = self.get_domain_info()

        _step("Enumerating users")
        users = self.collect_users()

        _step("Enumerating gMSA accounts")
        users.update(self.collect_gmsa())

        _step("Enumerating groups")
        groups = self.collect_groups()

        _step("Enumerating computers")
        computers = self.collect_computers()

        _step("Collecting ACLs (domain root + protected objects)")
        acls = self.collect_acls()

        _step("Enumerating ADCS templates")
        adcs = self.collect_adcs()

        _step("Collecting GPO links")
        gpos = self.collect_gpos()

        _step("Collecting domain trusts")
        trusts = self.collect_trusts()

        # ── Resolve memberOf DNs → SIDs using the accumulated _dn_map ─────────
        for obj in list(users.values()) + list(computers.values()):
            obj["member_of"] = [
                self._dn_map[dn.lower()]
                for dn in obj.get("member_of_dns", [])
                if dn.lower() in self._dn_map
            ]

        for grp in groups.values():
            grp["members"] = [
                self._dn_map[dn.lower()]
                for dn in grp.get("member_dns", [])
                if dn.lower() in self._dn_map
            ]
            grp["member_of"] = [
                self._dn_map[dn.lower()]
                for dn in grp.get("member_of_dns", [])
                if dn.lower() in self._dn_map
            ]

        # ── Compute transitive group membership (BFS) ─────────────────────────
        _step("Resolving transitive group membership")
        self._resolve_transitive_membership(users, groups, computers)

        self._telemetry["completed_at"] = datetime.now(timezone.utc).isoformat()
        self._telemetry["duration_ms"] = round(
            (time.perf_counter() - started) * 1000, 2
        )
        return {
            "domain":    domain,
            "users":     users,
            "groups":    groups,
            "computers": computers,
            "acls":      acls,
            "adcs":      adcs,
            "gpos":      gpos,
            "trusts":    trusts,
            "sid_name":  self._sid_name,
            "dn_map":    self._dn_map,
            "telemetry": self._telemetry,
        }
