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
    format_guid, parse_security_descriptor, parse_sid, WELL_KNOWN_SIDS,
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
    "544": "BUILTIN Administrators",
    "548": "Account Operators",
    "549": "Server Operators",
    "550": "Print Operators",
    "551": "Backup Operators",
}

# ── Objects whose ACLs we always collect ─────────────────────────────────────
_ACL_TARGET_FILTER = (
    "(|(objectClass=user)(objectClass=group)(objectClass=computer)"
    "(objectClass=organizationalUnit)(objectClass=container)"
    "(objectClass=groupPolicyContainer)(objectClass=domainDNS)"
    "(objectClass=domain))"
)

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


def _mapping_value(mapping: dict, name: str, default=None):
    """Read an LDAP attribute case-insensitively from a response mapping."""
    if name in mapping:
        return mapping[name]
    folded = name.casefold()
    for key, value in mapping.items():
        if str(key).casefold() == folded:
            return value
    return default


def _raw_values(entry: dict, name: str) -> list:
    """Return untouched LDAP wire values, falling back to decoded values."""
    raw = _mapping_value(entry.get("raw_attributes") or {}, name)
    if raw not in (None, [], ()):
        return _as_list(raw)
    decoded = _mapping_value(entry.get("attributes") or {}, name)
    return _as_list(decoded)


def _raw_first(entry: dict, name: str, default=None):
    return _first(_raw_values(entry, name), default)


def _sid_value(value) -> str:
    """Normalize a binary or already-canonical SID; reject mojibake IDs."""
    if isinstance(value, (bytes, bytearray)):
        return parse_sid(bytes(value))
    text = _str(value).strip()
    if re.fullmatch(r"S-\d+(?:-\d+)+", text, re.IGNORECASE):
        return text.upper()
    if text:
        try:
            recovered = parse_sid(text.encode("latin-1"))
            if recovered:
                return recovered
        except UnicodeEncodeError:
            pass
    return ""


def _sid_from_entry(entry: dict, name: str = "objectSid") -> str:
    return _sid_value(_raw_first(entry, name))


def _guid_from_entry(entry: dict, name: str = "objectGUID") -> str:
    value = _raw_first(entry, name)
    if isinstance(value, (bytes, bytearray)):
        return format_guid(bytes(value))
    return _str(value).strip().strip("{}").lower()


def _object_classes(entry: dict) -> set[str]:
    return {
        str(item).casefold()
        for item in _as_list(_mapping_value(entry.get("attributes") or {}, "objectClass"))
    }


def _directory_type(entry: dict) -> str:
    classes = _object_classes(entry)
    if "grouppolicycontainer" in classes:
        return "GPO"
    if "organizationalunit" in classes:
        return "OU"
    if "container" in classes:
        return "Container"
    if "group" in classes:
        return "Group"
    if "computer" in classes:
        return "Computer"
    if "user" in classes:
        return "User"
    if "domaindns" in classes or "domain" in classes:
        return "Domain"
    return "DirectoryObject"


def _parent_dn(dn: str) -> str:
    """Return the parent DN while respecting escaped commas in an RDN."""
    match = re.search(r"(?<!\\),", dn)
    return dn[match.end():] if match else ""


def _computer_role(is_dc: bool, operating_system: str) -> str:
    if is_dc:
        return "domain_controller"
    if "server" in (operating_system or "").casefold():
        return "server"
    return "workstation"


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
        """Search with SD_FLAGS control to retrieve owner and DACL data."""
        sd_ctrl = security_descriptor_control(sdflags=0x05)
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

        entry = entries[0]
        attrs = entry["attributes"]
        self.domain_sid = _sid_from_entry(entry)
        if not self.domain_sid:
            raise LDAPException(
                "The domain objectSid could not be decoded from the LDAP raw response"
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
        self._dn_map[self.base_dn.lower()] = self.domain_sid
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
            sid = _sid_from_entry(entry)
            if not sid:
                continue

            sam      = _str(attrs.get("samAccountName"))
            dn       = entry["dn"]
            uac      = _int(attrs.get("userAccountControl"))
            spns     = _as_list(attrs.get("servicePrincipalName"))
            members  = _as_list(attrs.get("memberOf"))
            enabled  = not bool(uac & UAC_ACCOUNTDISABLE)

            # RBCD trustees on this user (who can impersonate TO this account)
            rbcd_raw = _raw_first(entry, "msDS-AllowedToActOnBehalfOfOtherIdentity")
            rbcd_trustees = []
            if isinstance(rbcd_raw, bytes):
                for ace in parse_security_descriptor(rbcd_raw):
                    if ace.get("sid"):
                        rbcd_trustees.append(ace["sid"])

            # sIDHistory — token can impersonate previous domain identity
            sid_hist = []
            for raw in _raw_values(entry, "sIDHistory"):
                s = _sid_value(raw)
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
            sid = _sid_from_entry(entry)
            if not sid:
                continue

            sam = _str(attrs.get("samAccountName"))
            dn = entry["dn"]
            uac = _int(attrs.get("userAccountControl"))

            rbcd_trustees = []
            rbcd_raw = _raw_first(entry, "msDS-AllowedToActOnBehalfOfOtherIdentity")
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
                "gmsa_password_readable": bool(_raw_values(entry, "msDS-ManagedPassword")),
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
            attrs = entry["attributes"]
            sid = _sid_from_entry(entry)
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
            attrs = entry["attributes"]
            sid = _sid_from_entry(entry)
            if not sid:
                continue

            sam = _str(attrs.get("samAccountName"))
            dn  = entry["dn"]
            uac = _int(attrs.get("userAccountControl"))

            is_dc         = bool(uac & UAC_SERVER_TRUST)
            unconstrained = bool(uac & UAC_TRUSTED_FOR_DELEGATION)
            constrained   = bool(uac & UAC_TRUSTED_TO_AUTH_FOR_DELEGATION)

            rbcd_raw = _raw_first(entry, "msDS-AllowedToActOnBehalfOfOtherIdentity")
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

            operating_system = _str(attrs.get("operatingSystem"))
            computers[sid] = {
                "sid":                  sid,
                "name":                 sam,
                "dns":                  _str(attrs.get("dNSHostName")),
                "dn":                   dn,
                "uac":                  uac,
                "os":                   operating_system,
                "member_of_dns":        _as_list(attrs.get("memberOf")),
                "is_dc":                is_dc,
                "computer_role":        _computer_role(is_dc, operating_system),
                "unconstrained":        unconstrained,
                "constrained":          constrained,
                "delegation_targets":   _as_list(attrs.get("msDS-AllowedToDelegateTo")),
                "rbcd_trustees":        rbcd_trustees,
                # LAPS
                "laps_readable":        bool(laps_pwd),
                "laps_password":        laps_pwd,
                "laps_expiry":          laps_exp,
                "laps_scheme":          laps_scheme,
                "laps_encrypted":       bool(_raw_values(entry, "msLAPS-EncryptedPassword")),
            }
            self._dn_map[dn.lower()] = sid
            self._sid_name[sid]      = sam

        return computers

    # ── ACLs on key objects ───────────────────────────────────────────────────

    def collect_directory_structure(self) -> dict[str, dict]:
        """Collect OU/container hierarchy used by ACL and GPO attack paths."""
        entries = self._search(
            self.base_dn,
            "(&(|(objectClass=organizationalUnit)(objectClass=container))"
            "(!(objectClass=groupPolicyContainer)))",
            ["name", "distinguishedName", "objectGUID", "objectClass"],
        )
        objects: dict[str, dict] = {}
        for entry in entries:
            guid = _guid_from_entry(entry)
            if not guid:
                continue
            object_id = f"GUID:{guid}"
            attrs = entry["attributes"]
            dn = entry["dn"]
            object_type = _directory_type(entry)
            objects[object_id] = {
                "id": object_id,
                "guid": guid,
                "name": _str(attrs.get("name")) or dn.split(",", 1)[0],
                "dn": dn,
                "type": object_type,
                "parent_dn": _parent_dn(dn),
            }
            self._dn_map[dn.lower()] = object_id
            self._sid_name[object_id] = objects[object_id]["name"]
        return objects

    def _target_id(self, entry: dict) -> str:
        sid = _sid_from_entry(entry)
        if sid:
            return sid
        guid = _guid_from_entry(entry)
        if guid:
            return f"GUID:{guid}"
        return self._dn_map.get(entry.get("dn", "").lower(), "")

    def collect_acls(self) -> list[dict]:
        """Collect DACLs across AD structure objects, not only protected ones."""
        sd_ctrl = security_descriptor_control(sdflags=0x05)
        entries = self._search(
            self.base_dn,
            _ACL_TARGET_FILTER,
            [
                "nTSecurityDescriptor", "distinguishedName", "objectSid",
                "objectGUID", "objectClass", "samAccountName", "name",
            ],
            SUBTREE,
            sd_ctrl,
        )
        all_aces: list[dict] = []
        seen: set[tuple] = set()
        replication_rights: dict[tuple[str, str], set[str]] = {}

        for entry in entries:
            raw_sd = _raw_first(entry, "nTSecurityDescriptor")
            target_id = self._target_id(entry)
            if not isinstance(raw_sd, (bytes, bytearray)) or not target_id:
                continue
            attrs = entry["attributes"]
            target_dn = entry["dn"]
            target_type = _directory_type(entry)
            target_name = (
                _str(attrs.get("samAccountName"))
                or _str(attrs.get("name"))
                or target_dn.split(",", 1)[0]
            )

            for ace in parse_security_descriptor(bytes(raw_sd)):
                key = (
                    ace.get("sid"), target_id, ace.get("edge_type"),
                    ace.get("object_guid"), ace.get("ace_flags"),
                )
                if key in seen:
                    continue
                seen.add(key)
                record = {
                    **ace,
                    "target_dn": target_dn,
                    "target_sid": target_id,
                    "target_name": target_name,
                    "target_type": target_type,
                }
                all_aces.append(record)
                if ace.get("edge_type") in {
                    "GetChanges", "GetChangesAll", "GetChangesInFilteredSet"
                }:
                    replication_rights.setdefault(
                        (ace.get("sid", ""), target_id), set()
                    ).add(ace["edge_type"])

        # BloodHound-compatible post-processing: DCSync is effective only when
        # GetChanges and GetChangesAll are both present on the domain object.
        for (trustee_sid, target_id), rights in replication_rights.items():
            if {"GetChanges", "GetChangesAll"}.issubset(rights):
                all_aces.append({
                    "sid": trustee_sid,
                    "sid_name": self._sid_name.get(trustee_sid, ""),
                    "edge_type": "DCSync",
                    "mask": 0,
                    "object_guid": None,
                    "ace_flags": 0,
                    "mitre": None,
                    "target_dn": self.base_dn,
                    "target_sid": target_id,
                    "target_name": self.domain,
                    "target_type": "Domain",
                    "derived_from": sorted(rights),
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
        sd_ctrl  = security_descriptor_control(sdflags=0x05)

        # Certificate Authorities (correct base: Enrollment Services)
        ca_entries = self._search(
            ca_base,
            "(objectClass=pKIEnrollmentService)",
            [
                "cn", "distinguishedName", "dNSHostName", "cACertificateDN",
                "objectGUID", "nTSecurityDescriptor",
            ],
            controls=sd_ctrl,
        )
        cas = []
        for entry in ca_entries:
            attrs = entry["attributes"]
            guid = _guid_from_entry(entry)
            ca_id = f"GUID:{guid}" if guid else f"CA:{_str(attrs.get('cn'))}"
            raw_sd = _raw_first(entry, "nTSecurityDescriptor")
            acl_aces = (
                parse_security_descriptor(bytes(raw_sd))
                if isinstance(raw_sd, (bytes, bytearray)) else []
            )
            cas.append({
                "id": ca_id,
                "name": _str(attrs.get("cn")),
                "dn": entry["dn"],
                "dns": _str(attrs.get("dNSHostName")),
                "acl_aces": acl_aces,
            })
            self._dn_map[entry["dn"].lower()] = ca_id
            self._sid_name[ca_id] = _str(attrs.get("cn"))

        # Certificate templates (correct filter: pKICertificateTemplate)
        tmpl_entries = self._search(
            tmpl_base,
            "(objectClass=pKICertificateTemplate)",
            [
                "cn", "distinguishedName",
                "msPKI-Certificate-Name-Flag", "msPKI-Enrollment-Flag",
                "pKIExtendedKeyUsage", "msPKI-RA-Signature",
                "nTSecurityDescriptor", "objectGUID",
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
            raw_sd = _raw_first(entry, "nTSecurityDescriptor")
            enroll_aces = []
            acl_aces = []
            if isinstance(raw_sd, (bytes, bytearray)):
                acl_aces = parse_security_descriptor(bytes(raw_sd))
                for ace in acl_aces:
                    if ace.get("edge_type") in ("Enroll", "AllExtendedRights", "GenericAll"):
                        enroll_aces.append(ace["sid"])

            guid = _guid_from_entry(entry)
            template_id = f"GUID:{guid}" if guid else f"TMPL:{_str(attrs.get('cn'))}"
            self._dn_map[entry["dn"].lower()] = template_id
            self._sid_name[template_id] = _str(attrs.get("cn"))

            templates.append({
                "id":           template_id,
                "name":         _str(attrs.get("cn")),
                "dn":           entry["dn"],
                "esc1":         esc1,
                "ekus":         ekus,
                "enroll_sids":  enroll_aces,
                "acl_aces":     acl_aces,
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
            _guid_from_entry(e): {
                "id":       f"GUID:{_guid_from_entry(e)}",
                "name":     _str(e["attributes"].get("displayName")),
                "dn":       e["dn"],
                "guid":     _guid_from_entry(e),
                "path":     _str(e["attributes"].get("gPCFileSysPath")),
                "linked_to": [],
            }
            for e in gpo_entries
            if _guid_from_entry(e)
        }

        for gpo in gpos.values():
            self._dn_map[gpo["dn"].lower()] = gpo["id"]
            self._sid_name[gpo["id"]] = gpo["name"]

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

    def collect_all(
        self,
        progress_cb=None,
        include_acls: bool = True,
        include_adcs: bool = True,
    ) -> dict:
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

        _step("Collecting OU and container structure")
        directory_objects = self.collect_directory_structure()

        _step("Collecting GPO links")
        gpos = self.collect_gpos()

        if include_acls:
            _step("Collecting ACLs (all directory structure objects)")
            acls = self.collect_acls()
        else:
            acls = []

        if include_adcs:
            _step("Enumerating ADCS services and templates")
            adcs = self.collect_adcs()
        else:
            adcs = {"cas": [], "templates": []}

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

        all_sid_objects = [domain] + list(users.values()) + list(groups.values()) + list(computers.values())
        canonical_sids = sum(
            1 for obj in all_sid_objects
            if re.fullmatch(r"S-\d+(?:-\d+)+", str(obj.get("sid", "")), re.IGNORECASE)
        )
        system_counts = {
            role: sum(1 for item in computers.values() if item.get("computer_role") == role)
            for role in ("workstation", "server", "domain_controller")
        }

        self._telemetry["completed_at"] = datetime.now(timezone.utc).isoformat()
        self._telemetry["duration_ms"] = round(
            (time.perf_counter() - started) * 1000, 2
        )
        return {
            "domain":    domain,
            "users":     users,
            "groups":    groups,
            "computers": computers,
            "directory_objects": directory_objects,
            "acls":      acls,
            "adcs":      adcs,
            "gpos":      gpos,
            "trusts":    trusts,
            "sid_name":  self._sid_name,
            "dn_map":    self._dn_map,
            "telemetry": self._telemetry,
            "quality": {
                "status": "ok" if canonical_sids == len(all_sid_objects) else "degraded",
                "canonical_sids": canonical_sids,
                "identity_objects": len(all_sid_objects),
                "acl_relationships": len(acls),
                "acl_scope": "all-directory-objects" if include_acls else "disabled",
            },
            "system_counts": system_counts,
            "coverage": {
                "directory": {
                    "status": "collected",
                    "source": "LDAP",
                    "includes": [
                        "object properties", "group memberships", "trusts",
                        "OU/container hierarchy", "GPO links",
                        "AD object permissions", "AD CS",
                    ],
                },
                "host": {
                    "status": "not_collected",
                    "source": "SMB/RPC or host telemetry required",
                    "missing_relationships": [
                        "HasSession", "AdminTo", "CanRDP",
                        "ExecuteDCOM", "CanPSRemote", "SQLAdmin",
                    ],
                },
            },
        }
