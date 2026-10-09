"""
ldap_collector.py — Stealthy LDAP-only Active Directory enumerator.

Collects users, groups, computers, ACLs, ADCS templates, GPO links, and
domain trusts using a single LDAP session — no SMB, no NetWksta, no noise.

AraizCorp LLC — Serket
"""
from __future__ import annotations

import re
import hashlib
from datetime import datetime, timedelta, timezone
import struct
import time
import random
from typing import Optional

from ldap3 import (
    ALL, KERBEROS, NTLM, SASL, SIMPLE, SUBTREE, BASE,
    Connection, Server,
)
from ldap3.core.exceptions import LDAPBindError, LDAPException
from ldap3.protocol.microsoft import security_descriptor_control

from serket.collector.adcs_analysis import analyze_ca, analyze_template, summarize
from serket.collector.acl_parser import (
    format_guid, parse_security_descriptor, parse_sid, WELL_KNOWN_SIDS,
)


# ── UAC flag masks ────────────────────────────────────────────────────────────
UAC_ACCOUNTDISABLE              = 0x00000002
UAC_PASSWD_NOTREQD              = 0x00000020
UAC_ENCRYPTED_TEXT_PWD_ALLOWED  = 0x00000080
UAC_SMARTCARD_REQUIRED          = 0x00040000
UAC_DONT_REQ_PREAUTH            = 0x00400000
UAC_DONT_EXPIRE_PASSWORD        = 0x00010000
UAC_TRUSTED_FOR_DELEGATION      = 0x00080000   # Unconstrained
UAC_TRUSTED_TO_AUTH_FOR_DELEGATION = 0x01000000  # Constrained (S4U2Proxy)
UAC_NOT_DELEGATED               = 0x00100000
UAC_USE_DES_KEY_ONLY            = 0x00200000
UAC_SERVER_TRUST                = 0x00002000   # Domain Controller
UAC_PARTIAL_SECRETS_ACCOUNT     = 0x04000000   # Read-only domain controller

MAQ_ACTIVITY_WINDOW_DAYS = 30
MAQ_ACTIVITY_THRESHOLD = 3

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
    "525": "Protected Users",
    "571": "Key Admins",
    "572": "Enterprise Key Admins",
    "553": "RAS and IAS Servers",
    "544": "BUILTIN Administrators",
    "548": "Account Operators",
    "549": "Server Operators",
    "550": "Print Operators",
    "551": "Backup Operators",
}

_DNS_ADMIN_NAMES = {"dnsadmins", "dns admins"}
_EXCHANGE_HIGH_VALUE_NAMES = {
    "exchange trusted subsystem",
    "exchange windows permissions",
    "exchange organization administrators",
    "exchange recipient administrators",
}
_DANGEROUS_PREWIN2000_MEMBERS = {
    "S-1-1-0",   # Everyone
    "S-1-5-7",   # Anonymous Logon
    "S-1-5-11",  # Authenticated Users
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


def _filetime_to_datetime(value) -> Optional[datetime]:
    """Normalize an AD FILETIME (or ldap3 datetime) to an aware UTC datetime."""
    value = _first(value)
    if value is None or value == "":
        return None
    if isinstance(value, datetime):
        return (
            value.replace(tzinfo=timezone.utc)
            if value.tzinfo is None else value.astimezone(timezone.utc)
        )
    try:
        raw = int(value)
    except (TypeError, ValueError, OverflowError):
        return None
    if raw in (0, 0x7FFFFFFFFFFFFFFF):
        return None
    try:
        return datetime.fromtimestamp(
            (raw - 116444736000000000) / 10_000_000,
            tz=timezone.utc,
        )
    except (OSError, OverflowError, ValueError):
        return None


def _filetime_to_iso(value) -> Optional[str]:
    parsed = _filetime_to_datetime(value)
    return parsed.isoformat() if parsed else None


def _datetime_attr_to_iso(value) -> Optional[str]:
    value = _first(value)
    if value in (None, ""):
        return None
    if isinstance(value, datetime):
        return (
            value.replace(tzinfo=timezone.utc)
            if value.tzinfo is None else value.astimezone(timezone.utc)
        ).isoformat()
    return str(value)


def _days_since(value: Optional[datetime]) -> Optional[int]:
    if value is None:
        return None
    return max(0, (datetime.now(timezone.utc) - value).days)


def _datetime_days_since(value) -> Optional[int]:
    value = _first(value)
    if isinstance(value, datetime):
        parsed = value
    elif value:
        try:
            parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        except ValueError:
            return None
    else:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return _days_since(parsed.astimezone(timezone.utc))


def _windows_interval_to_seconds(value) -> int:
    """Convert an AD duration (negative 100 ns ticks) without losing minutes."""
    value = _first(value)
    if value in (None, "", 0, "0"):
        return 0
    if isinstance(value, timedelta):
        return abs(int(value.total_seconds()))
    try:
        return abs(int(value)) // 10_000_000
    except (TypeError, ValueError, OverflowError):
        return 0


def _windows_interval_to_days(value) -> int:
    return _windows_interval_to_seconds(value) // 86400


def _windows_interval_to_minutes(value) -> int:
    return _windows_interval_to_seconds(value) // 60


def _parse_pwd_properties(value) -> dict[str, bool]:
    props = _int(value)
    return {
        "complexity_required": bool(props & 0x01),
        "no_anon_change": bool(props & 0x02),
        "no_clear_change": bool(props & 0x04),
        "lockout_admins": bool(props & 0x08),
        "store_cleartext": bool(props & 0x10),
    }


def _sid_from_dn(value: str) -> str:
    """Extract a canonical SID from ForeignSecurityPrincipal-style DNs."""
    match = re.search(r"(?:^|,)CN=(S-\d+(?:-\d+)+)(?:,|$)", str(value), re.IGNORECASE)
    return match.group(1).upper() if match else ""


def _linked_dn(value) -> str:
    """Normalize DN, DN-Binary and DN-String link values returned by ldap3."""
    text = _str(value).strip()
    if re.match(r"^[BS]:\d+:", text, re.IGNORECASE):
        parts = text.split(":", 3)
        return parts[3] if len(parts) == 4 else ""
    match = re.search(r"(?i)(?:CN|OU|DC)=", text)
    return text[match.start():] if match else text


def _parse_gplink(value) -> list[dict]:
    """Parse ordered gPLink entries and their disabled/enforced option bits."""
    links = []
    pattern = re.compile(r"\[(?:LDAP://)?(.+?);(\d+)\]", re.IGNORECASE)
    for order, match in enumerate(pattern.finditer(_str(value)), start=1):
        gpo_dn = match.group(1).strip()
        options = _int(match.group(2))
        guid_match = re.search(r"\{([0-9A-Fa-f-]{36})\}", gpo_dn)
        if not guid_match:
            continue
        links.append({
            "guid": guid_match.group(1).lower(),
            "gpo_dn": gpo_dn,
            "order": order,
            "options": options,
            "enabled": not bool(options & 0x1),
            "enforced": bool(options & 0x2),
        })
    return links


def _dacl_fingerprint(raw_sd: bytes) -> str:
    """Hash the exact self-relative DACL bytes for AdminSDHolder comparison."""
    # TODO(pack3): add an optional semantic fingerprint that canonicalizes ACEs
    # before hashing. Keep this exact fingerprint for byte-level drift evidence.
    if not isinstance(raw_sd, (bytes, bytearray)) or len(raw_sd) < 20:
        return ""
    dacl_offset = struct.unpack_from("<L", raw_sd, 16)[0]
    if not dacl_offset or dacl_offset + 8 > len(raw_sd):
        return ""
    acl_size = struct.unpack_from("<H", raw_sd, dacl_offset + 2)[0]
    if acl_size < 8 or dacl_offset + acl_size > len(raw_sd):
        return ""
    return hashlib.sha256(bytes(raw_sd[dacl_offset:dacl_offset + acl_size])).hexdigest()


def _normalize_os_version(value: str) -> str:
    """Return a stable dotted LDAP OS version without guessing the product."""
    version = " ".join(str(value or "").split())
    match = re.fullmatch(r"(\d+(?:\.\d+)*)\s*\((\d+)\)", version)
    return f"{match.group(1)}.{match.group(2)}" if match else version


def _os_inventory_key(name: str, version: str, service_pack: str) -> str:
    """Build a stable aggregate key while preserving os_display for humans."""
    product = " ".join(str(name or "").split())
    product = re.sub(r"(?i)^Microsoft\s+", "", product)
    product = re.sub(r"(?i)^Windows Server\s+", "Server ", product)
    return " ".join(
        part for part in (
            product,
            _normalize_os_version(version),
            " ".join(str(service_pack or "").split()),
        ) if part
    ) or "Unknown"


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
        simple_auth: bool = False,
        use_ldaps:  bool = False,
        rate_limit: float = 0.08,
        jitter: float = 0.5,
    ):
        self.dc_host    = dc_host
        self.domain     = domain
        self.username   = username
        self.password   = password
        self.hashes     = hashes
        self.kerberos   = kerberos
        self.simple_auth = simple_auth
        self.use_ldaps  = use_ldaps
        self.rate_limit = rate_limit
        self.jitter = max(0.0, min(1.0, jitter))

        self.conn:      Optional[Connection] = None
        self.base_dn:   str = ""
        self.config_dn: str = ""
        self.domain_sid: str = ""

        self._active_stage = "Connection"
        self._telemetry = {
            "profile": "low-impact",
            "transport": "LDAPS" if use_ldaps else "LDAP",
            "auth": ("kerberos" if kerberos
                     else "simple" if simple_auth
                     else "ntlm-hash" if hashes else "ntlm"),
            "rate_limit_ms": round(rate_limit * 1000, 2),
        "jitter_pct": round(self.jitter * 100),
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
        self._dacl_fingerprints: dict[str, str] = {}
        self._adminsdholder_dacl_fingerprint: str = ""

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
            # ldap3 only accepts SIMPLE / ANONYMOUS / SASL / NTLM as the
            # authentication parameter; Kerberos is SASL with the GSSAPI
            # mechanism, driven by the KRB5CCNAME credential cache.
            self.conn = Connection(
                server,
                authentication=SASL,
                sasl_mechanism="GSSAPI",
                **connection_options,
            )
        elif self.simple_auth:
            # Emergency compatibility mode: some LDAP servers (notably Samba
            # AD DCs) terminate ldap3's Sicily/NTLMSSP exchange mid-handshake.
            # A SIMPLE bind with a UPN works there. It is opt-in via
            # --auth simple because it changes the operator's telemetry
            # signature: the DC logs a plain "simple bind", not NTLM.
            self.conn = Connection(
                server,
                user=f"{self.username}@{self.domain}",
                password=self.password or "",
                authentication=SIMPLE,
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
            time.sleep(self.rate_limit * (1 - self.jitter + 2 * self.jitter * random.random()))
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
            [
                "objectSid", "distinguishedName", "minPwdLength",
                "minPwdAge", "maxPwdAge", "pwdHistoryLength",
                "lockoutThreshold", "lockoutDuration",
                "lockoutObservationWindow", "pwdProperties",
                "ms-DS-MachineAccountQuota",
            ],
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

        password_flags = _parse_pwd_properties(attrs.get("pwdProperties"))
        password_policy = {
            "min_length": _int(attrs.get("minPwdLength")),
            "min_age_days": _windows_interval_to_days(attrs.get("minPwdAge")),
            "max_age_days": _windows_interval_to_days(attrs.get("maxPwdAge")),
            "history_length": _int(attrs.get("pwdHistoryLength")),
            **password_flags,
        }
        lockout_policy = {
            "threshold": _int(attrs.get("lockoutThreshold")),
            "duration_minutes": _windows_interval_to_minutes(attrs.get("lockoutDuration")),
            "observation_window_minutes": _windows_interval_to_minutes(
                attrs.get("lockoutObservationWindow")
            ),
        }
        result = {
            "name":              self.domain,
            "dn":                self.base_dn,
            "sid":               self.domain_sid,
            # Preserve the v2.0 flat keys for older consumers.
            "min_pwd_length":    password_policy["min_length"],
            "lockout_threshold": lockout_policy["threshold"],
            "maq":               _int(attrs.get("ms-DS-MachineAccountQuota"), 10),
            "password_policy":   password_policy,
            "lockout_policy":    lockout_policy,
        }
        self._sid_name[self.domain_sid] = self.domain
        self._dn_map[self.base_dn.lower()] = self.domain_sid
        return result

    # ── Users ─────────────────────────────────────────────────────────────────

    def collect_users(self) -> dict[str, dict]:
        """Enumerate all user accounts and detect kerberoastable / ASREPRoastable."""
        entries = self._search(
            self.base_dn,
            "(&(objectClass=user)(!(objectClass=computer))"
            "(!(objectClass=msDS-GroupManagedServiceAccount))"
            "(!(objectClass=msDS-ManagedServiceAccount)))",
            [
                "samAccountName", "userPrincipalName", "distinguishedName",
                "objectSid", "objectGUID", "memberOf", "userAccountControl",
                "servicePrincipalName", "adminCount", "description",
                "mail", "pwdLastSet", "accountExpires", "lastLogon",
                "lastLogonTimestamp", "lockoutTime", "logonHours",
                "userWorkstations", "primaryGroupID",
                "msDS-User-Account-Control-Computed",
                "msDS-KeyCredentialLink", "msDS-AssignedAuthNPolicy",
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
            delegation_targets = _as_list(attrs.get("msDS-AllowedToDelegateTo"))
            protocol_transition = bool(
                uac & UAC_TRUSTED_TO_AUTH_FOR_DELEGATION
            ) and bool(delegation_targets)

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
            pwd_last_set = _filetime_to_datetime(attrs.get("pwdLastSet"))
            last_logon = _filetime_to_datetime(attrs.get("lastLogon"))
            last_logon_timestamp = _filetime_to_datetime(
                attrs.get("lastLogonTimestamp")
            )
            last_activity = last_logon_timestamp or last_logon
            pwd_age_days = _days_since(pwd_last_set)
            last_logon_age_days = _days_since(last_activity)
            lockout_time = _filetime_to_datetime(attrs.get("lockoutTime"))
            computed_uac_raw = attrs.get("msDS-User-Account-Control-Computed")
            computed_uac = _int(computed_uac_raw)
            locked_out = (
                bool(computed_uac & 0x10)
                if _first(computed_uac_raw) not in (None, "")
                else lockout_time is not None
            )
            raw_workstations = _as_list(attrs.get("userWorkstations"))
            user_workstations = [
                item.strip()
                for raw in raw_workstations
                for item in str(raw).split(",")
                if item.strip()
            ]

            users[sid] = {
                "sid":                    sid,
                "guid":                   _guid_from_entry(entry),
                "name":                   sam,
                "upn":                    _str(attrs.get("userPrincipalName")),
                "dn":                     dn,
                "uac":                    uac,
                "spns":                   spns,
                "member_of_dns":          members,
                "admin_count":            _int(attrs.get("adminCount")),
                "enabled":                enabled,
                "kerberoastable":         enabled and bool(spns) and not sam.endswith("$"),
                "asreproastable":         enabled and bool(uac & UAC_DONT_REQ_PREAUTH),
                "unconstrained":          bool(uac & UAC_TRUSTED_FOR_DELEGATION),
                "constrained":            bool(delegation_targets),
                "constrained_kerberos_only": bool(delegation_targets) and not protocol_transition,
                "protocol_transition":    protocol_transition,
                "delegation_mode":        (
                    "unconstrained" if bool(uac & UAC_TRUSTED_FOR_DELEGATION)
                    else "constrained_protocol_transition" if protocol_transition
                    else "constrained_kerberos_only" if delegation_targets
                    else "none"
                ),
                "delegation_targets":     delegation_targets,
                "rbcd_trustees":          rbcd_trustees,
                "sid_history":            sid_hist,
                "description":            description,
                "has_password_hint":      _has_password_hint(description),
                "mail":                   _str(attrs.get("mail")),
                "pwd_last_set":           pwd_last_set.isoformat() if pwd_last_set else None,
                "pwd_age_days":           pwd_age_days,
                "pwd_never_expires":      bool(uac & UAC_DONT_EXPIRE_PASSWORD),
                "pwd_not_required":       bool(uac & UAC_PASSWD_NOTREQD),
                "reversible_encryption":  bool(uac & UAC_ENCRYPTED_TEXT_PWD_ALLOWED),
                "account_expires":        _filetime_to_iso(attrs.get("accountExpires")),
                "last_logon":             last_logon.isoformat() if last_logon else None,
                "last_logon_timestamp":   (
                    last_logon_timestamp.isoformat() if last_logon_timestamp else None
                ),
                "last_logon_age_days":    last_logon_age_days,
                "stale":                  last_logon_age_days is None or last_logon_age_days > 180,
                "has_key_credential_link": bool(_raw_values(entry, "msDS-KeyCredentialLink")),
                "smartcard_required":      bool(uac & UAC_SMARTCARD_REQUIRED),
                "not_delegated":           bool(uac & UAC_NOT_DELEGATED),
                "use_des_key_only":        bool(uac & UAC_USE_DES_KEY_ONLY),
                "locked_out":              locked_out,
                "lockout_time":            lockout_time.isoformat() if lockout_time else None,
                "logon_hours_restricted":  bool(_raw_values(entry, "logonHours")),
                "user_workstations":       user_workstations,
                "primary_group_id":        _int(attrs.get("primaryGroupID"), 513),
                "assigned_authn_policy":   _str(attrs.get("msDS-AssignedAuthNPolicy")),
                "authn_policy_assigned":   bool(_str(attrs.get("msDS-AssignedAuthNPolicy"))),
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
            delegation_targets = _as_list(attrs.get("msDS-AllowedToDelegateTo"))
            protocol_transition = bool(
                uac & UAC_TRUSTED_TO_AUTH_FOR_DELEGATION
            ) and bool(delegation_targets)

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
                "constrained": bool(delegation_targets),
                "constrained_kerberos_only": bool(delegation_targets) and not protocol_transition,
                "protocol_transition": protocol_transition,
                "delegation_mode": (
                    "unconstrained" if bool(uac & UAC_TRUSTED_FOR_DELEGATION)
                    else "constrained_protocol_transition" if protocol_transition
                    else "constrained_kerberos_only" if delegation_targets
                    else "none"
                ),
                "delegation_targets": delegation_targets,
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
                "samAccountName", "distinguishedName", "objectSid", "objectGUID",
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
            normalized = sam.casefold().strip()
            is_dns_admins = normalized in _DNS_ADMIN_NAMES
            is_exchange_privileged = normalized in _EXCHANGE_HIGH_VALUE_NAMES
            is_protected_users = rid == "525" or normalized == "protected users"
            is_key_admin = rid in {"571", "572"} or normalized in {
                "key admins", "enterprise key admins"
            }
            is_prewin2000 = sid.upper() == "S-1-5-32-554" or normalized == (
                "pre-windows 2000 compatible access"
            )
            high_value = (
                rid in HIGH_VALUE_RIDS
                or is_dns_admins
                or is_exchange_privileged
                or is_key_admin
            )

            groups[sid] = {
                "sid":          sid,
                "guid":         _guid_from_entry(entry),
                "name":         sam,
                "dn":           dn,
                "member_dns":   _as_list(attrs.get("member")),
                "member_of_dns": _as_list(attrs.get("memberOf")),
                "admin_count":  _int(attrs.get("adminCount")),
                "high_value":   high_value,
                "description":  _str(attrs.get("description")),
                "is_dns_admins": is_dns_admins,
                "is_exchange_privileged": is_exchange_privileged,
                "is_protected_users": is_protected_users,
                "is_key_admin": is_key_admin,
                "is_prewin2000_compatible": is_prewin2000,
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
                "objectSid", "objectGUID", "userAccountControl", "operatingSystem",
                "operatingSystemVersion", "operatingSystemServicePack",
                "memberOf", "primaryGroupID", "msDS-AllowedToDelegateTo",
                "msDS-AllowedToActOnBehalfOfOtherIdentity",
                "msDS-isRODC", "msDS-RevealedUsers", "msDS-RevealedList",
                "msDS-RevealOnDemandGroup", "msDS-NeverRevealGroup",
                "mS-DS-CreatorSID", "whenCreated",
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
            delegation_targets = _as_list(attrs.get("msDS-AllowedToDelegateTo"))
            protocol_transition = bool(
                uac & UAC_TRUSTED_TO_AUTH_FOR_DELEGATION
            ) and bool(delegation_targets)
            constrained = bool(delegation_targets)
            is_rodc = bool(
                uac & UAC_PARTIAL_SECRETS_ACCOUNT
                or _first(_mapping_value(attrs, "msDS-isRODC"), False)
                in (True, "TRUE", "True", "true", 1, "1")
            )

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
            os_version = _str(attrs.get("operatingSystemVersion"))
            os_service_pack = _str(attrs.get("operatingSystemServicePack"))
            normalized_os_version = _normalize_os_version(os_version)
            os_display = " ".join(
                part for part in (
                    operating_system,
                    normalized_os_version,
                    os_service_pack,
                ) if part
            )
            os_inventory_key = _os_inventory_key(
                operating_system, os_version, os_service_pack
            )
            revealed_dns = list(dict.fromkeys(
                linked
                for attribute in ("msDS-RevealedUsers", "msDS-RevealedList")
                for raw in _raw_values(entry, attribute)
                if (linked := _linked_dn(raw))
            ))
            computers[sid] = {
                "sid":                  sid,
                "guid":                 _guid_from_entry(entry),
                "name":                 sam,
                "dns":                  _str(attrs.get("dNSHostName")),
                "dn":                   dn,
                "uac":                  uac,
                "os":                   operating_system,
                "os_version":           os_version,
                "os_service_pack":      os_service_pack,
                "os_display":           os_display or "Unknown",
                "os_inventory_key":     os_inventory_key,
                "member_of_dns":        _as_list(attrs.get("memberOf")),
                "primary_group_id":     _int(attrs.get("primaryGroupID"), 515),
                "is_dc":                is_dc,
                "computer_role":        _computer_role(is_dc, operating_system),
                "unconstrained":        unconstrained,
                "constrained":          constrained,
                "constrained_kerberos_only": constrained and not protocol_transition,
                "protocol_transition":  protocol_transition,
                "delegation_mode":      (
                    "unconstrained" if unconstrained
                    else "constrained_protocol_transition" if protocol_transition
                    else "constrained_kerberos_only" if constrained
                    else "none"
                ),
                "delegation_targets":   delegation_targets,
                "creator_sid":          _sid_value(_raw_first(entry, "mS-DS-CreatorSID")),
                "created":              _datetime_attr_to_iso(attrs.get("whenCreated")),
                "rbcd_trustees":        rbcd_trustees,
                # LAPS
                "laps_readable":        bool(laps_pwd),
                "laps_password":        laps_pwd,
                "laps_expiry":          laps_exp,
                "laps_scheme":          laps_scheme,
                "laps_encrypted":       bool(_raw_values(entry, "msLAPS-EncryptedPassword")),
                # RODC password replication policy and observed cache state.
                "is_rodc":              is_rodc,
                "rodc_revealed_user_dns": revealed_dns,
                "rodc_reveal_on_demand_dns": [
                    _linked_dn(value) for value in _raw_values(entry, "msDS-RevealOnDemandGroup")
                    if _linked_dn(value)
                ],
                "rodc_never_reveal_dns": [
                    _linked_dn(value) for value in _raw_values(entry, "msDS-NeverRevealGroup")
                    if _linked_dn(value)
                ],
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

    def collect_schema_names(self) -> dict[str, str]:
        """Resolve GUIDs of password-bearing attributes from the schema.

        Legacy LAPS (ms-Mcs-AdmPwd) schema GUIDs are generated per forest, so
        they cannot be hardcoded; we ask the schema partition directly.
        Falls back to the well-known defaults when the query is unavailable.
        """
        wanted = {"ms-Mcs-AdmPwd", "ms-LAPS-Password", "ms-DS-ManagedPassword"}
        fallback = {
            "e362ed86-b728-0842-b27d-2dea7a9df218": "ms-DS-ManagedPassword",
        }
        try:
            entries = self._search(
                f"CN=Schema,CN=Configuration,{self.base_dn}",
                "(|(lDAPDisplayName=ms-Mcs-AdmPwd)(lDAPDisplayName=ms-LAPS-Password)"
                "(lDAPDisplayName=ms-DS-ManagedPassword))",
                ["lDAPDisplayName", "schemaIDGUID"],
                SUBTREE,
            )
        except LDAPException:
            return dict(fallback)
        names: dict[str, str] = {}
        for entry in entries:
            attrs = entry["attributes"]
            name = _str(attrs.get("lDAPDisplayName"))
            if name not in wanted:
                continue
            raw = _raw_first(entry, "schemaIDGUID")
            if isinstance(raw, (bytes, bytearray)):
                guid = format_guid(bytes(raw))
            else:
                guid = ""
            if guid:
                names[guid] = name
        for guid, name in fallback.items():
            names.setdefault(guid, name)
        return names

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
        schema_names = self.collect_schema_names()

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
            fingerprint = _dacl_fingerprint(bytes(raw_sd))
            if fingerprint:
                self._dacl_fingerprints[target_id] = fingerprint
                if target_dn.casefold() == (
                    f"CN=AdminSDHolder,CN=System,{self.base_dn}".casefold()
                ):
                    self._adminsdholder_dacl_fingerprint = fingerprint

            for ace in parse_security_descriptor(bytes(raw_sd), schema_names):
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
                "objectGUID", "nTSecurityDescriptor", "certificateTemplates",
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
            published_templates = _as_list(attrs.get("certificateTemplates"))
            ca_analysis = analyze_ca(acl_aces, published_templates)
            cas.append({
                "id": ca_id,
                "name": _str(attrs.get("cn")),
                "dn": entry["dn"],
                "dns": _str(attrs.get("dNSHostName")),
                "acl_aces": acl_aces,
                **ca_analysis,
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

        published = {
            str(name).casefold()
            for ca in cas for name in ca.get("published_templates", [])
        }
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

            template_name = _str(attrs.get("cn"))
            analysis = analyze_template(
                name_flag=name_flag,
                enrollment_flag=enroll_flag,
                ekus=ekus,
                ra_signatures=ra_sigs,
                enroll_sids=enroll_aces,
                acl_aces=acl_aces,
                published=template_name.casefold() in published if published else None,
            )
            templates.append({
                "id": template_id,
                "name": template_name,
                "dn": entry["dn"],
                "esc1": analysis["esc"]["esc1"],
                "ekus": ekus,
                "enroll_sids": enroll_aces,
                "acl_aces": acl_aces,
                "name_flags": name_flag,
                "enrollment_flags": enroll_flag,
                "ra_signatures": ra_sigs,
                **analysis,
            })

        return {"cas": cas, "templates": templates, "summary": summarize(cas, templates)}

    # ── GPO links ─────────────────────────────────────────────────────────────

    def collect_gpos(self) -> list[dict]:
        """Collect LDAP GPO metadata, ordered links and inheritance posture."""
        gpo_entries = self._search(
            self.base_dn,
            "(objectClass=groupPolicyContainer)",
            [
                "displayName", "distinguishedName", "objectGUID",
                "gPCFileSysPath", "gPCFunctionalityVersion",
                "gPCMachineExtensionNames", "gPCUserExtensionNames",
                "flags", "versionNumber", "whenCreated", "whenChanged",
            ],
        )
        gpos = {}
        for entry in gpo_entries:
            guid = _guid_from_entry(entry)
            if not guid:
                continue
            attrs = entry["attributes"]
            flags = _int(attrs.get("flags"))
            gpos[guid] = {
                "id": f"GUID:{guid}",
                "name": _str(attrs.get("displayName")),
                "dn": entry["dn"],
                "guid": guid,
                "path": _str(attrs.get("gPCFileSysPath")),
                "functionality_version": _int(attrs.get("gPCFunctionalityVersion")),
                "version_number": _int(attrs.get("versionNumber")),
                "flags": flags,
                "user_settings_enabled": not bool(flags & 0x1),
                "computer_settings_enabled": not bool(flags & 0x2),
                "machine_extensions": _as_list(attrs.get("gPCMachineExtensionNames")),
                "user_extensions": _as_list(attrs.get("gPCUserExtensionNames")),
                "created": _datetime_attr_to_iso(attrs.get("whenCreated")),
                "changed": _datetime_attr_to_iso(attrs.get("whenChanged")),
                "linked_to": [],
                "links": [],
                "coverage": "ldap_only",
            }

        for gpo in gpos.values():
            self._dn_map[gpo["dn"].lower()] = gpo["id"]
            self._sid_name[gpo["id"]] = gpo["name"]

        # Collect OU gPLink references
        ou_entries = self._search(
            self.base_dn,
            "(|(objectClass=organizationalUnit)(objectClass=domain))",
            ["distinguishedName", "gPLink", "gPOptions"],
        )
        for entry in ou_entries:
            attrs = entry["attributes"]
            gp_link = _str(attrs.get("gPLink"))
            if not gp_link:
                continue
            gp_options = _int(attrs.get("gPOptions"))
            for link in _parse_gplink(gp_link):
                guid = link["guid"]
                if guid in gpos:
                    gpos[guid]["linked_to"].append(entry["dn"])
                    gpos[guid]["links"].append({
                        **link,
                        "target_dn": entry["dn"],
                        "target_gp_options": gp_options,
                        "target_blocks_inheritance": bool(gp_options & 0x1),
                    })

        return list(gpos.values())

    # ── Trusts ────────────────────────────────────────────────────────────────

    def collect_trusts(self) -> list[dict]:
        """Enumerate domain trusts with direction, type and filtering posture."""
        entries = self._search(
            self.base_dn,
            "(objectClass=trustedDomain)",
            [
                "trustPartner", "trustDirection", "trustType", "trustAttributes",
                "securityIdentifier", "flatName", "whenCreated", "whenChanged",
                "msDS-SupportedEncryptionTypes",
            ],
        )
        directions = {1: "Inbound", 2: "Outbound", 3: "Bidirectional"}
        trust_types = {
            1: "Windows downlevel",
            2: "Windows Active Directory",
            3: "MIT Kerberos",
            4: "DCE (historical)",
            5: "Microsoft Entra ID",
        }
        trusts = []
        for entry in entries:
            attrs = entry["attributes"]
            direction_raw = _int(attrs.get("trustDirection"))
            trust_type_raw = _int(attrs.get("trustType"))
            flags = _int(attrs.get("trustAttributes"))
            is_quarantined = bool(flags & 0x00000004)
            is_forest = bool(flags & 0x00000008)
            treat_as_external = bool(flags & 0x00000040)
            pim_trust = bool(flags & 0x00000400)
            sid_filtering_status = (
                "quarantined"
                if is_quarantined
                else "forest-relaxed-to-external"
                if is_forest and treat_as_external
                else "forest-default"
                if is_forest
                else "not-declared-by-trust-flags"
            )
            trusts.append({
                "partner": _str(attrs.get("trustPartner")),
                "partner_sid": _sid_from_entry(entry, "securityIdentifier"),
                "partner_netbios": _str(attrs.get("flatName")),
                "direction": directions.get(direction_raw, "Unknown"),
                "direction_raw": direction_raw,
                "trust_type": trust_types.get(trust_type_raw, "Unknown"),
                "trust_type_raw": trust_type_raw,
                "attributes": flags,
                "attributes_raw": flags,
                "is_transitive": not bool(flags & 0x00000001),
                "is_quarantined": is_quarantined,
                "is_forest": is_forest,
                "is_cross_org": bool(flags & 0x00000010),
                "within_forest": bool(flags & 0x00000020),
                "treat_as_external": treat_as_external,
                "pim_trust": pim_trust,
                "sid_filtering_status": sid_filtering_status,
                "sid_filtering_enforced": is_quarantined,
                "sid_filtering_relaxed": is_forest and treat_as_external,
                "sid_filtering_risk": bool(is_forest and treat_as_external and not pim_trust),
                "tgt_delegation_disabled": bool(flags & 0x00000200),
                "tgt_delegation_enabled": bool(flags & 0x00000800),
                "supported_encryption_types": _int(attrs.get("msDS-SupportedEncryptionTypes")),
                "created": _datetime_attr_to_iso(attrs.get("whenCreated")),
                "changed": _datetime_attr_to_iso(attrs.get("whenChanged")),
            })
        return trusts

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

    def _apply_adminsdholder_drift(self, users: dict, groups: dict) -> None:
        """Compare protected-object DACLs to the exact AdminSDHolder DACL."""
        template = self._adminsdholder_dacl_fingerprint
        for sid, obj in {**users, **groups}.items():
            if obj.get("admin_count") != 1:
                continue
            actual = self._dacl_fingerprints.get(sid, "")
            obj["adminsdholder_checked"] = bool(template and actual)
            obj["adminsdholder_drift"] = bool(
                template and actual and actual != template
            )

    @staticmethod
    def _apply_security_posture(users: dict, groups: dict, computers: dict) -> None:
        protected_groups = {
            sid for sid, group in groups.items() if group.get("is_protected_users")
        }
        privileged_groups = {
            sid for sid, group in groups.items()
            if group.get("high_value") and not group.get("is_protected_users")
        }
        for user in users.values():
            memberships = set(user.get("effective_member_of", []))
            user["protected_user"] = bool(memberships & protected_groups)
            user["sensitive_admin"] = bool(
                user.get("admin_count") == 1 or memberships & privileged_groups
            )
            user["missing_protected_users"] = bool(
                user.get("enabled", True)
                and user["sensitive_admin"]
                and not user["protected_user"]
            )

        for group in groups.values():
            dangerous = sorted(
                set(group.get("members", [])) & _DANGEROUS_PREWIN2000_MEMBERS
            )
            group["dangerous_members"] = dangerous
            group["prewin2000_exposure"] = bool(
                group.get("is_prewin2000_compatible") and dangerous
            )

        tier0_users = {
            sid for sid, user in users.items()
            if user.get("admin_count") == 1
            or set(user.get("effective_member_of", [])) & privileged_groups
        }
        for computer in computers.values():
            revealed = set(computer.get("rodc_revealed_users", []))
            computer["rodc_tier0_revealed_users"] = sorted(revealed & tier0_users)
            computer["rodc_tier0_exposure"] = bool(
                computer.get("is_rodc") and computer["rodc_tier0_revealed_users"]
            )

    @staticmethod
    def _apply_maq_activity(domain: dict, users: dict, groups: dict,
                            computers: dict) -> None:
        """Separate configured MAQ exposure from observed recent machine creation."""
        privileged = {
            sid for sid, group in groups.items() if group.get("high_value")
        }
        privileged.update(
            sid for sid, user in users.items() if user.get("sensitive_admin")
        )
        by_creator: dict[str, list[str]] = {}
        for sid, computer in computers.items():
            creator = computer.get("creator_sid", "")
            age_days = _datetime_days_since(computer.get("created"))
            recent_non_admin = bool(
                int(domain.get("maq", 0) or 0) > 0
                and creator
                and creator not in privileged
                and age_days is not None
                and age_days <= MAQ_ACTIVITY_WINDOW_DAYS
            )
            computer["created_age_days"] = age_days
            computer["maq_created_by_non_admin"] = recent_non_admin
            computer["maq_abuse_suspected"] = False
            computer["maq_creator_volume"] = 0
            if recent_non_admin:
                by_creator.setdefault(creator, []).append(sid)

        suspicious = {
            creator: object_ids for creator, object_ids in by_creator.items()
            if len(object_ids) >= MAQ_ACTIVITY_THRESHOLD
        }
        for creator, object_ids in suspicious.items():
            for sid in object_ids:
                computers[sid]["maq_abuse_suspected"] = True
                computers[sid]["maq_creator_volume"] = len(object_ids)

        domain["maq_activity"] = {
            "status": "observed" if suspicious else "no_threshold_breach",
            "window_days": MAQ_ACTIVITY_WINDOW_DAYS,
            "threshold": MAQ_ACTIVITY_THRESHOLD,
            "recent_non_admin_computers": sum(len(items) for items in by_creator.values()),
            "suspected_computers": sum(len(items) for items in suspicious.values()),
            "creators": [
                {"sid": creator, "count": len(object_ids)}
                for creator, object_ids in sorted(suspicious.items())
            ],
        }

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
        def _resolve_reference(value) -> str:
            dn = _linked_dn(value)
            resolved = self._dn_map.get(dn.lower()) if dn else ""
            if resolved:
                return resolved
            sid = _sid_from_dn(dn or value)
            if sid:
                self._sid_name.setdefault(sid, WELL_KNOWN_SIDS.get(sid, sid))
            return sid

        for obj in list(users.values()) + list(computers.values()):
            memberships = [
                sid for value in obj.get("member_of_dns", [])
                if (sid := _resolve_reference(value))
            ]
            primary_group_id = obj.get("primary_group_id")
            primary_group_sid = (
                f"{self.domain_sid}-{primary_group_id}"
                if self.domain_sid and primary_group_id else ""
            )
            if primary_group_sid and primary_group_sid in groups:
                memberships.append(primary_group_sid)
            obj["primary_group_sid"] = primary_group_sid or None
            obj["member_of"] = list(dict.fromkeys(memberships))

        for grp in groups.values():
            grp["members"] = [
                sid for value in grp.get("member_dns", [])
                if (sid := _resolve_reference(value))
            ]
            grp["member_of"] = [
                sid for value in grp.get("member_of_dns", [])
                if (sid := _resolve_reference(value))
            ]

        for computer in computers.values():
            for source_key, target_key in (
                ("rodc_revealed_user_dns", "rodc_revealed_users"),
                ("rodc_reveal_on_demand_dns", "rodc_reveal_on_demand"),
                ("rodc_never_reveal_dns", "rodc_never_reveal"),
            ):
                computer[target_key] = list(dict.fromkeys(
                    sid for value in computer.get(source_key, [])
                    if (sid := _resolve_reference(value))
                ))

        # ── Compute transitive group membership (BFS) ─────────────────────────
        _step("Resolving transitive group membership")
        self._resolve_transitive_membership(users, groups, computers)

        # These checks depend on resolved membership and, for AdminSDHolder,
        # the DACL fingerprints collected above.
        self._apply_adminsdholder_drift(users, groups)
        self._apply_security_posture(users, groups, computers)
        self._apply_maq_activity(domain, users, groups, computers)

        domain["protected_users_group_present"] = any(
            group.get("is_protected_users") for group in groups.values()
        )
        domain["prewin2000_exposure"] = any(
            group.get("prewin2000_exposure") for group in groups.values()
        )
        domain["adminsdholder_drift_count"] = sum(
            1 for obj in [*users.values(), *groups.values()]
            if obj.get("adminsdholder_drift")
        )
        domain["rodc_count"] = sum(1 for item in computers.values() if item.get("is_rodc"))
        domain["rodc_tier0_exposure_count"] = sum(
            1 for item in computers.values() if item.get("rodc_tier0_exposure")
        )
        domain["operating_system_inventory"] = {
            name: sum(
                1 for item in computers.values()
                if (item.get("os_inventory_key") or item.get("os_display") or "Unknown") == name
            )
            for name in sorted({
                item.get("os_inventory_key") or item.get("os_display") or "Unknown"
                for item in computers.values()
            })
        }

        all_sid_objects = [domain] + list(users.values()) + list(groups.values()) + list(computers.values())
        canonical_sids = sum(
            1 for obj in all_sid_objects
            if re.fullmatch(r"S-\d+(?:-\d+)+", str(obj.get("sid", "")), re.IGNORECASE)
        )
        system_counts = {
            role: sum(1 for item in computers.values() if item.get("computer_role") == role)
            for role in ("workstation", "server", "domain_controller")
        }
        system_counts["rodc"] = domain["rodc_count"]

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
                        "AD object permissions", "AD CS", "operating system inventory",
                        "RODC password replication policy", "authentication policies",
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
