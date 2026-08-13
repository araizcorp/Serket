"""
acl_parser.py — Windows Security Descriptor binary parser.

Parses nTSecurityDescriptor and msDS-AllowedToActOnBehalfOfOtherIdentity attributes
returned from LDAP as raw bytes, without requiring impacket.

Reference:
  MS-DTYP §2.4 — SECURITY_DESCRIPTOR
  MS-ADTS §5.1.3 — Access control in Active Directory
"""
from __future__ import annotations

import struct
from typing import Optional


# ── Access mask constants ─────────────────────────────────────────────────────

ADS_RIGHT_DS_CONTROL_ACCESS = 0x00000100   # Extended rights gate
ADS_RIGHT_DS_WRITE_PROP     = 0x00000020   # Write property
ADS_RIGHT_DS_SELF           = 0x00000008   # Validated write
ADS_RIGHT_WRITE_DAC         = 0x00040000
ADS_RIGHT_WRITE_OWNER       = 0x00080000
ADS_RIGHT_DS_CREATE_CHILD   = 0x00000001
GENERIC_ALL                 = 0x10000000
GENERIC_WRITE               = 0x40000000

# AD full-access mask equivalent (GenericAll expanded)
_FULL_CONTROL_MASK = (
    ADS_RIGHT_DS_CONTROL_ACCESS |
    ADS_RIGHT_DS_WRITE_PROP     |
    ADS_RIGHT_DS_CREATE_CHILD   |
    ADS_RIGHT_DS_SELF           |
    ADS_RIGHT_WRITE_DAC         |
    ADS_RIGHT_WRITE_OWNER
)

# ── Extended rights GUIDs ─────────────────────────────────────────────────────
# Stored little-endian in the OBJECT_TYPE field of Object ACEs.

EXT_RIGHT = {
    "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2": "GetChanges",
    "1131f6ab-9c07-11d1-f79f-00c04fc2dcd2": "GetChangesAll",      # DCSync
    "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2": "GetChangesInFilteredSet",
    "00299570-246d-11d0-a768-00aa006e0529": "ForceChangePassword",
    "45ec5156-db7e-47bb-b53f-dbeb2d03c40f": "ReName",
    "0e10c968-78fb-11d2-90d4-00c04f79dc55": "Enroll",              # ADCS enroll
    "a05b8cc2-17bc-4802-a710-e7c15ab866a2": "AutoEnroll",
}

# Property write GUIDs (ADS_RIGHT_DS_WRITE_PROP on specific property)
PROP_GUID = {
    "bf9679c0-0de6-11d0-a285-00aa003049e2": "member",             # AddMember
    "5b47d60f-6090-40b2-9f37-2a4de88f3063": "msDS-KeyCredentialLink",
    "3f78c3e5-f79a-46bd-a0b8-9d18116ddc79": "msDS-AllowedToActOnBehalfOfOtherIdentity",  # RBCD
    "bf967a68-0de6-11d0-a285-00aa003049e2": "userAccountControl",
    "f3a64788-5306-11d1-a9c5-0000f80367c1": "servicePrincipalName",
    "800d94d7-b7a1-42a1-b14d-7cae1423d07f": "msDS-AllowedToDelegateTo",
}

# MITRE ATT&CK mapping per edge type
MITRE = {
    "DCSync":              {"id": "T1003.006", "name": "OS Credential Dumping: DCSync"},
    "GenericAll":          {"id": "T1484.001", "name": "Domain Policy Modification"},
    "WriteDACL":           {"id": "T1222.001", "name": "Windows File & Directory Permissions Modification"},
    "WriteOwner":          {"id": "T1222.001", "name": "Windows File & Directory Permissions Modification"},
    "AllExtendedRights":   {"id": "T1078.002", "name": "Valid Accounts: Domain Accounts"},
    "ForceChangePassword": {"id": "T1098",     "name": "Account Manipulation"},
    "AddMember":           {"id": "T1098.001", "name": "Account Manipulation: Additional Cloud Credentials"},
    "AddKeyCredentialLink": {"id": "T1098",     "name": "Account Manipulation"},
    "AddAllowedToAct":     {"id": "T1558",     "name": "Steal or Forge Kerberos Tickets"},
    "WriteSPN":            {"id": "T1558.003", "name": "Kerberoasting"},
    "WriteAccountRestrictions": {"id": "T1098", "name": "Account Manipulation"},
    "GenericWrite":        {"id": "T1098",     "name": "Account Manipulation"},
    "AddSelf":             {"id": "T1098",     "name": "Account Manipulation"},
    "Owns":                {"id": "T1222.001", "name": "Windows File & Directory Permissions Modification"},
}

# ── Well-known SID resolution ─────────────────────────────────────────────────
# These SIDs are never stored as full S-1-5-21-... objects in AD but appear
# in ACEs. Mapping them to names prevents losing attribution in ACL analysis.

WELL_KNOWN_SIDS: dict[str, str] = {
    "S-1-0-0":   "Null Authority",
    "S-1-1-0":   "Everyone",
    "S-1-2-0":   "Local",
    "S-1-3-0":   "Creator Owner",
    "S-1-3-1":   "Creator Group",
    "S-1-5-2":   "Network",
    "S-1-5-4":   "Interactive",
    "S-1-5-6":   "Service",
    "S-1-5-7":   "Anonymous",
    "S-1-5-9":   "Enterprise Domain Controllers",
    "S-1-5-10":  "Self",
    "S-1-5-11":  "Authenticated Users",
    "S-1-5-12":  "Restricted Code",
    "S-1-5-13":  "Terminal Server User",
    "S-1-5-14":  "Remote Interactive Logon",
    "S-1-5-15":  "This Organization",
    "S-1-5-17":  "IIS_USRS",
    "S-1-5-32-554": "Pre-Windows 2000 Compatible Access",
    "S-1-5-18":  "SYSTEM",
    "S-1-5-19":  "NT Authority\\Local Service",
    "S-1-5-20":  "NT Authority\\Network Service",
    "S-1-5-32-544": "BUILTIN\\Administrators",
    "S-1-5-32-545": "BUILTIN\\Users",
    "S-1-5-32-546": "BUILTIN\\Guests",
    "S-1-5-32-547": "BUILTIN\\Power Users",
    "S-1-5-32-548": "BUILTIN\\Account Operators",
    "S-1-5-32-549": "BUILTIN\\Server Operators",
    "S-1-5-32-550": "BUILTIN\\Print Operators",
    "S-1-5-32-551": "BUILTIN\\Backup Operators",
    "S-1-5-32-552": "BUILTIN\\Replicators",
    "S-1-5-32-554": "BUILTIN\\Pre-Windows 2000 Compatible Access",
    "S-1-5-32-555": "BUILTIN\\Remote Desktop Users",
    "S-1-5-32-556": "BUILTIN\\Network Configuration Operators",
    "S-1-5-32-557": "BUILTIN\\Incoming Forest Trust Builders",
    "S-1-5-32-558": "BUILTIN\\Performance Monitor Users",
    "S-1-5-32-559": "BUILTIN\\Performance Log Users",
    "S-1-5-32-560": "BUILTIN\\Windows Authorization Access Group",
    "S-1-5-32-561": "BUILTIN\\Terminal Server License Servers",
    "S-1-5-32-562": "BUILTIN\\Distributed COM Users",
    "S-1-5-32-568": "BUILTIN\\IIS_IUSRS",
    "S-1-5-32-569": "BUILTIN\\Cryptographic Operators",
    "S-1-5-32-573": "BUILTIN\\Event Log Readers",
    "S-1-5-32-574": "BUILTIN\\Certificate Service DCOM Access",
    "S-1-5-32-575": "BUILTIN\\RDS Remote Access Servers",
    "S-1-5-32-576": "BUILTIN\\RDS Endpoint Servers",
    "S-1-5-32-577": "BUILTIN\\RDS Management Servers",
    "S-1-5-32-578": "BUILTIN\\Hyper-V Administrators",
    "S-1-5-32-579": "BUILTIN\\Access Control Assistance Operators",
    "S-1-5-32-580": "BUILTIN\\Remote Management Users",
    "S-1-5-64-10":  "NTLM Authentication",
    "S-1-5-64-14":  "SChannel Authentication",
    "S-1-5-64-21":  "Digest Authentication",
    "S-1-16-0":     "Untrusted Mandatory Level",
    "S-1-16-4096":  "Low Mandatory Level",
    "S-1-16-8192":  "Medium Mandatory Level",
    "S-1-16-8448":  "Medium Plus Mandatory Level",
    "S-1-16-12288": "High Mandatory Level",
    "S-1-16-16384": "System Mandatory Level",
    "S-1-16-20480": "Protected Process Mandatory Level",
    "S-1-16-28672": "Secure Process Mandatory Level",
}


# ── SID / GUID helpers ────────────────────────────────────────────────────────

def parse_sid(data: bytes) -> str:
    """Convert raw SID bytes to canonical S-R-I-S... string."""
    if not data or len(data) < 8:
        return ""
    try:
        revision   = data[0]
        sub_count  = data[1]
        authority  = int.from_bytes(data[2:8], "big")
        if len(data) < 8 + sub_count * 4:
            return ""
        subs = [
            str(struct.unpack_from("<I", data, 8 + i * 4)[0])
            for i in range(sub_count)
        ]
        return f"S-{revision}-{authority}-{'-'.join(subs)}"
    except (struct.error, IndexError):
        return ""


def format_guid(raw: bytes) -> str:
    """Convert 16-byte GUID (Windows mixed-endian) to lowercase string."""
    if len(raw) < 16:
        return ""
    try:
        p1, p2, p3 = struct.unpack_from("<IHH", raw, 0)
        p4 = raw[8:10].hex()
        p5 = raw[10:16].hex()
        return f"{p1:08x}-{p2:04x}-{p3:04x}-{p4}-{p5}"
    except struct.error:
        return ""


# ── ACE parsing ───────────────────────────────────────────────────────────────

def _classify_ace(mask: int, obj_guid: Optional[str]) -> Optional[str]:
    """
    Map an (access mask, optional object GUID) pair to a named edge type,
    or None if the ACE represents no attack-relevant permission.
    """
    # Generic all / full control
    if mask & GENERIC_ALL or (mask & _FULL_CONTROL_MASK) == _FULL_CONTROL_MASK:
        return "GenericAll"

    # Modify DACL → can grant self anything
    if mask & ADS_RIGHT_WRITE_DAC:
        return "WriteDACL"

    # Take ownership → can modify DACL
    if mask & ADS_RIGHT_WRITE_OWNER:
        return "WriteOwner"

    # Extended rights (require objectType GUID to be specific)
    if mask & ADS_RIGHT_DS_CONTROL_ACCESS:
        if obj_guid is None:
            return "AllExtendedRights"
        right = EXT_RIGHT.get(obj_guid)
        if right in {"GetChanges", "GetChangesAll", "GetChangesInFilteredSet"}:
            return right
        if right == "ForceChangePassword":
            return "ForceChangePassword"
        if right == "Enroll":
            return "Enroll"   # handled separately for ADCS
        if right == "GetChanges":
            return None        # read-only sync, not DCSync by itself
        return "AllExtendedRights"

    # Write to a specific property
    if mask & ADS_RIGHT_DS_WRITE_PROP:
        if obj_guid is None:
            return "GenericWrite"
        prop = PROP_GUID.get(obj_guid)
        if prop == "member":
            return "AddMember"
        if prop == "msDS-KeyCredentialLink":
            return "AddKeyCredentialLink"
        if prop == "msDS-AllowedToActOnBehalfOfOtherIdentity":
            return "AddAllowedToAct"
        if prop == "servicePrincipalName":
            return "WriteSPN"
        if prop in {"userAccountControl", "msDS-AllowedToDelegateTo"}:
            return "WriteAccountRestrictions"
        return "GenericWrite"

    # Validated write (AddSelf to group member)
    if mask & ADS_RIGHT_DS_SELF:
        return "AddSelf"

    return None


# ── Security Descriptor parser ────────────────────────────────────────────────

def parse_security_descriptor(raw_sd: bytes) -> list[dict]:
    """
    Parse a Windows SECURITY_DESCRIPTOR and return a list of ACE dicts:
    {
      'sid':         'S-1-5-21-...',
      'sid_name':    'BUILTIN\\Administrators' (if well-known) | '',
      'edge_type':   'GenericAll' | 'WriteDACL' | 'DCSync' | ...,
      'mask':        int,
      'object_guid': str | None,
      'ace_flags':   int,
      'mitre':       {'id': ..., 'name': ...} | None,
    }
    Only ALLOW ACEs of attack-relevant types are returned.
    """
    if not raw_sd or len(raw_sd) < 20:
        return []

    # SECURITY_DESCRIPTOR layout (self-relative form):
    # Offset  Size  Field
    #  0       1    Revision
    #  1       1    Sbz1
    #  2       2    Control
    #  4       4    OffsetOwner
    #  8       4    OffsetGroup
    # 12       4    OffsetSacl
    # 16       4    OffsetDacl
    try:
        control     = struct.unpack_from("<H", raw_sd, 2)[0]
        offset_owner = struct.unpack_from("<I", raw_sd, 4)[0]
        offset_dacl = struct.unpack_from("<I", raw_sd, 16)[0]
    except struct.error:
        return []

    results = []
    if offset_owner and offset_owner < len(raw_sd):
        owner_sid = parse_sid(raw_sd[offset_owner:])
        if owner_sid:
            results.append({
                "sid": owner_sid,
                "sid_name": WELL_KNOWN_SIDS.get(owner_sid, ""),
                "edge_type": "Owns",
                "mask": 0,
                "object_guid": None,
                "ace_flags": 0,
                "mitre": MITRE.get("Owns"),
            })

    SE_DACL_PRESENT = 0x0004
    if not (control & SE_DACL_PRESENT) or offset_dacl == 0:
        return results

    # ACL header at offset_dacl:
    # Offset  Size  Field
    #  0       1    AclRevision
    #  1       1    Sbz1
    #  2       2    AclSize
    #  4       2    AceCount
    #  6       2    Sbz2
    try:
        ace_count = struct.unpack_from("<H", raw_sd, offset_dacl + 4)[0]
    except struct.error:
        return []

    ace_offset = offset_dacl + 8   # first ACE starts here

    for _ in range(ace_count):
        if ace_offset + 4 > len(raw_sd):
            break

        ace_type  = raw_sd[ace_offset]
        ace_flags = raw_sd[ace_offset + 1]
        ace_size  = struct.unpack_from("<H", raw_sd, ace_offset + 2)[0]

        if ace_size < 4:
            break

        # Skip DENY and AUDIT ACEs — only ALLOW matters for attack paths
        # Type 0x00 = ACCESS_ALLOWED_ACE
        # Type 0x05 = ACCESS_ALLOWED_OBJECT_ACE
        if ace_type not in (0x00, 0x05):
            ace_offset += max(ace_size, 4)
            continue

        ace_body = raw_sd[ace_offset + 4 : ace_offset + ace_size]

        if ace_type == 0x00:
            # ACCESS_ALLOWED_ACE: Mask (4) + Sid (variable)
            if len(ace_body) < 8:
                ace_offset += max(ace_size, 4)
                continue
            mask       = struct.unpack_from("<I", ace_body, 0)[0]
            sid        = parse_sid(ace_body[4:])
            edge_type  = _classify_ace(mask, None)

            if edge_type and sid:
                results.append({
                    "sid":         sid,
                    "sid_name":    WELL_KNOWN_SIDS.get(sid, ""),
                    "edge_type":   edge_type,
                    "mask":        mask,
                    "object_guid": None,
                    "ace_flags":   ace_flags,
                    "mitre":       MITRE.get(edge_type),
                })

        elif ace_type == 0x05:
            # ACCESS_ALLOWED_OBJECT_ACE:
            # Mask (4) + Flags (4) + [ObjectType (16)] + [InheritedObjectType (16)] + Sid
            if len(ace_body) < 8:
                ace_offset += max(ace_size, 4)
                continue

            mask      = struct.unpack_from("<I", ace_body, 0)[0]
            obj_flags = struct.unpack_from("<I", ace_body, 4)[0]

            cursor       = 8
            object_guid  = None

            if obj_flags & 0x01:   # ACE_OBJECT_TYPE_PRESENT
                if cursor + 16 <= len(ace_body):
                    raw_guid    = ace_body[cursor : cursor + 16]
                    object_guid = format_guid(raw_guid)
                cursor += 16

            if obj_flags & 0x02:   # ACE_INHERITED_OBJECT_TYPE_PRESENT
                cursor += 16        # skip inherited type

            sid       = parse_sid(ace_body[cursor:])
            edge_type = _classify_ace(mask, object_guid)

            if edge_type and sid:
                results.append({
                    "sid":         sid,
                    "sid_name":    WELL_KNOWN_SIDS.get(sid, ""),
                    "edge_type":   edge_type,
                    "mask":        mask,
                    "object_guid": object_guid,
                    "ace_flags":   ace_flags,
                    "mitre":       MITRE.get(edge_type),
                })

        ace_offset += max(ace_size, 4)

    return results
