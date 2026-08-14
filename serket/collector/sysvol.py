"""Bounded, offline SYSVOL evidence parser.

The collector only reads an explicitly supplied local or mounted directory. It
does not discover shares, authenticate to SMB, execute scripts, or persist GPP
password material.
"""
from __future__ import annotations

import hashlib
import re
import struct
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any


MAX_SYSVOL_FILES = 20_000
MAX_POLICY_FILE_BYTES = 16 * 1024 * 1024
_GUID = re.compile(r"^\{?([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\}?$", re.I)
_SCRIPT_SCOPES = {"startup", "shutdown", "logon", "logoff"}
_BROAD_PRINCIPALS = {
    "everyone", "authenticated users", "domain users", "usuarios del dominio",
    "todos", "anonymous logon",
}


class SysvolError(ValueError):
    """Raised when explicitly supplied SYSVOL evidence is unsafe or invalid."""


def _bounded_bytes(path: Path) -> bytes:
    try:
        size = path.stat().st_size
    except OSError as exc:
        raise SysvolError(f"Cannot inspect SYSVOL file: {path}") from exc
    if size > MAX_POLICY_FILE_BYTES:
        raise SysvolError(f"SYSVOL file exceeds {MAX_POLICY_FILE_BYTES} bytes: {path.name}")
    raw = path.read_bytes()
    if len(raw) > MAX_POLICY_FILE_BYTES:
        raise SysvolError(f"SYSVOL file exceeds {MAX_POLICY_FILE_BYTES} bytes: {path.name}")
    return raw


def _expect(raw: bytes, offset: int, token: bytes, label: str) -> int:
    if raw[offset:offset + len(token)] != token:
        raise SysvolError(f"Invalid Registry.pol {label} at offset {offset}")
    return offset + len(token)


def _utf16_field(raw: bytes, offset: int) -> tuple[str, int]:
    end = raw.find(b";\x00", offset)
    if end < 0 or (end - offset) % 2:
        raise SysvolError("Invalid Registry.pol UTF-16 field")
    try:
        value = raw[offset:end].decode("utf-16le").rstrip("\x00")
    except UnicodeDecodeError as exc:
        raise SysvolError("Invalid Registry.pol UTF-16 data") from exc
    return value, end + 2


def _decode_registry_value(value_type: int, data: bytes) -> Any:
    if value_type == 4 and len(data) == 4:
        return struct.unpack("<I", data)[0]
    if value_type == 5 and len(data) == 4:
        return struct.unpack(">I", data)[0]
    if value_type == 11 and len(data) == 8:
        return struct.unpack("<Q", data)[0]
    if value_type in {1, 2, 7}:
        try:
            text = data.decode("utf-16le").rstrip("\x00")
        except UnicodeDecodeError:
            return {"sha256": hashlib.sha256(data).hexdigest(), "size": len(data)}
        return text.split("\x00") if value_type == 7 else text
    return {"sha256": hashlib.sha256(data).hexdigest(), "size": len(data)}


def parse_registry_pol(raw: bytes) -> list[dict[str, Any]]:
    """Parse the MS-GPREG Registry Policy Message Syntax."""
    if len(raw) < 8 or raw[:4] != b"PReg" or struct.unpack("<I", raw[4:8])[0] != 1:
        raise SysvolError("Invalid Registry.pol signature or version")
    offset = 8
    records = []
    while offset < len(raw):
        while raw[offset:offset + 2] in {b"\x00\x00", b"\r\x00", b"\n\x00"}:
            offset += 2
            if offset >= len(raw):
                return records
        offset = _expect(raw, offset, b"[\x00", "record start")
        key, offset = _utf16_field(raw, offset)
        name, offset = _utf16_field(raw, offset)
        if offset + 4 > len(raw):
            raise SysvolError("Truncated Registry.pol value type")
        value_type = struct.unpack("<I", raw[offset:offset + 4])[0]
        offset = _expect(raw, offset + 4, b";\x00", "type delimiter")
        if offset + 4 > len(raw):
            raise SysvolError("Truncated Registry.pol value size")
        size = struct.unpack("<I", raw[offset:offset + 4])[0]
        if size > 65535:
            raise SysvolError("Registry.pol value exceeds protocol size limit")
        offset = _expect(raw, offset + 4, b";\x00", "size delimiter")
        if offset + size > len(raw):
            raise SysvolError("Truncated Registry.pol value data")
        data = raw[offset:offset + size]
        offset = _expect(raw, offset + size, b"]\x00", "record end")
        records.append({
            "key": key,
            "name": name,
            "type": value_type,
            "size": size,
            "value": _decode_registry_value(value_type, data),
        })
    return records


def _registry_issues(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    issues = []
    for record in records:
        key = str(record["key"]).casefold()
        name = str(record["name"]).casefold()
        value = record["value"]
        rule = None
        if name == "lmcompatibilitylevel" and isinstance(value, int) and value < 5:
            rule = ("ntlm_compatibility", "high", "LmCompatibilityLevel permits legacy NTLM responses")
        elif name == "nolmhash" and value == 0:
            rule = ("lm_hash_storage", "high", "NoLMHash is disabled")
        elif name == "runasppl" and value == 0 and "lsa" in key:
            rule = ("lsa_protection", "high", "LSA protection is explicitly disabled")
        elif name == "ldapserverintegrity" and isinstance(value, int) and value < 2:
            rule = ("ldap_signing", "high", "LDAP server signing is not required")
        elif name == "requiresecuritysignature" and value == 0:
            rule = ("smb_signing", "high", "SMB signing is not required")
        elif name in {"minimum_password_length", "minimumpasswordlength", "minpwdlen"} and isinstance(value, int) and value < 14:
            rule = ("password_length", "medium", "Minimum password length is below 14")
        elif name in {"passwordhistorysize", "passwordhistorylength"} and isinstance(value, int) and value < 24:
            rule = ("password_history", "medium", "Password history is below 24")
        if rule:
            issue, severity, description = rule
            issues.append({
                "kind": issue, "severity": severity, "description": description,
                "registry_key": record["key"], "value_name": record["name"],
                "configured_value": value,
            })
    return issues


def _sanitized_registry_record(record: dict[str, Any], scope: str) -> dict[str, Any]:
    value = record["value"]
    if not isinstance(value, (int, bool)):
        encoded = repr(value).encode("utf-8", errors="replace")
        value = {"sha256": hashlib.sha256(encoded).hexdigest(), "size": len(encoded)}
    return {
        "key": record["key"], "name": record["name"], "type": record["type"],
        "size": record["size"], "value": value, "scope": scope,
    }


def _gpo_guid(path: Path, root: Path) -> str | None:
    for part in reversed(path.relative_to(root).parts):
        match = _GUID.fullmatch(part)
        if match:
            return match.group(1).casefold()
    return None


def _groups_xml(path: Path, root: Path) -> tuple[list[dict], list[dict]]:
    raw = _bounded_bytes(path)
    if b"<!DOCTYPE" in raw.upper() or b"<!ENTITY" in raw.upper():
        raise SysvolError("DTD/entity declarations are not allowed in Groups.xml")
    try:
        document = ET.fromstring(raw)
    except ET.ParseError as exc:
        raise SysvolError(f"Invalid Groups.xml: {path}") from exc
    groups, issues = [], []
    if any("cpassword" in {key.casefold() for key in element.attrib} for element in document.iter()):
        issues.append({
            "kind": "gpp_cpassword", "severity": "critical",
            "description": "Group Policy Preference contains reversible cpassword material",
        })
    for group in document.iter():
        item_type = group.tag.rsplit("}", 1)[-1]
        if item_type not in {"Group", "User"}:
            continue
        props = next((child for child in group if child.tag.rsplit("}", 1)[-1] == "Properties"), None)
        if props is None:
            continue
        target = (
            props.attrib.get("groupName") or props.attrib.get("groupSid")
            or props.attrib.get("userName") or props.attrib.get("userSid")
            or group.attrib.get("name", "")
        )
        members = []
        for child in props.iter():
            if child.tag.rsplit("}", 1)[-1] == "Member":
                members.append({
                    "name": child.attrib.get("name", ""),
                    "sid": child.attrib.get("sid", ""),
                    "action": child.attrib.get("action", ""),
                })
        groups.append({
            "type": item_type.casefold(), "target": target,
            "action": props.attrib.get("action", ""), "members": members,
        })
        if item_type == "Group" and "admin" in target.casefold():
            broad = [m for m in members if m["name"].casefold() in _BROAD_PRINCIPALS]
            if broad:
                issues.append({
                    "kind": "broad_local_admin", "severity": "critical",
                    "description": "Broad principal is added to a local Administrators group",
                    "principals": [item["name"] for item in broad],
                })
    return groups, issues


def collect_sysvol(root_path: str | Path, gpos: list[dict]) -> dict[str, Any]:
    """Collect bounded evidence from an explicitly supplied SYSVOL copy."""
    root = Path(root_path).expanduser().resolve()
    if not root.is_dir():
        raise SysvolError(f"SYSVOL root is not a directory: {root}")
    files = []
    for path in root.rglob("*"):
        try:
            resolved = path.resolve()
            resolved.relative_to(root)
        except (OSError, ValueError) as exc:
            raise SysvolError(f"SYSVOL path escapes the explicit root: {path}") from exc
        if resolved.is_file():
            files.append(path)
    if len(files) > MAX_SYSVOL_FILES:
        raise SysvolError(f"SYSVOL root exceeds {MAX_SYSVOL_FILES} files")
    by_guid = {str(gpo.get("guid", "")).casefold(): gpo for gpo in gpos if gpo.get("guid")}
    parsed_files = 0
    errors = []
    for path in files:
        guid = _gpo_guid(path, root)
        gpo = by_guid.get(guid or "")
        if not gpo:
            continue
        evidence = gpo.setdefault("sysvol", {
            "coverage": "sysvol_offline", "registry": [], "scripts": [],
            "local_groups": [], "issues": [],
        })
        relative = path.relative_to(root).as_posix()
        try:
            if path.name.casefold() == "registry.pol":
                records = parse_registry_pol(_bounded_bytes(path))
                scope = "user" if any(part.casefold() == "user" for part in path.parts) else "machine"
                evidence["registry"].extend(
                    _sanitized_registry_record(record, scope) for record in records
                )
                evidence["issues"].extend(_registry_issues(records))
                parsed_files += 1
            elif path.name.casefold() == "groups.xml":
                groups, issues = _groups_xml(path, root)
                evidence["local_groups"].extend(groups)
                evidence["issues"].extend(issues)
                parsed_files += 1
            elif any(part.casefold() in _SCRIPT_SCOPES for part in path.parts):
                raw = _bounded_bytes(path)
                evidence["scripts"].append({
                    "path": relative, "size": len(raw),
                    "sha256": hashlib.sha256(raw).hexdigest(),
                    "scope": next(part.casefold() for part in path.parts if part.casefold() in _SCRIPT_SCOPES),
                })
                parsed_files += 1
        except (OSError, SysvolError) as exc:
            errors.append({"path": relative, "error": str(exc)})
    for gpo in gpos:
        evidence = gpo.get("sysvol")
        if evidence:
            evidence["issues"] = sorted(
                evidence["issues"], key=lambda item: (item.get("kind", ""), item.get("description", ""))
            )
    return {
        "status": "collected" if not errors else "partial",
        "coverage": "sysvol_offline",
        "source": "explicit_local_copy",
        "files_seen": len(files),
        "files_parsed": parsed_files,
        "gpos_with_evidence": sum(1 for gpo in gpos if gpo.get("sysvol")),
        "errors": errors,
    }
