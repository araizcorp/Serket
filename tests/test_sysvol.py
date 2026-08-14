from __future__ import annotations

import struct

import pytest

from serket.collector.sysvol import SysvolError, collect_sysvol, parse_registry_pol


def _record(key: str, name: str, value: int) -> bytes:
    return (
        "[".encode("utf-16le")
        + key.encode("utf-16le") + ";".encode("utf-16le")
        + name.encode("utf-16le") + ";".encode("utf-16le")
        + struct.pack("<I", 4) + ";".encode("utf-16le")
        + struct.pack("<I", 4) + ";".encode("utf-16le")
        + struct.pack("<I", value) + "]".encode("utf-16le")
    )


def _string_record(key: str, name: str, value: str) -> bytes:
    data = (value + "\x00").encode("utf-16le")
    return (
        "[".encode("utf-16le")
        + key.encode("utf-16le") + ";".encode("utf-16le")
        + name.encode("utf-16le") + ";".encode("utf-16le")
        + struct.pack("<I", 1) + ";".encode("utf-16le")
        + struct.pack("<I", len(data)) + ";".encode("utf-16le")
        + data + "]".encode("utf-16le")
    )


def test_registry_pol_parser_preserves_order_and_typed_values():
    raw = b"PReg" + struct.pack("<I", 1) + _record(
        r"SYSTEM\CurrentControlSet\Control\Lsa", "LmCompatibilityLevel", 2,
    ) + _record(
        r"SYSTEM\CurrentControlSet\Services\NTDS\Parameters", "LDAPServerIntegrity", 1,
    )

    records = parse_registry_pol(raw)

    assert [item["name"] for item in records] == ["LmCompatibilityLevel", "LDAPServerIntegrity"]
    assert [item["value"] for item in records] == [2, 1]


def test_registry_pol_rejects_truncation():
    with pytest.raises(SysvolError, match="Truncated|Invalid"):
        parse_registry_pol(b"PReg" + struct.pack("<I", 1) + b"[\x00")


def test_explicit_sysvol_collects_registry_scripts_and_sanitized_groups(tmp_path):
    guid = "11111111-2222-3333-4444-555555555555"
    policy = tmp_path / "Policies" / f"{{{guid}}}"
    machine = policy / "Machine"
    machine.mkdir(parents=True)
    registry_secret = "arbitrary-registry-text"
    (machine / "Registry.pol").write_bytes(
        b"PReg" + struct.pack("<I", 1)
        + _record(r"SYSTEM\CurrentControlSet\Control\Lsa", "LmCompatibilityLevel", 1)
        + _string_record(r"Software\Vendor", "CustomValue", registry_secret)
    )
    startup = machine / "Scripts" / "Startup"
    startup.mkdir(parents=True)
    (startup / "bootstrap.ps1").write_text("Write-Host safe", encoding="utf-8")
    groups = machine / "Preferences" / "Groups"
    groups.mkdir(parents=True)
    secret_marker = "encrypted-value-must-not-survive"
    (groups / "Groups.xml").write_text(
        f'''<Groups><Group name="Local admins"><Properties action="U" groupName="Administrators" cpassword="{secret_marker}"><Members><Member name="Domain Users" action="ADD" /></Members></Properties></Group></Groups>''',
        encoding="utf-8",
    )
    gpos = [{"guid": guid, "id": f"GUID:{guid}", "name": "Weak policy"}]

    summary = collect_sysvol(tmp_path, gpos)

    assert summary["status"] == "collected"
    assert summary["files_parsed"] == 3
    evidence = gpos[0]["sysvol"]
    assert {item["kind"] for item in evidence["issues"]} == {
        "ntlm_compatibility", "gpp_cpassword", "broad_local_admin",
    }
    assert evidence["scripts"][0]["sha256"]
    assert secret_marker not in repr(evidence)
    assert registry_secret not in repr(evidence)
