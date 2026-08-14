"""Optional process-level orchestration for the standalone Portico collector."""
from __future__ import annotations

import os
from pathlib import Path
import shutil
import subprocess
import tempfile
from typing import Any

from serket.external_surface import load_external_bridge


def collect_external_surface_bridge(
    domain: str,
    *,
    probe_ldaps: bool = True,
    timeout_seconds: int = 900,
) -> tuple[dict[str, Any] | None, dict[str, Any]]:
    """Run Portico only after explicit caller opt-in and return its sanitized bridge."""
    executable = shutil.which("portico")
    if not executable:
        return None, {
            "status": "unavailable",
            "mode": "optional_subprocess",
            "reason": "portico executable was not found in PATH",
        }
    if not isinstance(domain, str) or not domain.strip():
        return None, {"status": "error", "mode": "optional_subprocess", "reason": "domain is required"}

    flags = getattr(subprocess, "CREATE_NO_WINDOW", 0) if os.name == "nt" else 0
    try:
        with tempfile.TemporaryDirectory(prefix="serket-portico-") as temporary:
            root = Path(temporary)
            report = root / "assessment.portico.json"
            bridge = root / "portico-bridge.json"
            scan = [executable, "scan", domain.strip(), "--output", str(report)]
            if probe_ldaps:
                scan.append("--probe-ldaps")
            _run(scan, timeout_seconds, flags)
            _run([
                executable, "export", "--input", str(report),
                "--format", "serket-bridge", "--output", str(bridge),
            ], timeout_seconds, flags)
            return load_external_bridge(bridge), {
                "status": "collected",
                "mode": "optional_subprocess",
                "probe_ldaps": probe_ldaps,
            }
    except (OSError, subprocess.SubprocessError, ValueError) as exc:
        return None, {
            "status": "error",
            "mode": "optional_subprocess",
            "reason": str(exc)[:500],
        }


def _run(command: list[str], timeout_seconds: int, creationflags: int) -> None:
    completed = subprocess.run(
        command,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=timeout_seconds,
        check=False,
        shell=False,
        creationflags=creationflags,
    )
    if completed.returncode:
        detail = (completed.stderr or completed.stdout or "Portico command failed").strip()
        raise subprocess.SubprocessError(detail[:500])
