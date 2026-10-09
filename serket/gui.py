"""Native desktop window for the Serket Workbench (pywebview).

Opens the local FastAPI workbench inside a native OS window instead of a
browser tab — the same UI that ``--serve`` exposes, so behaviour is identical
whether the analysis runs on Kali (browser) or on a Windows foothold (GUI).

pywebview is a lazy, optional dependency (BSD-3, no copyleft). When it is not
installed or no graphical session exists, callers fall back to ``--serve``.
"""
from __future__ import annotations

import threading
import time
from typing import Any

WINDOW_TITLE = "Serket Workbench — AraizCorp"


def gui_available() -> bool:
    """True when a native window can be opened on this machine."""
    try:
        import webview  # noqa: F401
    except ImportError:
        return False
    # Headless Linux (typical Kali over SSH): no point trying to open a window.
    import os
    if os.name != "nt" and not os.environ.get("DISPLAY") and not os.environ.get("WAYLAND_DISPLAY"):
        return False
    return True


def run_gui(data: dict[str, Any], port: int = 8080) -> None:
    """Serve the loaded bundle locally and show it in a native window."""
    import uvicorn

    from serket.server.api import create_app

    import webview

    app = create_app(data)
    config = uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning")
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()

    # Wait for the socket before pointing the webview at it.
    deadline = time.time() + 15
    while not server.started:
        if time.time() > deadline or not thread.is_alive():
            server.should_exit = True
            raise RuntimeError("The local workbench server failed to start")
        time.sleep(0.05)

    window = webview.create_window(
        WINDOW_TITLE,
        f"http://127.0.0.1:{port}",
        width=1480,
        height=920,
        min_size=(1024, 640),
    )

    def _on_closed() -> None:
        server.should_exit = True

    window.events.closed += _on_closed
    try:
        webview.start()
    finally:
        server.should_exit = True
        thread.join(timeout=5)
