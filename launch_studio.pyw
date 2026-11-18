#!/usr/bin/env python3
"""
JCT DownMax Studio - Zero-CMD Silent Launcher (Audited).
Verifies exact Studio identity on port 8798, handles concurrent launches safely,
and opens a new browser tab cleanly without black CMD popups.
"""

import json
import sys
import threading
import urllib.request
import webbrowser
from pathlib import Path

STUDIO_ROOT = Path(__file__).resolve().parent
if str(STUDIO_ROOT) not in sys.path:
    sys.path.insert(0, str(STUDIO_ROOT))

from app.server import StudioContext, create_server
from core.media_engine import set_subperceptual_priority

HOST = "127.0.0.1"
PORT = 8798


def is_studio_running(host: str, port: int) -> bool:
    try:
        with urllib.request.urlopen(f"http://{host}:{port}/api/health", timeout=1.0) as resp:
            if resp.status != 200:
                return False
            data = json.loads(resp.read().decode("utf-8"))
            return data.get("app") == "JCT DownMax Studio"
    except Exception:
        return False


def main() -> None:
    set_subperceptual_priority()
    url = f"http://{HOST}:{PORT}/"
    if is_studio_running(HOST, PORT):
        webbrowser.open_new_tab(url)
        return

    ctx = StudioContext()
    try:
        server = create_server(host=HOST, port=PORT, ctx=ctx)
    except OSError:
        ctx.shutdown()
        if is_studio_running(HOST, PORT):
            webbrowser.open_new_tab(url)
        return

    threading.Timer(0.4, lambda: webbrowser.open_new_tab(url)).start()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        ctx.shutdown()
        server.server_close()


if __name__ == "__main__":
    main()
