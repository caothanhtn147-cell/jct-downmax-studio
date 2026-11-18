#!/usr/bin/env python3
"""
JCT DownMax Studio - Standalone Desktop App Window Launcher (0% CMD).
Starts the local sovereign server on 127.0.0.1:8798 (or reuses an active instance)
and launches a clean frameless App Window via Edge/Chrome --app mode.
"""

import json
import os
import shutil
import subprocess
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
CREATE_NO_WINDOW = 0x08000000 if os.name == "nt" else 0


def is_studio_running(host: str, port: int) -> bool:
    try:
        with urllib.request.urlopen(f"http://{host}:{port}/api/health", timeout=1.0) as resp:
            if resp.status != 200:
                return False
            data = json.loads(resp.read().decode("utf-8"))
            return data.get("app") == "JCT DownMax Studio"
    except Exception:
        return False


def _find_app_browser() -> str | None:
    candidates = [
        r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
        r"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
        r"C:\Program Files\Google\Chrome\Application\chrome.exe",
        shutil.which("msedge"),
        shutil.which("chrome"),
    ]
    for c in candidates:
        if c and os.path.isfile(c):
            return c
    return None


def open_desktop_window(url: str) -> None:
    browser_exe = _find_app_browser()
    if browser_exe:
        profile_dir = Path(os.environ.get("LOCALAPPDATA", str(Path.home()))) / "JCT_DownMax" / "app_profile"
        profile_dir.mkdir(parents=True, exist_ok=True)
        try:
            subprocess.Popen(
                [
                    browser_exe,
                    f"--app={url}",
                    f"--user-data-dir={profile_dir}",
                    "--window-size=1160,840",
                    "--no-first-run",
                    "--no-default-browser-check",
                ],
                creationflags=CREATE_NO_WINDOW,
            )
            return
        except Exception:
            pass
    webbrowser.open_new_tab(url)


def main() -> None:
    set_subperceptual_priority()
    url = f"http://{HOST}:{PORT}/"
    if is_studio_running(HOST, PORT):
        open_desktop_window(url)
        return

    ctx = StudioContext()
    try:
        server = create_server(host=HOST, port=PORT, ctx=ctx)
    except OSError:
        ctx.shutdown()
        if is_studio_running(HOST, PORT):
            open_desktop_window(url)
        return

    threading.Timer(0.4, lambda: open_desktop_window(url)).start()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        ctx.shutdown()
        server.server_close()


if __name__ == "__main__":
    main()
