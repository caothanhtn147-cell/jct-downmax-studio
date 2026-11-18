#!/usr/bin/env python3
"""
JCT DownMax Studio - Hardened Local Web UI & API Server (Phase 4 & 5 Audited).
Fixes all Codex GPT Red-Team findings:
- Host & Origin allowlist validation (blocks DNS Rebinding & cross-site CSRF)
- Strict application/json Content-Type enforcement & Transfer-Encoding rejection
- URL routing via urlsplit(path).path (supports query strings)
- Socket read timeout & full-body read verification
- Self-recovering background queue scheduler (wakes up for deferred/retry jobs & startup backlog)
"""

from __future__ import annotations

import json
import shutil
import sys
import threading
import time
import urllib.parse
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Dict, Optional

STUDIO_ROOT = Path(__file__).resolve().parent.parent
if str(STUDIO_ROOT) not in sys.path:
    sys.path.insert(0, str(STUDIO_ROOT))

from core.db_vault import JobVault
from core.media_engine import (
    DEFAULT_DOWNLOAD_ROOT,
    configure_utf8_io,
    detect_environment,
    detect_platform,
    probe_metadata,
    set_subperceptual_priority,
    validate_cookies_browser,
    validate_media_url,
    validate_proxy_url,
)
from core.resilience import HostCircuitBreaker, QueueWorker

configure_utf8_io()

def get_default_db_path() -> Path:
    local_data = STUDIO_ROOT / "data"
    try:
        local_data.mkdir(parents=True, exist_ok=True)
        return local_data / "downmax_vault.db"
    except OSError:
        fallback = Path(os.environ.get("LOCALAPPDATA", str(Path.home()))) / "JCT_DownMax"
        fallback.mkdir(parents=True, exist_ok=True)
        return fallback / "downmax_vault.db"

UI_INDEX_PATH = STUDIO_ROOT / "app" / "ui" / "index.html"
DEFAULT_DB_PATH = get_default_db_path()
ALLOWED_STATUS_CLASSES = frozenset({"completed", "downloading", "queued", "failed", "probing", "cancelled"})


class StudioContext:
    def __init__(
        self,
        db_path: Path = DEFAULT_DB_PATH,
        download_root: Path = DEFAULT_DOWNLOAD_ROOT,
        enable_scheduler: bool = True,
    ) -> None:
        self.vault = JobVault(db_path)
        self.download_root = Path(download_root)
        self.download_root.mkdir(parents=True, exist_ok=True)
        self.breaker = HostCircuitBreaker(failure_threshold=3, cooldown_seconds=60.0)
        self.env = detect_environment()
        self._worker_lock = threading.Lock()
        self._stop_event = threading.Event()
        self._wake_event = threading.Event()
        self._worker = QueueWorker(
            vault=self.vault,
            breaker=self.breaker,
            env=self.env,
            allowed_root=self.download_root,
        )
        self._scheduler_thread: Optional[threading.Thread] = None
        if enable_scheduler:
            self._scheduler_thread = threading.Thread(target=self._scheduler_loop, daemon=True)
            self._scheduler_thread.start()

    def _scheduler_loop(self) -> None:
        """Continuously drains ready jobs & recovers deferred/startup backlog."""
        set_subperceptual_priority()
        while not self._stop_event.is_set():
            try:
                self.drain_once()
            except Exception:
                # Keep scheduler alive across transient DB or disk guard errors
                pass
            self._wake_event.wait(timeout=5.0)
            self._wake_event.clear()

    def drain_once(self) -> int:
        if not self._worker_lock.acquire(blocking=False):
            return 0
        try:
            return self._worker.drain_queue(max_jobs=20)
        finally:
            self._worker_lock.release()

    def run_drain_async(self) -> bool:
        self._wake_event.set()
        if self._scheduler_thread and self._scheduler_thread.is_alive():
            return True
        if not self._worker_lock.acquire(blocking=False):
            return False

        def _bg() -> None:
            try:
                set_subperceptual_priority()
                self._worker.drain_queue(max_jobs=20)
            finally:
                self._worker_lock.release()

        threading.Thread(target=_bg, daemon=True).start()
        return True

    def shutdown(self) -> None:
        self._stop_event.set()
        self._wake_event.set()
        if self._scheduler_thread and self._scheduler_thread.is_alive():
            self._scheduler_thread.join(timeout=2.0)


def _is_valid_local_host(host_header: str, server_port: int) -> bool:
    if not host_header:
        return False
    host = host_header.strip().lower()
    allowed = {
        f"127.0.0.1:{server_port}",
        f"localhost:{server_port}",
        "127.0.0.1",
        "localhost",
    }
    return host in allowed


def _is_valid_local_origin(origin_header: Optional[str], server_port: int) -> bool:
    if not origin_header:
        return True  # Non-browser local CLI/API call without Origin header
    parsed = urllib.parse.urlparse(origin_header.strip().lower())
    if parsed.scheme not in ("http", "https"):
        return False
    if parsed.hostname not in ("127.0.0.1", "localhost"):
        return False
    if parsed.port is not None and parsed.port != server_port:
        return False
    return True


def make_handler(ctx: StudioContext):
    class StudioHandler(BaseHTTPRequestHandler):
        server_version = "JCTDownMax/1.0"

        def setup(self) -> None:
            super().setup()
            self.request.settimeout(5.0)

        def log_message(self, format: str, *args: Any) -> None:
            return

        def _send_json(self, status: int, payload: Dict[str, Any]) -> None:
            body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.end_headers()
            self.wfile.write(body)

        def _validate_host(self) -> bool:
            port = self.server.server_address[1]
            if not _is_valid_local_host(self.headers.get("Host", ""), port):
                self._send_json(HTTPStatus.FORBIDDEN, {"ok": False, "error": "Invalid Host header."})
                return False
            return True

        def _read_json_body(self) -> Dict[str, Any]:
            if self.headers.get("Transfer-Encoding"):
                raise ValueError("Transfer-Encoding is not supported.")
            ctype = (self.headers.get("Content-Type") or "").split(";")[0].strip().lower()
            if ctype != "application/json":
                raise ValueError("Content-Type must be application/json.")
            length = int(self.headers.get("Content-Length") or "0")
            if length <= 0 or length > 65536:
                raise ValueError("Invalid request body size.")
            raw_bytes = self.rfile.read(length)
            if len(raw_bytes) != length:
                raise ValueError("Incomplete request body.")
            parsed = json.loads(raw_bytes.decode("utf-8"))
            if not isinstance(parsed, dict):
                raise ValueError("JSON body must be an object.")
            return parsed

        def do_GET(self) -> None:
            if not self._validate_host():
                return
            route = urllib.parse.urlsplit(self.path).path

            if route in ("/", "/index.html"):
                if not UI_INDEX_PATH.is_file():
                    self.send_error(HTTPStatus.NOT_FOUND, "UI not found")
                    return
                data = UI_INDEX_PATH.read_bytes()
                self.send_response(HTTPStatus.OK)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(data)))
                self.send_header("X-Content-Type-Options", "nosniff")
                self.end_headers()
                self.wfile.write(data)
                return

            if route == "/api/health":
                c_free = round(shutil.disk_usage("C:").free / (1024 ** 3), 2)
                self._send_json(
                    HTTPStatus.OK,
                    {
                        "app": "JCT DownMax Studio",
                        "status": "ok",
                        "yt_dlp": ctx.env.has_yt_dlp,
                        "ffmpeg": ctx.env.has_ffmpeg,
                        "c_free_gb": c_free,
                        "db_integrity": ctx.vault.integrity_check(),
                        "download_root": str(ctx.download_root),
                        "circuits": {
                            p: ctx.breaker.get_state(p)
                            for p in ("youtube", "tiktok", "facebook", "douyin", "generic")
                        },
                    },
                )
                return

            if route == "/api/jobs":
                jobs = ctx.vault.list_jobs(limit=50)
                for j in jobs:
                    sz = 0.0
                    op = str(j.get("output_path") or "")
                    if op:
                        try:
                            p = Path(op)
                            if p.is_file():
                                sz = round(p.stat().st_size / (1024 * 1024), 2)
                        except OSError:
                            pass
                    j["file_size_mb"] = sz
                self._send_json(HTTPStatus.OK, {"jobs": jobs})
                return

            self._send_json(HTTPStatus.NOT_FOUND, {"error": "Not found"})

        def do_POST(self) -> None:
            if not self._validate_host():
                return
            port = self.server.server_address[1]
            if not _is_valid_local_origin(self.headers.get("Origin"), port):
                self._send_json(HTTPStatus.FORBIDDEN, {"ok": False, "error": "Cross-origin POST forbidden."})
                return

            route = urllib.parse.urlsplit(self.path).path
            try:
                body = self._read_json_body()
            except Exception as exc:
                self._send_json(HTTPStatus.BAD_REQUEST, {"ok": False, "error": str(exc)})
                return

            if route == "/api/probe":
                url = str(body.get("url") or "")
                proxy = str(body.get("proxy") or "")
                cookies_browser = str(body.get("cookies_browser") or "")
                try:
                    clean = validate_media_url(url)
                    clean_proxy = validate_proxy_url(proxy)
                    clean_browser = validate_cookies_browser(cookies_browser)
                    meta = probe_metadata(clean, env=ctx.env, proxy=clean_proxy, cookies_browser=clean_browser)
                    self._send_json(HTTPStatus.OK, {"ok": True, "meta": meta})
                except Exception as exc:
                    self._send_json(HTTPStatus.BAD_REQUEST, {"ok": False, "error": str(exc)})
                return

            if route == "/api/enqueue":
                url = str(body.get("url") or "")
                quality = str(body.get("quality") or "best")
                title = str(body.get("title") or "")[:200]
                subtitles = bool(body.get("subtitles", False))
                proxy = str(body.get("proxy") or "")
                cookies_browser = str(body.get("cookies_browser") or "")
                if quality not in ("best", "1080p", "audio"):
                    quality = "best"
                try:
                    clean = validate_media_url(url)
                    clean_proxy = validate_proxy_url(proxy)
                    clean_browser = validate_cookies_browser(cookies_browser)
                    platform = detect_platform(clean)
                    target_dir = ctx.download_root / platform
                    job_id = ctx.vault.enqueue_job(
                        url=clean,
                        platform=platform,
                        output_dir=str(target_dir),
                        quality=quality,
                        title=title,
                        subtitles=subtitles,
                        proxy=clean_proxy,
                        cookies_browser=clean_browser,
                    )
                    started = ctx.run_drain_async()
                    self._send_json(
                        HTTPStatus.OK,
                        {"ok": True, "job_id": job_id, "platform": platform, "worker_triggered": started},
                    )
                except Exception as exc:
                    self._send_json(HTTPStatus.BAD_REQUEST, {"ok": False, "error": str(exc)})
                return

            if route == "/api/drain":
                started = ctx.run_drain_async()
                self._send_json(HTTPStatus.OK, {"ok": True, "worker_triggered": started})
                return

            self._send_json(HTTPStatus.NOT_FOUND, {"error": "Not found"})

    return StudioHandler


def create_server(host: str = "127.0.0.1", port: int = 8798, ctx: Optional[StudioContext] = None) -> ThreadingHTTPServer:
    active_ctx = ctx or StudioContext()
    server = ThreadingHTTPServer((host, port), make_handler(active_ctx))
    server.daemon_threads = True
    return server


if __name__ == "__main__":
    set_subperceptual_priority()
    ctx = StudioContext()
    server = create_server(host="127.0.0.1", port=8798, ctx=ctx)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        ctx.shutdown()
        server.server_close()
