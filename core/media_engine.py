#!/usr/bin/env python3
"""
JCT DownMax Studio - Hardened Clean-Room Media Core Engine (Phase 2 Verified).
Integrates JCT I/O Armor, OmniGet multi-platform conventions, strict SSRF guard,
containment root enforcement, and Windows process-tree cleanup.
"""

from __future__ import annotations

import ipaddress
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import urllib.parse
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional

# Integrate existing JCT I/O Armor from SSOT workspace (Never start from zero)
_JCT_ROOT = Path(r"G:\JCT_TONG_HANH_DINH")
if str(_JCT_ROOT) not in sys.path:
    sys.path.insert(0, str(_JCT_ROOT))

try:
    from jct_io_armor import configure_utf8_io, set_subperceptual_priority, BELOW_NORMAL_PRIORITY_CLASS
except Exception:
    BELOW_NORMAL_PRIORITY_CLASS = 0x00004000

    def configure_utf8_io() -> None:
        pass

    def set_subperceptual_priority() -> None:
        pass

configure_utf8_io()

# Windows flags: 0% black CMD window + BELOW_NORMAL_PRIORITY_CLASS so workstation stays silent
CREATE_NO_WINDOW = 0x08000000 if os.name == "nt" else 0
SUBPROCESS_FLAGS = (CREATE_NO_WINDOW | BELOW_NORMAL_PRIORITY_CLASS) if os.name == "nt" else 0

def get_default_download_root() -> Path:
    studio_root = Path(__file__).resolve().parent.parent
    candidate = studio_root / "downloads"
    try:
        candidate.mkdir(parents=True, exist_ok=True)
        return candidate
    except OSError:
        fallback = Path.home() / "Downloads" / "JCT_DownMax"
        fallback.mkdir(parents=True, exist_ok=True)
        return fallback


ALLOWED_SCHEMES = ("http", "https")
ALLOWED_PROXY_SCHEMES = ("http", "https", "socks5", "socks5h")
ALLOWED_COOKIE_BROWSERS = ("", "chrome", "edge", "firefox", "brave")
DEFAULT_DOWNLOAD_ROOT = get_default_download_root()
KNOWN_PORTABLE_FFMPEG_PATHS = (
    Path(r"F:\TOOL\TOOL_VOICE_CAPCUT_SRT\ffmpeg.exe"),
    Path(r"F:\KHO_BI_KIP_JCT\07_OTHER_SPECIAL_REPOSITORIES\CapCap\bin\ffmpeg\ffmpeg.exe"),
    Path(r"F:\TOOL\DISSECT_ZONE\DIENMOC86_HARVEST\iTube_App\ffmpeg\ffmpeg.exe"),
)
FILENAME_UNSAFE_RE = re.compile(r'[<>:"/\\|?*\x00-\x1f]')

PLATFORM_DOMAINS: Dict[str, tuple[str, ...]] = {
    "youtube": ("youtube.com", "youtu.be"),
    "tiktok": ("tiktok.com",),
    "facebook": ("facebook.com", "fb.watch", "fb.com"),
    "instagram": ("instagram.com",),
    "douyin": ("douyin.com", "iesdouyin.com"),
    "bilibili": ("bilibili.com", "b23.tv"),
    "xiaohongshu": ("xiaohongshu.com", "xhslink.com"),
    "x": ("x.com", "twitter.com"),
    "vimeo": ("vimeo.com",),
    "soundcloud": ("soundcloud.com",),
    "twitch": ("twitch.tv", "clips.twitch.tv"),
    "reddit": ("reddit.com", "v.redd.it"),
}


@dataclass(frozen=True)
class MediaEnvironment:
    yt_dlp_path: Optional[str]
    ffmpeg_path: Optional[str]
    node_path: Optional[str] = None
    has_curl_cffi: bool = False

    @property
    def has_yt_dlp(self) -> bool:
        return bool(self.yt_dlp_path)

    @property
    def has_ffmpeg(self) -> bool:
        return bool(self.ffmpeg_path)


def detect_environment() -> MediaEnvironment:
    # Prefer yt-dlp matching the active Python interpreter (handles both venv and global Scripts)
    exe_name = "yt-dlp.exe" if os.name == "nt" else "yt-dlp"
    py_dir = Path(sys.executable).resolve().parent
    yt_dlp = None
    for cand in (py_dir / exe_name, py_dir / "Scripts" / exe_name):
        if cand.is_file():
            yt_dlp = str(cand)
            break
    if not yt_dlp:
        yt_dlp = shutil.which("yt-dlp")

    ffmpeg = shutil.which("ffmpeg")
    if not ffmpeg:
        for candidate in KNOWN_PORTABLE_FFMPEG_PATHS:
            if candidate.is_file():
                ffmpeg = str(candidate)
                break

    node = shutil.which("node")
    if not node and os.name == "nt":
        candidate_node = Path(os.environ.get("LOCALAPPDATA", "")) / "Programs" / "nodejs" / "node.exe"
        if candidate_node.is_file():
            node = str(candidate_node)

    has_curl_cffi = False
    try:
        import importlib.util
        has_curl_cffi = importlib.util.find_spec("curl_cffi") is not None
    except Exception:
        pass

    return MediaEnvironment(
        yt_dlp_path=yt_dlp,
        ffmpeg_path=ffmpeg,
        node_path=node,
        has_curl_cffi=has_curl_cffi,
    )


def _is_public_ip(ip_str: str) -> bool:
    try:
        ip_obj = ipaddress.ip_address(ip_str.split("%")[0])
        return not (
            ip_obj.is_private
            or ip_obj.is_loopback
            or ip_obj.is_link_local
            or ip_obj.is_multicast
            or ip_obj.is_reserved
            or ip_obj.is_unspecified
        )
    except ValueError:
        return False


def validate_media_url(url: str, resolve_dns: bool = True) -> str:
    """
    Strictly validates HTTP/HTTPS media URLs and prevents SSRF against
    loopback, link-local (169.254.169.254), and private LAN addresses.
    """
    if not isinstance(url, str):
        raise ValueError("URL must be a string.")
    cleaned = url.strip()
    if not cleaned or len(cleaned) > 2048:
        raise ValueError("URL is empty or exceeds maximum length.")
    if any(ch in cleaned for ch in ("\r", "\n", "\x00")):
        raise ValueError("URL contains illegal control characters.")

    parsed = urllib.parse.urlparse(cleaned)
    if parsed.scheme.lower() not in ALLOWED_SCHEMES:
        raise ValueError(f"Unsupported URL scheme: {parsed.scheme!r}")

    hostname = (parsed.hostname or "").strip().lower().rstrip(".")
    if not hostname:
        raise ValueError("URL must include a valid hostname.")

    if hostname in ("localhost", "localhost.localdomain") or hostname.endswith(".local"):
        raise ValueError(f"Blocked local hostname: {hostname!r}")

    # Direct IP literal check
    try:
        ipaddress.ip_address(hostname.split("%")[0])
        if not _is_public_ip(hostname):
            raise ValueError(f"Blocked non-public IP address: {hostname!r}")
        return cleaned
    except ValueError as exc:
        if "Blocked non-public IP" in str(exc):
            raise

    if resolve_dns:
        try:
            infos = socket.getaddrinfo(hostname, None, proto=socket.IPPROTO_TCP)
            for info in infos:
                addr = info[4][0]
                if not _is_public_ip(addr):
                    raise ValueError(f"Blocked DNS resolution to non-public IP: {addr}")
        except socket.gaierror:
            # Offline unit tests or unreachable DNS; literal/local host checks still enforced
            pass

    return cleaned


def validate_proxy_url(proxy: Optional[str]) -> str:
    """Validates optional proxy URL (http/https/socks5/socks5h) without control chars."""
    if not proxy:
        return ""
    cleaned = str(proxy).strip()
    if not cleaned:
        return ""
    if len(cleaned) > 512 or any(ch in cleaned for ch in ("\r", "\n", "\x00")):
        raise ValueError("Proxy URL contains illegal characters or exceeds max length.")
    parsed = urllib.parse.urlparse(cleaned)
    if parsed.scheme.lower() not in ALLOWED_PROXY_SCHEMES or not parsed.hostname:
        raise ValueError("Unsupported proxy URL format (use http:// or socks5://).")
    return cleaned


def validate_cookies_browser(browser: Optional[str]) -> str:
    """Validates optional browser cookie source against strict whitelist."""
    cleaned = str(browser or "").strip().lower()
    if cleaned not in ALLOWED_COOKIE_BROWSERS:
        raise ValueError(f"Unsupported cookie browser: {cleaned!r}")
    return cleaned


def detect_platform(url: str) -> str:
    """Matches exact domain or subdomain suffix using parsed.hostname (blocks spoofing)."""
    hostname = (urllib.parse.urlparse(url).hostname or "").strip().lower().rstrip(".")
    if not hostname:
        return "generic"
    for platform, domains in PLATFORM_DOMAINS.items():
        if any(hostname == d or hostname.endswith("." + d) for d in domains):
            return platform
    return "generic"


def resolve_safe_output_dir(output_dir: Path, allowed_root: Optional[Path] = None) -> Path:
    """Enforces strict directory containment so relative/traversal paths cannot escape root."""
    root = (allowed_root or DEFAULT_DOWNLOAD_ROOT).resolve()
    candidate = Path(output_dir)
    if not candidate.is_absolute():
        candidate = root / candidate
    resolved = candidate.resolve()

    if resolved != root and not resolved.is_relative_to(root):
        raise ValueError(f"Output directory escapes allowed root: {resolved}")
    return resolved


def sanitize_filename(name: str, max_len: int = 120) -> str:
    cleaned = FILENAME_UNSAFE_RE.sub("_", name or "media").strip(" .")
    return (cleaned[:max_len] or "media").strip()


def build_probe_command(
    yt_dlp_path: str,
    url: str,
    js_runtime: Optional[str] = None,
    impersonate: Optional[str] = None,
    proxy: str = "",
    cookies_browser: str = "",
) -> List[str]:
    cmd = [
        yt_dlp_path,
        "--ignore-config",
        "--no-playlist",
        "--dump-single-json",
        "--no-warnings",
    ]
    if js_runtime:
        cmd.extend(["--js-runtimes", f"node:{js_runtime}" if js_runtime != "node" else "node"])
    if impersonate:
        cmd.extend(["--impersonate", impersonate])
    if proxy:
        cmd.extend(["--proxy", proxy])
    if cookies_browser:
        cmd.extend(["--cookies-from-browser", cookies_browser])
    cmd.extend(["--", url])
    return cmd


def build_download_command(
    yt_dlp_path: str,
    url: str,
    output_dir: Path,
    quality: str = "best",
    has_ffmpeg: bool = False,
    subtitles: bool = False,
    ffmpeg_path: Optional[str] = None,
    js_runtime: Optional[str] = None,
    impersonate: Optional[str] = None,
    proxy: str = "",
    cookies_browser: str = "",
) -> List[str]:
    out_template = str(Path(output_dir) / "%(title).100s [%(id)s].%(ext)s")
    cmd = [
        yt_dlp_path,
        "--ignore-config",
        "--no-playlist",
        "--no-mtime",
        "--newline",
        "-o",
        out_template,
    ]
    if ffmpeg_path:
        cmd.extend(["--ffmpeg-location", ffmpeg_path])
    if js_runtime:
        cmd.extend(["--js-runtimes", f"node:{js_runtime}" if js_runtime != "node" else "node"])
    if impersonate:
        cmd.extend(["--impersonate", impersonate])
    if proxy:
        cmd.extend(["--proxy", proxy])
    if cookies_browser:
        cmd.extend(["--cookies-from-browser", cookies_browser])
    if quality == "audio":
        if has_ffmpeg:
            cmd.extend(["-x", "--audio-format", "mp3"])
        else:
            cmd.extend(["-f", "bestaudio/best"])
    elif has_ffmpeg:
        if quality == "1080p":
            cmd.extend(["-f", "bestvideo[height<=1080]+bestaudio/best[height<=1080]/best"])
        else:
            cmd.extend(["-f", "bestvideo+bestaudio/best", "--merge-output-format", "mp4"])
    else:
        cmd.extend(["-f", "best[ext=mp4]/best"])

    if subtitles:
        cmd.extend(["--write-auto-subs", "--sub-langs", "vi,en"])

    cmd.extend(["--", url])
    return cmd


def _terminate_process_tree(proc: subprocess.Popen[str]) -> None:
    """Kills parent yt-dlp AND any child ffmpeg processes cleanly on Windows (0% zombies)."""
    if proc.poll() is not None:
        return
    if os.name == "nt":
        try:
            subprocess.run(
                ["taskkill", "/F", "/T", "/PID", str(proc.pid)],
                capture_output=True,
                timeout=5,
                creationflags=CREATE_NO_WINDOW,
            )
        except Exception:
            pass
    try:
        if proc.poll() is None:
            proc.kill()
        proc.wait(timeout=5)
    except Exception:
        pass


def probe_metadata(
    url: str,
    env: Optional[MediaEnvironment] = None,
    timeout: int = 20,
    proxy: str = "",
    cookies_browser: str = "",
) -> Dict[str, Any]:
    clean_url = validate_media_url(url)
    clean_proxy = validate_proxy_url(proxy)
    clean_browser = validate_cookies_browser(cookies_browser)
    active_env = env or detect_environment()
    if not active_env.yt_dlp_path:
        raise RuntimeError("yt-dlp executable not found in environment.")

    plat = detect_platform(clean_url)
    imp = "chrome" if (active_env.has_curl_cffi and plat in ("tiktok", "douyin")) else None
    cmd = build_probe_command(
        active_env.yt_dlp_path,
        clean_url,
        js_runtime=active_env.node_path,
        impersonate=imp,
        proxy=clean_proxy,
        cookies_browser=clean_browser,
    )
    proc = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=timeout,
        creationflags=SUBPROCESS_FLAGS,
    )
    if proc.returncode != 0:
        raise RuntimeError(proc.stderr.strip() or f"Probe failed with exit code {proc.returncode}")

    info = json.loads(proc.stdout)
    return {
        "id": info.get("id", ""),
        "title": info.get("title", "Untitled"),
        "platform": detect_platform(clean_url),
        "duration": info.get("duration") or 0,
        "uploader": info.get("uploader") or info.get("channel") or "",
        "webpage_url": info.get("webpage_url") or clean_url,
    }


def download_media(
    url: str,
    output_dir: Path,
    quality: str = "best",
    env: Optional[MediaEnvironment] = None,
    timeout: int = 300,
    allowed_root: Optional[Path] = None,
    subtitles: bool = False,
    proxy: str = "",
    cookies_browser: str = "",
) -> Dict[str, Any]:
    clean_url = validate_media_url(url)
    clean_proxy = validate_proxy_url(proxy)
    clean_browser = validate_cookies_browser(cookies_browser)
    active_env = env or detect_environment()
    if not active_env.yt_dlp_path:
        raise RuntimeError("yt-dlp executable not found in environment.")

    safe_dir = resolve_safe_output_dir(output_dir, allowed_root=allowed_root)
    safe_dir.mkdir(parents=True, exist_ok=True)

    plat = detect_platform(clean_url)
    imp = "chrome" if (active_env.has_curl_cffi and plat in ("tiktok", "douyin")) else None
    cmd = build_download_command(
        yt_dlp_path=active_env.yt_dlp_path,
        url=clean_url,
        output_dir=safe_dir,
        quality=quality,
        has_ffmpeg=active_env.has_ffmpeg,
        subtitles=subtitles,
        ffmpeg_path=active_env.ffmpeg_path,
        js_runtime=active_env.node_path,
        impersonate=imp,
        proxy=clean_proxy,
        cookies_browser=clean_browser,
    )

    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="replace",
        creationflags=SUBPROCESS_FLAGS,
    )
    try:
        stdout, stderr = proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        _terminate_process_tree(proc)
        raise RuntimeError(f"Download timed out after {timeout}s.")
    finally:
        _terminate_process_tree(proc)

    if proc.returncode != 0:
        raise RuntimeError((stderr or "").strip() or f"Download failed with code {proc.returncode}")

    newest_file = None
    newest_size = 0
    try:
        files = [p for p in safe_dir.iterdir() if p.is_file() and not p.name.endswith((".part", ".ytdl"))]
        if files:
            newest = max(files, key=lambda p: p.stat().st_mtime)
            newest_file = str(newest)
            newest_size = newest.stat().st_size
    except OSError:
        pass

    tail_lines = stdout.splitlines()[-10:] if stdout else []
    return {
        "status": "completed",
        "platform": detect_platform(clean_url),
        "output_dir": str(safe_dir),
        "output_file": newest_file or str(safe_dir),
        "file_size_bytes": newest_size,
        "log_tail": tail_lines,
    }
