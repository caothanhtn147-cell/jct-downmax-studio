#!/usr/bin/env python3
"""
Hardened Unit & Red-Team Security Verification Suite for JCT DownMax Studio (Phase 2).
Covers SSRF, Domain Spoofing, Path Traversal, Option Injection, Deduplication,
Atomic Worker Claiming, and Zero-CMD Flag enforcement.
"""

import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

sys.path.insert(0, r"F:\JCT_DOWNMAX_STUDIO")

from core.db_vault import JobVault
from core.media_engine import (
    SUBPROCESS_FLAGS,
    MediaEnvironment,
    build_download_command,
    build_probe_command,
    detect_environment,
    detect_platform,
    probe_metadata,
    resolve_safe_output_dir,
    sanitize_filename,
    validate_media_url,
)


class TestDownMaxHardenedCore(unittest.TestCase):

    def test_01_sqlite_wal_dedup_and_atomic_claim(self):
        with tempfile.TemporaryDirectory() as tmp:
            vault = JobVault(Path(tmp) / "jobs.db")
            self.assertTrue(vault.integrity_check())

            id1 = vault.enqueue_job("https://www.youtube.com/watch?v=dQw4w9WgXcQ", "youtube", tmp, "1080p")
            id2 = vault.enqueue_job("https://www.youtube.com/watch?v=dQw4w9WgXcQ", "youtube", tmp, "1080p")
            self.assertEqual(id1, id2, "Duplicate active job must deduplicate to same ID")

            claimed1 = vault.claim_next_job("worker-A", lease_seconds=60)
            claimed2 = vault.claim_next_job("worker-B", lease_seconds=60)
            self.assertIsNotNone(claimed1)
            self.assertEqual(claimed1["id"], id1)
            self.assertIsNone(claimed2, "Second worker must NOT claim an already-leased job")

            # Wrong owner cannot complete job
            self.assertFalse(vault.complete_job(id1, "worker-B", "completed"))
            # Correct owner completes job
            self.assertTrue(vault.complete_job(id1, "worker-A", "completed", title="Demo", output_path="F:/out.mp4"))

            job = vault.get_job(id1)
            self.assertEqual(job["status"], "completed")
            self.assertEqual(job["attempts"], 1)

    def test_02_ssrf_and_scheme_blocking(self):
        self.assertEqual(
            validate_media_url("https://www.youtube.com/watch?v=abc", resolve_dns=False),
            "https://www.youtube.com/watch?v=abc",
        )
        blocked_urls = [
            "",
            "file:///C:/Windows/win.ini",
            "javascript:alert(1)",
            "http://127.0.0.1:8080/admin",
            "http://169.254.169.254/latest/meta-data/",
            "http://[::1]:8790/",
            "http://192.168.1.48:8795/",
            "http://10.0.0.1/internal",
            "http://localhost:3000/",
            "https://evil.com\n--exec",
        ]
        for bad in blocked_urls:
            with self.assertRaises(ValueError, msg=f"Must block SSRF/unsafe URL: {bad}"):
                validate_media_url(bad, resolve_dns=False)

    def test_03_platform_detection_anti_spoofing(self):
        self.assertEqual(detect_platform("https://youtu.be/abc"), "youtube")
        self.assertEqual(detect_platform("https://m.youtube.com/watch?v=abc"), "youtube")
        self.assertEqual(detect_platform("https://www.tiktok.com/@a/video/1"), "tiktok")
        self.assertEqual(detect_platform("https://fb.watch/xyz/"), "facebook")
        self.assertEqual(detect_platform("https://www.douyin.com/video/999"), "douyin")
        # Spoofing attempts must resolve to generic, NOT youtube
        self.assertEqual(detect_platform("https://youtube.com.evil.example/watch"), "generic")
        self.assertEqual(detect_platform("https://youtube.com@evil.example/watch"), "generic")

    def test_04_output_dir_containment_blocks_traversal(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "downloads"
            root.mkdir()
            safe = resolve_safe_output_dir(Path("youtube"), allowed_root=root)
            self.assertTrue(safe.is_relative_to(root.resolve()))

            for bad_dir in [Path(r"..\outside"), Path(r"C:\Windows\Temp"), root.parent / "escape"]:
                with self.assertRaises(ValueError):
                    resolve_safe_output_dir(bad_dir, allowed_root=root)

    def test_05_command_builder_has_double_dash_and_ignore_config(self):
        probe_cmd = build_probe_command("yt-dlp", "https://youtu.be/1")
        self.assertIn("--ignore-config", probe_cmd)
        self.assertEqual(probe_cmd[-2:], ["--", "https://youtu.be/1"])

        dl_cmd = build_download_command("yt-dlp", "https://youtu.be/1", Path("F:/out"), quality="best", has_ffmpeg=True, subtitles=True)
        self.assertIn("--ignore-config", dl_cmd)
        self.assertIn("--write-auto-subs", dl_cmd)
        self.assertEqual(dl_cmd[-2:], ["--", "https://youtu.be/1"])

    def test_06_probe_metadata_uses_zero_cmd_window_and_utf8(self):
        env = MediaEnvironment(yt_dlp_path="yt-dlp.exe", ffmpeg_path=None)
        fake_stdout = json.dumps({
            "id": "abc123",
            "title": "Sample Clip Tiếng Việt",
            "duration": 42,
            "uploader": "JCT Channel",
            "webpage_url": "https://youtu.be/abc123",
        })
        mock_proc = MagicMock(returncode=0, stdout=fake_stdout, stderr="")
        with patch("core.media_engine.subprocess.run", return_value=mock_proc) as mocked_run:
            info = probe_metadata("https://youtu.be/abc123", env=env)
            self.assertEqual(info["title"], "Sample Clip Tiếng Việt")
            _, kwargs = mocked_run.call_args
            self.assertEqual(kwargs.get("creationflags"), SUBPROCESS_FLAGS)
            self.assertEqual(kwargs.get("encoding"), "utf-8")

    def test_07_real_environment_has_yt_dlp(self):
        env = detect_environment()
        self.assertTrue(env.has_yt_dlp, "yt-dlp must be detected on workstation")


if __name__ == "__main__":
    unittest.main(verbosity=2)
