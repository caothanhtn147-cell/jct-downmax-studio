#!/usr/bin/env python3
"""
Hardened Phase 3 Verification Suite (Includes all Codex GPT Regression Cases):
- Generation-scoped Circuit Breaker & HALF_OPEN permit release on local errors
- Non-blocking multi-platform queue drain (TikTok blocked -> YouTube still runs)
- Circuit block does NOT burn job attempts
- Strict lease ownership verification (lost_lease handling)
- Stale completion cannot close a newly opened circuit
- Drive C strictly >44.0 GB enforcement + portable ffmpeg auto-detection
"""

import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, r"F:\JCT_DOWNMAX_STUDIO")

from core.db_vault import JobVault
from core.media_engine import detect_environment
from core.resilience import (
    DiskGuardError,
    HostCircuitBreaker,
    QueueWorker,
    check_disk_guard,
)


class FakeClock:
    def __init__(self, start: float = 100.0) -> None:
        self.now = start

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


class TestPhase3HardenedResilience(unittest.TestCase):

    def test_01_circuit_breaker_transitions_and_stale_completion_guard(self):
        clock = FakeClock()
        cb = HostCircuitBreaker(failure_threshold=2, cooldown_seconds=30.0, clock=clock)

        p_old_a = cb.allow_request("youtube")
        p_old_b = cb.allow_request("youtube")
        self.assertIsNotNone(p_old_a)
        self.assertIsNotNone(p_old_b)

        # Request A fails twice and opens the circuit (generation advances!)
        cb.record_failure("youtube", p_old_a)
        cb.record_failure("youtube", p_old_a)
        self.assertEqual(cb.get_state("youtube"), "OPEN")

        # Stale completion B from old generation MUST NOT close the newly opened circuit!
        cb.record_success("youtube", p_old_b)
        self.assertEqual(cb.get_state("youtube"), "OPEN")
        self.assertIsNone(cb.allow_request("youtube"))

        # Advance past cooldown -> HALF_OPEN
        clock.advance(31.0)
        p_probe = cb.allow_request("youtube")
        self.assertIsNotNone(p_probe)
        self.assertIsNone(cb.allow_request("youtube"), "HALF_OPEN allows only 1 concurrent probe")

        cb.record_success("youtube", p_probe)
        self.assertEqual(cb.get_state("youtube"), "CLOSED")

    def test_02_half_open_permit_released_on_local_error(self):
        clock = FakeClock()
        cb = HostCircuitBreaker(failure_threshold=1, cooldown_seconds=10.0, clock=clock)
        p1 = cb.allow_request("tiktok")
        cb.record_failure("tiktok", p1)
        self.assertEqual(cb.get_state("tiktok"), "OPEN")

        clock.advance(11.0)
        p_probe = cb.allow_request("tiktok")
        self.assertIsNotNone(p_probe)
        # Simulate local exception before network call -> release_permit
        cb.release_permit("tiktok", p_probe)
        # Probe slot must be free again!
        self.assertIsNotNone(cb.allow_request("tiktok"))

    def test_03_drive_c_guard_strictly_greater_than_44gb(self):
        with patch("core.resilience.shutil.disk_usage") as mock_du:
            mock_du.return_value = type("DU", (), {"free": 44 * (1024 ** 3)})()
            with self.assertRaises(DiskGuardError):
                check_disk_guard(Path("sub"), min_drive_c_gb=44.0, allowed_root=Path("F:/JCT_DOWNMAX_STUDIO"))

    def test_04_multi_platform_drain_skips_blocked_host_without_burning_attempts(self):
        with tempfile.TemporaryDirectory() as tmp:
            vault = JobVault(Path(tmp) / "jobs.db")
            tt_id = vault.enqueue_job("https://tiktok.com/@a/video/1", "tiktok", tmp, "best")
            yt_id = vault.enqueue_job("https://youtu.be/good1", "youtube", tmp, "best")

            cb = HostCircuitBreaker(failure_threshold=1, cooldown_seconds=60.0)
            p_tt = cb.allow_request("tiktok")
            cb.record_failure("tiktok", p_tt)  # TikTok circuit is now OPEN

            def ok_downloader(**kwargs):
                return {"status": "completed", "output_dir": tmp}

            worker = QueueWorker(
                vault,
                breaker=cb,
                downloader=ok_downloader,
                max_attempts=3,
                defer_seconds=60.0,
                allowed_root=Path(tmp),
            )
            with patch("core.resilience.check_disk_guard", return_value=Path(tmp)):
                processed = worker.drain_queue()

            self.assertEqual(processed, 2)
            tt_job = vault.get_job(tt_id)
            yt_job = vault.get_job(yt_id)
            self.assertEqual(tt_job["status"], "queued", "Circuit-blocked job must stay queued")
            self.assertEqual(tt_job["attempts"], 0, "Circuit block must NOT burn attempts")
            self.assertEqual(yt_job["status"], "completed", "YouTube job must NOT be starved by blocked TikTok")

    def test_05_lost_lease_detected_on_completion(self):
        with tempfile.TemporaryDirectory() as tmp:
            vault = JobVault(Path(tmp) / "jobs.db")
            jid = vault.enqueue_job("https://youtu.be/lease1", "youtube", tmp, "best")

            def steal_lease_downloader(**kwargs):
                # Another process steals ownership before completion
                with vault._connect() as conn:
                    conn.execute("BEGIN IMMEDIATE;")
                    conn.execute("UPDATE jobs SET owner_token='other-worker' WHERE id=?", (jid,))
                    conn.execute("COMMIT;")
                return {"status": "completed", "output_dir": tmp}

            worker = QueueWorker(vault, downloader=steal_lease_downloader, allowed_root=Path(tmp))
            with patch("core.resilience.check_disk_guard", return_value=Path(tmp)):
                res = worker.process_one()

            self.assertEqual(res["outcome"], "lost_lease")
            self.assertEqual(worker.stats.succeeded, 0)
            self.assertEqual(worker.stats.lost_lease, 1)

    def test_06_portable_ffmpeg_auto_detected(self):
        env = detect_environment()
        self.assertTrue(env.has_yt_dlp)
        self.assertTrue(env.has_ffmpeg, "Portable ffmpeg.exe on Drive F must be auto-detected")


if __name__ == "__main__":
    unittest.main(verbosity=2)
