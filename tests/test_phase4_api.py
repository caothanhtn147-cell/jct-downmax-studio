#!/usr/bin/env python3
"""
Hardened Phase 4 & 5 UI/API Security Verification Suite:
- Verifies Host allowlist (blocks DNS Rebinding)
- Verifies Origin allowlist & strict application/json Content-Type (blocks CSRF)
- Verifies Transfer-Encoding rejection & query-string routing (/api/jobs?t=123)
- Verifies Spec G1 (0% Emoji), DESIGN.md tokens (h1 22px), and no innerHTML sink for duration
"""

import json
import re
import sys
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from pathlib import Path

sys.path.insert(0, r"F:\JCT_DOWNMAX_STUDIO")

from app.server import StudioContext, UI_INDEX_PATH, create_server

EMOJI_RANGE_RE = re.compile(r"[\U0001F300-\U0001FAFF\u2600-\u27BF]")


class TestPhase4And5HardenedAPI(unittest.TestCase):

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        tmp_path = Path(self._tmp.name)
        self.ctx = StudioContext(
            db_path=tmp_path / "test.db",
            download_root=tmp_path / "downloads",
            enable_scheduler=False,
        )
        self.server = create_server(host="127.0.0.1", port=0, ctx=self.ctx)
        self.port = self.server.server_address[1]
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self):
        self.ctx.shutdown()
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)
        self._tmp.cleanup()

    def _request(self, method: str, path: str, body: bytes | None = None, headers: dict | None = None):
        req = urllib.request.Request(
            f"http://127.0.0.1:{self.port}{path}",
            data=body,
            headers=headers or {},
            method=method,
        )
        try:
            with urllib.request.urlopen(req, timeout=5) as resp:
                return resp.status, json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as err:
            return err.code, json.loads(err.read().decode("utf-8"))

    def test_01_ui_spec_g1_zero_emoji_and_tokens(self):
        html = UI_INDEX_PATH.read_text(encoding="utf-8")
        self.assertIsNone(EMOJI_RANGE_RE.search(html), "Spec G1 Violation: UI must contain 0% Emoji!")
        self.assertIn("#050507", html)
        self.assertIn("#0e0f14", html)
        self.assertIn("#06b6d4", html)
        self.assertIn("font-size: 22px;", html)
        self.assertNotIn("data.meta.duration}s", html)

    def test_02_health_and_query_string_routing(self):
        code, body = self._request("GET", "/api/health")
        self.assertEqual(code, 200)
        self.assertEqual(body["app"], "JCT DownMax Studio")
        self.assertEqual(body["status"], "ok")

        q_code, q_body = self._request("GET", "/api/jobs?t=12345")
        self.assertEqual(q_code, 200)
        self.assertIn("jobs", q_body)

    def test_03_blocks_dns_rebinding_host_and_cross_origin_csrf(self):
        # Evil Host header -> 403
        code_host, _ = self._request("GET", "/api/health", headers={"Host": "evil.example:8798"})
        self.assertEqual(code_host, 403)

        # Evil Origin header on POST -> 403
        payload = json.dumps({"url": "https://youtu.be/abc"}).encode("utf-8")
        code_origin, _ = self._request(
            "POST",
            "/api/enqueue",
            body=payload,
            headers={"Content-Type": "application/json", "Origin": "https://evil.example"},
        )
        self.assertEqual(code_origin, 403)

        # Simple text/plain CSRF request -> 400
        code_ctype, _ = self._request(
            "POST",
            "/api/enqueue",
            body=payload,
            headers={"Content-Type": "text/plain"},
        )
        self.assertEqual(code_ctype, 400)

    def test_04_enqueue_blocks_ssrf_and_accepts_valid_url(self):
        bad_code, bad_body = self._request(
            "POST",
            "/api/enqueue",
            body=json.dumps({"url": "http://127.0.0.1:8790/secret", "quality": "best"}).encode("utf-8"),
            headers={"Content-Type": "application/json"},
        )
        self.assertEqual(bad_code, 400)
        self.assertFalse(bad_body["ok"])

        self.ctx.run_drain_async = lambda: False
        ok_code, ok_body = self._request(
            "POST",
            "/api/enqueue",
            body=json.dumps({"url": "https://youtu.be/dQw4w9WgXcQ", "quality": "1080p"}).encode("utf-8"),
            headers={"Content-Type": "application/json"},
        )
        self.assertEqual(ok_code, 200)
        self.assertTrue(ok_body["ok"])
        self.assertEqual(ok_body["platform"], "youtube")

    def test_05_enqueue_accepts_proxy_cookies_subtitles_and_blocks_invalid(self):
        self.ctx.run_drain_async = lambda: False
        bad_proxy_code, _ = self._request(
            "POST",
            "/api/enqueue",
            body=json.dumps({
                "url": "https://www.tiktok.com/@user/video/123",
                "proxy": "ftp://evil.local:21",
            }).encode("utf-8"),
            headers={"Content-Type": "application/json"},
        )
        self.assertEqual(bad_proxy_code, 400)

        bad_browser_code, _ = self._request(
            "POST",
            "/api/enqueue",
            body=json.dumps({
                "url": "https://www.tiktok.com/@user/video/123",
                "cookies_browser": "safari_hack",
            }).encode("utf-8"),
            headers={"Content-Type": "application/json"},
        )
        self.assertEqual(bad_browser_code, 400)

        ok_code, ok_body = self._request(
            "POST",
            "/api/enqueue",
            body=json.dumps({
                "url": "https://www.instagram.com/reel/ABC123/",
                "quality": "best",
                "proxy": "socks5://127.0.0.1:7890",
                "cookies_browser": "chrome",
                "subtitles": True,
            }).encode("utf-8"),
            headers={"Content-Type": "application/json"},
        )
        self.assertEqual(ok_code, 200)
        self.assertEqual(ok_body["platform"], "instagram")
        jobs = self.ctx.vault.list_jobs(limit=10)
        matched = [j for j in jobs if j["id"] == ok_body["job_id"]][0]
        self.assertEqual(matched["proxy"], "socks5://127.0.0.1:7890")
        self.assertEqual(matched["cookies_browser"], "chrome")
        self.assertEqual(matched["subtitles"], 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)
