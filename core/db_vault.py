#!/usr/bin/env python3
"""
JCT DownMax Studio - Hardened SQLite WAL Vault (Dieu 201 Compliant).
Supports deduplicated job enqueueing, atomic lease-based worker claiming,
not_before scheduling/deferral, lease renewal, and strict ownership checks.
"""

from __future__ import annotations

import hashlib
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, Iterator, List, Optional


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _utc_iso(dt: Optional[datetime] = None) -> str:
    return (dt or _utc_now()).strftime("%Y-%m-%dT%H:%M:%SZ")


def compute_job_key(url: str, quality: str) -> str:
    normalized = f"{url.strip()}|{quality.strip().lower()}"
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()[:24]


class JobVault:
    """RAII SQLite WAL database manager with atomic lease claiming and deferral."""

    def __init__(self, db_path: Path) -> None:
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_schema()

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        conn = sqlite3.connect(str(self.db_path), timeout=10.0, isolation_level=None)
        conn.row_factory = sqlite3.Row
        try:
            conn.execute("PRAGMA journal_mode=WAL;")
            conn.execute("PRAGMA synchronous=NORMAL;")
            conn.execute("PRAGMA temp_store=MEMORY;")
            conn.execute("PRAGMA wal_autocheckpoint=1000;")
            conn.execute("PRAGMA busy_timeout=5000;")
            yield conn
        finally:
            conn.close()

    def _init_schema(self) -> None:
        with self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE;")
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS jobs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    job_key TEXT NOT NULL,
                    url TEXT NOT NULL,
                    platform TEXT NOT NULL,
                    title TEXT DEFAULT '',
                    quality TEXT NOT NULL DEFAULT 'best',
                    output_dir TEXT NOT NULL,
                    output_path TEXT DEFAULT '',
                    status TEXT NOT NULL DEFAULT 'queued',
                    owner_token TEXT DEFAULT '',
                    lease_until TEXT DEFAULT '',
                    not_before TEXT DEFAULT '',
                    attempts INTEGER NOT NULL DEFAULT 0,
                    error_msg TEXT DEFAULT '',
                    subtitles INTEGER NOT NULL DEFAULT 0,
                    proxy TEXT DEFAULT '',
                    cookies_browser TEXT DEFAULT '',
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                """
            )
            cols = {r["name"] for r in conn.execute("PRAGMA table_info(jobs);").fetchall()}
            if "not_before" not in cols:
                conn.execute("ALTER TABLE jobs ADD COLUMN not_before TEXT DEFAULT '';")
            if "subtitles" not in cols:
                conn.execute("ALTER TABLE jobs ADD COLUMN subtitles INTEGER NOT NULL DEFAULT 0;")
            if "proxy" not in cols:
                conn.execute("ALTER TABLE jobs ADD COLUMN proxy TEXT DEFAULT '';")
            if "cookies_browser" not in cols:
                conn.execute("ALTER TABLE jobs ADD COLUMN cookies_browser TEXT DEFAULT '';")

            conn.execute("CREATE INDEX IF NOT EXISTS idx_jobs_status ON jobs(status);")
            conn.execute(
                """
                CREATE UNIQUE INDEX IF NOT EXISTS idx_active_job_key
                ON jobs(job_key)
                WHERE status IN ('queued', 'probing', 'downloading');
                """
            )
            conn.execute("COMMIT;")

    def integrity_check(self) -> bool:
        with self._connect() as conn:
            row = conn.execute("PRAGMA integrity_check;").fetchone()
            return bool(row and str(row[0]).lower() == "ok")

    def enqueue_job(
        self,
        url: str,
        platform: str,
        output_dir: str,
        quality: str = "best",
        title: str = "",
        subtitles: bool = False,
        proxy: str = "",
        cookies_browser: str = "",
    ) -> int:
        now = _utc_iso()
        job_key = compute_job_key(url, quality)
        with self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE;")
            existing = conn.execute(
                """
                SELECT id FROM jobs
                WHERE job_key = ? AND status IN ('queued', 'probing', 'downloading')
                """,
                (job_key,),
            ).fetchone()
            if existing:
                conn.execute("COMMIT;")
                return int(existing["id"])

            cur = conn.execute(
                """
                INSERT INTO jobs (job_key, url, platform, title, quality, output_dir, status, not_before, subtitles, proxy, cookies_browser, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, 'queued', '', ?, ?, ?, ?, ?)
                """,
                (job_key, url, platform, title, quality, output_dir, int(bool(subtitles)), proxy, cookies_browser, now, now),
            )
            conn.execute("COMMIT;")
            return int(cur.lastrowid)

    def claim_next_job(
        self,
        owner_token: str,
        lease_seconds: int = 360,
        excluded_platforms: Iterable[str] = (),
    ) -> Optional[Dict[str, Any]]:
        """Atomically claims the oldest ready job (respecting not_before & excluded_platforms)."""
        now_dt = _utc_now()
        now_str = _utc_iso(now_dt)
        lease_str = _utc_iso(now_dt + timedelta(seconds=lease_seconds))
        excluded = [str(p) for p in excluded_platforms if p]

        exclusion_sql = ""
        params: List[Any] = [now_str, now_str]
        if excluded:
            placeholders = ",".join("?" for _ in excluded)
            exclusion_sql = f"AND platform NOT IN ({placeholders})"
            params.extend(excluded)

        with self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE;")
            candidate = conn.execute(
                f"""
                SELECT id FROM jobs
                WHERE (
                    (status = 'queued' AND (not_before = '' OR not_before <= ?))
                    OR (status IN ('probing', 'downloading') AND lease_until != '' AND lease_until < ?)
                )
                {exclusion_sql}
                ORDER BY id ASC
                LIMIT 1
                """,
                params,
            ).fetchone()

            if not candidate:
                conn.execute("COMMIT;")
                return None

            job_id = int(candidate["id"])
            cur = conn.execute(
                """
                UPDATE jobs
                SET status = 'downloading',
                    owner_token = ?,
                    lease_until = ?,
                    attempts = attempts + 1,
                    updated_at = ?
                WHERE id = ?
                  AND (
                    (status = 'queued' AND (not_before = '' OR not_before <= ?))
                    OR (status IN ('probing', 'downloading') AND lease_until != '' AND lease_until < ?)
                  )
                """,
                (owner_token, lease_str, now_str, job_id, now_str, now_str),
            )
            if cur.rowcount != 1:
                conn.execute("ROLLBACK;")
                return None

            row = conn.execute("SELECT * FROM jobs WHERE id = ?", (job_id,)).fetchone()
            conn.execute("COMMIT;")
            return dict(row) if row else None

    def renew_lease(self, job_id: int, owner_token: str, lease_seconds: int = 360) -> bool:
        """Extends active lease if owner_token still holds the job."""
        now_dt = _utc_now()
        lease_str = _utc_iso(now_dt + timedelta(seconds=lease_seconds))
        with self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE;")
            cur = conn.execute(
                """
                UPDATE jobs
                SET lease_until = ?, updated_at = ?
                WHERE id = ? AND owner_token = ? AND status IN ('probing', 'downloading')
                """,
                (lease_str, _utc_iso(now_dt), job_id, owner_token),
            )
            conn.execute("COMMIT;")
            return cur.rowcount == 1

    def defer_job(
        self,
        job_id: int,
        owner_token: str,
        delay_seconds: float = 30.0,
        error_msg: Optional[str] = None,
        refund_attempt: bool = True,
    ) -> bool:
        """Returns a claimed job to queued with a not_before delay, optionally refunding attempt count."""
        now_dt = _utc_now()
        not_before = _utc_iso(now_dt + timedelta(seconds=max(0.0, delay_seconds)))
        attempt_expr = "CASE WHEN attempts > 0 THEN attempts - 1 ELSE 0 END" if refund_attempt else "attempts"

        fields = [
            "status = 'queued'",
            "owner_token = ''",
            "lease_until = ''",
            "not_before = ?",
            f"attempts = {attempt_expr}",
            "updated_at = ?",
        ]
        params: List[Any] = [not_before, _utc_iso(now_dt)]
        if error_msg is not None:
            fields.append("error_msg = ?")
            params.append(error_msg)
        params.extend([job_id, owner_token])

        with self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE;")
            cur = conn.execute(
                f"UPDATE jobs SET {', '.join(fields)} WHERE id = ? AND owner_token = ?",
                params,
            )
            conn.execute("COMMIT;")
            return cur.rowcount == 1

    def complete_job(
        self,
        job_id: int,
        owner_token: str,
        status: str,
        title: Optional[str] = None,
        output_path: Optional[str] = None,
        error_msg: Optional[str] = None,
    ) -> bool:
        """Updates final status ONLY if owner_token still owns the job."""
        if status not in ("completed", "failed", "cancelled", "queued"):
            raise ValueError(f"Invalid terminal status: {status}")

        fields = ["status = ?", "owner_token = ''", "lease_until = ''", "not_before = ''", "updated_at = ?"]
        params: List[Any] = [status, _utc_iso()]
        if title is not None:
            fields.append("title = ?")
            params.append(title)
        if output_path is not None:
            fields.append("output_path = ?")
            params.append(output_path)
        if error_msg is not None:
            fields.append("error_msg = ?")
            params.append(error_msg)

        params.extend([job_id, owner_token])
        with self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE;")
            cur = conn.execute(
                f"UPDATE jobs SET {', '.join(fields)} WHERE id = ? AND owner_token = ?",
                params,
            )
            conn.execute("COMMIT;")
            return cur.rowcount == 1

    def get_job(self, job_id: int) -> Optional[Dict[str, Any]]:
        with self._connect() as conn:
            row = conn.execute("SELECT * FROM jobs WHERE id = ?", (job_id,)).fetchone()
            return dict(row) if row else None

    def list_jobs(self, limit: int = 50) -> List[Dict[str, Any]]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM jobs ORDER BY id DESC LIMIT ?", (max(1, limit),)
            ).fetchall()
            return [dict(r) for r in rows]
