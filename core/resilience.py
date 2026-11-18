#!/usr/bin/env python3
"""
JCT DownMax Studio - Hardened Phase 3 Resilience, Host Circuit Breaker & Queue Worker.
Fixes all Codex GPT Red-Team findings:
- Generation-scoped Circuit Breaker permits with RAII release_permit()
- Strict Drive C (>44.0 GB) & relative-path resolution via resolve_safe_output_dir()
- Non-blocking multi-platform drain_queue() using not_before deferral (0 wasted attempts)
- Strict lease ownership verification on completion
"""

from __future__ import annotations

import shutil
import threading
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Dict, Optional, Set

from core.db_vault import JobVault
from core.media_engine import (
    MediaEnvironment,
    detect_environment,
    download_media,
    resolve_safe_output_dir,
)


class DiskGuardError(RuntimeError):
    """Raised when free disk space does not meet safety policy (>44.0 GB on C:)."""


def check_disk_guard(
    target_dir: Path,
    min_target_gb: float = 2.0,
    min_drive_c_gb: float = 44.0,
    allowed_root: Optional[Path] = None,
) -> Path:
    """Enforces Dieu 185: Drive C must remain strictly >44.0 GB and target dir safe."""
    c_free_gb = shutil.disk_usage("C:").free / (1024 ** 3)
    if c_free_gb <= min_drive_c_gb:
        raise DiskGuardError(
            f"Drive C free space {c_free_gb:.2f}GB must be strictly > {min_drive_c_gb:.1f}GB."
        )

    safe_dir = resolve_safe_output_dir(target_dir, allowed_root=allowed_root)
    anchor = safe_dir
    while not anchor.exists() and anchor.parent != anchor:
        anchor = anchor.parent
    t_free_gb = shutil.disk_usage(anchor).free / (1024 ** 3)
    if t_free_gb < min_target_gb:
        raise DiskGuardError(f"Target drive free space {t_free_gb:.2f}GB is below {min_target_gb:.1f}GB.")
    return safe_dir


@dataclass
class _CircuitState:
    state: str = "CLOSED"  # CLOSED | OPEN | HALF_OPEN
    failures: int = 0
    opened_at: float = 0.0
    generation: int = 1
    half_open_in_flight: bool = False


class HostCircuitBreaker:
    """Per-platform generation-aware Circuit Breaker (CLOSED -> OPEN -> HALF_OPEN)."""

    def __init__(
        self,
        failure_threshold: int = 3,
        cooldown_seconds: float = 60.0,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.failure_threshold = max(1, failure_threshold)
        self.cooldown_seconds = max(0.0, cooldown_seconds)
        self._clock = clock
        self._lock = threading.Lock()
        self._hosts: Dict[str, _CircuitState] = {}

    def allow_request(self, host_key: str) -> Optional[int]:
        """Returns a generation permit integer if allowed, or None if blocked."""
        with self._lock:
            entry = self._hosts.setdefault(host_key, _CircuitState())
            if entry.state == "CLOSED":
                return entry.generation
            if entry.state == "OPEN":
                if (self._clock() - entry.opened_at) >= self.cooldown_seconds:
                    entry.state = "HALF_OPEN"
                    entry.generation += 1
                    entry.half_open_in_flight = True
                    return entry.generation
                return None
            # HALF_OPEN: allow only 1 probe request at a time
            if not entry.half_open_in_flight:
                entry.half_open_in_flight = True
                return entry.generation
            return None

    def release_permit(self, host_key: str, permit: Optional[int]) -> None:
        """Releases an unused HALF_OPEN probe slot on local/non-host errors."""
        if permit is None:
            return
        with self._lock:
            entry = self._hosts.get(host_key)
            if not entry or entry.generation != permit:
                return
            if entry.state == "HALF_OPEN":
                entry.half_open_in_flight = False

    def record_success(self, host_key: str, permit: Optional[int]) -> None:
        """Closes circuit only if the permit matches the current generation."""
        if permit is None:
            return
        with self._lock:
            entry = self._hosts.setdefault(host_key, _CircuitState())
            if entry.generation != permit:
                # Stale completion from an older generation cannot close a newly opened circuit
                return
            entry.state = "CLOSED"
            entry.failures = 0
            entry.opened_at = 0.0
            entry.half_open_in_flight = False

    def record_failure(self, host_key: str, permit: Optional[int]) -> str:
        """Records a host failure only if the permit matches the current generation."""
        with self._lock:
            entry = self._hosts.setdefault(host_key, _CircuitState())
            if permit is not None and entry.generation != permit:
                return entry.state

            entry.half_open_in_flight = False
            if entry.state == "HALF_OPEN":
                entry.state = "OPEN"
                entry.opened_at = self._clock()
                entry.generation += 1
                entry.failures = self.failure_threshold
                return entry.state

            entry.failures += 1
            if entry.failures >= self.failure_threshold:
                entry.state = "OPEN"
                entry.opened_at = self._clock()
                entry.generation += 1
            return entry.state

    def get_state(self, host_key: str) -> str:
        with self._lock:
            entry = self._hosts.get(host_key)
            if not entry:
                return "CLOSED"
            if entry.state == "OPEN" and (self._clock() - entry.opened_at) >= self.cooldown_seconds:
                return "HALF_OPEN"
            return entry.state


_SHARED_DEFAULT_BREAKER = HostCircuitBreaker()


@dataclass
class WorkerStats:
    processed: int = 0
    succeeded: int = 0
    retried: int = 0
    failed: int = 0
    circuit_blocked: int = 0
    lost_lease: int = 0


class QueueWorker:
    """Bounded worker consuming jobs atomically from JobVault with circuit breaking."""

    def __init__(
        self,
        vault: JobVault,
        breaker: Optional[HostCircuitBreaker] = None,
        downloader: Callable[..., Dict[str, object]] = download_media,
        env: Optional[MediaEnvironment] = None,
        max_attempts: int = 3,
        lease_seconds: int = 360,
        defer_seconds: float = 30.0,
        allowed_root: Optional[Path] = None,
        owner_token: Optional[str] = None,
    ) -> None:
        self.vault = vault
        self.breaker = breaker or _SHARED_DEFAULT_BREAKER
        self.downloader = downloader
        self.env = env or detect_environment()
        self.max_attempts = max(1, max_attempts)
        self.lease_seconds = max(30, lease_seconds)
        self.defer_seconds = max(1.0, defer_seconds)
        self.allowed_root = allowed_root
        self.owner_token = owner_token or f"worker-{uuid.uuid4().hex[:8]}"
        self.stats = WorkerStats()

    def process_one(self, excluded_platforms: Set[str] | tuple[str, ...] = ()) -> Optional[Dict[str, object]]:
        job = self.vault.claim_next_job(
            self.owner_token,
            lease_seconds=self.lease_seconds,
            excluded_platforms=excluded_platforms,
        )
        if not job:
            return None

        self.stats.processed += 1
        job_id = int(job["id"])
        platform = str(job["platform"])
        url = str(job["url"])
        output_dir = Path(str(job["output_dir"]))
        quality = str(job["quality"])
        attempts = int(job["attempts"])

        # 1. Validate local path & disk guard BEFORE acquiring a HALF_OPEN probe permit
        try:
            safe_dir = check_disk_guard(output_dir, allowed_root=self.allowed_root)
        except (DiskGuardError, ValueError) as exc:
            self.vault.complete_job(job_id, self.owner_token, "failed", error_msg=str(exc))
            self.stats.failed += 1
            return {"job_id": job_id, "outcome": "local_blocked", "error": str(exc)}

        # 2. Check host circuit breaker
        permit = self.breaker.allow_request(platform)
        if permit is None:
            self.stats.circuit_blocked += 1
            self.vault.defer_job(
                job_id,
                self.owner_token,
                delay_seconds=self.defer_seconds,
                error_msg=f"Circuit breaker OPEN for platform: {platform}",
                refund_attempt=True,
            )
            return {"job_id": job_id, "platform": platform, "outcome": "circuit_blocked"}

        permit_settled = False
        try:
            dl_kwargs: Dict[str, object] = {
                "url": url,
                "output_dir": safe_dir,
                "quality": quality,
                "env": self.env,
                "allowed_root": self.allowed_root,
            }
            if bool(job.get("subtitles")):
                dl_kwargs["subtitles"] = True
            if job.get("proxy"):
                dl_kwargs["proxy"] = str(job["proxy"])
            if job.get("cookies_browser"):
                dl_kwargs["cookies_browser"] = str(job["cookies_browser"])

            result = self.downloader(**dl_kwargs)
            self.breaker.record_success(platform, permit)
            permit_settled = True

            updated = self.vault.complete_job(
                job_id,
                self.owner_token,
                "completed",
                output_path=str(result.get("output_file") or result.get("output_dir") or safe_dir),
            )
            if not updated:
                self.stats.lost_lease += 1
                return {"job_id": job_id, "outcome": "lost_lease"}

            self.stats.succeeded += 1
            return {"job_id": job_id, "outcome": "completed", "result": result}

        except (ValueError, DiskGuardError, FileNotFoundError) as exc:
            # Local/validation error: do NOT penalize the remote host circuit breaker
            self.breaker.release_permit(platform, permit)
            permit_settled = True
            self.vault.complete_job(job_id, self.owner_token, "failed", error_msg=str(exc))
            self.stats.failed += 1
            return {"job_id": job_id, "outcome": "local_blocked", "error": str(exc)}

        except Exception as exc:
            self.breaker.record_failure(platform, permit)
            permit_settled = True
            if attempts < self.max_attempts:
                backoff = min(60.0, float(2 ** max(0, attempts - 1)))
                self.vault.defer_job(
                    job_id,
                    self.owner_token,
                    delay_seconds=backoff,
                    error_msg=str(exc),
                    refund_attempt=False,
                )
                self.stats.retried += 1
                return {"job_id": job_id, "outcome": "requeued", "error": str(exc)}

            self.vault.complete_job(job_id, self.owner_token, "failed", error_msg=str(exc))
            self.stats.failed += 1
            return {"job_id": job_id, "outcome": "failed", "error": str(exc)}

        finally:
            if not permit_settled:
                self.breaker.release_permit(platform, permit)

    def drain_queue(self, max_jobs: int = 20) -> int:
        """Processes ready jobs across platforms without head-of-line blocking."""
        count = 0
        blocked_platforms: Set[str] = set()
        for _ in range(max_jobs):
            outcome = self.process_one(excluded_platforms=blocked_platforms)
            if outcome is None:
                break
            count += 1
            if outcome.get("outcome") == "circuit_blocked":
                plat = str(outcome.get("platform") or "")
                if plat:
                    blocked_platforms.add(plat)
        return count
