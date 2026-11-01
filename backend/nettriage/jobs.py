"""Analysis jobs: each capture is analysed in its own process, with a hard time limit.

A separate process means a pathological capture can be killed outright, and a
crash in it cannot take the web server down. The uploaded file is deleted as
soon as the worker finishes, whatever the outcome.
"""

from __future__ import annotations

import multiprocessing as mp
import os
import queue
import shutil
import tempfile
import threading
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path

from .config import Limits
from .schema import Report

TEMP_PREFIX = "nettriage-"
_CTX = mp.get_context("spawn")


def _worker(path: str, display_name: str, limits: Limits, out: mp.Queue) -> None:
    """Runs in the child process."""
    from .engine import analyze
    from .ingest.capture import CaptureFormatError

    def progress(info: dict) -> None:
        out.put(("progress", info))

    try:
        result = analyze(Path(path), display_name, limits, progress)
        out.put(("done", (result.report.model_dump(mode="json"), result.evidence)))
    except CaptureFormatError as e:
        out.put(("rejected", str(e)))
    except Exception:  # noqa: BLE001 - never leak internals to the client
        out.put(("error", "The capture could not be analysed."))


@dataclass
class Job:
    id: str
    file_name: str
    size: int
    created: float = field(default_factory=time.time)
    status: str = "queued"  # queued, running, done, rejected, error
    message: str = ""
    progress: dict = field(default_factory=dict)
    report: Report | None = None
    evidence: dict[str, bytes] = field(default_factory=dict)
    upload_deleted_at: float | None = None
    finished: threading.Event = field(default_factory=threading.Event)

    def public(self) -> dict:
        return {"id": self.id, "file_name": self.file_name, "size": self.size, "status": self.status,
                "message": self.message, "progress": self.progress, "created": self.created,
                "upload_deleted_at": self.upload_deleted_at}


class JobManager:
    def __init__(self, limits: Limits, ttl_seconds: int, max_queued: int = 4):
        self.limits = limits
        self.ttl = ttl_seconds
        self.max_queued = max_queued
        self.jobs: dict[str, Job] = {}
        self.lock = threading.Lock()
        self.run_lock = threading.Lock()  # one analysis at a time
        sweep_stale_uploads()
        self.upload_dir = Path(tempfile.mkdtemp(prefix=TEMP_PREFIX))
        os.chmod(self.upload_dir, 0o700)

    # --- uploads --------------------------------------------------------

    def new_upload_path(self) -> Path:
        # Recreated if it vanished: another instance's startup sweep or an OS temp cleaner can remove a folder
        # that has been idle for a while.
        self.upload_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        # Never derived from the client's file name, so no path traversal is possible.
        return self.upload_dir / f"{uuid.uuid4().hex}.capture"

    def busy(self) -> bool:
        with self.lock:
            return sum(1 for j in self.jobs.values() if j.status in ("queued", "running")) >= self.max_queued

    # --- jobs -----------------------------------------------------------

    def submit(self, path: Path, file_name: str, size: int, delete_after: bool = True) -> Job:
        job = Job(id=uuid.uuid4().hex, file_name=file_name, size=size)
        with self.lock:
            self._expire()
            self.jobs[job.id] = job
        threading.Thread(target=self._run, args=(job, path, delete_after), daemon=True).start()
        return job

    def get(self, job_id: str) -> Job | None:
        with self.lock:
            return self.jobs.get(job_id)

    def delete(self, job_id: str) -> bool:
        with self.lock:
            return self.jobs.pop(job_id, None) is not None

    def _expire(self) -> None:
        cutoff = time.time() - self.ttl
        for jid in [j.id for j in self.jobs.values() if j.created < cutoff and j.finished.is_set()]:
            del self.jobs[jid]

    def _run(self, job: Job, path: Path, delete_after: bool) -> None:
        try:
            with self.run_lock:
                job.status = "running"
                self._analyse(job, path)
        finally:
            if delete_after:
                try:
                    path.unlink(missing_ok=True)
                finally:
                    job.upload_deleted_at = time.time()
            job.finished.set()

    def _analyse(self, job: Job, path: Path) -> None:
        out: mp.Queue = _CTX.Queue()
        proc = _CTX.Process(target=_worker, args=(str(path), job.file_name, self.limits, out), daemon=True)
        proc.start()
        deadline = time.monotonic() + self.limits.max_analysis_seconds + 30
        try:
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    job.status, job.message = "error", "Analysis took too long and was stopped."
                    return
                try:
                    kind, payload = out.get(timeout=min(remaining, 1.0))
                except queue.Empty:
                    if not proc.is_alive():
                        job.status, job.message = "error", "The capture could not be analysed."
                        return
                    continue
                if kind == "progress":
                    job.progress = payload
                elif kind == "done":
                    report, evidence = payload
                    job.report = Report.model_validate(report)
                    job.evidence = evidence
                    job.status = "done"
                    return
                else:
                    job.status, job.message = kind, payload
                    return
        finally:
            if proc.is_alive():
                proc.kill()
            proc.join(timeout=5)

    def close(self) -> None:
        shutil.rmtree(self.upload_dir, ignore_errors=True)


def sweep_stale_uploads(min_age_seconds: float = 600) -> int:
    """Remove upload folders left behind by a previous run that was killed.

    Only folders older than ``min_age_seconds`` go, so a second running instance keeps its uploads.
    """
    removed = 0
    cutoff = time.time() - min_age_seconds
    for d in Path(tempfile.gettempdir()).glob(f"{TEMP_PREFIX}*"):
        try:
            if d.is_dir() and d.stat().st_mtime < cutoff:
                shutil.rmtree(d, ignore_errors=True)
                removed += 1
        except OSError:
            continue
    return removed
