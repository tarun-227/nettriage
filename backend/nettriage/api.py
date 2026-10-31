"""HTTP API. Everything is local: the server binds to loopback and makes no outbound calls."""

from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path

from fastapi import APIRouter, Header, HTTPException, Request, Response
from fastapi.responses import StreamingResponse

from . import __version__
from .config import Limits
from .ingest.validate import check_extension, sniff
from .jobs import JobManager
from .security.sanitize import display_safe

ID = r"^[0-9a-f]{32}$"
FINDING_ID = r"^[a-z_]+-[0-9a-f]{10}$"
SAMPLE_NAME = r"^[a-z0-9_.]{1,80}$"


def samples_dir() -> Path:
    env = os.environ.get("NETTRIAGE_SAMPLES_DIR")
    return Path(env) if env else Path(__file__).resolve().parents[2] / "samples"


def list_samples() -> dict[str, dict]:
    """Bundled captures, keyed by file name. Only names in this listing can be analysed."""
    out: dict[str, dict] = {}
    base = samples_dir()
    for meta_path in sorted((base / "scenarios").glob("*.labels.json")):
        try:
            meta = json.loads(meta_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        pcap = meta_path.with_name(meta_path.name.replace(".labels.json", ".pcap"))
        if pcap.is_file():
            out[pcap.name] = {"name": pcap.name, "title": meta.get("title", pcap.name),
                              "description": meta.get("description", ""), "category": meta.get("category", ""),
                              "size": pcap.stat().st_size, "path": pcap}
    for pcap in sorted((base / "malicious").glob("*.pcap*")):
        out[pcap.name] = {"name": pcap.name, "title": pcap.name, "description": "Hostile or broken file, to show "
                          "safe handling.", "category": "malicious", "size": pcap.stat().st_size, "path": pcap}
    return out


def build_router(jobs: JobManager, limits: Limits) -> APIRouter:
    r = APIRouter(prefix="/api")

    @r.get("/health")
    def health() -> dict:
        return {"status": "ok", "version": __version__}

    @r.get("/config")
    def config() -> dict:
        return {"version": __version__, "max_upload_bytes": limits.max_upload_bytes,
                "max_packets": limits.max_packets, "max_analysis_seconds": limits.max_analysis_seconds,
                "retention_minutes": jobs.ttl // 60, "offline": True,
                "accepted_extensions": [".pcap", ".pcapng", ".cap"]}

    @r.post("/analyses", status_code=202)
    async def upload(request: Request, x_filename: str = Header(default="capture.pcap", max_length=255)) -> dict:
        # The name is only ever displayed; it never touches the file system.
        name = display_safe(Path(x_filename.replace("\\", "/")).name or "capture.pcap", 120)
        if not check_extension(name):
            raise HTTPException(415, "Only .pcap, .pcapng and .cap files are accepted.")
        declared = request.headers.get("content-length")
        if declared and declared.isdigit() and int(declared) > limits.max_upload_bytes:
            raise HTTPException(413, f"File is larger than the {limits.max_upload_bytes // (1024 * 1024)} MB limit.")
        if jobs.busy():
            raise HTTPException(429, "Too many analyses are running; try again shortly.")
        path = jobs.new_upload_path()
        size, head, checked = 0, b"", False
        try:
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0), 0o600)
            with os.fdopen(fd, "wb") as f:
                async for chunk in request.stream():
                    size += len(chunk)
                    if size > limits.max_upload_bytes:
                        raise HTTPException(413, "File is larger than the "
                                                 f"{limits.max_upload_bytes // (1024 * 1024)} MB limit.")
                    if not checked:
                        head += chunk[: 24 - len(head)]
                        if len(head) >= 24:
                            _reject_unless_capture(head)
                            checked = True
                    f.write(chunk)
            if not checked:
                _reject_unless_capture(head)
        except BaseException:
            path.unlink(missing_ok=True)
            raise
        return {"id": jobs.submit(path, name, size).id}

    @r.get("/analyses/{job_id}")
    def status(job_id: str = _path(ID)) -> dict:
        job = _job(jobs, job_id)
        data = job.public()
        if job.report is not None:
            data["report"] = job.report.model_dump(mode="json")
        return data

    @r.get("/analyses/{job_id}/events")
    async def events(request: Request, job_id: str = _path(ID)) -> StreamingResponse:
        job = _job(jobs, job_id)

        async def stream():
            last = None
            while True:
                snapshot = json.dumps(job.public())
                if snapshot != last:
                    yield f"data: {snapshot}\n\n"
                    last = snapshot
                if job.finished.is_set() or await request.is_disconnected():
                    break
                await asyncio.sleep(0.25)
            yield f"data: {json.dumps(job.public())}\n\n"

        return StreamingResponse(stream(), media_type="text/event-stream")

    @r.get("/analyses/{job_id}/evidence/{finding_id}")
    def evidence(job_id: str = _path(ID), finding_id: str = _path(FINDING_ID)) -> Response:
        job = _job(jobs, job_id)
        data = job.evidence.get(finding_id)
        if data is None:
            raise HTTPException(404, "No evidence for that finding.")
        return Response(data, media_type="application/vnd.tcpdump.pcap",
                        headers={"Content-Disposition": f'attachment; filename="evidence-{finding_id}.pcap"'})

    @r.get("/analyses/{job_id}/report")
    def report(job_id: str = _path(ID)) -> Response:
        job = _job(jobs, job_id)
        if job.report is None:
            raise HTTPException(409, "The analysis has not finished.")
        return Response(job.report.model_dump_json(indent=2), media_type="application/json",
                        headers={"Content-Disposition": f'attachment; filename="nettriage-{job_id[:8]}.json"'})

    @r.delete("/analyses/{job_id}", status_code=204)
    def delete(job_id: str = _path(ID)) -> Response:
        if not jobs.delete(job_id):
            raise HTTPException(404, "No such analysis.")
        return Response(status_code=204)

    @r.get("/samples")
    def samples() -> list[dict]:
        return [{k: v for k, v in s.items() if k != "path"} for s in list_samples().values()]

    @r.post("/samples/{name}", status_code=202)
    def analyse_sample(name: str = _path(SAMPLE_NAME)) -> dict:
        sample = list_samples().get(name)
        if sample is None:
            raise HTTPException(404, "No such sample.")
        if jobs.busy():
            raise HTTPException(429, "Too many analyses are running; try again shortly.")
        head = sample["path"].read_bytes()[:24]
        _reject_unless_capture(head)
        return {"id": jobs.submit(sample["path"], name, sample["size"], delete_after=False).id}

    return r


def _path(pattern: str):
    from fastapi import Path as PathParam

    return PathParam(pattern=pattern)


def _job(jobs: JobManager, job_id: str):
    job = jobs.get(job_id)
    if job is None:
        raise HTTPException(404, "No such analysis. Results are kept only for a limited time.")
    return job


def _reject_unless_capture(head: bytes) -> None:
    result = sniff(head)
    if not result.ok:
        raise HTTPException(415, result.message)
