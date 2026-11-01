"""FastAPI application: the API plus the bundled web UI."""

from __future__ import annotations

from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from starlette.middleware.trustedhost import TrustedHostMiddleware

from . import __version__
from .api import build_router
from .config import Limits, ServerSettings, load_limits, load_server_settings
from .jobs import JobManager
from .security.headers import SecurityHeadersMiddleware

STATIC = Path(__file__).parent / "static"


def create_app(limits: Limits | None = None, settings: ServerSettings | None = None) -> FastAPI:
    limits = limits or load_limits()
    settings = settings or load_server_settings()
    jobs = JobManager(limits, settings.result_ttl_seconds)

    @asynccontextmanager
    async def lifespan(_app: FastAPI):
        yield
        jobs.close()  # remove the upload folder and anything still in it

    # No docs UI: it would load scripts from a CDN, which breaks offline use and the CSP.
    app = FastAPI(title="NetTriage", version=__version__, docs_url=None, redoc_url=None, openapi_url=None,
                  lifespan=lifespan)
    app.state.jobs = jobs
    # Only answer to known host names: local ones, plus a deployment's own domain when one is
    # configured. This blocks DNS-rebinding attacks, where a web page the user visits points its
    # own domain at 127.0.0.1 to reach this server.
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=list(settings.allowed_hosts))
    app.add_middleware(SecurityHeadersMiddleware)
    app.include_router(build_router(jobs, limits))

    @app.exception_handler(RequestValidationError)
    async def bad_request(_request: Request, _exc: RequestValidationError) -> JSONResponse:
        return JSONResponse({"detail": "Invalid request."}, status_code=400)

    @app.exception_handler(Exception)
    async def internal(_request: Request, _exc: Exception) -> JSONResponse:
        return JSONResponse({"detail": "Something went wrong."}, status_code=500)

    if (STATIC / "index.html").is_file():
        app.mount("/assets", StaticFiles(directory=STATIC / "assets"), name="assets")

        @app.get("/{path:path}", include_in_schema=False)
        def spa(path: str) -> FileResponse:
            if path.startswith("api/"):
                raise HTTPException(404, "Not found.")
            candidate = (STATIC / path).resolve()
            if path and candidate.is_file() and STATIC.resolve() in candidate.parents:
                return FileResponse(candidate)
            return FileResponse(STATIC / "index.html")

    return app
