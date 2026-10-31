"""FastAPI application. The API routes are added as the engine comes together."""

from __future__ import annotations

from fastapi import FastAPI

from . import __version__
from .security.headers import SecurityHeadersMiddleware


def create_app() -> FastAPI:
    # No docs UI: it would load scripts from a CDN, which breaks offline use and our CSP.
    app = FastAPI(title="NetTriage", version=__version__, docs_url=None, redoc_url=None)
    app.add_middleware(SecurityHeadersMiddleware)

    @app.get("/api/health")
    def health() -> dict:
        return {"status": "ok", "version": __version__}

    return app
