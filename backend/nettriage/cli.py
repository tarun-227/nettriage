"""Command line: ``nettriage serve`` for the web UI."""

from __future__ import annotations

import argparse


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="nettriage", description="Diagnose packet captures offline.")
    sub = parser.add_subparsers(dest="command", required=True)
    serve = sub.add_parser("serve", help="start the local web UI")
    serve.add_argument("--port", type=int, default=None)
    args = parser.parse_args(argv)

    if args.command == "serve":
        import uvicorn

        from .config import load_server_settings
        from .main import create_app

        settings = load_server_settings()
        uvicorn.run(create_app(), host=settings.host, port=args.port or settings.port, log_level="info")
    return 0
