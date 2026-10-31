"""Proofs for two promises: NetTriage works fully offline, and it never runs external tools."""

from __future__ import annotations

import ast
import socket
from pathlib import Path

import pytest
from nettriage.config import Limits
from nettriage.engine import analyze

PACKAGE = Path(__file__).resolve().parents[1] / "nettriage"
SAMPLES = Path(__file__).resolve().parents[2] / "samples" / "scenarios"

FORBIDDEN_MODULES = {"subprocess", "requests", "httpx", "urllib.request", "http.client", "socketserver",
                     "ftplib", "smtplib", "pyshark", "scapy"}


def _imports(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8-sig"))
    names = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names.update(a.name for a in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            names.add(node.module)
    return names


def test_no_external_tools_or_network_clients_in_the_app():
    offenders = {}
    for path in PACKAGE.rglob("*.py"):
        bad = {m for m in _imports(path) if m in FORBIDDEN_MODULES or m.split(".")[0] in {"subprocess", "scapy"}}
        if bad:
            offenders[str(path.relative_to(PACKAGE))] = bad
    assert not offenders, f"the app must not shell out or make network calls: {offenders}"


def test_analysis_opens_no_network_connections(monkeypatch):
    def refuse(*_args, **_kwargs):
        raise AssertionError("NetTriage tried to use the network")

    monkeypatch.setattr(socket.socket, "connect", refuse)
    monkeypatch.setattr(socket, "create_connection", refuse)
    monkeypatch.setattr(socket, "getaddrinfo", refuse)
    samples = sorted(SAMPLES.glob("*.pcap"))[:8]
    if not samples:
        pytest.skip("scenario captures not generated")
    for pcap in samples:
        analyze(pcap, pcap.name, Limits())
