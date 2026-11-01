"""Runtime limits and settings.

Every limit is a defence against a hostile or broken capture, so each has a hard
default and can only be changed through environment variables, never through
the HTTP API.
"""

from __future__ import annotations

import os
from dataclasses import dataclass

MIB = 1024 * 1024


def _env_int(name: str, default: int, lo: int, hi: int) -> int:
    raw = os.environ.get(name)
    if raw is None:
        return default
    try:
        value = int(raw)
    except ValueError:
        return default
    return max(lo, min(hi, value))


@dataclass(frozen=True, slots=True)
class Limits:
    max_upload_bytes: int = 500 * MIB
    max_packets: int = 5_000_000
    # A single packet record larger than this is treated as file corruption.
    # 256 KiB matches libpcap's largest snapshot length.
    max_record_bytes: int = 262_144
    # pcapng blocks can carry metadata as well as packets; 16 MiB is far above
    # anything a real writer produces.
    max_block_bytes: int = 16 * MIB
    max_analysis_seconds: int = 300
    # Bounded state tables keep a flood of spoofed sources from exhausting memory.
    max_flows: int = 200_000
    max_dns_transactions: int = 100_000
    max_hosts: int = 50_000
    # Evidence frames kept in memory per finding, for evidence.pcap export.
    max_evidence_frames: int = 200
    # Examples of skipped packets kept for the integrity report.
    max_skip_examples: int = 50


def load_limits() -> Limits:
    return Limits(
        max_upload_bytes=_env_int("NETTRIAGE_MAX_UPLOAD_MB", 500, 1, 4096) * MIB,
        max_packets=_env_int("NETTRIAGE_MAX_PACKETS", 5_000_000, 1, 50_000_000),
        max_analysis_seconds=_env_int("NETTRIAGE_MAX_ANALYSIS_SECONDS", 300, 5, 3600),
    )


LOCAL_HOSTS = ("127.0.0.1", "localhost", "[::1]", "::1")


@dataclass(frozen=True, slots=True)
class ServerSettings:
    host: str = "127.0.0.1"
    port: int = 8765
    result_ttl_seconds: int = 3600
    # Host names the server answers to. Anything else is refused, which blocks DNS rebinding.
    allowed_hosts: tuple[str, ...] = LOCAL_HOSTS


def load_server_settings() -> ServerSettings:
    # A hosting platform (Railway) assigns the port in PORT and publishes its domain in
    # RAILWAY_PUBLIC_DOMAIN. There the platform wins: inside its container only all interfaces on
    # its port are reachable, so a copied local setting such as NETTRIAGE_HOST=127.0.0.1 must not
    # take the service down. Everywhere else NETTRIAGE_* settings win.
    extra = [h.strip().lower() for h in os.environ.get("NETTRIAGE_ALLOWED_HOSTS", "").split(",") if h.strip()]
    platform = os.environ.get("RAILWAY_PUBLIC_DOMAIN", "").strip().lower()
    on_railway = bool(os.environ.get("RAILWAY_ENVIRONMENT") or os.environ.get("RAILWAY_ENVIRONMENT_NAME"))
    # Railway's health checker sends Host: healthcheck.railway.app.
    probe = "healthcheck.railway.app" if on_railway else ""
    hosts = LOCAL_HOSTS + tuple(h for h in [*extra, platform, probe] if h and h not in LOCAL_HOSTS)
    if on_railway and os.environ.get("PORT"):
        host, port = "0.0.0.0", _env_int("PORT", 8765, 1, 65535)  # noqa: S104 - container on a platform
    else:
        host = os.environ.get("NETTRIAGE_HOST", "127.0.0.1")
        port = _env_int("NETTRIAGE_PORT", _env_int("PORT", 8765, 1, 65535), 1, 65535)
    return ServerSettings(
        host=host,
        port=port,
        result_ttl_seconds=_env_int("NETTRIAGE_RESULT_TTL_MINUTES", 60, 1, 24 * 60) * 60,
        allowed_hosts=hosts,
    )
