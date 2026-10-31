"""Run every detector over a capture in one streaming pass and assemble the Report."""

from __future__ import annotations

import hashlib
import time
from collections import Counter
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

from .config import Limits
from .decode.layers import linktype_name
from .decode.model import Packet
from .detectors.arp import ArpDetector
from .detectors.base import Context, Detector, is_multicast_mac, is_public_unicast
from .detectors.portscan import PortScanDetector
from .detectors.tcp import TcpHealthDetector
from .evidence.pcapwriter import pcap_bytes
from .ingest.capture import IngestCounters, RawPacket, read_capture
from .ingest.stream import stream_packets
from .schema import (
    CaptureInfo,
    Finding,
    IngestStats,
    IntegrityCheck,
    Report,
    SkipExample,
    TimelineBucket,
    Verdict,
)
from .security.sanitize import display_safe

# Order matters at finalize time: the scan detector marks scanners so the TCP
# health detector can leave their failed connections out.
DETECTORS: list[type[Detector]] = [ArpDetector, PortScanDetector, TcpHealthDetector]

ProgressFn = Callable[[dict], None]
_BUCKET_SIZES = [1, 2, 5, 10, 15, 30, 60, 120, 300, 600, 900, 1800, 3600, 7200, 21600, 43200, 86400]
_PROGRESS_EVERY = 5000


@dataclass
class AnalysisResult:
    report: Report
    evidence: dict[str, bytes] = field(default_factory=dict)  # finding id -> pcap bytes


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _protocol(p: Packet) -> str:
    if p.arp:
        return "ARP"
    if p.dhcp:
        return "DHCP"
    if p.dns:
        return "mDNS" if p.dns.multicast else "DNS"
    if p.tcp:
        return "TCP"
    if p.udp:
        return "UDP"
    if p.icmp:
        return "ICMP" if p.icmp.version == 4 else "ICMPv6"
    if p.ip:
        return "IPv4 other" if p.ip.version == 4 else "IPv6 other"
    return "Other"


def _timeline(per_second: dict[int, list[int]], first: float, duration: float) -> list[TimelineBucket]:
    if not per_second:
        return []
    size = next((s for s in _BUCKET_SIZES if duration / s <= 120), _BUCKET_SIZES[-1])
    buckets: dict[int, list[int]] = {}
    for sec, (pk, by) in per_second.items():
        b = buckets.setdefault(sec // size, [0, 0])
        b[0] += pk
        b[1] += by
    last = int(duration // size)
    return [TimelineBucket(t=first + i * size, packets=buckets.get(i, [0, 0])[0], bytes=buckets.get(i, [0, 0])[1])
            for i in range(last + 1)]


def _sanitize(obj):
    if isinstance(obj, str):
        return display_safe(obj)
    if isinstance(obj, list):
        return [_sanitize(v) for v in obj]
    if isinstance(obj, dict):
        return {k: _sanitize(v) for k, v in obj.items()}
    return obj


def _quality(ctx: Context, counters: IngestCounters) -> None:
    silent = ctx.silent_macs()
    if silent and ctx.tx_by_mac:
        heavy = sorted(silent, key=lambda m: -ctx.rx_by_mac[m])
        ctx.warn("one_directional",
                 "Only one direction of traffic was captured for some devices.",
                 f"{len(silent)} device(s), e.g. {heavy[0]}, received {ctx.rx_by_mac[heavy[0]]} frames but sent none. "
                 "Replies from them are missing, so NetTriage will not blame them for not answering. "
                 "Capture on a mirror port that copies both directions.")
    if counters.skipped:
        ctx.warn("skipped_packets", f"{counters.skipped:,} damaged or unsupported packet(s) were skipped.",
                 "; ".join(f"{r}: {n}" for r, n in counters.skip_reasons.most_common(5)))
    if counters.stopped_early:
        ctx.warn("stopped_early", "The capture could not be read to the end.", counters.stop_reason or "")


def analyze(path: Path, display_name: str, limits: Limits, progress: ProgressFn | None = None) -> AnalysisResult:
    """Analyse one capture file. Raises CaptureFormatError if it is not a capture."""
    started = time.perf_counter()
    size = path.stat().st_size
    sha = sha256_file(path)
    counters = IngestCounters(limits=limits)
    ctx = Context(limits=limits, counters=counters)
    detectors = [cls(limits) for cls in DETECTORS]
    protocols: Counter = Counter()
    per_second: dict[int, list[int]] = {}
    ips: set[str] = set()
    devices: set[str] = set()
    first = last = None
    n = 0

    with open(path, "rb", buffering=1 << 20) as f:
        for p in stream_packets(f, limits, counters):
            n += 1
            if p.error and p.link is None and p.ip is None:
                continue
            ts = p.ts
            if first is None:
                first = ts
            last = ts if last is None or ts > last else last
            protocols[_protocol(p)] += 1
            if first is not None:
                sec = int(ts - first) if ts >= first else 0
                b = per_second.get(sec)
                if b is None:
                    if len(per_second) < 200_000:
                        per_second[sec] = [1, p.wire_len]
                else:
                    b[0] += 1
                    b[1] += p.wire_len
            link = p.link
            if link and link.src and not is_multicast_mac(link.src):
                ctx.tx_by_mac[link.src] += 1
                if len(devices) < limits.max_hosts:
                    devices.add(link.src)
            if link and link.dst and not is_multicast_mac(link.dst):
                ctx.rx_by_mac[link.dst] += 1
            if p.dns and p.dns.qr and len(ctx.dns_answers) < limits.max_dns_transactions:
                ctx.dns_answers.update(a.data for a in p.dns.answers if a.rtype in (1, 28))
            if p.ip:
                if len(ips) < limits.max_hosts:
                    ips.add(p.ip.src)
                if link and link.src and is_public_unicast(p.ip.src):
                    ctx.offsubnet_macs[link.src] += 1
                if link and link.dst and not is_multicast_mac(link.dst):
                    m = ctx.rx_ip_mac.get(p.ip.dst)
                    if m is None and len(ctx.rx_ip_mac) < limits.max_hosts:
                        m = ctx.rx_ip_mac[p.ip.dst] = Counter()
                    if m is not None:
                        m[link.dst] += 1
            for d in detectors:
                d.on_packet(p)
            if n % _PROGRESS_EVERY == 0:
                elapsed = time.perf_counter() - started
                if elapsed > limits.max_analysis_seconds:
                    counters.stop(f"Stopped after the {limits.max_analysis_seconds}-second analysis time limit.")
                    break
                if progress:
                    progress({"stage": "analyze", "packets": n, "skipped": counters.skipped,
                              "bytes": f.tell(), "size": size})

    ctx.first_ts, ctx.last_ts = first, last
    if progress:
        progress({"stage": "explain", "packets": n, "skipped": counters.skipped, "bytes": size, "size": size})
    findings: list[Finding] = []
    for d in detectors:
        findings.extend(d.finalize(ctx))
    _quality(ctx, counters)

    order = {Verdict.ATTACK: 0, Verdict.FAULT: 1, Verdict.NEEDS_REVIEW: 2, Verdict.BENIGN: 3}
    sev = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    findings.sort(key=lambda f: (order[f.verdict], sev[f.severity], -f.confidence, f.time_start))
    alerts = [f for f in findings if f.verdict != Verdict.BENIGN]
    ruled_out = [f for f in findings if f.verdict == Verdict.BENIGN]

    evidence = _collect_evidence(path, limits, alerts + ruled_out)
    for f in alerts + ruled_out:
        f.has_evidence_pcap = f.id in evidence

    duration = (last - first) if first is not None and last is not None else 0.0
    report = Report(
        capture=CaptureInfo(file_name=display_name, sha256=sha, size_bytes=size, first_ts=first, last_ts=last,
                            duration=duration),
        ingest=IngestStats(
            format=counters.format,
            link_types=sorted({linktype_name(lt) for lt in counters.link_types}),
            packets_total=counters.frames,
            packets_decoded=counters.decoded,
            packets_skipped=counters.skipped,
            skip_reasons=dict(counters.skip_reasons),
            skip_examples=[SkipExample(frame=fr, reason=r) for fr, r in counters.skip_examples],
            stopped_early=counters.stopped_early,
            stop_reason=counters.stop_reason,
            state_caps_hit=sorted(counters.state_caps_hit),
        ),
        integrity=[
            IntegrityCheck(name="Format check", passed=True,
                           detail=f"{counters.format} signature found before parsing"),
            IntegrityCheck(name="Size limit", passed=size <= limits.max_upload_bytes,
                           detail=f"{size:,} bytes (limit {limits.max_upload_bytes:,})"),
            IntegrityCheck(name="Read to the end", passed=not counters.stopped_early,
                           detail=counters.stop_reason or "every record was read"),
            IntegrityCheck(name="Damaged packets isolated", passed=True,
                           detail=f"{counters.skipped:,} skipped without affecting the rest"),
        ],
        quality=ctx.quality,
        findings=alerts,
        ruled_out=ruled_out,
        hosts=len(ips),
        devices=len(devices),
        protocols=dict(protocols.most_common()),
        timeline=_timeline(per_second, first or 0.0, duration),
        analysis_seconds=round(time.perf_counter() - started, 3),
    )
    report = Report.model_validate(_sanitize(report.model_dump()))
    return AnalysisResult(report=report, evidence=evidence)


def _collect_evidence(path: Path, limits: Limits, findings: list[Finding]) -> dict[str, bytes]:
    """Second pass: copy each finding's evidence frames into a small pcap of its own."""
    wanted: dict[int, list[str]] = {}
    for f in findings:
        for fr in f.frames[: limits.max_evidence_frames]:
            wanted.setdefault(fr, []).append(f.id)
    if not wanted:
        return {}
    per_finding: dict[str, list[RawPacket]] = {}
    linktypes: dict[str, int] = {}
    counters = IngestCounters(limits=limits)
    top = max(wanted)
    with open(path, "rb", buffering=1 << 20) as fh:
        for raw in read_capture(fh, limits, counters):
            ids = wanted.get(raw.frame)
            if ids:
                for fid in ids:
                    per_finding.setdefault(fid, []).append(raw)
                    linktypes.setdefault(fid, raw.linktype)
            if raw.frame >= top:
                break
    return {fid: pcap_bytes(((r.ts_ns, r.data, r.wire_len) for r in raws if r.linktype == linktypes[fid]),
                            linktypes[fid])
            for fid, raws in per_finding.items()}
