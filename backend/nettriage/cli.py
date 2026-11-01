"""Command line: ``nettriage serve`` for the web UI, ``nettriage analyze`` for a terminal report."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .security.sanitize import strip_ansi

VERDICT_LABEL = {"attack": "ATTACK", "fault": "FAULT", "needs_review": "REVIEW", "benign": "OK"}


def _print_report(report, show_ruled_out: bool) -> None:
    out = []
    cap = report.capture
    out.append(f"{cap.file_name}  {report.ingest.packets_total:,} packets, {cap.duration:.1f} s, "
               f"{report.devices} devices  (analysed in {report.analysis_seconds:.2f} s)")
    out.append(f"sha256 {cap.sha256}")
    for w in report.quality:
        out.append(f"  ! {w.message} {w.detail}")
    if not report.findings:
        out.append("\nNo problems found.")
    for f in report.findings:
        out.append(f"\n[{VERDICT_LABEL[f.verdict]} {f.confidence:.0%} {f.severity}] {f.title}")
        out.append(f"  {f.summary_simple}")
        out.append("  Why: " + "; ".join(e.reason for e in f.hypotheses[0].evidence[:4]))
        alt = f.hypotheses[1] if len(f.hypotheses) > 1 else None
        if alt:
            out.append(f"  Next most likely: {alt.label} ({alt.probability:.0%})")
        out.append(f"  Fix: {f.fix_steps[0]}")
        out.append(f"  Evidence: frames {', '.join(map(str, f.frames[:12]))}{' ...' if len(f.frames) > 12 else ''}"
                   f"   Wireshark: {f.wireshark_filter}")
    if show_ruled_out and report.ruled_out:
        out.append("\nChecked and ruled out:")
        for f in report.ruled_out:
            out.append(f"  - {f.title} ({f.confidence:.0%}): {f.summary_simple}")
    # Packet-derived text is already escaped; strip ANSI anyway so nothing can drive the terminal.
    print(strip_ansi("\n".join(out)))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="nettriage", description="Diagnose packet captures offline.")
    sub = parser.add_subparsers(dest="command", required=True)
    serve = sub.add_parser("serve", help="start the local web UI")
    serve.add_argument("--port", type=int, default=None)
    an = sub.add_parser("analyze", help="analyse a capture and print the findings")
    an.add_argument("capture", type=Path)
    an.add_argument("--json", action="store_true", help="print the full report as JSON")
    an.add_argument("--all", action="store_true", help="also list what was checked and ruled out")
    an.add_argument("--evidence-dir", type=Path, help="write one evidence pcap per finding here")
    pr = sub.add_parser("proof", help="analyse a capture and write a privacy-safe, tamper-evident Proof Pack")
    pr.add_argument("capture", type=Path)
    pr.add_argument("--out", type=Path, help="where to write the zip (default: next to the capture)")
    ve = sub.add_parser("verify", help="check that a Proof Pack has not been changed")
    ve.add_argument("pack", type=Path)
    ve.add_argument("--root", help="the root hash you were given with the pack")
    args = parser.parse_args(argv)

    if args.command == "verify":
        from .evidence.proofpack import MAX_TOTAL_BYTES, verify_proof_pack

        if not args.pack.is_file() or args.pack.stat().st_size > MAX_TOTAL_BYTES:
            print(f"error: {args.pack} is not a file of a sensible size", file=sys.stderr)
            return 2
        v = verify_proof_pack(args.pack.read_bytes(), args.root)
        print(strip_ansi(f"{'VERIFIED' if v.ok else 'NOT VERIFIED'}  root {v.root or '-'}  ({v.files} files)"))
        if v.source_capture_sha256:
            print(f"  from capture sha256 {v.source_capture_sha256}, packed {v.created}")
        if not args.root and v.ok:
            print("  Compare this root with the one you were given; a pack can be rebuilt, the root you hold can't.")
        for p in v.problems:
            print(strip_ansi(f"  - {p}"))
        return 0 if v.ok else 1

    if args.command == "serve":
        import uvicorn

        from .config import load_server_settings
        from .main import create_app

        settings = load_server_settings()
        uvicorn.run(create_app(), host=settings.host, port=args.port or settings.port, log_level="info")
        return 0

    from .config import load_limits
    from .engine import analyze
    from .ingest.capture import CaptureFormatError

    path: Path = args.capture
    if not path.is_file():
        print(f"error: {path} is not a file", file=sys.stderr)
        return 2
    try:
        result = analyze(path, path.name, load_limits())
    except CaptureFormatError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    if args.command == "proof":
        from .evidence.proofpack import build_proof_pack

        pack = build_proof_pack(result.report, result.evidence)
        out: Path = args.out or path.with_name(f"{path.stem}.proof.zip")
        out.write_bytes(pack.data)
        print(f"Wrote {out} ({len(pack.data):,} bytes, {len(pack.files)} files)")
        print(f"Root hash: {pack.root}")
        print("Share the root hash separately from the zip. Anyone can check the pack with:")
        print(f"  nettriage verify {out.name} --root {pack.root}")
        return 0
    if args.json:
        print(json.dumps(result.report.model_dump(mode="json"), indent=2))
    else:
        _print_report(result.report, args.all)
    if args.evidence_dir:
        args.evidence_dir.mkdir(parents=True, exist_ok=True)
        for fid, data in result.evidence.items():
            (args.evidence_dir / f"{fid}.pcap").write_bytes(data)
    return 0
