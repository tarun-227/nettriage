"""Measure NetTriage against labelled captures.

    python eval/run_eval.py samples/scenarios                 # curated set
    python eval/run_eval.py eval/generated/holdout --write    # also update eval/results.md

A label is matched by a finding of the same kind that names at least one of the
label's entities and overlaps its time window (with slack). Findings that are
alerts (attack or fault) and match no label are false alarms. "Needs review"
findings are counted but never treated as alarms.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path

from nettriage.config import Limits
from nettriage.engine import analyze

SLACK = 15.0
ALERT = {"attack", "fault"}


@dataclass
class Tally:
    tp: int = 0
    fn: int = 0
    fp: int = 0

    @property
    def precision(self) -> float | None:
        return self.tp / (self.tp + self.fp) if self.tp + self.fp else None

    @property
    def recall(self) -> float | None:
        return self.tp / (self.tp + self.fn) if self.tp + self.fn else None


@dataclass
class Results:
    captures: int = 0
    per_kind: dict[str, Tally] = field(default_factory=lambda: defaultdict(Tally))
    verdicts: Counter = field(default_factory=Counter)  # (expected, predicted)
    negatives: int = 0
    negative_alarms: int = 0
    needs_review: int = 0
    calibration: list[tuple[float, bool]] = field(default_factory=list)
    quality_hits: int = 0
    quality_expected: int = 0
    misses: list[str] = field(default_factory=list)
    false_alarms: list[str] = field(default_factory=list)
    seconds: float = 0.0
    packets: int = 0


def matches(label: dict, finding) -> bool:
    if finding.kind != label["kind"]:
        return False
    values = {e.value for e in finding.entities}
    if label["entities"] and not values & set(label["entities"]):
        return False
    return finding.time_end >= label["start"] - SLACK and finding.time_start <= label["end"] + SLACK


def evaluate(folder: Path) -> Results:
    res = Results()
    for meta_path in sorted(folder.glob("*.labels.json")):
        meta = json.loads(meta_path.read_text())
        pcap = meta_path.with_name(meta_path.name.replace(".labels.json", ".pcap"))
        report = analyze(pcap, pcap.name, Limits()).report
        res.captures += 1
        res.seconds += report.analysis_seconds
        res.packets += report.ingest.packets_total
        alerts = [f for f in report.findings if f.verdict in ALERT]
        res.needs_review += sum(1 for f in report.findings if f.verdict == "needs_review")
        used: set[str] = set()
        for label in meta["labels"]:
            hit = next((f for f in alerts if f.id not in used and matches(label, f)), None)
            if hit is None:
                # Did we see it but call it something else (wrong verdict or still under review)?
                near = next((f for f in report.findings + report.ruled_out if matches(label, f)), None)
                res.verdicts[(label["verdict"], near.verdict if near else "missed")] += 1
                res.per_kind[label["kind"]].fn += 1
                res.misses.append(f"{pcap.name}: {label['kind']} {label['entities'][:2]}"
                                  + (f" (seen as {near.verdict} {near.confidence:.0%})" if near else ""))
                continue
            used.add(hit.id)
            res.per_kind[label["kind"]].tp += 1
            res.verdicts[(label["verdict"], hit.verdict)] += 1
            res.calibration.append((hit.confidence, hit.verdict == label["verdict"]))
        for f in alerts:
            if f.id not in used:
                res.per_kind[f.kind].fp += 1
                res.calibration.append((f.confidence, False))
                res.false_alarms.append(f"{pcap.name}: {f.kind} {f.verdict} {f.confidence:.0%} - {f.title}")
        if meta["category"] == "negative":
            res.negatives += 1
            res.negative_alarms += sum(1 for f in alerts if f.id not in used)
        for q in meta.get("quality", []):
            res.quality_expected += 1
            res.quality_hits += any(w.code == q for w in report.quality)
    return res


def pct(x: float | None) -> str:
    return "n/a" if x is None else f"{x:.1%}"


def render(res: Results, title: str) -> str:
    lines = [f"## {title}", "",
             f"{res.captures} captures, {res.packets:,} packets, analysed in {res.seconds:.1f} s "
             f"({res.packets / res.seconds:,.0f} packets/s)." if res.seconds else "", "",
             "| Finding kind | TP | FN | FP | Precision | Recall |", "|---|---:|---:|---:|---:|---:|"]
    tot = Tally()
    for kind in sorted(res.per_kind):
        t = res.per_kind[kind]
        tot.tp, tot.fn, tot.fp = tot.tp + t.tp, tot.fn + t.fn, tot.fp + t.fp
        lines.append(f"| {kind} | {t.tp} | {t.fn} | {t.fp} | {pct(t.precision)} | {pct(t.recall)} |")
    lines.append(f"| **all** | **{tot.tp}** | **{tot.fn}** | **{tot.fp}** | **{pct(tot.precision)}** | "
                 f"**{pct(tot.recall)}** |")
    labelled = sum(res.verdicts.values())
    correct = sum(n for (exp, got), n in res.verdicts.items() if exp == got)
    lines += ["", f"**Fault vs. attack:** {correct}/{labelled} labelled problems detected with the right verdict "
                  f"({pct(correct / labelled if labelled else None)}).",
              "", "| Expected \\ Got | attack | fault | needs_review | benign | missed |",
              "|---|---:|---:|---:|---:|---:|"]
    for exp in ("attack", "fault"):
        row = [str(res.verdicts.get((exp, g), 0)) for g in ("attack", "fault", "needs_review", "benign", "missed")]
        lines.append(f"| {exp} | " + " | ".join(row) + " |")
    lines += ["", f"**False alarms on hard negatives:** {res.negative_alarms} across {res.negatives} benign captures.",
              f"**Needs-review findings (not counted as alarms):** {res.needs_review}."]
    if res.quality_expected:
        lines.append(f"**Capture-quality problems recognised:** {res.quality_hits}/{res.quality_expected}.")
    if res.calibration:
        brier = sum((c - (1.0 if ok else 0.0)) ** 2 for c, ok in res.calibration) / len(res.calibration)
        lines += ["", f"**Calibration** (alerts only, Brier score {brier:.3f}; lower is better):", "",
                  "| Stated confidence | Alerts | Actually correct |", "|---|---:|---:|"]
        for lo, hi in ((0.6, 0.8), (0.8, 0.9), (0.9, 0.99), (0.99, 1.01)):
            bucket = [ok for c, ok in res.calibration if lo <= c < hi]
            if bucket:
                lines.append(f"| {lo:.0%}-{min(hi, 1):.0%} | {len(bucket)} | {sum(bucket) / len(bucket):.0%} |")
    if res.misses:
        lines += ["", "<details><summary>Missed</summary>", ""] + [f"- {m}" for m in res.misses] + ["", "</details>"]
    if res.false_alarms:
        lines += ["", "<details><summary>False alarms</summary>", ""] + [f"- {m}" for m in res.false_alarms] + [
            "", "</details>"]
    return "\n".join(lines) + "\n"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("folders", nargs="+", type=Path)
    ap.add_argument("--write", action="store_true", help="write eval/results.md")
    args = ap.parse_args()
    sections = []
    for folder in args.folders:
        if not folder.is_dir():
            print(f"error: {folder} is not a directory", file=sys.stderr)
            return 2
        sections.append(render(evaluate(folder), folder.as_posix()))
    text = "\n".join(sections)
    print(text)
    if args.write:
        out = Path(__file__).with_name("results.md")
        out.write_text(
            "# Accuracy\n\n"
            "Generated by `eval/run_eval.py`. Detector weights were set on the dev seeds (1-3) only. The holdout "
            "seeds (101-105) were generated once and evaluated once, after development.\n\n"
            "**How to read these numbers.** Every capture here comes from our own seeded office simulator "
            "(`samples/generate/`), and the same team wrote the simulator and the detectors. The scores show that "
            "each detector does what it was designed to do. They also show that it stays stable across random "
            "seeds, scenario sizes and background noise, and that it does not fire on the benign look-alikes we "
            "modelled. They are **not** a measurement of accuracy on real networks, which have behaviour we did "
            "not model. Real-tool captures from an isolated lab are the next test.\n\n" + text,
            encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())
