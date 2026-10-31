"""Turn a diagnosis into a user-facing Finding, using the winning hypothesis's narrative."""

from __future__ import annotations

import hashlib
import string
from dataclasses import dataclass
from typing import Any

from ..schema import Entity, Finding, KeyPacket, Severity, Verdict
from .differential import Diagnosis


@dataclass(frozen=True, slots=True)
class Narrative:
    """Text shown when this hypothesis wins. Templates use {placeholders} from the detector's context."""

    kind: str
    title: str
    simple: str
    technical: str
    cause: str
    fix: tuple[str, ...]


class _SafeDict(dict):
    def __missing__(self, key: str) -> str:
        return "{" + key + "}"


_FORMATTER = string.Formatter()


def fill(template: str, ctx: dict[str, Any]) -> str:
    try:
        return _FORMATTER.vformat(template, (), _SafeDict(ctx))
    except (ValueError, IndexError, AttributeError):
        return template


# Impact describes how much of the network is at stake; severity combines it with the verdict.
_SEVERITY = {
    Verdict.ATTACK: {"critical_asset": Severity.CRITICAL, "multi_host": Severity.HIGH,
                     "single_host": Severity.HIGH, "minor": Severity.MEDIUM},
    Verdict.FAULT: {"critical_asset": Severity.HIGH, "multi_host": Severity.MEDIUM,
                    "single_host": Severity.MEDIUM, "minor": Severity.LOW},
}


def severity_for(verdict: Verdict, impact: str) -> Severity:
    if verdict == Verdict.BENIGN:
        return Severity.INFO
    if verdict == Verdict.NEEDS_REVIEW:
        return Severity.LOW
    return _SEVERITY[verdict].get(impact, Severity.MEDIUM)


def build_finding(*, analyzer: str, diagnosis: Diagnosis, narratives: dict[str, Narrative], ctx: dict[str, Any],
                  entities: list[Entity], frames: list[int], key_packets: list[KeyPacket], time_start: float,
                  time_end: float, wireshark_filter: str, impact: str, max_frames: int = 200) -> Finding:
    n = narratives[diagnosis.top]
    digest = hashlib.sha1(
        f"{n.kind}|{'|'.join(sorted(e.value for e in entities))}|{time_start:.3f}".encode(),
        usedforsecurity=False,
    ).hexdigest()[:10]
    title = fill(n.title, ctx)
    if diagnosis.verdict == Verdict.NEEDS_REVIEW:
        title = f"Possible: {title[0].lower()}{title[1:]}"
    return Finding(
        id=f"{n.kind}-{digest}",
        analyzer=analyzer,
        kind=n.kind,
        title=title,
        verdict=diagnosis.verdict,
        confidence=diagnosis.confidence,
        margin=diagnosis.margin,
        severity=severity_for(diagnosis.verdict, impact),
        summary_simple=fill(n.simple, ctx),
        summary_technical=fill(n.technical, ctx),
        cause=fill(n.cause, ctx),
        fix_steps=[fill(s, ctx) for s in n.fix],
        hypotheses=diagnosis.hypotheses,
        entities=entities,
        time_start=time_start,
        time_end=time_end,
        frames=sorted(set(frames))[:max_frames],
        key_packets=sorted(key_packets, key=lambda k: k.frame)[:25],
        wireshark_filter=wireshark_filter,
    )
