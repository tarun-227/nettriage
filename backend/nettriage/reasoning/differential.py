"""Differential diagnosis: score competing explanations for one observed issue.

A detector describes an issue (say "two MACs claim 10.0.0.1") as a list of
observations. Each analyzer owns a rule table mapping an observation to a
weight for one hypothesis (Attack, Fault or Benign explanations). Scores are
prior + sum of weights, turned into probabilities with a softmax.

The same rule rows produce the reasoning text shown to the user, so the
explanation can never drift from the score.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from typing import Any

from ..schema import EvidenceItem, Hypothesis, Verdict

ALERT_THRESHOLD = 0.60
INSUFFICIENT_CAP = 0.50


@dataclass(frozen=True, slots=True)
class HypothesisDef:
    key: str
    label: str
    verdict: Verdict
    prior: float = 0.0


@dataclass(frozen=True, slots=True)
class Rule:
    feature: str
    hypothesis: str
    weight: float
    reason: str  # str.format template filled from Observation.detail


@dataclass(slots=True)
class Observation:
    feature: str
    frames: list[int] = field(default_factory=list)
    detail: dict[str, Any] = field(default_factory=dict)
    strength: float = 1.0  # 0..1, scales every rule weight for this feature


@dataclass(slots=True)
class Diagnosis:
    verdict: Verdict
    confidence: float
    margin: float
    top: str
    hypotheses: list[Hypothesis]

    @property
    def is_alert(self) -> bool:
        return self.verdict in (Verdict.ATTACK, Verdict.FAULT)


class Differential:
    def __init__(self, hypotheses: list[HypothesisDef], rules: list[Rule]):
        self.hypotheses = {h.key: h for h in hypotheses}
        self.rules: dict[str, list[Rule]] = {}
        for rule in rules:
            if rule.hypothesis not in self.hypotheses:
                raise ValueError(f"rule for unknown hypothesis {rule.hypothesis!r}")
            self.rules.setdefault(rule.feature, []).append(rule)

    def diagnose(self, observations: list[Observation], sufficient: bool = True) -> Diagnosis:
        scores = {key: h.prior for key, h in self.hypotheses.items()}
        evidence: dict[str, list[EvidenceItem]] = {key: [] for key in self.hypotheses}
        for obs in observations:
            for rule in self.rules.get(obs.feature, ()):
                w = rule.weight * obs.strength
                scores[rule.hypothesis] += w
                evidence[rule.hypothesis].append(EvidenceItem(
                    reason=_fill(rule.reason, obs.detail),
                    weight=round(w, 2),
                    frames=obs.frames[:50],
                ))

        top_score = max(scores.values())
        exps = {k: math.exp(s - top_score) for k, s in scores.items()}
        total = sum(exps.values())
        probs = {k: v / total for k, v in exps.items()}
        ranked = sorted(probs, key=probs.get, reverse=True)
        top = ranked[0]
        confidence = probs[top]
        margin = confidence - (probs[ranked[1]] if len(ranked) > 1 else 0.0)

        verdict = self.hypotheses[top].verdict
        if not sufficient:
            verdict = Verdict.NEEDS_REVIEW
            confidence = min(confidence, INSUFFICIENT_CAP)
        elif verdict in (Verdict.ATTACK, Verdict.FAULT) and confidence < ALERT_THRESHOLD:
            verdict = Verdict.NEEDS_REVIEW

        hypotheses = [
            Hypothesis(
                key=k,
                label=self.hypotheses[k].label,
                verdict=self.hypotheses[k].verdict,
                probability=round(probs[k], 4),
                evidence=sorted(evidence[k], key=lambda e: -abs(e.weight)),
            )
            for k in ranked
        ]
        return Diagnosis(verdict, round(confidence, 4), round(margin, 4), top, hypotheses)


def _fill(template: str, detail: dict[str, Any]) -> str:
    try:
        return template.format(**detail)
    except (KeyError, IndexError, ValueError):
        return template
