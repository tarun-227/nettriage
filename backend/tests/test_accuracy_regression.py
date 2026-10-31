"""Guard the accuracy we have reached on the committed scenario captures.

This is a regression net, not the accuracy claim: the reported numbers come from
held-out seeds via eval/run_eval.py.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
SCENARIOS = ROOT / "samples" / "scenarios"
sys.path.insert(0, str(ROOT / "eval"))

run_eval = pytest.importorskip("run_eval")

BUILT = {"arp_spoofing", "duplicate_ip", "host_unreachable", "port_scan", "tcp_retransmissions",
         "connection_refused", "high_latency"}


@pytest.fixture(scope="module")
def results():
    if not any(SCENARIOS.glob("*.labels.json")):
        pytest.skip("scenario captures not generated")
    return run_eval.evaluate(SCENARIOS)


def test_no_false_alarms(results):
    assert results.negative_alarms == 0, results.false_alarms
    assert sum(t.fp for t in results.per_kind.values()) == 0, results.false_alarms


def test_built_detectors_find_every_labelled_problem(results):
    missed = {k: t.fn for k, t in results.per_kind.items() if k in BUILT and t.fn}
    assert not missed, results.misses


def test_verdicts_are_never_swapped(results):
    assert results.verdicts.get(("attack", "fault"), 0) == 0
    assert results.verdicts.get(("fault", "attack"), 0) == 0


def test_one_directional_capture_is_recognised(results):
    assert results.quality_hits == results.quality_expected
