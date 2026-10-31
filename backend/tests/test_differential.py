from nettriage.reasoning.differential import Differential, HypothesisDef, Observation, Rule
from nettriage.schema import Verdict

ENGINE = Differential(
    [
        HypothesisDef("spoof", "ARP spoofing", Verdict.ATTACK, prior=-1.0),
        HypothesisDef("dup", "Duplicate IP", Verdict.FAULT, prior=0.0),
        HypothesisDef("failover", "Router failover", Verdict.BENIGN, prior=0.0),
    ],
    [
        Rule("unsolicited", "spoof", 3.0, "{count} unsolicited ARP replies"),
        Rule("unsolicited", "dup", -1.0, "Duplicate IPs rarely send unsolicited replies"),
        Rule("vrrp", "failover", 4.0, "VRRP traffic seen"),
    ],
)


def test_strong_evidence_gives_confident_attack_with_reasons():
    d = ENGINE.diagnose([Observation("unsolicited", [3, 4], {"count": 42})])
    assert d.verdict == Verdict.ATTACK and d.confidence > 0.8 and d.is_alert
    spoof = next(h for h in d.hypotheses if h.key == "spoof")
    assert spoof.evidence[0].reason == "42 unsolicited ARP replies"
    assert spoof.evidence[0].frames == [3, 4]
    assert abs(sum(h.probability for h in d.hypotheses) - 1) < 1e-3


def test_benign_explanation_wins():
    d = ENGINE.diagnose([Observation("vrrp")])
    assert d.verdict == Verdict.BENIGN and not d.is_alert


def test_weak_evidence_needs_review():
    d = ENGINE.diagnose([Observation("unsolicited", strength=0.55)])
    assert d.top == "spoof" and d.confidence < 0.6
    assert d.verdict == Verdict.NEEDS_REVIEW


def test_insufficient_data_caps_confidence():
    d = ENGINE.diagnose([Observation("unsolicited", detail={"count": 50})], sufficient=False)
    assert d.verdict == Verdict.NEEDS_REVIEW and d.confidence <= 0.5


def test_missing_template_value_does_not_crash():
    d = ENGINE.diagnose([Observation("unsolicited")])
    assert d.hypotheses[0].evidence[0].reason == "{count} unsolicited ARP replies"
