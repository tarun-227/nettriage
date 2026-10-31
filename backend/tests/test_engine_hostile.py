"""The whole analysis pipeline, not just the decoders, must survive hostile and corrupted captures."""

from __future__ import annotations

import random
from pathlib import Path

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st
from nettriage.config import Limits
from nettriage.engine import analyze
from nettriage.ingest.capture import CaptureFormatError

ROOT = Path(__file__).resolve().parents[2]
MALICIOUS = sorted((ROOT / "samples" / "malicious").glob("*.pcap*"))
SEED_CAPTURE = ROOT / "samples" / "scenarios" / "arp_spoof_mitm.pcap"


@pytest.mark.parametrize("path", MALICIOUS, ids=lambda p: p.name)
def test_engine_handles_every_hostile_sample(path):
    try:
        result = analyze(path, path.name, Limits())
    except CaptureFormatError:
        assert path.name in ("not_a_pcap.exe.pcap", "empty.pcap")
        return
    report = result.report
    assert report.capture.sha256
    assert report.ingest.packets_total >= 0


def test_hostile_strings_never_carry_control_characters():
    report = analyze(ROOT / "samples" / "malicious" / "xss_payloads.pcap", "x.pcap", Limits()).report
    text = report.model_dump_json()
    assert "\x1b" not in text and "‮" not in text


@settings(max_examples=150, deadline=None, suppress_health_check=[HealthCheck.function_scoped_fixture])
@given(seed=st.integers(0, 2**32 - 1), flips=st.integers(1, 200), cut=st.floats(0.05, 1.0))
def test_engine_survives_corrupted_real_capture(tmp_path, seed, flips, cut):
    if not SEED_CAPTURE.exists():
        pytest.skip("scenario captures not generated")
    data = bytearray(SEED_CAPTURE.read_bytes())
    rng = random.Random(seed)
    for _ in range(flips):
        # Leave the 24-byte header mostly intact so the corruption reaches the packets.
        data[rng.randrange(20, len(data))] = rng.randrange(256)
    data = data[: max(24, int(len(data) * cut))]
    path = tmp_path / f"mutant_{seed}.pcap"
    path.write_bytes(bytes(data))
    try:
        analyze(path, path.name, Limits(max_packets=5000))
    except CaptureFormatError:
        pass
